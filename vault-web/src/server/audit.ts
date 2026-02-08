import { promises as fs } from 'node:fs'
import path from 'node:path'
import { createReadStream } from 'node:fs'
import readline from 'node:readline'
import { Readable, Transform } from 'node:stream'
import crypto from 'node:crypto'
import { env } from '../env/server'

export type AuditEvent = {
  timestamp: string
  action: string
  detail: string
  source?: string
}

export type AuditRecord = AuditEvent & {
  seq?: number
  prevHash?: string
  hash?: string
  version?: number
  valid?: boolean
}

export type AuditIntegritySummary = {
  total: number
  valid: number
  invalid: number
  lastHash?: string
  lastSeq?: number
  hasLegacy: boolean
}

const AUDIT_DIR = path.join(process.cwd(), '.data')
const AUDIT_FILE = path.join(AUDIT_DIR, 'audit.log')
const AUDIT_HASH_VERSION = 1
const GENESIS_HASH = 'genesis'
const AUDIT_STORAGE = env.INTERNAL_UI_AUDIT_STORAGE || 'file'

const ensureAuditFile = async () => {
  if (AUDIT_STORAGE !== 'file') {
    // Log here to make unexpected storage configuration visible in logs.
    // Keeping it server-side only to avoid leaking to clients.
    const { serverLogger } = await import('../lib/server-logger')
    serverLogger.warn('Unsupported audit storage configured', {
      storage: AUDIT_STORAGE,
    })
    throw new Error(
      `Unsupported audit storage: ${AUDIT_STORAGE}. Only 'file' is available right now.`,
    )
  }
  await fs.mkdir(AUDIT_DIR, { recursive: true })
  try {
    await fs.access(AUDIT_FILE)
  } catch {
    await fs.writeFile(AUDIT_FILE, '')
  }
}

type AuditTail = { hash: string; seq: number }
let cachedTail: AuditTail | null = null

const computeAuditHash = (prevHash: string, payload: AuditEvent & { seq: number; version: number }) => {
  const hash = crypto.createHash('sha256')
  hash.update(prevHash)
  hash.update(JSON.stringify(payload))
  return hash.digest('hex')
}

const readLastLine = async (): Promise<string | null> => {
  await ensureAuditFile()
  const file = await fs.open(AUDIT_FILE, 'r')
  try {
    const stats = await file.stat()
    if (stats.size === 0) return null

    let position = stats.size
    let buffer = Buffer.alloc(Math.min(4096, position))
    let data = ''

    while (position > 0 && !data.includes('\n')) {
      const readSize = Math.min(buffer.length, position)
      position -= readSize
      const { bytesRead } = await file.read(buffer, 0, readSize, position)
      data = buffer.toString('utf8', 0, bytesRead) + data
      if (position === 0) break
      if (readSize === buffer.length && buffer.length < 64 * 1024) {
        buffer = Buffer.alloc(Math.min(buffer.length * 2, 64 * 1024))
      }
    }

    const lines = data.trim().split('\n')
    return lines.length ? lines[lines.length - 1] : null
  } finally {
    await file.close()
  }
}

const getTailState = async (): Promise<AuditTail> => {
  if (cachedTail) return cachedTail
  const lastLine = await readLastLine()
  if (!lastLine) {
    cachedTail = { hash: GENESIS_HASH, seq: 0 }
    return cachedTail
  }
  try {
    const record = JSON.parse(lastLine) as AuditRecord
    if (record.hash && typeof record.seq === 'number') {
      cachedTail = { hash: record.hash, seq: record.seq }
      return cachedTail
    }
  } catch {
    // Ignore malformed last line.
  }
  cachedTail = { hash: GENESIS_HASH, seq: 0 }
  return cachedTail
}

export const appendAuditEvent = async (event: AuditEvent) => {
  await ensureAuditFile()
  const tail = await getTailState()
  const seq = tail.seq + 1
  const base = {
    timestamp: event.timestamp,
    action: event.action,
    detail: event.detail,
    source: event.source,
    seq,
    version: AUDIT_HASH_VERSION,
  }
  const hash = computeAuditHash(tail.hash, base)
  const record: AuditRecord = {
    ...base,
    prevHash: tail.hash,
    hash,
  }
  const line = `${JSON.stringify(record)}\n`
  await fs.appendFile(AUDIT_FILE, line, 'utf8')
  cachedTail = { hash, seq }
}

const loadAuditRecords = async () => {
  await ensureAuditFile()
  const content = await fs.readFile(AUDIT_FILE, 'utf8')
  const lines = content.split('\n').filter(Boolean)

  const records: AuditRecord[] = []
  let prevHash = GENESIS_HASH
  let expectedSeq = 1
  let hasLegacy = false

  for (const line of lines) {
    let record: AuditRecord | null = null
    try {
      record = JSON.parse(line) as AuditRecord
    } catch {
      record = null
    }
    if (!record) continue

    const seq = typeof record.seq === 'number' ? record.seq : null
    const version = typeof record.version === 'number' ? record.version : null
    const base =
      seq && version
        ? {
            timestamp: record.timestamp,
            action: record.action,
            detail: record.detail,
            source: record.source,
            seq,
            version,
          }
        : null

    let valid = false
    if (base && record.hash && record.prevHash) {
      const expected = computeAuditHash(record.prevHash, base)
      valid =
        record.hash === expected &&
        record.prevHash === prevHash &&
        seq === expectedSeq
    } else {
      hasLegacy = true
    }

    record.valid = valid
    records.push(record)

    if (record.hash) {
      prevHash = record.hash
    }
    if (seq !== null) {
      expectedSeq = seq + 1
    }
  }

  const validCount = records.filter((record) => record.valid).length
  const integrity: AuditIntegritySummary = {
    total: records.length,
    valid: validCount,
    invalid: records.length - validCount,
    lastHash: records.length ? records[records.length - 1].hash : undefined,
    lastSeq: records.length ? records[records.length - 1].seq : undefined,
    hasLegacy,
  }

  return { records, integrity }
}

export const readAuditEvents = async (options?: {
  action?: string
  since?: string
  until?: string
  limit?: number
  offset?: number
  sort?: 'asc' | 'desc'
}) => {
  const { records, integrity } = await loadAuditRecords()

  const sinceTime = options?.since ? Date.parse(options.since) : null
  const untilTime = options?.until ? Date.parse(options.until) : null
  const filtered = records.filter((event) => {
    if (options?.action && !event.action.includes(options.action)) {
      return false
    }
    if (sinceTime && !Number.isNaN(sinceTime)) {
      const eventTime = Date.parse(event.timestamp)
      if (Number.isNaN(eventTime) || eventTime < sinceTime) {
        return false
      }
    }
    if (untilTime && !Number.isNaN(untilTime)) {
      const eventTime = Date.parse(event.timestamp)
      if (Number.isNaN(eventTime) || eventTime > untilTime) {
        return false
      }
    }
    return true
  })

  const ordered = options?.sort === 'asc' ? filtered : filtered.reverse()
  const offset = options?.offset ?? 0
  const limited = options?.limit
    ? ordered.slice(offset, offset + options.limit)
    : ordered
  return { events: limited, integrity }
}

export const countAuditEvents = async (options?: {
  action?: string
  since?: string
  until?: string
}) => {
  const { records } = await loadAuditRecords()
  const sinceTime = options?.since ? Date.parse(options.since) : null
  const untilTime = options?.until ? Date.parse(options.until) : null

  return records.filter((event) => {
    if (options?.action && !event.action.includes(options.action)) {
      return false
    }
    if (sinceTime && !Number.isNaN(sinceTime)) {
      const eventTime = Date.parse(event.timestamp)
      if (Number.isNaN(eventTime) || eventTime < sinceTime) {
        return false
      }
    }
    if (untilTime && !Number.isNaN(untilTime)) {
      const eventTime = Date.parse(event.timestamp)
      if (Number.isNaN(eventTime) || eventTime > untilTime) {
        return false
      }
    }
    return true
  }).length
}

export const auditFileSize = async () => {
  try {
    const stats = await fs.stat(AUDIT_FILE)
    return stats.size
  } catch {
    return 0
  }
}

export const streamAuditCsv = async (options?: {
  action?: string
  since?: string
  until?: string
  onBytes?: (bytes: number) => void
}) => {
  await ensureAuditFile()
  const sinceTime = options?.since ? Date.parse(options.since) : null
  const untilTime = options?.until ? Date.parse(options.until) : null
  const stream = createReadStream(AUDIT_FILE, { encoding: 'utf8' })
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity })

  async function* generate() {
    yield 'timestamp,action,detail,source,seq,valid\n'
    let prevHash = GENESIS_HASH
    let expectedSeq = 1
    for await (const line of rl) {
      if (!line) continue
      let event: AuditRecord | null = null
      try {
        event = JSON.parse(line) as AuditRecord
      } catch {
        continue
      }
      if (options?.action && !event.action.includes(options.action)) {
        continue
      }
      if (sinceTime && !Number.isNaN(sinceTime)) {
        const eventTime = Date.parse(event.timestamp)
        if (Number.isNaN(eventTime) || eventTime < sinceTime) {
          continue
        }
      }
      if (untilTime && !Number.isNaN(untilTime)) {
        const eventTime = Date.parse(event.timestamp)
        if (Number.isNaN(eventTime) || eventTime > untilTime) {
          continue
        }
      }
      let valid = false
      if (
        event.hash &&
        event.prevHash &&
        typeof event.seq === 'number' &&
        typeof event.version === 'number'
      ) {
        const base = {
          timestamp: event.timestamp,
          action: event.action,
          detail: event.detail,
          source: event.source,
          seq: event.seq,
          version: event.version,
        }
        const expected = computeAuditHash(event.prevHash, base)
        valid =
          event.hash === expected &&
          event.prevHash === prevHash &&
          event.seq === expectedSeq
      }
      if (event.hash) {
        prevHash = event.hash
      }
      if (typeof event.seq === 'number') {
        expectedSeq = event.seq + 1
      }
      const row = [
        event.timestamp,
        event.action,
        event.detail,
        event.source ?? '',
        event.seq ?? '',
        valid ? 'true' : 'false',
      ]
        .map((value) => `"${String(value ?? '').replace(/\"/g, '""')}"`)
        .join(',')
      yield `${row}\n`
    }
  }

  const readable = Readable.from(generate())
  if (!options?.onBytes) return readable

  const counter = new Transform({
    transform(chunk, _encoding, callback) {
      options.onBytes?.(Buffer.byteLength(chunk))
      callback(null, chunk)
    },
  })

  return readable.pipe(counter)
}

export const getAuditIntegrity = async () => {
  const { integrity } = await loadAuditRecords()
  return integrity
}

export const getAuditStorage = () => AUDIT_STORAGE
