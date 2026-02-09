import { Redis } from 'ioredis'

const SESSION_COOKIE_NAME = 'vault_ui_session'
const CSRF_TOKEN_COOKIE_NAME = 'vault_ui_csrf'
const SESSION_TTL_MS = 1000 * 60 * 60 * 8
const CSRF_TOKEN_TTL_MS = 1000 * 60 * 60 * 24

export type SessionUser = {
  email: string
  name?: string
  role?: 'admin' | 'superadmin'
}

export type SessionRecord = {
  token: string
  createdAt: number
  user: SessionUser
  csrfToken: string
}

type MemoryValue<T> = {
  value: T
  expiresAt: number
}

let redis: Redis | null = null
const memorySessions = new Map<string, MemoryValue<SessionRecord>>()
const memoryCsrf = new Map<string, MemoryValue<string>>()

const getSessionKey = (token: string) => `session:${token}`
const getCsrfKey = (token: string) => `csrf:${token}`

const generateToken = () => crypto.randomUUID()

const generateCsrfToken = () => {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

const cleanupMemory = () => {
  const now = Date.now()
  for (const [token, entry] of memorySessions.entries()) {
    if (entry.expiresAt <= now) {
      memorySessions.delete(token)
    }
  }
  for (const [token, entry] of memoryCsrf.entries()) {
    if (entry.expiresAt <= now) {
      memoryCsrf.delete(token)
    }
  }
}

const getRedis = (): Redis | null => {
  const redisUrl = process.env.REDIS_URL
  if (!redisUrl) {
    return null
  }
  if (redis) {
    return redis
  }

  redis = new Redis(redisUrl, {
    retryStrategy: (attempt: number) => {
      if (attempt > 3) return null
      return Math.min(attempt * 100, 3000)
    },
    maxRetriesPerRequest: 3,
  })
  return redis
}

export const getSessionCookieName = () => SESSION_COOKIE_NAME
export const getCsrfCookieName = () => CSRF_TOKEN_COOKIE_NAME
export const getSessionTtlSeconds = () => Math.floor(SESSION_TTL_MS / 1000)
export const getCsrfTtlSeconds = () => Math.floor(CSRF_TOKEN_TTL_MS / 1000)

export const createSession = async (user: SessionUser): Promise<SessionRecord> => {
  cleanupMemory()

  const token = generateToken()
  const csrfToken = generateCsrfToken()
  const record: SessionRecord = {
    token,
    createdAt: Date.now(),
    user,
    csrfToken,
  }

  const client = getRedis()
  if (!client) {
    memorySessions.set(token, {
      value: record,
      expiresAt: Date.now() + SESSION_TTL_MS,
    })
    memoryCsrf.set(token, {
      value: csrfToken,
      expiresAt: Date.now() + CSRF_TOKEN_TTL_MS,
    })
    return record
  }

  await Promise.all([
    client.setex(getSessionKey(token), getSessionTtlSeconds(), JSON.stringify(record)),
    client.setex(getCsrfKey(token), getCsrfTtlSeconds(), csrfToken),
  ])
  return record
}

export const revokeSession = async (token: string): Promise<void> => {
  cleanupMemory()
  memorySessions.delete(token)
  memoryCsrf.delete(token)

  const client = getRedis()
  if (!client) return
  await Promise.all([client.del(getSessionKey(token)), client.del(getCsrfKey(token))])
}

export const validateSession = async (token: string): Promise<boolean> => {
  cleanupMemory()

  const client = getRedis()
  if (!client) {
    return memorySessions.has(token)
  }

  const value = await client.get(getSessionKey(token))
  return Boolean(value)
}

export const getSession = async (token: string): Promise<SessionRecord | null> => {
  cleanupMemory()

  const client = getRedis()
  if (!client) {
    const entry = memorySessions.get(token)
    if (!entry) return null
    memorySessions.set(token, {
      value: entry.value,
      expiresAt: Date.now() + SESSION_TTL_MS,
    })
    return entry.value
  }

  const raw = await client.get(getSessionKey(token))
  if (!raw) return null
  await client.expire(getSessionKey(token), getSessionTtlSeconds())
  return JSON.parse(raw) as SessionRecord
}

export const getSessionUser = async (token: string): Promise<SessionUser | null> => {
  const session = await getSession(token)
  return session?.user ?? null
}

export const getCsrfToken = async (sessionToken: string): Promise<string | null> => {
  cleanupMemory()

  const client = getRedis()
  if (!client) {
    return memoryCsrf.get(sessionToken)?.value ?? null
  }
  return await client.get(getCsrfKey(sessionToken))
}

export const validateCsrfToken = async (
  sessionToken: string,
  csrfToken: string,
): Promise<boolean> => {
  const stored = await getCsrfToken(sessionToken)
  return Boolean(stored && stored === csrfToken)
}

export const parseCookie = (cookieHeader: string | null, name: string): string | null => {
  if (!cookieHeader) return null
  const parts = cookieHeader.split(';')
  for (const part of parts) {
    const [key, ...rest] = part.trim().split('=')
    if (key === name) {
      return decodeURIComponent(rest.join('='))
    }
  }
  return null
}

export const createSecureCookieHeader = (
  name: string,
  value: string,
  maxAge: number,
): string => {
  const isProd = process.env.NODE_ENV === 'production'
  return [
    `${name}=${encodeURIComponent(value)}`,
    'HttpOnly',
    isProd ? 'Secure' : '',
    'SameSite=Strict',
    `Max-Age=${maxAge}`,
    'Path=/',
  ]
    .filter(Boolean)
    .join('; ')
}

export const createClearCookieHeader = (name: string): string =>
  `${name}=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/`

export const closeRedis = async (): Promise<void> => {
  if (!redis) return
  await redis.quit()
  redis = null
}
