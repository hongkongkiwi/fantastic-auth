import createClient from 'openapi-fetch'
import type { paths } from '../sdk/internal'

type FetchOptions = {
  timeoutMs?: number
  retries?: number
  retryDelayMs?: number
}

const DEFAULT_TIMEOUT_MS = 10_000
const DEFAULT_RETRIES = 2
const DEFAULT_RETRY_DELAY_MS = 250

const shouldRetry = (response: Response | null) => {
  if (!response) return true
  return [429, 502, 503, 504].includes(response.status)
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

export const fetchWithRetry = async (
  input: RequestInfo,
  init: RequestInit = {},
  options: FetchOptions = {},
): Promise<Response> => {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const retries = options.retries ?? DEFAULT_RETRIES
  const retryDelayMs = options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS

  let attempt = 0
  let lastError: unknown = null
  const method = (init.method ?? 'GET').toUpperCase()
  const canRetry = method === 'GET' || method === 'HEAD'

  while (attempt <= retries) {
    const controller = new AbortController()
    const id = setTimeout(() => controller.abort(), timeoutMs)

    try {
      const response = await fetch(input, {
        ...init,
        signal: controller.signal,
      })
      clearTimeout(id)

      if (!canRetry || !shouldRetry(response) || attempt === retries) {
        return response
      }

      await sleep(retryDelayMs * Math.pow(2, attempt))
      attempt += 1
      continue
    } catch (err) {
      clearTimeout(id)
      lastError = err
      if (!canRetry || attempt === retries) {
        throw err
      }
      await sleep(retryDelayMs * Math.pow(2, attempt))
      attempt += 1
    }
  }

  throw lastError instanceof Error ? lastError : new Error('Request failed')
}

export const createInternalClient = (baseUrl: string) =>
  createClient<paths>({
    baseUrl,
    fetch: (input: Request) => fetchWithRetry(input),
  })
