import { describe, expect, it, vi } from 'vitest'
import { fetchWithRetry } from './internal-client'

describe('fetchWithRetry', () => {
  it('retries GET requests on 503', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response('', { status: 503 }))
      .mockResolvedValueOnce(new Response('ok', { status: 200 }))

    global.fetch = fetchMock as unknown as typeof fetch

    const res = await fetchWithRetry('https://example.com', { method: 'GET' }, { retries: 1, retryDelayMs: 1 })
    expect(res.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('does not retry POST requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('', { status: 503 }))
    global.fetch = fetchMock as unknown as typeof fetch

    const res = await fetchWithRetry('https://example.com', { method: 'POST' }, { retries: 2, retryDelayMs: 1 })
    expect(res.status).toBe(503)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
