import { describe, expect, it, vi } from 'vitest'

const createClientMock = vi.fn((config) => ({ config }))
vi.mock('openapi-fetch', () => ({
  default: createClientMock,
}))

import { fetchWithRetry, createInternalClient } from './internal-client'

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

  it('retries on network errors for GET requests', async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error('Network'))
      .mockResolvedValueOnce(new Response('ok', { status: 200 }))
    global.fetch = fetchMock as unknown as typeof fetch

    const res = await fetchWithRetry('https://example.com', { method: 'GET' }, { retries: 1, retryDelayMs: 0 })
    expect(res.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('throws after retries are exhausted', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('Network'))
    global.fetch = fetchMock as unknown as typeof fetch

    await expect(
      fetchWithRetry('https://example.com', { method: 'GET' }, { retries: 1, retryDelayMs: 0 })
    ).rejects.toThrow('Network')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('retries on 429 for HEAD requests', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response('', { status: 429 }))
      .mockResolvedValueOnce(new Response('ok', { status: 200 }))
    global.fetch = fetchMock as unknown as typeof fetch

    const res = await fetchWithRetry('https://example.com', { method: 'HEAD' }, { retries: 1, retryDelayMs: 0 })
    expect(res.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('does not retry on non-retryable status codes', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('', { status: 400 }))
    global.fetch = fetchMock as unknown as typeof fetch

    const res = await fetchWithRetry('https://example.com', { method: 'GET' }, { retries: 2, retryDelayMs: 0 })
    expect(res.status).toBe(400)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('creates an internal client with baseUrl and fetch', () => {
    const client = createInternalClient('https://api.example.com')
    expect(createClientMock).toHaveBeenCalledWith({
      baseUrl: 'https://api.example.com',
      fetch: expect.any(Function),
    })
    expect(client).toEqual({ config: { baseUrl: 'https://api.example.com', fetch: expect.any(Function) } })
  })
})
