import { describe, expect, it, vi, beforeEach } from 'vitest'

const envMock = vi.hoisted(() => ({
  INTERNAL_UI_PASSWORD: undefined as string | undefined,
  INTERNAL_UI_TOKEN: undefined as string | undefined,
}))
const loggerMock = vi.hoisted(() => ({
  warn: vi.fn(),
}))

vi.mock('@tanstack/react-start', () => ({
  createMiddleware: () => ({
    server: (handler: unknown) => handler,
  }),
}))

vi.mock('../env/server', () => ({
  env: envMock,
}))

vi.mock('../lib/server-logger', () => ({
  serverLogger: loggerMock,
}))

import { authMiddleware, assertAuthConfigured } from './auth-middleware'
import { createSession, getSessionCookieName } from './session'

describe('auth middleware', () => {
  beforeEach(() => {
    envMock.INTERNAL_UI_PASSWORD = undefined
    envMock.INTERNAL_UI_TOKEN = undefined
    loggerMock.warn.mockReset()
  })

  it('throws when auth is not configured', () => {
    expect(() => assertAuthConfigured()).toThrow(/UI auth is not configured/)
    expect(loggerMock.warn).toHaveBeenCalled()
  })

  it('allows requests when only token auth is configured', async () => {
    envMock.INTERNAL_UI_TOKEN = 'token'
    const next = vi.fn(async () => new Response('ok'))
    const request = new Request('https://example.com')

    const response = await authMiddleware({ request, next })
    expect(next).toHaveBeenCalled()
    expect(response.status).toBe(200)
  })

  it('rejects when session cookie is missing', async () => {
    envMock.INTERNAL_UI_PASSWORD = 'secret'
    const next = vi.fn(async () => new Response('ok'))
    const request = new Request('https://example.com')

    const response = await authMiddleware({ request, next })
    expect(response.status).toBe(401)
    expect(loggerMock.warn).toHaveBeenCalledWith('Unauthorized UI request')
  })

  it('allows requests with valid session cookie', async () => {
    envMock.INTERNAL_UI_PASSWORD = 'secret'
    const session = createSession()
    const cookie = `${getSessionCookieName()}=${encodeURIComponent(session.token)}`
    const request = new Request('https://example.com', {
      headers: { cookie },
    })
    const next = vi.fn(async () => new Response('ok'))

    const response = await authMiddleware({ request, next })
    expect(next).toHaveBeenCalled()
    expect(response.status).toBe(200)
  })
})
