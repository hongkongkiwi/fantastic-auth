import { describe, expect, it, vi } from 'vitest'
import {
  createSession,
  parseCookie,
  validateSession,
  revokeSession,
  getSessionCookieName,
  getSessionTtlSeconds,
} from './session'

describe('session', () => {
  it('creates and validates a session', async () => {
    const session = await createSession({ email: 'admin@vault.local', role: 'admin' })
    await expect(validateSession(session.token)).resolves.toBe(true)
  })

  it('revokes a session', async () => {
    const session = await createSession({ email: 'admin@vault.local', role: 'admin' })
    await revokeSession(session.token)
    await expect(validateSession(session.token)).resolves.toBe(false)
  })

  it('expires sessions after ttl', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'))
    const session = await createSession({ email: 'admin@vault.local', role: 'admin' })
    vi.advanceTimersByTime((getSessionTtlSeconds() + 1) * 1000)
    await expect(validateSession(session.token)).resolves.toBe(false)
    vi.useRealTimers()
  })

  it('parses cookies', () => {
    const token = 'abc123'
    const header = `foo=bar; vault_ui_session=${token}; baz=qux`
    expect(parseCookie(header, getSessionCookieName())).toBe(token)
  })

  it('returns null for missing cookies', () => {
    expect(parseCookie(null, getSessionCookieName())).toBeNull()
    expect(parseCookie('foo=bar', getSessionCookieName())).toBeNull()
  })
})
