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
  it('creates and validates a session', () => {
    const session = createSession()
    expect(validateSession(session.token)).toBe(true)
  })

  it('revokes a session', () => {
    const session = createSession()
    revokeSession(session.token)
    expect(validateSession(session.token)).toBe(false)
  })

  it('expires sessions after ttl', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'))
    const session = createSession()
    vi.advanceTimersByTime((getSessionTtlSeconds() + 1) * 1000)
    expect(validateSession(session.token)).toBe(false)
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
