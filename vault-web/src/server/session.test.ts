import { describe, expect, it } from 'vitest'
import { createSession, parseCookie, validateSession } from './session'

describe('session', () => {
  it('creates and validates a session', () => {
    const session = createSession()
    expect(validateSession(session.token)).toBe(true)
  })

  it('parses cookies', () => {
    const token = 'abc123'
    const header = `foo=bar; vault_ui_session=${token}; baz=qux`
    expect(parseCookie(header, 'vault_ui_session')).toBe(token)
  })
})
