import { describe, expect, it } from 'vitest'
import { validateSession } from './session'

// Basic sanity check that session validation behaves as expected.
// Request middleware relies on validateSession internally.

describe('auth middleware session', () => {
  it('returns false for missing session', () => {
    expect(validateSession('missing')).toBe(false)
  })
})
