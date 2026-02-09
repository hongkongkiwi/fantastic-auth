import { describe, expect, it } from 'vitest'
import { sanitizeRedirectPath } from './redirect'

describe('sanitizeRedirectPath', () => {
  it('allows same-origin relative paths', () => {
    expect(sanitizeRedirectPath('/security')).toBe('/security')
    expect(sanitizeRedirectPath('/devices?tab=trusted#latest')).toBe(
      '/devices?tab=trusted#latest',
    )
  })

  it('rejects external URLs and protocol-relative values', () => {
    expect(sanitizeRedirectPath('https://evil.example/phish')).toBe('/')
    expect(sanitizeRedirectPath('//evil.example/phish')).toBe('/')
  })

  it('rejects non-path garbage and trims whitespace', () => {
    expect(sanitizeRedirectPath('   javascript:alert(1)   ')).toBe('/')
    expect(sanitizeRedirectPath('   /activity  ')).toBe('/activity')
  })
})

