import { describe, it, expect } from 'vitest'
import {
  cn,
  formatDate,
  formatNumber,
  formatCurrency,
  formatRelativeTime,
  truncate,
  capitalize,
} from './utils'

describe('cn', () => {
  it('merges classes correctly', () => {
    expect(cn('class1', 'class2')).toBe('class1 class2')
  })

  it('handles conditional classes', () => {
    expect(cn('base', true && 'active', false && 'inactive')).toBe('base active')
  })

  it('handles undefined and null', () => {
    expect(cn('base', undefined, null, 'end')).toBe('base end')
  })
})

describe('formatDate', () => {
  it('formats date string correctly', () => {
    const date = '2024-01-15T10:30:00Z'
    const formatted = formatDate(date)
    expect(formatted).toContain('Jan')
    expect(formatted).toContain('15')
    expect(formatted).toContain('2024')
  })

  it('formats Date object correctly', () => {
    const date = new Date('2024-01-15T10:30:00Z')
    const formatted = formatDate(date)
    expect(formatted).toContain('Jan')
  })
})

describe('formatNumber', () => {
  it('formats large numbers with commas', () => {
    expect(formatNumber(1000)).toBe('1,000')
    expect(formatNumber(1000000)).toBe('1,000,000')
  })

  it('handles decimal numbers', () => {
    expect(formatNumber(1234.56)).toBe('1,234.56')
  })
})

describe('formatCurrency', () => {
  it('formats USD correctly', () => {
    expect(formatCurrency(100)).toBe('$100.00')
    expect(formatCurrency(1234.56)).toBe('$1,234.56')
  })

  it('formats EUR correctly', () => {
    expect(formatCurrency(100, 'EUR')).toContain('100.00')
  })
})

describe('formatRelativeTime', () => {
  it('returns "just now" for recent dates', () => {
    const now = new Date()
    expect(formatRelativeTime(now)).toBe('just now')
  })

  it('returns minutes ago for recent past', () => {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000)
    expect(formatRelativeTime(fiveMinutesAgo)).toMatch(/5.*minute/i)
  })
})

describe('truncate', () => {
  it('truncates long strings', () => {
    expect(truncate('hello world', 5)).toBe('hello…')
  })

  it('returns original if shorter than limit', () => {
    expect(truncate('hi', 10)).toBe('hi')
  })
})

describe('capitalize', () => {
  it('capitalizes first letter', () => {
    expect(capitalize('hello')).toBe('Hello')
    expect(capitalize('HELLO')).toBe('Hello')
  })
})
