import { describe, it, expect } from 'vitest'
import { cn, formatDate, formatRelativeTime, getTrustScoreColor } from './utils'

describe('cn (className utility)', () => {
  it('should merge class names', () => {
    expect(cn('foo', 'bar')).toBe('foo bar')
  })

  it('should handle conditional classes', () => {
    expect(cn('foo', true && 'bar', false && 'baz')).toBe('foo bar')
  })

  it('should merge tailwind classes correctly', () => {
    expect(cn('px-2 py-1', 'px-4')).toBe('py-1 px-4')
  })
})

describe('formatDate', () => {
  it('should format date correctly', () => {
    const date = new Date('2024-01-15T10:30:00Z')
    const result = formatDate(date)
    expect(result).toContain('Jan')
    expect(result).toContain('15')
    expect(result).toContain('2024')
  })

  it('should handle ISO string', () => {
    const result = formatDate('2024-01-15T00:00:00Z')
    expect(result).toBeTruthy()
  })
})

describe('formatRelativeTime', () => {
  it('should format recent dates', () => {
    const now = new Date()
    const oneMinuteAgo = new Date(now.getTime() - 60 * 1000)
    expect(formatRelativeTime(oneMinuteAgo)).toContain('minute')
  })

  it('should format hours ago', () => {
    const now = new Date()
    const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000)
    expect(formatRelativeTime(twoHoursAgo)).toContain('2')
    expect(formatRelativeTime(twoHoursAgo)).toContain('hour')
  })

  it('should format days ago', () => {
    const now = new Date()
    const threeDaysAgo = new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000)
    expect(formatRelativeTime(threeDaysAgo)).toContain('3')
    expect(formatRelativeTime(threeDaysAgo)).toContain('day')
  })
})

describe('getTrustScoreColor', () => {
  it('should return green for high trust scores', () => {
    expect(getTrustScoreColor(80)).toBe('text-green-500')
    expect(getTrustScoreColor(100)).toBe('text-green-500')
  })

  it('should return yellow for medium trust scores', () => {
    expect(getTrustScoreColor(50)).toBe('text-yellow-500')
    expect(getTrustScoreColor(70)).toBe('text-yellow-500')
  })

  it('should return red for low trust scores', () => {
    expect(getTrustScoreColor(30)).toBe('text-red-500')
    expect(getTrustScoreColor(0)).toBe('text-red-500')
  })
})
