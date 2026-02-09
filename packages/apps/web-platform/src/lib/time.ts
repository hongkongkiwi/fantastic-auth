const RELATIVE_UNITS: { unit: Intl.RelativeTimeFormatUnit; ms: number; short: string }[] = [
  { unit: 'year', ms: 1000 * 60 * 60 * 24 * 365, short: 'y' },
  { unit: 'month', ms: 1000 * 60 * 60 * 24 * 30, short: 'mo' },
  { unit: 'day', ms: 1000 * 60 * 60 * 24, short: 'd' },
  { unit: 'hour', ms: 1000 * 60 * 60, short: 'h' },
  { unit: 'minute', ms: 1000 * 60, short: 'm' },
  { unit: 'second', ms: 1000, short: 's' },
]

export const formatRelativeTime = (iso: string) => {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return 'invalid date'
  const diffMs = date.getTime() - Date.now()
  const abs = Math.abs(diffMs)
  if (abs < 5000) return 'just now'
  const unit = RELATIVE_UNITS.find((entry) => abs >= entry.ms) ?? RELATIVE_UNITS.at(-1)!
  const value = Math.round(abs / unit.ms)
  const suffix = diffMs < 0 ? 'ago' : 'from now'
  return `${value}${unit.short} ${suffix}`
}

export const formatDateTimeWithZone = (iso: string) => {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return 'invalid date'
  return date.toLocaleString('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZoneName: 'short',
  })
}
