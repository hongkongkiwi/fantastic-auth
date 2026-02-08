export const required = (value: string, label = 'Field') => {
  if (!value || !value.trim()) {
    return `${label} is required`
  }
  return null
}

export const isSlug = (value: string) => /^[a-z0-9-]+$/.test(value)

export const validateSlug = (value: string) =>
  value && !isSlug(value) ? 'Slug must be lowercase letters, numbers, and hyphens' : null

export const isIsoDateTime = (value: string) => {
  if (!value) return true
  const parsed = Date.parse(value)
  return !Number.isNaN(parsed)
}

export const validateIsoDateTime = (value: string) =>
  value && !isIsoDateTime(value) ? 'Must be a valid ISO 8601 timestamp' : null

export const validateEmail = (value: string) =>
  value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
    ? 'Must be a valid email address'
    : null

export const validateNumberRange = (
  value: number | undefined,
  {
    min,
    max,
    label = 'Value',
  }: { min?: number; max?: number; label?: string },
) => {
  if (typeof value !== 'number' || Number.isNaN(value)) return null
  if (min !== undefined && value < min) {
    return `${label} must be at least ${min}`
  }
  if (max !== undefined && value > max) {
    return `${label} must be at most ${max}`
  }
  return null
}
