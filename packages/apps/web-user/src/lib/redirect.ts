export const sanitizeRedirectPath = (raw: string | null | undefined): string => {
  if (!raw) return '/'
  const candidate = raw.trim()
  if (!candidate || candidate.startsWith('//')) return '/'

  const fallbackOrigin = 'http://localhost'
  const origin = typeof window === 'undefined' ? fallbackOrigin : window.location.origin

  try {
    const parsed = new URL(candidate, origin)
    if (parsed.origin !== origin) return '/'
    return `${parsed.pathname}${parsed.search}${parsed.hash}` || '/'
  } catch {
    return candidate.startsWith('/') ? candidate : '/'
  }
}
