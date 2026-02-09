import { env } from '../env/server'

// Content Security Policy configuration
export const generateCSP = (nonce: string): string => {
  const directives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    `connect-src 'self' ${env.INTERNAL_API_BASE_URL || ''} https://*.sentry.io`,
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
  ]
  
  return directives.join('; ')
}

// Security headers to add to all responses
export const securityHeaders = {
  'Content-Security-Policy': '', // Set dynamically with nonce
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
}

// HSTS header (only in production)
export const getHSTSHeader = (): string | null => {
  if (env.NODE_ENV === 'production') {
    return 'max-age=31536000; includeSubDomains; preload'
  }
  return null
}

// Generate nonce for CSP
export const generateNonce = (): string => {
  const array = new Uint8Array(16)
  crypto.getRandomValues(array)
  return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

// Apply security headers to response
export const applySecurityHeaders = (
  response: Response,
  nonce: string
): Response => {
  const headers = new Headers(response.headers)
  
  // Set CSP
  headers.set('Content-Security-Policy', generateCSP(nonce))
  
  // Set other security headers
  Object.entries(securityHeaders).forEach(([key, value]) => {
    if (value) {
      headers.set(key, value)
    }
  })
  
  // Set HSTS in production
  const hsts = getHSTSHeader()
  if (hsts) {
    headers.set('Strict-Transport-Security', hsts)
  }
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}
