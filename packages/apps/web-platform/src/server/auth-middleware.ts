import { createMiddleware } from '@tanstack/react-start'
import {
  getSessionCookieName,
  parseCookie,
  validateSession,
  validateCsrfToken,
  getCsrfToken,
} from './session'
import { env } from '../env/server'
import { serverLogger } from '../lib/server-logger'

const hasUiPassword = () => Boolean(env.INTERNAL_UI_PASSWORD)

export const assertAuthConfigured = () => {
  if (!hasUiPassword()) {
    serverLogger.warn('UI session auth is not configured')
    throw new Error('UI session auth is not configured. Set INTERNAL_UI_PASSWORD.')
  }
}

// Main auth middleware - validates session
export const authMiddleware = createMiddleware({ type: 'request' }).server(
  async ({ request, next }) => {
    assertAuthConfigured()
    
    const token = parseCookie(
      request.headers.get('cookie'),
      getSessionCookieName(),
    )

    if (!token) {
      serverLogger.warn('Unauthorized UI request - no session token')
      return new Response('Unauthorized', { status: 401 })
    }

    const isValid = await validateSession(token)
    if (!isValid) {
      serverLogger.warn('Unauthorized UI request - invalid session')
      return new Response('Unauthorized', { status: 401 })
    }

    // Add session info to request context
    return next({
      context: {
        sessionToken: token,
      },
    })
  },
)

// CSRF protection middleware for mutations
export const csrfMiddleware = createMiddleware({ type: 'request' }).server(
  async ({ request, next }) => {
    const sessionToken = parseCookie(
      request.headers.get('cookie'),
      getSessionCookieName(),
    )

    if (!sessionToken) {
      return new Response('Unauthorized', { status: 401 })
    }

    // Get CSRF token from header
    const csrfToken = request.headers.get('X-CSRF-Token')
    
    if (!csrfToken) {
      serverLogger.warn('CSRF validation failed - missing token')
      return new Response('CSRF token required', { status: 403 })
    }

    const isValid = await validateCsrfToken(sessionToken, csrfToken)
    
    if (!isValid) {
      serverLogger.warn('CSRF validation failed - invalid token')
      return new Response('Invalid CSRF token', { status: 403 })
    }

    return next({
      context: {
        sessionToken,
      },
    })
  },
)

// Combined auth + CSRF middleware for write operations
export const secureMiddleware = createMiddleware({ type: 'request' }).server(
  async ({ request, next }) => {
    assertAuthConfigured()
    
    const sessionToken = parseCookie(
      request.headers.get('cookie'),
      getSessionCookieName(),
    )

    if (!sessionToken) {
      serverLogger.warn('Unauthorized request - no session token')
      return new Response('Unauthorized', { status: 401 })
    }

    const isSessionValid = await validateSession(sessionToken)
    if (!isSessionValid) {
      serverLogger.warn('Unauthorized request - invalid session')
      return new Response('Unauthorized', { status: 401 })
    }

    // Validate CSRF for mutating methods
    const method = request.method
    if (method === 'POST' || method === 'PUT' || method === 'DELETE' || method === 'PATCH') {
      const csrfToken = request.headers.get('X-CSRF-Token')
      
      if (!csrfToken) {
        serverLogger.warn('CSRF validation failed - missing token')
        return new Response('CSRF token required', { status: 403 })
      }

      const isCsrfValid = await validateCsrfToken(sessionToken, csrfToken)
      
      if (!isCsrfValid) {
        serverLogger.warn('CSRF validation failed - invalid token')
        return new Response('Invalid CSRF token', { status: 403 })
      }
    }

    // Get fresh CSRF token for the response
    const freshCsrfToken = await getCsrfToken(sessionToken)

    return next({
      context: {
        sessionToken,
        csrfToken: freshCsrfToken,
      },
    })
  },
)

// Optional auth middleware for public routes that may have auth
export const optionalAuthMiddleware = createMiddleware({ type: 'request' }).server(
  async ({ request, next }) => {
    const token = parseCookie(
      request.headers.get('cookie'),
      getSessionCookieName(),
    )

    if (token) {
      const isValid = await validateSession(token)
      if (isValid) {
        return next({
          context: {
            sessionToken: token,
          },
        })
      }
    }

    return next()
  },
)
