import { createMiddleware } from '@tanstack/react-start'
import { getSessionCookieName, parseCookie, validateSession } from './session'
import { env } from '../env/server'
import { serverLogger } from '../lib/server-logger'

const hasUiPassword = () => Boolean(env.INTERNAL_UI_PASSWORD)
const hasUiToken = () => Boolean(env.INTERNAL_UI_TOKEN)

export const assertAuthConfigured = () => {
  if (!hasUiPassword() && !hasUiToken()) {
    serverLogger.warn('UI auth is not configured')
    throw new Error(
      'UI auth is not configured. Set INTERNAL_UI_PASSWORD and/or INTERNAL_UI_TOKEN.',
    )
  }
}

export const authMiddleware = createMiddleware({ type: 'request' }).server(
  async ({ request, next }) => {
    assertAuthConfigured()
    const requiredPassword = env.INTERNAL_UI_PASSWORD
    if (!requiredPassword) {
      return next()
    }

    const token = parseCookie(
      request.headers.get('cookie'),
      getSessionCookieName(),
    )

    if (!token || !validateSession(token)) {
      serverLogger.warn('Unauthorized UI request')
      return new Response('Unauthorized', { status: 401 })
    }

    return next()
  },
)
