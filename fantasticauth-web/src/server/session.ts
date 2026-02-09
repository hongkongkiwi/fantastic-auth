const SESSION_COOKIE_NAME = 'vault_ui_session'
const SESSION_TTL_MS = 1000 * 60 * 60 * 8

export type SessionRecord = {
  token: string
  createdAt: number
}

const sessions = new Map<string, SessionRecord>()

export const getSessionCookieName = () => SESSION_COOKIE_NAME
export const getSessionTtlSeconds = () => Math.floor(SESSION_TTL_MS / 1000)

export const createSession = () => {
  const token = crypto.randomUUID()
  const record = { token, createdAt: Date.now() }
  sessions.set(token, record)
  return record
}

export const revokeSession = (token: string) => {
  sessions.delete(token)
}

export const validateSession = (token: string) => {
  const record = sessions.get(token)
  if (!record) return false
  if (Date.now() - record.createdAt > SESSION_TTL_MS) {
    sessions.delete(token)
    return false
  }
  return true
}

export const parseCookie = (cookieHeader: string | null, name: string) => {
  if (!cookieHeader) return null
  const parts = cookieHeader.split(';')
  for (const part of parts) {
    const [key, ...rest] = part.trim().split('=')
    if (key === name) {
      return decodeURIComponent(rest.join('='))
    }
  }
  return null
}
