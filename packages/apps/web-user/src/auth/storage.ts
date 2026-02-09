/**
 * Authentication Storage Module
 * 
 * SECURITY NOTE: This application uses httpOnly cookies for session management.
 * The session token is NEVER stored in localStorage or sessionStorage.
 * Cookies are automatically sent with requests via credentials: 'include'.
 * 
 * The token storage functions below are DEPRECATED and will be removed in a future version.
 * They are kept temporarily for backwards compatibility during migration.
 */

const AUTH_TOKEN_KEY = 'vault_user_token'
const LEGACY_TOKEN_KEY = 'access_token'
export const AUTH_UNAUTHORIZED_EVENT = 'vault-auth-unauthorized'

// CSRF token management (non-sensitive, stored in memory only)
let csrfToken: string | null = null

export const getCsrfToken = (): string | null => csrfToken

export const setCsrfToken = (token: string) => {
  csrfToken = token
}

export const clearCsrfToken = () => {
  csrfToken = null
}

// Clear any legacy tokens that might exist from previous versions
export const clearLegacyTokens = () => {
  if (typeof window === 'undefined') return
  try {
    localStorage.removeItem(AUTH_TOKEN_KEY)
    localStorage.removeItem(LEGACY_TOKEN_KEY)
    sessionStorage.removeItem(AUTH_TOKEN_KEY)
    sessionStorage.removeItem(LEGACY_TOKEN_KEY)
  } catch {
    // Ignore storage errors
  }
}

/**
 * @deprecated Session tokens are now stored in httpOnly cookies.
 * This function is kept for backwards compatibility only.
 * It will always return null as tokens are no longer stored in JavaScript.
 */
export const getAuthToken = (): string | null => {
  // DEPRECATED: Tokens now stored in httpOnly cookies only
  return null
}

/**
 * @deprecated Session tokens are now stored in httpOnly cookies.
 * This function is kept for backwards compatibility only.
 * It no longer stores tokens in sessionStorage.
 */
export const setAuthToken = (_token: string) => {
  // DEPRECATED: Tokens now stored in httpOnly cookies only
  // This function is a no-op
}

/**
 * @deprecated Session tokens are now stored in httpOnly cookies.
 * This function is kept for backwards compatibility only.
 * It clears any legacy tokens from storage.
 */
export const clearAuthToken = () => {
  // Clear any legacy tokens that might exist
  clearLegacyTokens()
}

export const notifyAuthUnauthorized = () => {
  clearAuthToken()
  if (typeof window === 'undefined') return
  window.dispatchEvent(new Event(AUTH_UNAUTHORIZED_EVENT))
}

// Initialize - clear legacy tokens on load
if (typeof window !== 'undefined') {
  clearLegacyTokens()
}
