const STORAGE_KEYS = {
  baseUrl: 'vault_internal_api_base_url',
  uiSession: 'vault_internal_ui_session',
}

const SESSION_COOKIE = 'vault_ui_session'

export const getStorageKeys = () => STORAGE_KEYS

export const getStoredValue = (key: string, fallback: string) => {
  if (typeof window === 'undefined') return fallback
  return window.localStorage.getItem(key) ?? fallback
}

export const setStoredValue = (key: string, value: string) => {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(key, value)
}

export const getSessionValue = (key: string, fallback: string) => {
  if (typeof window === 'undefined') return fallback
  return window.sessionStorage.getItem(key) ?? fallback
}

export const setSessionValue = (key: string, value: string) => {
  if (typeof window === 'undefined') return
  window.sessionStorage.setItem(key, value)
}

export const clearSessionValue = (key: string) => {
  if (typeof window === 'undefined') return
  window.sessionStorage.removeItem(key)
}

export const setSessionCookie = (token: string) => {
  document.cookie = `${SESSION_COOKIE}=${encodeURIComponent(
    token,
  )}; Path=/; SameSite=Lax`
}

export const clearSessionCookie = () => {
  document.cookie = `${SESSION_COOKIE}=; Max-Age=0; Path=/; SameSite=Lax`
}

export const getSessionCookieName = () => SESSION_COOKIE
