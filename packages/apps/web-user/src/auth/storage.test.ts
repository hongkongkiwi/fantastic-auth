import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  AUTH_UNAUTHORIZED_EVENT,
  clearAuthToken,
  getAuthToken,
  notifyAuthUnauthorized,
  setAuthToken,
} from './storage'

const createStorage = () => {
  const map = new Map<string, string>()
  return {
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => {
      map.set(key, value)
    },
    removeItem: (key: string) => {
      map.delete(key)
    },
    clear: () => {
      map.clear()
    },
  }
}

describe('auth storage', () => {
  let dispatchEventSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    const localStorageMock = createStorage()
    const sessionStorageMock = createStorage()
    dispatchEventSpy = vi.fn()

    vi.stubGlobal('localStorage', localStorageMock)
    vi.stubGlobal('sessionStorage', sessionStorageMock)
    vi.stubGlobal('window', {
      dispatchEvent: dispatchEventSpy,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('does not read legacy storage tokens for auth session', () => {
    localStorage.setItem('access_token', 'legacy-token')
    expect(getAuthToken()).toBeNull()
    expect(sessionStorage.getItem('vault_user_token')).toBeNull()
    expect(localStorage.getItem('access_token')).toBe('legacy-token')
  })

  it('setAuthToken is a no-op for cookie-based auth sessions', () => {
    localStorage.setItem('vault_user_token', 'old')
    localStorage.setItem('access_token', 'legacy')
    setAuthToken('fresh-token')

    expect(sessionStorage.getItem('vault_user_token')).toBeNull()
    expect(localStorage.getItem('vault_user_token')).toBe('old')
    expect(localStorage.getItem('access_token')).toBe('legacy')
  })

  it('clears token and emits unauthorized event', () => {
    setAuthToken('token')
    notifyAuthUnauthorized()

    expect(sessionStorage.getItem('vault_user_token')).toBeNull()
    expect(dispatchEventSpy).toHaveBeenCalledTimes(1)
    const eventArg = dispatchEventSpy.mock.calls[0]?.[0] as Event
    expect(eventArg.type).toBe(AUTH_UNAUTHORIZED_EVENT)
  })

  it('clearAuthToken removes current and legacy keys', () => {
    sessionStorage.setItem('vault_user_token', 'session-token')
    localStorage.setItem('vault_user_token', 'legacy-a')
    localStorage.setItem('access_token', 'legacy-b')
    clearAuthToken()

    expect(sessionStorage.getItem('vault_user_token')).toBeNull()
    expect(localStorage.getItem('vault_user_token')).toBeNull()
    expect(localStorage.getItem('access_token')).toBeNull()
  })
})
