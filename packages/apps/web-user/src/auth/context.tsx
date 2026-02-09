/**
 * Authentication Context
 * 
 * SECURITY NOTE: This application uses httpOnly cookies for session management.
 * The session token is stored in an httpOnly cookie (not accessible to JavaScript).
 * All API requests automatically include credentials via fetch's credentials: 'include'.
 * The token field in the context is kept for backwards compatibility but always returns null.
 */

import type { ReactNode } from 'react'
import * as React from 'react'
import { authApi, type AuthUser } from './api'
import { AUTH_UNAUTHORIZED_EVENT, clearAuthToken } from './storage'

type AuthContextValue = {
  /** @deprecated Tokens are now stored in httpOnly cookies. This field is kept for backwards compatibility but always returns null. */
  token: string | null
  user: AuthUser | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (email: string, password: string, mfaCode?: string, mfaToken?: string) => Promise<void>
  logout: () => Promise<void>
  refreshSession: () => Promise<void>
  updateProfile: (data: Partial<AuthUser>) => Promise<AuthUser>
}

const AuthContext = React.createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = React.useState<AuthUser | null>(null)
  const [isLoading, setIsLoading] = React.useState(true)

  const clearSession = React.useCallback(() => {
    clearAuthToken()
    setUser(null)
  }, [])

  const refreshSession = React.useCallback(async () => {
    try {
      const profile = await authApi.getMe()
      setUser(profile)
    } catch {
      clearSession()
    } finally {
      setIsLoading(false)
    }
  }, [clearSession])

  React.useEffect(() => {
    void refreshSession()
  }, [refreshSession])

  React.useEffect(() => {
    if (typeof window === 'undefined') return
    const onUnauthorized = () => {
      clearSession()
    }
    window.addEventListener(AUTH_UNAUTHORIZED_EVENT, onUnauthorized)
    return () => {
      window.removeEventListener(AUTH_UNAUTHORIZED_EVENT, onUnauthorized)
    }
  }, [clearSession])

  const login = React.useCallback(
    async (email: string, password: string, mfaCode?: string, mfaToken?: string) => {
      setIsLoading(true)
      try {
        const result = await authApi.login(email, password, mfaCode, mfaToken)
        setUser(result.user)
      } finally {
        setIsLoading(false)
      }
    },
    [],
  )

  const logout = React.useCallback(async () => {
    try {
      await authApi.logout()
    } finally {
      clearSession()
    }
  }, [clearSession])

  const updateProfile = React.useCallback(async (data: Partial<AuthUser>) => {
    const next = await authApi.updateMe(data)
    setUser(next)
    return next
  }, [])

  const value = React.useMemo<AuthContextValue>(
    () => ({
      // Token is always null - authentication is handled via httpOnly cookies
      token: null,
      user,
      isAuthenticated: Boolean(user),
      isLoading,
      login,
      logout,
      refreshSession,
      updateProfile,
    }),
    [user, isLoading, login, logout, refreshSession, updateProfile],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export const useAuth = () => {
  const context = React.useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider.')
  }
  return context
}
