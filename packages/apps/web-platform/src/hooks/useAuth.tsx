import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { useNavigate } from '@tanstack/react-router'
import { env } from '../env/client'

export interface User {
  id: string
  email: string
  name?: string
  firstName?: string
  lastName?: string
  displayName?: string
  role?: string
}

interface AuthState {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
  csrfToken: string | null
}

interface AuthContextValue extends AuthState {
  login: (email: string, password: string, mfaCode?: string, mfaToken?: string) => Promise<void>
  logout: () => Promise<void>
  clearError: () => void
  refreshCsrfToken: () => Promise<void>
}

export class AuthMfaRequiredError extends Error {
  code = 'MFA_REQUIRED'
  mfaToken?: string

  constructor(message: string, mfaToken?: string) {
    super(message)
    this.name = 'AuthMfaRequiredError'
    this.mfaToken = mfaToken
  }
}

const SESSION_COOKIE_NAME = 'vault_ui_session'
const INTERNAL_API_BASE_URL = env.VITE_INTERNAL_API_BASE_URL || '/api/v1'
const AuthContext = createContext<AuthContextValue | null>(null)

const parseCookie = (cookieHeader: string | null, name: string): string | null => {
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

const buildApiUrl = (path: string) => {
  const normalizedBase = INTERNAL_API_BASE_URL.endsWith('/')
    ? INTERNAL_API_BASE_URL.slice(0, -1)
    : INTERNAL_API_BASE_URL
  const normalizedPath = path.startsWith('/') ? path : `/${path}`

  if (/^https?:\/\//.test(normalizedBase)) {
    return `${normalizedBase}${normalizedPath}`
  }

  const origin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost'
  return new URL(`${normalizedBase}${normalizedPath}`, origin).toString()
}

function useProvideAuth(): AuthContextValue {
  const navigate = useNavigate()
  const [state, setState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    error: null,
    csrfToken: null,
  })

  useEffect(() => {
    const checkSession = async () => {
      const sessionCookie = parseCookie(document.cookie, SESSION_COOKIE_NAME)
      if (!sessionCookie) {
        setState((prev) => ({ ...prev, isLoading: false }))
        return
      }

      try {
        const response = await fetch(buildApiUrl('/auth/verify'), {
          credentials: 'include',
        })

        if (!response.ok) {
          setState((prev) => ({ ...prev, isLoading: false }))
          return
        }

        const data = await response.json()
        setState((prev) => ({
          ...prev,
          user: data.user,
          isAuthenticated: true,
          isLoading: false,
          csrfToken: data.csrfToken,
        }))
      } catch {
        setState((prev) => ({ ...prev, isLoading: false }))
      }
    }

    void checkSession()
  }, [])

  const refreshCsrfToken = useCallback(async () => {
    try {
      const response = await fetch(buildApiUrl('/auth/csrf'), {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setState((prev) => ({ ...prev, csrfToken: data.csrfToken }))
      }
    } catch (error) {
      console.error('Failed to refresh CSRF token:', error)
    }
  }, [])

  const login = useCallback(
    async (email: string, password: string, mfaCode?: string, mfaToken?: string) => {
      setState((prev) => ({ ...prev, isLoading: true, error: null }))

      try {
        const response = await fetch(buildApiUrl('/auth/login'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ email, password, mfaCode, mfaToken }),
        })

        const data = await response.json()
        const requiresMfa = Boolean(data?.mfaRequired || data?.requires_mfa)
        if (requiresMfa) {
          throw new AuthMfaRequiredError(
            'Multi-factor authentication code required.',
            data?.mfaToken || data?.mfa_token,
          )
        }

        if (!response.ok) {
          throw new Error(data.message || 'Login failed')
        }

        setState({
          user: data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
          csrfToken: data.csrfToken,
        })

        navigate({ to: '/' })
      } catch (error) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          error: error instanceof Error ? error.message : 'Login failed',
        }))
        throw error
      }
    },
    [navigate],
  )

  const logout = useCallback(async () => {
    setState((prev) => ({ ...prev, isLoading: true }))

    try {
      await fetch(buildApiUrl('/auth/logout'), {
        method: 'POST',
        credentials: 'include',
        headers: {
          'X-CSRF-Token': state.csrfToken || '',
        },
      })
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      setState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
        csrfToken: null,
      })
      navigate({ to: '/login' })
    }
  }, [navigate, state.csrfToken])

  const clearError = useCallback(() => {
    setState((prev) => ({ ...prev, error: null }))
  }, [])

  return useMemo(
    () => ({
      ...state,
      login,
      logout,
      clearError,
      refreshCsrfToken,
    }),
    [state, login, logout, clearError, refreshCsrfToken],
  )
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const value = useProvideAuth()
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}
