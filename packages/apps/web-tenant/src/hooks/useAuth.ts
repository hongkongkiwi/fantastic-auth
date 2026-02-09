import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi } from '../services/api'
import type { User } from '../services/api'

interface AuthState {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
}

interface AuthContextValue extends AuthState {
  login: (email: string, password: string, mfaCode?: string, mfaToken?: string) => Promise<void>
  logout: () => Promise<void>
  clearError: () => void
  verifySession: () => Promise<boolean>
}

export function useAuth(): AuthContextValue {
  const navigate = useNavigate()
  const [state, setState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    error: null,
  })

  // Verify session on mount - relies on httpOnly cookie
  useEffect(() => {
    const verifySession = async () => {
      try {
        const isValid = await authApi.verifySession()
        if (isValid) {
          const user = await authApi.getCurrentUser()
          setState(prev => ({
            ...prev,
            user,
            isAuthenticated: true,
            isLoading: false,
          }))
        } else {
          setState(prev => ({
            ...prev,
            user: null,
            isAuthenticated: false,
            isLoading: false,
          }))
        }
      } catch {
        setState(prev => ({
          ...prev,
          user: null,
          isAuthenticated: false,
          isLoading: false,
        }))
      }
    }

    verifySession()
  }, [])

  const login = useCallback(
    async (email: string, password: string, mfaCode?: string, mfaToken?: string) => {
      setState(prev => ({ ...prev, isLoading: true, error: null }))

      try {
        const result = await authApi.login(email, password, mfaCode, mfaToken)

        setState({
          user: result.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        })

        navigate('/')
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Login failed'
        setState(prev => ({
          ...prev,
          isLoading: false,
          error: message,
        }))
        throw error
      }
    },
    [navigate]
  )

  const logout = useCallback(async () => {
    setState(prev => ({ ...prev, isLoading: true }))

    try {
      await authApi.logout()
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      setState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
      })
      navigate('/login')
    }
  }, [navigate])

  const verifySession = useCallback(async (): Promise<boolean> => {
    try {
      const isValid = await authApi.verifySession()
      if (!isValid && state.isAuthenticated) {
        setState({
          user: null,
          isAuthenticated: false,
          isLoading: false,
          error: null,
        })
        navigate('/login?error=session_expired')
      }
      return isValid
    } catch {
      return false
    }
  }, [state.isAuthenticated, navigate])

  const clearError = useCallback(() => {
    setState(prev => ({ ...prev, error: null }))
  }, [])

  // Periodic session verification
  useEffect(() => {
    if (!state.isAuthenticated) return

    const interval = setInterval(() => {
      verifySession()
    }, 60000) // Check every minute

    return () => clearInterval(interval)
  }, [state.isAuthenticated, verifySession])

  return {
    ...state,
    login,
    logout,
    clearError,
    verifySession,
  }
}
