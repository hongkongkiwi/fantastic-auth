import * as React from 'react'
import { useNavigate, useLocation } from '@tanstack/react-router'
import { toast } from '../components/ui/Toaster'
import { useServerFn } from '@tanstack/react-start'
import { getUiSessionStatus, loginUi, logoutUi } from '../server/internal-api'

export interface User {
  id: string
  email: string
  name?: string
  role?: 'admin' | 'superadmin'
  avatar?: string
}

interface AuthContextType {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  checkAuth: () => Promise<boolean>
}

const AuthContext = React.createContext<AuthContextType | undefined>(undefined)

const USER_STORAGE_KEY = 'vault_ui_user'

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = React.useState<User | null>(null)
  const [isLoading, setIsLoading] = React.useState(true)
  const navigate = useNavigate()
  const location = useLocation()
  const loginUiFn = useServerFn(loginUi)
  const logoutUiFn = useServerFn(logoutUi)
  const getUiSessionStatusFn = useServerFn(getUiSessionStatus)

  // Initialize auth state from session and validate cookie-based session
  React.useEffect(() => {
    let isMounted = true
    const initAuth = async () => {
      const storedUser = sessionStorage.getItem(USER_STORAGE_KEY)
      let storedUserValue: User | null = null
      if (storedUser) {
        try {
          storedUserValue = JSON.parse(storedUser) as User
          setUser(storedUserValue)
        } catch {
          sessionStorage.removeItem(USER_STORAGE_KEY)
        }
      }

      try {
        await getUiSessionStatusFn()
        if (isMounted && !storedUserValue) {
          setUser({ id: 'ui', email: 'admin', name: 'Admin User', role: 'admin' })
        }
      } catch {
        sessionStorage.removeItem(USER_STORAGE_KEY)
        if (isMounted) setUser(null)
      } finally {
        if (isMounted) setIsLoading(false)
      }
    }
    void initAuth()
    return () => {
      isMounted = false
    }
  }, [])

  // Protect routes
  React.useEffect(() => {
    if (!isLoading && !user && location.pathname !== '/login') {
      navigate({ to: '/login', search: { redirect: location.pathname } })
    }
  }, [user, isLoading, location.pathname, navigate])

  const login = async (email: string, password: string) => {
    setIsLoading(true)
    try {
      await loginUiFn({ data: { password } })

      const user: User = {
        id: 'ui',
        email,
        name: email.split('@')[0] || 'Admin',
        role: 'admin',
      }
      setUser(user)
      sessionStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user))

      toast.success('Welcome back!')

      // Redirect to original destination or dashboard
      const redirect = new URLSearchParams(location.search).get('redirect') || '/'
      navigate({ to: redirect })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Login failed')
      throw error
    } finally {
      setIsLoading(false)
    }
  }

  const logout = async () => {
    setIsLoading(true)
    try {
      await logoutUiFn({ data: {} })
      setUser(null)
      sessionStorage.removeItem(USER_STORAGE_KEY)
      
      toast.success('Logged out successfully')
      navigate({ to: '/login' })
    } catch (error) {
      toast.error('Logout failed')
    } finally {
      setIsLoading(false)
    }
  }

  const checkAuth = async (): Promise<boolean> => {
    try {
      await getUiSessionStatusFn()
      return true
    } catch {
      return false
    }
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        checkAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = React.useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// Protected route wrapper component
export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  React.useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      navigate({ to: '/login', search: { redirect: location.pathname } })
    }
  }, [isAuthenticated, isLoading, navigate, location.pathname])

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-8 w-8 border-4 border-primary border-t-transparent rounded-full animate-spin" />
          <p className="text-muted-foreground text-sm">Loading…</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return null
  }

  return <>{children}</>
}
