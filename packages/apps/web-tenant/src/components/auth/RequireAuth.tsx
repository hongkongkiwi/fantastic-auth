import { useEffect, useState, useCallback } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '@/hooks/useAuth'
import { Loader2 } from 'lucide-react'

interface RequireAuthProps {
  children: React.ReactNode
  fallback?: React.ReactNode
}

export function RequireAuth({ children, fallback }: RequireAuthProps) {
  const { isAuthenticated, isLoading, verifySession } = useAuth()
  const location = useLocation()
  const [isVerifying, setIsVerifying] = useState(true)
  const [isValid, setIsValid] = useState(false)

  const checkSession = useCallback(async () => {
    try {
      const valid = await verifySession()
      setIsValid(valid)
    } catch {
      setIsValid(false)
    } finally {
      setIsVerifying(false)
    }
  }, [verifySession])

  useEffect(() => {
    if (!isLoading) {
      void checkSession()
    }
  }, [isLoading, checkSession])

  // Show loading state
  if (isLoading || isVerifying) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        {fallback || (
          <div className="flex flex-col items-center gap-4">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <p className="text-sm text-muted-foreground">Verifying session...</p>
          </div>
        )}
      </div>
    )
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated || !isValid) {
    return (
      <Navigate
        to={`/login?redirect=${encodeURIComponent(location.pathname + location.search)}`}
        replace
      />
    )
  }

  return <>{children}</>
}
