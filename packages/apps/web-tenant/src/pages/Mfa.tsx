import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { useAuth } from '@/hooks/useAuth'
import { clearPendingMfaLogin, getPendingMfaLogin } from '@/lib/pending-mfa'

export function Mfa() {
  const navigate = useNavigate()
  const { login, isLoading } = useAuth()
  const [code, setCode] = useState('')
  const pending = getPendingMfaLogin()

  if (!pending) {
    navigate('/login', { replace: true })
    return null
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()
    try {
      await login(pending.email, pending.password, code, pending.mfaToken)
      clearPendingMfaLogin()
      navigate(pending.redirectPath || '/', { replace: true })
    } catch {
      // Error shown via auth hook.
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md p-8">
        <div className="mb-6">
          <h1 className="text-xl font-semibold">Two-Factor Verification</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Enter the code from your authenticator app to continue.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1">
            <label htmlFor="mfaCode" className="text-sm font-medium">
              Verification Code
            </label>
            <input
              id="mfaCode"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              autoComplete="one-time-code"
              inputMode="numeric"
              required
            />
          </div>

          <Button type="submit" className="w-full" isLoading={isLoading}>
            Verify and Sign In
          </Button>

          <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={() => {
              clearPendingMfaLogin()
              navigate('/login', { replace: true })
            }}
          >
            Back to Login
          </Button>
        </form>
      </Card>
    </div>
  )
}
