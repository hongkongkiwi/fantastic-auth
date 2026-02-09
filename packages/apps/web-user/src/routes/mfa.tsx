import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState, type FormEvent } from 'react'
import { Shield } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { features } from '@/lib/features'
import { useAuth } from '@/auth/context'
import { clearPendingMfaLogin, getPendingMfaLogin } from '@/auth/pending-mfa'
import { toast } from 'sonner'

export const Route = createFileRoute('/mfa')({
  component: MfaPage,
})

function MfaPage() {
  const navigate = useNavigate()
  const { login, isLoading } = useAuth()
  const [code, setCode] = useState('')
  const pending = getPendingMfaLogin()

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!pending) return

    try {
      await login(pending.email, pending.password, code, pending.mfaToken)
      clearPendingMfaLogin()
      toast.success('MFA verification successful')
      void navigate({ to: pending.redirectPath || '/' })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Invalid MFA code')
    }
  }

  if (pending) {
    return (
      <Card className="max-w-md">
        <CardHeader>
          <CardTitle>Two-Factor Authentication</CardTitle>
          <CardDescription>Enter the verification code from your authenticator app.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="mfaCode">Verification Code</Label>
              <Input
                id="mfaCode"
                value={code}
                onChange={(event) => setCode(event.target.value)}
                autoComplete="one-time-code"
                inputMode="numeric"
                required
              />
            </div>
            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? 'Verifying...' : 'Verify and Sign In'}
            </Button>
            <Button
              type="button"
              variant="outline"
              className="w-full"
              onClick={() => {
                clearPendingMfaLogin()
                void navigate({ to: '/login' })
              }}
            >
              Back to Login
            </Button>
          </form>
        </CardContent>
      </Card>
    )
  }

  if (!features.security) {
    return (
      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-muted-foreground" />
            MFA Controls Disabled
          </CardTitle>
          <CardDescription>
            Multi-factor authentication controls are currently disabled.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild variant="outline">
            <Link to="/">Back to Profile</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="max-w-2xl">
      <CardHeader>
        <CardTitle>MFA Management</CardTitle>
        <CardDescription>
          MFA settings are available from the Security page in this environment.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Button asChild>
          <Link to="/security">Go to Security Settings</Link>
        </Button>
      </CardContent>
    </Card>
  )
}
