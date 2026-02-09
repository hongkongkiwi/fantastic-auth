import { useForm } from '@tanstack/react-form'
import { useState, type ReactNode } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Shield, Chrome, Github, Apple, BadgeCheck } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card } from '@/components/ui/Card'
import { useAuth } from '@/hooks/useAuth'
import { useAuthStore } from '@/store'
import { authApi, AuthMfaRequiredError } from '@/services/api'
import { setPendingMfaLogin } from '@/lib/pending-mfa'
import { env } from '@/env/client'

type LocationState = {
  from?: {
    pathname?: string
  }
}

export function Login() {
  const navigate = useNavigate()
  const location = useLocation()
  const { isAuthenticated } = useAuthStore()
  const { login, isLoading, error } = useAuth()
  const from = ((location.state as LocationState | null)?.from?.pathname) || '/'
  const [oauthLoading, setOauthLoading] = useState<string | null>(null)

  const form = useForm({
    defaultValues: {
      email: '',
      password: '',
      mfaCode: '',
    },
    onSubmit: async ({ value }) => {
      try {
        await login(value.email, value.password, value.mfaCode || undefined)
        navigate(from, { replace: true })
      } catch (err) {
        if (err instanceof AuthMfaRequiredError) {
          setPendingMfaLogin({
            email: value.email,
            password: value.password,
            mfaToken: err.mfaToken,
            redirectPath: from,
          })
          navigate('/mfa', { replace: true })
          return
        }
        // Error state is surfaced via `error`.
      }
    },
  })

  const handleOAuthLogin = async (
    provider: 'google' | 'github' | 'microsoft' | 'apple',
  ) => {
    setOauthLoading(provider)
    try {
      const response = await authApi.getOAuthRedirect(
        provider,
        `${window.location.origin}/oauth/callback`,
      )
      const authUrl = response.authUrl || response.authorizationUrl
      if (!authUrl) throw new Error('No authorization URL returned')
      window.location.href = authUrl
    } catch {
      // Keep surface minimal; login error remains on page.
    } finally {
      setOauthLoading(null)
    }
  }

  const socialProviders = ([
    { id: 'google', label: 'Google', enabled: env.VITE_OAUTH_GOOGLE_ENABLED === 'true', icon: <Chrome className="h-4 w-4" /> },
    { id: 'github', label: 'GitHub', enabled: env.VITE_OAUTH_GITHUB_ENABLED === 'true', icon: <Github className="h-4 w-4" /> },
    { id: 'microsoft', label: 'Microsoft', enabled: env.VITE_OAUTH_MICROSOFT_ENABLED === 'true', icon: <BadgeCheck className="h-4 w-4" /> },
    { id: 'apple', label: 'Apple', enabled: env.VITE_OAUTH_APPLE_ENABLED === 'true', icon: <Apple className="h-4 w-4" /> },
  ] as const satisfies Array<{
    id: 'google' | 'github' | 'microsoft' | 'apple'
    label: string
    enabled: boolean
    icon: ReactNode
  }>).filter((provider) => provider.enabled)

  if (isAuthenticated) {
    return <Navigate to={from} replace />
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md p-8">
        <div className="mb-6 flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
            <Shield className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">Tenant Admin Login</h1>
            <p className="text-sm text-muted-foreground">Sign in to continue</p>
          </div>
        </div>

        <form
          onSubmit={(event) => {
            event.preventDefault()
            event.stopPropagation()
            void form.handleSubmit()
          }}
          className="space-y-4"
        >
          <div className="space-y-1">
            <label htmlFor="email" className="text-sm font-medium">
              Email
            </label>
            <form.Field
              name="email"
              validators={{
                onSubmit: ({ value }) => (!value ? 'Email is required' : undefined),
              }}
            >
              {(field) => (
                <input
                  id="email"
                  type="email"
                  value={field.state.value}
                  onChange={(event) => field.handleChange(event.target.value)}
                  className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  autoComplete="email"
                  required
                />
              )}
            </form.Field>
          </div>

          <div className="space-y-1">
            <label htmlFor="password" className="text-sm font-medium">
              Password
            </label>
            <form.Field
              name="password"
              validators={{
                onSubmit: ({ value }) => (!value ? 'Password is required' : undefined),
              }}
            >
              {(field) => (
                <input
                  id="password"
                  type="password"
                  value={field.state.value}
                  onChange={(event) => field.handleChange(event.target.value)}
                  className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  autoComplete="current-password"
                  required
                />
              )}
            </form.Field>
          </div>

          <div className="space-y-1">
            <label htmlFor="mfaCode" className="text-sm font-medium">
              MFA Code (optional)
            </label>
            <form.Field name="mfaCode">
              {(field) => (
                <input
                  id="mfaCode"
                  value={field.state.value}
                  onChange={(event) => field.handleChange(event.target.value)}
                  className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                  autoComplete="one-time-code"
                  inputMode="numeric"
                />
              )}
            </form.Field>
          </div>

          {error ? (
            <p className="text-sm text-red-600">{error}</p>
          ) : null}

          <Button type="submit" className="w-full" isLoading={isLoading}>
            Sign In
          </Button>
        </form>

        {socialProviders.length > 0 && (
          <div className="mt-6 space-y-3">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background px-2 text-muted-foreground">Or continue with</span>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {socialProviders.map((provider) => (
                <Button
                  key={provider.id}
                  type="button"
                  variant="outline"
                  className="gap-2"
                  onClick={() => void handleOAuthLogin(provider.id)}
                  disabled={Boolean(oauthLoading)}
                >
                  {provider.icon}
                  {provider.label}
                </Button>
              ))}
            </div>
          </div>
        )}
      </Card>
    </div>
  )
}
