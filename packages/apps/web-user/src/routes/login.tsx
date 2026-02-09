import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useForm } from '@tanstack/react-form'
import { useEffect, useState, type ReactNode } from 'react'
import { Shield, Chrome, Github, Apple, BadgeCheck } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { useAuth } from '@/auth/context'
import { authApi, AuthMfaRequiredError } from '@/auth/api'
import { setPendingMfaLogin } from '@/auth/pending-mfa'
import { sanitizeRedirectPath } from '@/lib/redirect'
import { env } from '@/env/client'
import { toast } from 'sonner'

export const Route = createFileRoute('/login' as any)({
  component: LoginPage,
})

function LoginPage() {
  const navigate = useNavigate()
  const { login, isLoading, isAuthenticated } = useAuth()
  const redirectPath = sanitizeRedirectPath(
    typeof window === 'undefined'
      ? '/'
      : new URLSearchParams(window.location.search).get('redirect'),
  )
  const [error, setError] = useState<string | null>(null)
  const [oauthLoading, setOauthLoading] = useState<string | null>(null)

  const form = useForm({
    defaultValues: {
      email: '',
      password: '',
      mfaCode: '',
    },
    onSubmit: async ({ value }) => {
      setError(null)
      try {
        await login(value.email, value.password, value.mfaCode || undefined)
        toast.success('Signed in successfully')
        void navigate({ to: redirectPath })
      } catch (err) {
        if (err instanceof AuthMfaRequiredError) {
          setPendingMfaLogin({
            email: value.email,
            password: value.password,
            mfaToken: err.mfaToken,
            redirectPath,
          })
          void navigate({ to: '/mfa' })
          return
        }
        const message = err instanceof Error ? err.message : 'Unable to sign in.'
        setError(message)
        toast.error(message)
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
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to start social login.'
      toast.error(message)
    } finally {
      setOauthLoading(null)
    }
  }

  const socialProviders = ([
    { id: 'google', label: 'Google', enabled: env.VITE_OAUTH_GOOGLE_ENABLED === 'true', icon: <Chrome className="h-4 w-4" aria-hidden="true" /> },
    { id: 'github', label: 'GitHub', enabled: env.VITE_OAUTH_GITHUB_ENABLED === 'true', icon: <Github className="h-4 w-4" aria-hidden="true" /> },
    { id: 'microsoft', label: 'Microsoft', enabled: env.VITE_OAUTH_MICROSOFT_ENABLED === 'true', icon: <BadgeCheck className="h-4 w-4" aria-hidden="true" /> },
    { id: 'apple', label: 'Apple', enabled: env.VITE_OAUTH_APPLE_ENABLED === 'true', icon: <Apple className="h-4 w-4" aria-hidden="true" /> },
  ] as const satisfies Array<{
    id: 'google' | 'github' | 'microsoft' | 'apple'
    label: string
    enabled: boolean
    icon: ReactNode
  }>).filter((provider) => provider.enabled)

  useEffect(() => {
    if (!isAuthenticated) return
    void navigate({ to: redirectPath })
  }, [isAuthenticated, navigate, redirectPath])

  if (isAuthenticated) return null

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="mb-2 flex items-center gap-2">
            <div className="h-9 w-9 rounded-lg bg-primary/10 flex items-center justify-center">
              <Shield className="h-5 w-5 text-primary" aria-hidden="true" />
            </div>
            <CardTitle>Sign In</CardTitle>
          </div>
          <CardDescription>Access your user portal securely.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(event) => {
              event.preventDefault()
              event.stopPropagation()
              void form.handleSubmit()
            }}
            className="space-y-4"
          >
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <form.Field
                name="email"
                validators={{
                  onSubmit: ({ value }) => (!value ? 'Email is required' : undefined),
                }}
              >
                {(field) => (
                  <Input
                    id="email"
                    type="email"
                    value={field.state.value}
                    onChange={(event) => field.handleChange(event.target.value)}
                    autoComplete="email"
                    required
                  />
                )}
              </form.Field>
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <form.Field
                name="password"
                validators={{
                  onSubmit: ({ value }) => (!value ? 'Password is required' : undefined),
                }}
              >
                {(field) => (
                  <Input
                    id="password"
                    type="password"
                    value={field.state.value}
                    onChange={(event) => field.handleChange(event.target.value)}
                    autoComplete="current-password"
                    required
                  />
                )}
              </form.Field>
            </div>

            <div className="space-y-2">
              <Label htmlFor="mfaCode">MFA Code (optional)</Label>
              <form.Field name="mfaCode">
                {(field) => (
                  <Input
                    id="mfaCode"
                    value={field.state.value}
                    onChange={(event) => field.handleChange(event.target.value)}
                    autoComplete="one-time-code"
                    inputMode="numeric"
                  />
                )}
              </form.Field>
            </div>

            {error ? <p className="text-sm text-destructive">{error}</p> : null}

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? 'Signing in...' : 'Sign In'}
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
        </CardContent>
      </Card>
    </div>
  )
}
