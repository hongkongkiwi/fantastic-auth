/**
 * Hosted Sign-Up Page
 * 
 * Pre-built hosted registration page with theming support.
 * URL: /hosted/sign-up?tenant_id=xxx&redirect_url=xxx
 */

import { createFileRoute, useNavigate, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Eye, EyeOff, Lock, Mail, ArrowRight, User, CheckCircle, AlertCircle } from 'lucide-react'
import { Button } from '../../components/ui/Button'
import { Input } from '../../components/ui/Input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/Card'
import { Alert, AlertDescription } from '../../components/ui/Alert'
import { Checkbox } from '../../components/ui/Checkbox'
import { useForm } from '@tanstack/react-form'
import { HostedLayout } from '../../hosted/HostedLayout'
import { useHostedConfig } from '../../hosted/useHostedConfig'
import { hostedSignUp, hostedOAuthStart } from '../../hosted/api'
import { SocialLoginButtons } from '../../components/auth/SocialLoginButtons'
import type { OAuthProvider } from '../../hosted/types'

export const Route = createFileRoute('/hosted/sign-up' as any)({
  component: HostedSignUpPage,
})

function HostedSignUpPage() {
  return (
    <HostedLayout 
      searchParams={new URLSearchParams(window.location.search)}
    >
      <SignUpContent />
    </HostedLayout>
  )
}

function SignUpContent() {
  const navigate = useNavigate()
  const { config, tenantId, redirectUrl } = useHostedConfig()
  const prefersReducedMotion = useReducedMotion()
  
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [oauthLoading, setOauthLoading] = useState<string | null>(null)
  const [isSuccess, setIsSuccess] = useState(false)

  const form = useForm({
    defaultValues: {
      name: '',
      email: '',
      password: '',
      agreeToTerms: false,
    },
    onSubmit: async ({ value }) => {
      if (!tenantId) return
      
      setIsLoading(true)
      setError(null)
      
      try {
        const result = await hostedSignUp({
          data: {
            name: value.name,
            email: value.email,
            password: value.password,
            tenantId,
            redirectUrl: redirectUrl || undefined,
          },
        })
        
        // Check if email verification is required
        if (config?.requireEmailVerification) {
          setIsSuccess(true)
        } else {
          // Redirect directly
          window.location.href = result.redirectUrl
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Sign up failed')
      } finally {
        setIsLoading(false)
      }
    },
  })

  const handleOAuthSignUp = async (provider: OAuthProvider) => {
    if (!tenantId) return
    
    setOauthLoading(provider)
    setError(null)
    
    try {
      const result = await hostedOAuthStart({
        data: {
          provider,
          tenantId,
          redirectUrl: redirectUrl || undefined,
        },
      })
      
      // Store state for callback verification
      sessionStorage.setItem('hosted_oauth_state', result.state)
      
      // Redirect to OAuth provider
      window.location.href = result.authUrl
    } catch (err) {
      setError(err instanceof Error ? err.message : 'OAuth failed')
      setOauthLoading(null)
    }
  }

  if (!config || !tenantId) {
    return null
  }

  // Redirect to sign-in if sign-up is not allowed
  if (!config.allowSignUp) {
    navigate({
      to: '/hosted/sign-in' as any,
      search: { tenant_id: tenantId, redirect_url: redirectUrl || undefined } as any,
    })
    return null
  }

  const availableOAuthProviders = config.oauthProviders.filter(p => 
    ['google', 'github', 'apple', 'slack', 'discord'].includes(p)
  )

  if (isSuccess) {
    return (
      <Card className="shadow-elevated">
        <CardContent className="pt-6">
          <div className="text-center space-y-4 py-8">
            <div className="w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto">
              <CheckCircle className="w-8 h-8 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <h3 className="text-xl font-semibold">Verify your email</h3>
              <p className="text-sm text-muted-foreground mt-2">
                We&apos;ve sent a verification link to <strong>{form.getFieldValue('email')}</strong>
              </p>
              <p className="text-xs text-muted-foreground mt-2">
                Click the link in your email to complete your registration.
              </p>
            </div>
            <Button
              variant="outline"
              fullWidth
              onClick={() =>
                navigate({ to: '/hosted/sign-in' as any, search: { tenant_id: tenantId } as any })
              }
            >
              Back to Sign In
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="shadow-elevated">
      <CardHeader className="space-y-1">
        <CardTitle className="text-2xl text-center">
          {config.signUpTitle || `Create your ${config.companyName} account`}
        </CardTitle>
        <CardDescription className="text-center">
          Enter your details to get started
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Error Alert */}
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* OAuth Buttons */}
        {availableOAuthProviders.length > 0 && (
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.1 }}
          >
            <SocialLoginButtons
              onGoogleClick={availableOAuthProviders.includes('google') ? () => handleOAuthSignUp('google') : undefined}
              onGitHubClick={availableOAuthProviders.includes('github') ? () => handleOAuthSignUp('github') : undefined}
              onAppleClick={availableOAuthProviders.includes('apple') ? () => handleOAuthSignUp('apple') : undefined}
              onSlackClick={availableOAuthProviders.includes('slack') ? () => handleOAuthSignUp('slack') : undefined}
              onDiscordClick={availableOAuthProviders.includes('discord') ? () => handleOAuthSignUp('discord') : undefined}
              isLoading={!!oauthLoading}
            />
          </motion.div>
        )}

        {/* Sign Up Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault()
            e.stopPropagation()
            void form.handleSubmit()
          }}
          className="space-y-4"
        >
          <form.Field
            name="name"
            validators={{
              onChange: ({ value }: { value: string }) => {
                if (!value.trim()) return 'Name is required'
                if (value.trim().length < 2) return 'Name must be at least 2 characters'
                return undefined
              },
            }}
          >
            {(field: any) => (
              <Input
                label="Full Name"
                type="text"
                placeholder="John Doe"
                value={field.state.value}
                onChange={(e) => field.handleChange(e.target.value)}
                onBlur={field.handleBlur}
                error={field.state.meta.isTouched ? field.state.meta.errors[0] : undefined}
                leftIcon={<User className="h-4 w-4 text-muted-foreground" />}
                autoComplete="name"
                required
                disabled={isLoading}
              />
            )}
          </form.Field>

          <form.Field
            name="email"
            validators={{
              onChange: ({ value }: { value: string }) => {
                if (!value.trim()) return 'Email is required'
                if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                  return 'Please enter a valid email'
                }
                return undefined
              },
            }}
          >
            {(field: any) => (
              <Input
                label="Email"
                type="email"
                placeholder="you@example.com"
                value={field.state.value}
                onChange={(e) => field.handleChange(e.target.value)}
                onBlur={field.handleBlur}
                error={field.state.meta.isTouched ? field.state.meta.errors[0] : undefined}
                leftIcon={<Mail className="h-4 w-4 text-muted-foreground" />}
                autoComplete="email"
                autoCapitalize="none"
                spellCheck={false}
                required
                disabled={isLoading}
              />
            )}
          </form.Field>

          <form.Field
            name="password"
            validators={{
              onChange: ({ value }: { value: string }) => {
                if (!value) return 'Password is required'
                if (value.length < 8) return 'Password must be at least 8 characters'
                if (!/[A-Z]/.test(value)) return 'Password must contain an uppercase letter'
                if (!/[a-z]/.test(value)) return 'Password must contain a lowercase letter'
                if (!/[0-9]/.test(value)) return 'Password must contain a number'
                return undefined
              },
            }}
          >
            {(field: any) => (
              <Input
                label="Password"
                type={showPassword ? 'text' : 'password'}
                placeholder="••••••••"
                value={field.state.value}
                onChange={(e) => field.handleChange(e.target.value)}
                onBlur={field.handleBlur}
                error={field.state.meta.isTouched ? field.state.meta.errors[0] : undefined}
                leftIcon={<Lock className="h-4 w-4 text-muted-foreground" />}
                autoComplete="new-password"
                rightIcon={
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="text-muted-foreground hover:text-foreground transition-colors"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                }
                required
                disabled={isLoading}
              />
            )}
          </form.Field>

          {/* Terms Agreement */}
          {(config.termsUrl || config.privacyUrl) && (
            <form.Field
              name="agreeToTerms"
              validators={{
                onChange: ({ value }: { value: boolean }) => {
                  if (!value) return 'You must agree to continue'
                  return undefined
                },
              }}
            >
              {(field: any) => (
                <div className="space-y-2">
                  <div className="flex items-start gap-2">
                    <Checkbox
                      id="agreeToTerms"
                      checked={field.state.value}
                      onCheckedChange={(checked) => field.handleChange(checked as boolean)}
                      disabled={isLoading}
                    />
                    <label htmlFor="agreeToTerms" className="text-sm text-muted-foreground leading-relaxed cursor-pointer">
                      I agree to the{' '}
                      {config.termsUrl ? (
                        <a 
                          href={config.termsUrl} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-primary hover:underline"
                          onClick={(e) => e.stopPropagation()}
                        >
                          Terms of Service
                        </a>
                      ) : 'Terms of Service'}
                      {config.termsUrl && config.privacyUrl && ' and '}
                      {config.privacyUrl ? (
                        <a 
                          href={config.privacyUrl} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-primary hover:underline"
                          onClick={(e) => e.stopPropagation()}
                        >
                          Privacy Policy
                        </a>
                      ) : config.termsUrl ? 'Privacy Policy' : null}
                    </label>
                  </div>
                  {field.state.meta.isTouched && field.state.meta.errors[0] && (
                    <p className="text-sm text-destructive">{field.state.meta.errors[0]}</p>
                  )}
                </div>
              )}
            </form.Field>
          )}

          <Button
            type="submit"
            fullWidth
            size="lg"
            isLoading={isLoading}
            rightIcon={<ArrowRight className="h-4 w-4" />}
          >
            Create Account
          </Button>
        </form>

        {/* Footer Links */}
        <div className="text-center text-sm pt-4 border-t">
          <span className="text-muted-foreground">Already have an account?{' '}</span>
          <Link
            to={'/hosted/sign-in' as any}
            search={{ tenant_id: tenantId, redirect_url: redirectUrl || undefined } as any}
            className="text-primary hover:underline"
          >
            Sign in
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}
