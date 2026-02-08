/**
 * Hosted Sign-In Page
 * 
 * Pre-built hosted authentication page with theming support.
 * URL: /hosted/sign-in?tenant_id=xxx&redirect_url=xxx
 */

import { createFileRoute, useNavigate, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Eye, EyeOff, Lock, Mail, ArrowRight, Fingerprint, Zap, AlertCircle } from 'lucide-react'
import { Button } from '../../components/ui/Button'
import { Input } from '../../components/ui/Input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/Card'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../../components/ui/Tabs'
import { Alert, AlertDescription } from '../../components/ui/Alert'
import { useForm, type ReactFormExtendedApi } from '@tanstack/react-form'
import { HostedLayout } from '../../hosted/HostedLayout'
import { useHostedConfig } from '../../hosted/useHostedConfig'
import { hostedSignIn, hostedSendMagicLink, hostedOAuthStart } from '../../hosted/api'
import { SocialLoginButtons } from '../../components/auth/SocialLoginButtons'
import type { OAuthProvider } from '../../hosted/types'

export const Route = createFileRoute('/hosted/sign-in' as any)({
  component: HostedSignInPage,
})

type LoginMethod = 'password' | 'magic-link'

function HostedSignInPage() {
  return (
    <HostedLayout 
      searchParams={new URLSearchParams(window.location.search)}
    >
      <SignInContent />
    </HostedLayout>
  )
}

function SignInContent() {
  const navigate = useNavigate()
  const { config, tenantId, redirectUrl, error: configError } = useHostedConfig()
  const prefersReducedMotion = useReducedMotion()
  
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loginMethod, setLoginMethod] = useState<LoginMethod>('password')
  const [oauthLoading, setOauthLoading] = useState<string | null>(null)
  const [magicLinkSent, setMagicLinkSent] = useState(false)

  const passwordForm = useForm({
    defaultValues: {
      email: '',
      password: '',
    },
    onSubmit: async ({ value }) => {
      if (!tenantId) return
      
      setIsLoading(true)
      setError(null)
      
      try {
        const result = await hostedSignIn({
          data: {
            email: value.email,
            password: value.password,
            tenantId,
            redirectUrl: redirectUrl || undefined,
          },
        })
        
        // Handle MFA challenge if required
        if (result.requiresMfa && result.mfaToken) {
          navigate({
            to: '/hosted/mfa' as any,
            search: {
              tenant_id: tenantId,
              mfa_token: result.mfaToken,
              redirect_url: redirectUrl || undefined,
            } as any,
          })
          return
        }
        
        // Redirect to the specified URL
        window.location.href = result.redirectUrl
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Sign in failed')
      } finally {
        setIsLoading(false)
      }
    },
  })

  const magicLinkForm = useForm({
    defaultValues: {
      email: '',
    },
    onSubmit: async ({ value }) => {
      if (!tenantId) return
      
      setIsLoading(true)
      setError(null)
      
      try {
        await hostedSendMagicLink({
          data: {
            email: value.email,
            tenantId,
            redirectUrl: redirectUrl || undefined,
          },
        })
        setMagicLinkSent(true)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to send magic link')
      } finally {
        setIsLoading(false)
      }
    },
  })

  const handleOAuthLogin = async (provider: OAuthProvider) => {
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

  const handleWebAuthn = async () => {
    setError('WebAuthn coming soon')
  }

  if (!config || !tenantId) {
    return null
  }

  const availableOAuthProviders = config.oauthProviders.filter(p => 
    ['google', 'github', 'apple', 'slack', 'discord'].includes(p)
  )

  return (
    <Card className="shadow-elevated">
      <CardHeader className="space-y-1">
        <CardTitle className="text-2xl text-center">
          {config.signInTitle || `Sign in to ${config.companyName}`}
        </CardTitle>
        <CardDescription className="text-center">
          Enter your credentials to access your account
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
        
        {/* Config Error */}
        {configError && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{configError}</AlertDescription>
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
              onGoogleClick={availableOAuthProviders.includes('google') ? () => handleOAuthLogin('google') : undefined}
              onGitHubClick={availableOAuthProviders.includes('github') ? () => handleOAuthLogin('github') : undefined}
              onAppleClick={availableOAuthProviders.includes('apple') ? () => handleOAuthLogin('apple') : undefined}
              onSlackClick={availableOAuthProviders.includes('slack') ? () => handleOAuthLogin('slack') : undefined}
              onDiscordClick={availableOAuthProviders.includes('discord') ? () => handleOAuthLogin('discord') : undefined}
              isLoading={!!oauthLoading}
            />
          </motion.div>
        )}

        {/* Login Method Tabs */}
        {(config.showMagicLink || config.showWebAuthn) ? (
          <Tabs value={loginMethod} onValueChange={(v) => setLoginMethod(v as LoginMethod)}>
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="password" className="gap-2">
                <Lock className="h-4 w-4" />
                Password
              </TabsTrigger>
              {config.showMagicLink && (
                <TabsTrigger value="magic-link" className="gap-2">
                  <Zap className="h-4 w-4" />
                  Magic Link
                </TabsTrigger>
              )}
            </TabsList>

            <TabsContent value="password" className="mt-4 space-y-4">
              <PasswordForm 
                form={passwordForm}
                showPassword={showPassword}
                setShowPassword={setShowPassword}
                isLoading={isLoading}
                config={config}
              />
            </TabsContent>

            {config.showMagicLink && (
              <TabsContent value="magic-link" className="mt-4">
                {magicLinkSent ? (
                  <MagicLinkSuccess email={magicLinkForm.getFieldValue('email')} />
                ) : (
                  <MagicLinkForm form={magicLinkForm} isLoading={isLoading} />
                )}
              </TabsContent>
            )}
          </Tabs>
        ) : (
          <PasswordForm 
            form={passwordForm}
            showPassword={showPassword}
            setShowPassword={setShowPassword}
            isLoading={isLoading}
            config={config}
          />
        )}

        {/* WebAuthn Button */}
        {config.showWebAuthn && (
          <Button
            variant="outline"
            fullWidth
            onClick={handleWebAuthn}
            disabled={isLoading}
            className="gap-2"
          >
            <Fingerprint className="h-4 w-4" />
            Sign in with Passkey
          </Button>
        )}

        {/* Footer Links */}
        <div className="flex items-center justify-between text-sm pt-4 border-t">
          {config.allowSignUp ? (
            <Link
              to={'/hosted/sign-up' as any}
              search={{ tenant_id: tenantId, redirect_url: redirectUrl || undefined } as any}
              className="text-primary hover:underline"
            >
              Create account
            </Link>
          ) : (
            <span />
          )}
          <Link
            to={'/hosted/forgot-password' as any}
            search={{ tenant_id: tenantId } as any}
            className="text-primary hover:underline"
          >
            Forgot password?
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}

type AnyReactFormApi = ReactFormExtendedApi<any, any, any, any, any, any, any, any, any, any, any, any>

interface PasswordFormProps {
  form: AnyReactFormApi
  showPassword: boolean
  setShowPassword: (value: boolean) => void
  isLoading: boolean
  config: { companyName: string }
}

function PasswordForm({ form, showPassword, setShowPassword, isLoading, config }: PasswordFormProps) {
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        e.stopPropagation()
        void form.handleSubmit()
      }}
      className="space-y-4"
    >
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
            placeholder={`you@${config.companyName.toLowerCase().replace(/\s+/g, '')}.com`}
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
            autoComplete="current-password"
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

      <Button
        type="submit"
        fullWidth
        size="lg"
        isLoading={isLoading}
        rightIcon={<ArrowRight className="h-4 w-4" />}
      >
        Sign In
      </Button>
    </form>
  )
}

interface MagicLinkFormProps {
  form: AnyReactFormApi
  isLoading: boolean
}

function MagicLinkForm({ form, isLoading }: MagicLinkFormProps) {
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        e.stopPropagation()
        void form.handleSubmit()
      }}
      className="space-y-4"
    >
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
            required
            disabled={isLoading}
          />
        )}
      </form.Field>

      <Button
        type="submit"
        fullWidth
        isLoading={isLoading}
        rightIcon={<Zap className="h-4 w-4" />}
      >
        Send Magic Link
      </Button>

      <p className="text-xs text-center text-muted-foreground">
        You&apos;ll receive an email with a secure link to sign in instantly
      </p>
    </form>
  )
}

function MagicLinkSuccess({ email }: { email: string }) {
  return (
    <div className="text-center space-y-4 py-8">
      <div className="w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto">
        <Mail className="w-8 h-8 text-green-600 dark:text-green-400" />
      </div>
      <div>
        <h3 className="text-lg font-semibold">Check your email</h3>
        <p className="text-sm text-muted-foreground mt-1">
          We&apos;ve sent a magic link to <strong>{email}</strong>
        </p>
        <p className="text-xs text-muted-foreground mt-2">
          Link expires in 15 minutes
        </p>
      </div>
    </div>
  )
}
