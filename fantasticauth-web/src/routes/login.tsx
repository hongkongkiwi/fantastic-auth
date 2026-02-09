import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Shield, Eye, EyeOff, Lock, Mail, ArrowRight, Zap } from 'lucide-react'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/Tabs'
import { useAuth } from '../hooks/useAuth'
import { MagicLinkForm } from '../components/auth/MagicLinkForm'
import { SocialLoginButtons } from '../components/auth/SocialLoginButtons'
import { useForm } from '@tanstack/react-form'
import { clientLogger } from '../lib/client-logger'

export const Route = createFileRoute('/login')({
  component: LoginPage,
})

type LoginMethod = 'password' | 'magic-link'

function LoginPage() {
  const navigate = useNavigate()
  const { login, isAuthenticated } = useAuth()
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [loginMethod, setLoginMethod] = useState<LoginMethod>('password')
  const [oauthLoading, setOauthLoading] = useState<string | null>(null)
  const prefersReducedMotion = useReducedMotion()

  const form = useForm({
    defaultValues: {
      email: '',
      password: '',
    },
    onSubmit: async ({ value }) => {
      setIsLoading(true)
      try {
        await login(value.email, value.password)
      } finally {
        setIsLoading(false)
      }
    },
  })

  // Redirect if already logged in
  if (isAuthenticated) {
    navigate({ to: '/' })
    return null
  }

  const handleOAuthLogin = async (provider: string) => {
    setOauthLoading(provider)
    try {
      const response = await fetch(`/api/v1/auth/oauth/${provider}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ redirectUri: window.location.origin + '/oauth/callback' }),
      })
      
      if (!response.ok) throw new Error('Failed to initiate OAuth')
      
      const { authUrl } = await response.json()
      window.location.href = authUrl
    } catch (error) {
      clientLogger.error('OAuth error', error)
    } finally {
      setOauthLoading(null)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-background via-background to-muted">
      {/* Background decoration */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-1/2 -right-1/2 w-full h-full bg-primary/5 rounded-full blur-3xl" />
        <div className="absolute -bottom-1/2 -left-1/2 w-full h-full bg-secondary/5 rounded-full blur-3xl" />
      </div>

      <motion.div
        initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={prefersReducedMotion ? { duration: 0 } : { duration: 0.5 }}
        className="w-full max-w-md relative z-10"
      >
        {/* Logo */}
        <div className="flex justify-center mb-8">
          <motion.div
            initial={prefersReducedMotion ? false : { scale: 0.8 }}
            animate={{ scale: 1 }}
            transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.2, type: 'spring' }}
            className="flex items-center gap-3"
          >
            <div className="h-12 w-12 rounded-xl bg-primary flex items-center justify-center shadow-glow">
              <Shield className="h-7 w-7 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Vault</h1>
              <p className="text-sm text-muted-foreground">Admin Console</p>
            </div>
          </motion.div>
        </div>

        <Card className="shadow-elevated">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl text-center">Welcome back</CardTitle>
            <CardDescription className="text-center">
              Sign in to access your admin panel
            </CardDescription>
          </CardHeader>
          <CardContent>
            {/* Login Method Tabs */}
            <Tabs value={loginMethod} onValueChange={(v) => setLoginMethod(v as LoginMethod)} className="mb-6">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="password" className="gap-2">
                  <Lock className="h-4 w-4" />
                  Password
                </TabsTrigger>
                <TabsTrigger value="magic-link" className="gap-2">
                  <Zap className="h-4 w-4" />
                  Magic Link
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="password" className="mt-4">
                <form
                  onSubmit={(event) => {
                    event.preventDefault()
                    event.stopPropagation()
                    void form.handleSubmit()
                  }}
                  className="space-y-4"
                >
                  <motion.div
                    initial={prefersReducedMotion ? false : { opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.3 }}
                  >
                    <form.Field
                      name="email"
                      validators={{
                        onChange: ({ value }) => {
                          if (!value.trim()) return 'Email is required'
                          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                            return 'Please enter a valid email'
                          }
                          return undefined
                        },
                      }}
                    >
                      {(field) => (
                          <Input
                            label="Email"
                            type="email"
                            placeholder="admin@vault.local"
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                            error={
                              field.state.meta.isTouched
                                ? field.state.meta.errors[0]
                                : undefined
                            }
                            leftIcon={<Mail className="h-4 w-4 text-muted-foreground" />}
                            autoComplete="email"
                            autoCapitalize="none"
                            spellCheck={false}
                            required
                          />
                      )}
                    </form.Field>
                  </motion.div>

                  <motion.div
                    initial={prefersReducedMotion ? false : { opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.4 }}
                  >
                    <div className="relative">
                      <form.Field
                        name="password"
                        validators={{
                          onChange: ({ value }) => {
                            if (loginMethod === 'password' && !value) {
                              return 'Password is required'
                            }
                            return undefined
                          },
                        }}
                      >
                        {(field) => (
                          <Input
                            label="Password"
                            type={showPassword ? 'text' : 'password'}
                            placeholder="••••••••"
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                            error={
                              field.state.meta.isTouched
                                ? field.state.meta.errors[0]
                                : undefined
                            }
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
                          />
                        )}
                      </form.Field>
                    </div>
                  </motion.div>

                  <motion.div
                    initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.5 }}
                    className="flex items-center justify-between text-sm"
                  >
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input type="checkbox" className="rounded border-input" />
                      <span className="text-muted-foreground">Remember me</span>
                    </label>
                    <a href="#" className="text-primary hover:underline">
                      Forgot password?
                    </a>
                  </motion.div>

                  <motion.div
                    initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.6 }}
                  >
                    <Button
                      type="submit"
                      fullWidth
                      size="lg"
                      isLoading={isLoading}
                      rightIcon={<ArrowRight className="h-4 w-4" />}
                    >
                      Sign In
                    </Button>
                  </motion.div>
                </form>

                {/* Social Login */}
                <motion.div
                  initial={prefersReducedMotion ? false : { opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.7 }}
                  className="mt-6"
                >
                  <SocialLoginButtons
                    onGoogleClick={() => handleOAuthLogin('google')}
                    onGitHubClick={() => handleOAuthLogin('github')}
                    onAppleClick={() => handleOAuthLogin('apple')}
                    isLoading={!!oauthLoading}
                  />
                </motion.div>
              </TabsContent>
              
              <TabsContent value="magic-link" className="mt-4">
                <MagicLinkForm />
              </TabsContent>
            </Tabs>

            {/* Demo credentials */}
            <motion.div
              initial={prefersReducedMotion ? false : { opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.8 }}
              className="mt-6 p-4 rounded-lg bg-muted/50 border border-dashed"
            >
              <p className="text-xs text-muted-foreground text-center mb-2">Demo Credentials</p>
              <div className="flex items-center justify-center gap-2 text-sm">
                <Badge variant="secondary">admin@vault.local</Badge>
                <span className="text-muted-foreground">/</span>
                <Badge variant="secondary">admin</Badge>
              </div>
            </motion.div>
          </CardContent>
        </Card>

        <motion.p
          initial={prefersReducedMotion ? false : { opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.9 }}
          className="text-center text-sm text-muted-foreground mt-6"
        >
          Protected by industry-standard encryption
        </motion.p>
      </motion.div>
    </div>
  )
}
