/**
 * Hosted Forgot Password Page
 * 
 * Pre-built hosted password reset page with theming support.
 * URL: /hosted/forgot-password?tenant_id=xxx
 */

import { createFileRoute, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Mail, ArrowLeft, CheckCircle, AlertCircle, KeyRound } from 'lucide-react'
import { Button } from '../../components/ui/Button'
import { Input } from '../../components/ui/Input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/Card'
import { Alert, AlertDescription } from '../../components/ui/Alert'
import { useForm } from '@tanstack/react-form'
import { HostedLayout } from '../../hosted/HostedLayout'
import { useHostedConfig } from '../../hosted/useHostedConfig'
import { hostedRequestPasswordReset } from '../../hosted/api'

export const Route = createFileRoute('/hosted/forgot-password' as any)({
  component: HostedForgotPasswordPage,
})

function HostedForgotPasswordPage() {
  return (
    <HostedLayout 
      searchParams={new URLSearchParams(window.location.search)}
    >
      <ForgotPasswordContent />
    </HostedLayout>
  )
}

function ForgotPasswordContent() {
  const { config, tenantId } = useHostedConfig()
  const prefersReducedMotion = useReducedMotion()
  
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isSuccess, setIsSuccess] = useState(false)

  const form = useForm({
    defaultValues: {
      email: '',
    },
    onSubmit: async ({ value }) => {
      if (!tenantId) return
      
      setIsLoading(true)
      setError(null)
      
      try {
        await hostedRequestPasswordReset({
          data: {
            email: value.email,
            tenantId,
          },
        })
        setIsSuccess(true)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to send reset email')
      } finally {
        setIsLoading(false)
      }
    },
  })

  if (!config || !tenantId) {
    return null
  }

  if (isSuccess) {
    return (
      <Card className="shadow-elevated">
        <CardContent className="pt-6">
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="text-center space-y-6 py-8"
          >
            <div className="w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto">
              <CheckCircle className="w-8 h-8 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <h3 className="text-xl font-semibold">Check your email</h3>
              <p className="text-sm text-muted-foreground mt-2">
                We&apos;ve sent password reset instructions to <strong>{form.getFieldValue('email')}</strong>
              </p>
              <p className="text-xs text-muted-foreground mt-2">
                The link will expire in 1 hour.
              </p>
            </div>
            <div className="space-y-3">
              <Button
                variant="outline"
                fullWidth
                onClick={() => setIsSuccess(false)}
              >
                Use a different email
              </Button>
              <Link
                to={'/hosted/sign-in' as any}
                search={{ tenant_id: tenantId } as any}
                className="block"
              >
                <Button variant="ghost" fullWidth className="gap-2">
                  <ArrowLeft className="h-4 w-4" />
                  Back to Sign In
                </Button>
              </Link>
            </div>
          </motion.div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="shadow-elevated">
      <CardHeader className="space-y-1">
        <div className="mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-2">
          <KeyRound className="h-6 w-6 text-primary" />
        </div>
        <CardTitle className="text-2xl text-center">Forgot password?</CardTitle>
        <CardDescription className="text-center">
          Enter your email and we&apos;ll send you reset instructions
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
                autoCapitalize="none"
                spellCheck={false}
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
          >
            Send Reset Instructions
          </Button>
        </form>

        {/* Back to Sign In */}
        <div className="text-center pt-4 border-t">
          <Link
            to="/hosted/sign-in"
            search={{ tenant_id: tenantId }}
            className="inline-flex items-center gap-2 text-sm text-primary hover:underline"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Sign In
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}
