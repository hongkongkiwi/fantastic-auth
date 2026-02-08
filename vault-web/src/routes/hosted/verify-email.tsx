/**
 * Hosted Email Verification Page
 * 
 * Pre-built hosted email verification page.
 * URL: /hosted/verify-email?token=xxx&tenant_id=xxx
 */

import { createFileRoute, useNavigate, Link } from '@tanstack/react-router'
import { useState, useEffect } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { CheckCircle, XCircle, Loader2, Mail, ArrowRight } from 'lucide-react'
import { Button } from '../../components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/Card'
import { Alert, AlertDescription } from '../../components/ui/Alert'
import { HostedLayout } from '../../hosted/HostedLayout'
import { useHostedConfig, useHostedSearchParams } from '../../hosted/useHostedConfig'
import { hostedVerifyEmail } from '../../hosted/api'

export const Route = createFileRoute('/hosted/verify-email')({
  component: HostedVerifyEmailPage,
})

type VerificationState = 'loading' | 'success' | 'error'

function HostedVerifyEmailPage() {
  const searchParams = useHostedSearchParams()
  
  return (
    <HostedLayout 
      searchParams={new URLSearchParams(window.location.search)}
    >
      <VerifyEmailContent searchParams={searchParams} />
    </HostedLayout>
  )
}

interface VerifyEmailContentProps {
  searchParams: ReturnType<typeof useHostedSearchParams>
}

function VerifyEmailContent({ searchParams }: VerifyEmailContentProps) {
  const navigate = useNavigate()
  const { config, tenantId } = useHostedConfig()
  const prefersReducedMotion = useReducedMotion()
  
  const [state, setState] = useState<VerificationState>('loading')
  const [error, setError] = useState<string | null>(null)

  const token = new URLSearchParams(window.location.search).get('token')

  useEffect(() => {
    if (!tenantId || !token) {
      setState('error')
      setError(!token ? 'Missing verification token' : 'Missing tenant ID')
      return
    }

    const verifyEmail = async () => {
      try {
        const result = await hostedVerifyEmail({
          data: {
            token,
            tenantId,
          },
        })

        if (result.success) {
          setState('success')
        } else {
          setState('error')
          setError('Verification failed')
        }
      } catch (err) {
        setState('error')
        setError(err instanceof Error ? err.message : 'Invalid or expired verification link')
      }
    }

    void verifyEmail()
  }, [tenantId, token])

  if (!config || !tenantId) {
    return null
  }

  const handleContinue = () => {
    const redirectUrl = config.afterSignInUrl || '/hosted/sign-in'
    navigate({
      to: redirectUrl as '/hosted/sign-in',
      search: { tenant_id: tenantId },
    })
  }

  return (
    <Card className="shadow-elevated">
      <CardContent className="pt-6">
        {state === 'loading' && (
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-center space-y-6 py-12"
          >
            <div className="w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto">
              <Loader2 className="w-8 h-8 text-primary animate-spin" />
            </div>
            <div>
              <h3 className="text-xl font-semibold">Verifying your email...</h3>
              <p className="text-sm text-muted-foreground mt-2">
                Please wait while we verify your email address
              </p>
            </div>
          </motion.div>
        )}

        {state === 'success' && (
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="text-center space-y-6 py-8"
          >
            <div className="w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto">
              <CheckCircle className="w-8 h-8 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <h3 className="text-xl font-semibold">Email verified!</h3>
              <p className="text-sm text-muted-foreground mt-2">
                Your email has been successfully verified. You can now sign in to your account.
              </p>
            </div>
            <Button onClick={handleContinue} fullWidth rightIcon={<ArrowRight className="h-4 w-4" />}>
              Continue to Sign In
            </Button>
          </motion.div>
        )}

        {state === 'error' && (
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="text-center space-y-6 py-8"
          >
            <div className="w-16 h-16 bg-destructive/10 rounded-full flex items-center justify-center mx-auto">
              <XCircle className="w-8 h-8 text-destructive" />
            </div>
            <div>
              <h3 className="text-xl font-semibold">Verification failed</h3>
              <p className="text-sm text-muted-foreground mt-2">
                {error || 'The verification link is invalid or has expired.'}
              </p>
            </div>
            
            <Alert>
              <Mail className="h-4 w-4" />
              <AlertDescription>
                Please request a new verification email or contact support if the problem persists.
              </AlertDescription>
            </Alert>

            <div className="space-y-3">
              <Link
                to="/hosted/sign-in"
                search={{ tenant_id: tenantId }}
                className="block"
              >
                <Button fullWidth>
                  Go to Sign In
                </Button>
              </Link>
              {config.allowSignUp && (
                <Link
                  to="/hosted/sign-up"
                  search={{ tenant_id: tenantId }}
                  className="block"
                >
                  <Button variant="outline" fullWidth>
                    Create New Account
                  </Button>
                </Link>
              )}
            </div>
          </motion.div>
        )}
      </CardContent>
    </Card>
  )
}
