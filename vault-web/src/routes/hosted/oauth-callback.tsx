/**
 * Hosted OAuth Callback Page
 * 
 * Handles OAuth provider callbacks and exchanges code for tokens.
 * URL: /hosted/oauth-callback?code=xxx&state=xxx&tenant_id=xxx
 */

import { createFileRoute, useNavigate, Link } from '@tanstack/react-router'
import { useState, useEffect } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Loader2, CheckCircle, XCircle, ArrowRight } from 'lucide-react'
import { Button } from '../../components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/Card'
import { HostedLayout } from '../../hosted/HostedLayout'
import { useHostedConfig } from '../../hosted/useHostedConfig'
import { hostedOAuthCallback } from '../../hosted/api'

export const Route = createFileRoute('/hosted/oauth-callback' as any)({
  component: HostedOAuthCallbackPage,
})

type CallbackState = 'processing' | 'success' | 'error'

function HostedOAuthCallbackPage() {
  return (
    <HostedLayout 
      searchParams={new URLSearchParams(window.location.search)}
    >
      <OAuthCallbackContent />
    </HostedLayout>
  )
}

function OAuthCallbackContent() {
  const navigate = useNavigate()
  const { config, tenantId, redirectUrl } = useHostedConfig()
  const prefersReducedMotion = useReducedMotion()
  
  const [state, setState] = useState<CallbackState>('processing')
  const [error, setError] = useState<string | null>(null)
  const [requiresMfa, setRequiresMfa] = useState(false)
  const [mfaToken, setMfaToken] = useState<string | null>(null)

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const code = urlParams.get('code')
    const state = urlParams.get('state')
    const errorParam = urlParams.get('error')
    const errorDescription = urlParams.get('error_description')

    // Check for OAuth errors
    if (errorParam) {
      setState('error')
      setError(errorDescription || `OAuth error: ${errorParam}`)
      return
    }

    // Validate required parameters
    if (!tenantId) {
      setState('error')
      setError('Missing tenant_id parameter')
      return
    }

    if (!code || !state) {
      setState('error')
      setError('Invalid OAuth callback: missing code or state')
      return
    }

    // Verify state to prevent CSRF
    const storedState = sessionStorage.getItem('hosted_oauth_state')
    if (storedState && storedState !== state) {
      setState('error')
      setError('Invalid state parameter. Possible CSRF attack.')
      return
    }

    // Clear stored state
    sessionStorage.removeItem('hosted_oauth_state')

    // Exchange code for tokens
    const exchangeCode = async () => {
      try {
        const result = await hostedOAuthCallback({
          data: {
            code,
            state,
            tenantId,
            redirectUrl: redirectUrl || undefined,
          },
        })

        // Check if MFA is required
        if (result.requiresMfa && result.mfaToken) {
          setRequiresMfa(true)
          setMfaToken(result.mfaToken)
          setState('success')
          return
        }

        setState('success')

        // Redirect after a short delay
        setTimeout(() => {
          window.location.href = result.redirectUrl
        }, 1500)
      } catch (err) {
        setState('error')
        setError(err instanceof Error ? err.message : 'OAuth authentication failed')
      }
    }

    void exchangeCode()
  }, [tenantId, redirectUrl])

  if (!config || !tenantId) {
    return null
  }

  const handleContinue = () => {
    if (requiresMfa && mfaToken) {
      navigate({
        to: '/hosted/mfa' as any,
        search: {
          tenant_id: tenantId,
          mfa_token: mfaToken,
          redirect_url: redirectUrl || undefined,
        } as any,
      })
    } else {
      const targetUrl = redirectUrl || config.afterSignInUrl || '/hosted/sign-in'
      window.location.href = targetUrl
    }
  }

  return (
    <Card className="shadow-elevated">
      <CardHeader className="space-y-1">
        <CardTitle className="text-2xl text-center">
          {state === 'processing' && 'Completing Sign In...'}
          {state === 'success' && requiresMfa && 'Additional Verification Required'}
          {state === 'success' && !requiresMfa && 'Sign In Successful!'}
          {state === 'error' && 'Sign In Failed'}
        </CardTitle>
        <CardDescription className="text-center">
          {state === 'processing' && 'Please wait while we complete the authentication...'}
          {state === 'success' && requiresMfa && 'Please verify your identity to continue.'}
          {state === 'success' && !requiresMfa && 'Redirecting you to your account...'}
          {state === 'error' && 'We couldn\'t complete the sign in process.'}
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {state === 'processing' && (
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex flex-col items-center py-8"
          >
            <div className="w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mb-4">
              <Loader2 className="w-8 h-8 text-primary animate-spin" />
            </div>
            <p className="text-sm text-muted-foreground">
              Exchanging authorization code...
            </p>
          </motion.div>
        )}

        {state === 'success' && (
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="text-center space-y-6 py-4"
          >
            <div className="w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto">
              <CheckCircle className="w-8 h-8 text-green-600 dark:text-green-400" />
            </div>
            
            {requiresMfa ? (
              <>
                <p className="text-sm text-muted-foreground">
                  For added security, we need to verify your identity with multi-factor authentication.
                </p>
                <Button onClick={handleContinue} fullWidth rightIcon={<ArrowRight className="h-4 w-4" />}>
                  Continue to Verification
                </Button>
              </>
            ) : (
              <>
                <p className="text-sm text-muted-foreground">
                  You&apos;re being redirected to your account...
                </p>
                <div className="w-full bg-muted rounded-full h-2 overflow-hidden">
                  <motion.div
                    initial={{ width: '0%' }}
                    animate={{ width: '100%' }}
                    transition={{ duration: 1.5, ease: 'easeInOut' }}
                    className="h-full bg-primary"
                  />
                </div>
              </>
            )}
          </motion.div>
        )}

        {state === 'error' && (
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="text-center space-y-6 py-4"
          >
            <div className="w-16 h-16 bg-destructive/10 rounded-full flex items-center justify-center mx-auto">
              <XCircle className="w-8 h-8 text-destructive" />
            </div>
            
            <div className="bg-destructive/5 border border-destructive/20 rounded-lg p-4">
              <p className="text-sm text-destructive">
                {error || 'An unexpected error occurred'}
              </p>
            </div>

            <div className="space-y-3">
              <Link
                to={'/hosted/sign-in' as any}
                search={{ tenant_id: tenantId, redirect_url: redirectUrl || undefined } as any}
                className="block"
              >
                <Button fullWidth>
                  Try Again
                </Button>
              </Link>
              
              {config.allowSignUp && (
                <Link
                  to={'/hosted/sign-up' as any}
                  search={{ tenant_id: tenantId, redirect_url: redirectUrl || undefined } as any}
                  className="block"
                >
                  <Button variant="outline" fullWidth>
                    Create Account
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
