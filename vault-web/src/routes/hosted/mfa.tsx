/**
 * Hosted MFA Challenge Page
 * 
 * Pre-built hosted multi-factor authentication page.
 * URL: /hosted/mfa?tenant_id=xxx&mfa_token=xxx&redirect_url=xxx
 */

import { createFileRoute, useNavigate, Link } from '@tanstack/react-router'
import { useState, useEffect } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Shield, Lock, Mail, Smartphone, ArrowRight, AlertCircle, ArrowLeft } from 'lucide-react'
import { Button } from '../../components/ui/Button'
import { Input } from '../../components/ui/Input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/Card'
import { Alert, AlertDescription } from '../../components/ui/Alert'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../../components/ui/Tabs'
import { HostedLayout } from '../../hosted/HostedLayout'
import { useHostedConfig, useHostedSearchParams } from '../../hosted/useHostedConfig'
import { hostedVerifyMfa } from '../../hosted/api'

export const Route = createFileRoute('/hosted/mfa')({
  component: HostedMfaPage,
})

type MfaMethod = 'totp' | 'email' | 'sms'

const methodConfig = {
  totp: {
    icon: Shield,
    title: 'Authenticator App',
    description: 'Enter the 6-digit code from your authenticator app',
    showResend: false,
  },
  email: {
    icon: Mail,
    title: 'Email Code',
    description: 'Enter the 6-digit code sent to your email',
    showResend: true,
  },
  sms: {
    icon: Smartphone,
    title: 'SMS Code',
    description: 'Enter the 6-digit code sent to your phone',
    showResend: true,
  },
}

function HostedMfaPage() {
  const searchParams = useHostedSearchParams()
  
  return (
    <HostedLayout 
      searchParams={new URLSearchParams(window.location.search)}
    >
      <MfaContent searchParams={searchParams} />
    </HostedLayout>
  )
}

interface MfaContentProps {
  searchParams: ReturnType<typeof useHostedSearchParams>
}

function MfaContent({ searchParams }: MfaContentProps) {
  const navigate = useNavigate()
  const { config, tenantId, redirectUrl } = useHostedConfig()
  const prefersReducedMotion = useReducedMotion()
  
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [method, setMethod] = useState<MfaMethod>('totp')
  const [resendTimer, setResendTimer] = useState(30)
  const [canResend, setCanResend] = useState(false)

  const urlParams = new URLSearchParams(window.location.search)
  const mfaToken = urlParams.get('mfa_token')

  // Countdown timer for resend
  useEffect(() => {
    if (resendTimer > 0 && !canResend) {
      const timer = setTimeout(() => setResendTimer(resendTimer - 1), 1000)
      return () => clearTimeout(timer)
    } else if (resendTimer === 0) {
      setCanResend(true)
    }
  }, [resendTimer, canResend])

  if (!config || !tenantId) {
    return null
  }

  // Redirect if missing MFA token
  if (!mfaToken) {
    navigate({
      to: '/hosted/sign-in',
      search: { tenant_id: tenantId, redirect_url: redirectUrl || undefined },
    })
    return null
  }

  const handleVerify = async () => {
    if (code.length !== 6) {
      setError('Please enter a 6-digit code')
      return
    }

    setIsLoading(true)
    setError(null)

    try {
      const result = await hostedVerifyMfa({
        data: {
          code,
          method,
          mfaToken,
          tenantId,
          redirectUrl: redirectUrl || undefined,
        },
      })

      // Redirect on success
      window.location.href = result.redirectUrl
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid verification code')
      setCode('')
    } finally {
      setIsLoading(false)
    }
  }

  const handleResend = async () => {
    if (!canResend) return

    setIsLoading(true)
    setError(null)

    try {
      // In a real implementation, this would request a new code
      // await requestMfaCode({ tenantId, mfaToken, method })
      
      setResendTimer(30)
      setCanResend(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to resend code')
    } finally {
      setIsLoading(false)
    }
  }

  const currentMethodConfig = methodConfig[method]

  return (
    <Card className="shadow-elevated">
      <CardHeader className="space-y-1">
        <div className="mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-2">
          <Lock className="h-6 w-6 text-primary" />
        </div>
        <CardTitle className="text-2xl text-center">Two-Factor Authentication</CardTitle>
        <CardDescription className="text-center">
          Choose a verification method to continue
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

        {/* Method Tabs */}
        <Tabs value={method} onValueChange={(v) => setMethod(v as MfaMethod)}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="totp" className="gap-2">
              <Shield className="h-4 w-4" />
              <span className="hidden sm:inline">App</span>
            </TabsTrigger>
            <TabsTrigger value="email" className="gap-2">
              <Mail className="h-4 w-4" />
              <span className="hidden sm:inline">Email</span>
            </TabsTrigger>
            <TabsTrigger value="sms" className="gap-2">
              <Smartphone className="h-4 w-4" />
              <span className="hidden sm:inline">SMS</span>
            </TabsTrigger>
          </TabsList>

          {(Object.keys(methodConfig) as MfaMethod[]).map((m) => {
            const Icon = methodConfig[m].icon
            return (
              <TabsContent key={m} value={m} className="mt-4 space-y-4">
                <motion.div
                  initial={prefersReducedMotion ? false : { opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-4"
                >
                  <div className="text-center">
                    <div className="w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-3">
                      <Icon className="h-6 w-6 text-primary" />
                    </div>
                    <h3 className="font-semibold">{methodConfig[m].title}</h3>
                    <p className="text-sm text-muted-foreground">{methodConfig[m].description}</p>
                  </div>

                  <div className="space-y-2">
                    <Input
                      type="text"
                      placeholder="000000"
                      value={code}
                      onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      className="text-center text-2xl tracking-widest font-mono"
                      maxLength={6}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      autoFocus
                      disabled={isLoading}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && code.length === 6) {
                          void handleVerify()
                        }
                      }}
                    />
                  </div>

                  <Button
                    fullWidth
                    size="lg"
                    isLoading={isLoading}
                    disabled={code.length !== 6}
                    onClick={handleVerify}
                    rightIcon={<ArrowRight className="h-4 w-4" />}
                  >
                    Verify
                  </Button>

                  {methodConfig[m].showResend && (
                    <div className="text-center">
                      <button
                        onClick={handleResend}
                        disabled={!canResend || isLoading}
                        className="text-sm text-primary hover:underline disabled:text-muted-foreground disabled:no-underline disabled:cursor-not-allowed"
                      >
                        {canResend 
                          ? 'Resend code' 
                          : `Resend code in ${resendTimer}s`
                        }
                      </button>
                    </div>
                  )}
                </motion.div>
              </TabsContent>
            )
          })}
        </Tabs>

        {/* Back Link */}
        <div className="text-center pt-4 border-t">
          <Link
            to="/hosted/sign-in"
            search={{ tenant_id: tenantId, redirect_url: redirectUrl || undefined }}
            className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
            Use a different sign-in method
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}
