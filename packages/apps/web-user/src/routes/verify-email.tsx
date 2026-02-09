import { createFileRoute, useNavigate, useSearch } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { Loader2, CheckCircle2, XCircle } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { toast } from 'sonner'

export const Route = createFileRoute('/verify-email')({
  component: VerifyEmailPage,
})

function VerifyEmailPage() {
  const navigate = useNavigate()
  const search = useSearch({ from: '/verify-email' }) as { token?: string }
  const token = search.token

  const [status, setStatus] = useState<'verifying' | 'success' | 'error'>('verifying')
  const [message, setMessage] = useState('Verifying your email...')
  const [resendLoading, setResendLoading] = useState(false)

  useEffect(() => {
    if (token) {
      verifyEmail()
    } else {
      setStatus('error')
      setMessage('Invalid verification link. Please request a new one.')
    }
  }, [token])

  const verifyEmail = async () => {
    try {
      const response = await fetch('/api/v1/auth/verify-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.message || 'Verification failed')
      }

      setStatus('success')
      setMessage('Your email has been verified successfully!')
      toast.success('Email verified')
    } catch (error) {
      setStatus('error')
      setMessage(error instanceof Error ? error.message : 'Verification failed')
      toast.error('Failed to verify email')
    }
  }

  const handleResend = async () => {
    setResendLoading(true)
    
    try {
      const response = await fetch('/api/v1/auth/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.message || 'Failed to resend verification email')
      }

      toast.success('Verification email sent')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to resend email')
    } finally {
      setResendLoading(false)
    }
  }

  const getIcon = () => {
    switch (status) {
      case 'verifying':
        return <Loader2 className="h-12 w-12 animate-spin text-primary" />
      case 'success':
        return <CheckCircle2 className="h-12 w-12 text-green-500" />
      case 'error':
        return <XCircle className="h-12 w-12 text-red-500" />
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="h-16 w-16 bg-primary/10 rounded-full flex items-center justify-center">
              {getIcon()}
            </div>
          </div>
          <CardTitle>
            {status === 'verifying' && 'Verifying Email'}
            {status === 'success' && 'Email Verified'}
            {status === 'error' && 'Verification Failed'}
          </CardTitle>
          <CardDescription>{message}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {status === 'success' && (
            <Button 
              className="w-full" 
              onClick={() => navigate({ to: '/login' })}
            >
              Continue to Login
            </Button>
          )}

          {status === 'error' && (
            <>
              <Button
                variant="outline"
                className="w-full"
                onClick={handleResend}
                disabled={resendLoading}
              >
                {resendLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Sending...
                  </>
                ) : (
                  'Resend Verification Email'
                )}
              </Button>
              <Button
                variant="ghost"
                className="w-full"
                onClick={() => navigate({ to: '/login' })}
              >
                Back to Login
              </Button>
            </>
          )}

          {status === 'verifying' && (
            <p className="text-center text-sm text-muted-foreground">
              Please wait while we verify your email address...
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
