import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import {
  Smartphone,
  Key,
  Copy,
  CheckCircle2,
  Loader2,
  ArrowRight,
  ArrowLeft,
  Shield,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Alert, AlertDescription } from '@/components/ui/Alert'
import { toast } from 'sonner'
import {
  useSetupMfa,
  useVerifyMfaSetup,
  useMfaFactors,
} from '@/lib/api'

export const Route = createFileRoute('/mfa/setup')({
  component: MfaSetupPage,
})

type SetupStep = 'select' | 'authenticator' | 'verify' | 'backup-codes' | 'complete'

function MfaSetupPage() {
  const navigate = useNavigate()
  const [step, setStep] = useState<SetupStep>('select')
  const [selectedMethod, setSelectedMethod] = useState<'totp' | 'sms' | null>(null)
  const [factorName, setFactorName] = useState('')
  const [verificationCode, setVerificationCode] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [copiedCodes, setCopiedCodes] = useState(false)

  const setupMutation = useSetupMfa()
  const verifyMutation = useVerifyMfaSetup()
  const { refetch: refetchFactors } = useMfaFactors()

  const handleSelectMethod = (method: 'totp' | 'sms') => {
    setSelectedMethod(method)
    setFactorName(method === 'totp' ? 'Authenticator App' : 'SMS')
    setStep('authenticator')
  }

  const handleStartSetup = async () => {
    if (!selectedMethod) return

    try {
      await setupMutation.mutateAsync({
        type: selectedMethod,
        name: factorName,
      })
      setStep('verify')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to start MFA setup')
    }
  }

  const handleVerify = async () => {
    if (!selectedMethod) return

    try {
      const result = await verifyMutation.mutateAsync({
        type: selectedMethod,
        code: verificationCode,
      })
      
      if (result.backupCodes) {
        setBackupCodes(result.backupCodes)
      }
      
      await refetchFactors()
      setStep('backup-codes')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Invalid verification code')
    }
  }

  const handleCopyCodes = () => {
    navigator.clipboard.writeText(backupCodes.join('\n'))
    setCopiedCodes(true)
    toast.success('Backup codes copied to clipboard')
    setTimeout(() => setCopiedCodes(false), 3000)
  }

  const handleComplete = () => {
    toast.success('MFA setup complete!')
    navigate({ to: '/security' })
  }

  const renderSelectMethod = () => (
    <div className="space-y-4">
      <Alert>
        <Shield className="h-4 w-4" />
        <AlertDescription>
          Two-factor authentication adds an extra layer of security to your account.
          You'll need to provide a verification code along with your password when signing in.
        </AlertDescription>
      </Alert>

      <div className="grid gap-4">
        <button
          type="button"
          onClick={() => handleSelectMethod('totp')}
          className="flex items-center gap-4 p-4 rounded-lg border hover:bg-accent transition-colors text-left"
        >
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
            <Smartphone className="h-6 w-6 text-primary" />
          </div>
          <div className="flex-1">
            <h3 className="font-medium">Authenticator App</h3>
            <p className="text-sm text-muted-foreground">
              Use an app like Google Authenticator, Authy, or 1Password
            </p>
          </div>
          <ArrowRight className="h-5 w-5 text-muted-foreground" />
        </button>

        <button
          type="button"
          onClick={() => handleSelectMethod('sms')}
          className="flex items-center gap-4 p-4 rounded-lg border hover:bg-accent transition-colors text-left"
        >
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
            <Smartphone className="h-6 w-6 text-primary" />
          </div>
          <div className="flex-1">
            <h3 className="font-medium">SMS/Text Message</h3>
            <p className="text-sm text-muted-foreground">
              Receive verification codes via text message
            </p>
          </div>
          <ArrowRight className="h-5 w-5 text-muted-foreground" />
        </button>
      </div>
    </div>
  )

  const renderAuthenticatorSetup = () => (
    <div className="space-y-6">
      <Button
        variant="ghost"
        onClick={() => setStep('select')}
        className="-ml-4"
      >
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back
      </Button>

      <div className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="factorName">Device Name</Label>
          <Input
            id="factorName"
            value={factorName}
            onChange={(e) => setFactorName(e.target.value)}
            placeholder="e.g., My iPhone, Work Laptop"
          />
          <p className="text-xs text-muted-foreground">
            Give this MFA method a name so you can identify it later
          </p>
        </div>

        {setupMutation.data?.qrCode && (
          <div className="flex flex-col items-center space-y-4">
            <div className="p-4 bg-white rounded-lg">
              <img
                src={setupMutation.data.qrCode}
                alt="QR Code for authenticator app"
                className="w-48 h-48"
              />
            </div>
            <p className="text-sm text-muted-foreground text-center">
              Scan this QR code with your authenticator app
            </p>
          </div>
        )}

        {setupMutation.data?.secret && (
          <div className="space-y-2">
            <Label>Manual Entry Code</Label>
            <div className="flex gap-2">
              <code className="flex-1 p-3 bg-muted rounded text-sm break-all">
                {setupMutation.data.secret}
              </code>
              <Button
                variant="outline"
                size="icon"
                onClick={() => {
                  navigator.clipboard.writeText(setupMutation.data?.secret || '')
                  toast.success('Secret copied')
                }}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}

        <Button
          onClick={handleStartSetup}
          disabled={!factorName || setupMutation.isPending}
          className="w-full"
        >
          {setupMutation.isPending ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Setting up...
            </>
          ) : setupMutation.data ? (
            'Continue'
          ) : (
            'Generate QR Code'
          )}
        </Button>
      </div>
    </div>
  )

  const renderVerify = () => (
    <div className="space-y-6">
      <Button
        variant="ghost"
        onClick={() => setStep('authenticator')}
        className="-ml-4"
      >
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back
      </Button>

      <div className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="verificationCode">Verification Code</Label>
          <Input
            id="verificationCode"
            value={verificationCode}
            onChange={(e) => setVerificationCode(e.target.value)}
            placeholder="Enter 6-digit code"
            maxLength={6}
            inputMode="numeric"
            autoComplete="one-time-code"
          />
          <p className="text-xs text-muted-foreground">
            Enter the 6-digit code from your authenticator app
          </p>
        </div>

        <Button
          onClick={handleVerify}
          disabled={verificationCode.length < 6 || verifyMutation.isPending}
          className="w-full"
        >
          {verifyMutation.isPending ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Verifying...
            </>
          ) : (
            'Verify and Continue'
          )}
        </Button>
      </div>
    </div>
  )

  const renderBackupCodes = () => (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto" />
        <h3 className="text-lg font-medium">MFA Enabled Successfully!</h3>
        <p className="text-sm text-muted-foreground">
          Save these backup codes in a safe place. You'll need them if you lose access to your authenticator.
        </p>
      </div>

      <div className="bg-muted p-4 rounded-lg">
        <div className="grid grid-cols-2 gap-2">
          {backupCodes.map((code, index) => (
            <code key={index} className="text-sm font-mono text-center p-2 bg-background rounded">
              {code}
            </code>
          ))}
        </div>
      </div>

      <div className="flex gap-2">
        <Button
          variant="outline"
          onClick={handleCopyCodes}
          className="flex-1"
        >
          {copiedCodes ? (
            <>
              <CheckCircle2 className="mr-2 h-4 w-4 text-green-500" />
              Copied!
            </>
          ) : (
            <>
              <Copy className="mr-2 h-4 w-4" />
              Copy Codes
            </>
          )}
        </Button>
        <Button onClick={handleComplete} className="flex-1">
          Done
        </Button>
      </div>
    </div>
  )

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            Set Up Two-Factor Authentication
          </CardTitle>
          <CardDescription>
            {step === 'select' && 'Choose your preferred authentication method'}
            {step === 'authenticator' && 'Set up your authenticator app'}
            {step === 'verify' && 'Verify your setup'}
            {step === 'backup-codes' && 'Save your backup codes'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {step === 'select' && renderSelectMethod()}
          {step === 'authenticator' && renderAuthenticatorSetup()}
          {step === 'verify' && renderVerify()}
          {step === 'backup-codes' && renderBackupCodes()}
        </CardContent>
      </Card>
    </div>
  )
}
