import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Smartphone, Mail, Copy, Check, Download } from 'lucide-react'
import { Button } from '../ui/Button'
import { Input } from '../ui/Input'
import { QRCodeSVG } from 'qrcode.react'

interface MfaEnrollProps {
  method: 'totp' | 'email' | 'sms'
  onEnroll: (code: string) => Promise<void>
  onCancel: () => void
}

interface TotpEnrollment {
  secret: string
  qr_uri: string
  backup_codes: string[]
}

export function MfaEnroll({ method, onEnroll, onCancel }: MfaEnrollProps) {
  const [step, setStep] = useState<'intro' | 'setup' | 'verify' | 'backup'>('intro')
  const [verificationCode, setVerificationCode] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [totpData, setTotpData] = useState<TotpEnrollment | null>(null)
  const [copiedSecret, setCopiedSecret] = useState(false)
  const [copiedCodes, setCopiedCodes] = useState(false)

  useEffect(() => {
    if (method === 'totp' && step === 'setup') {
      // Fetch TOTP enrollment data
      fetch('/api/v1/auth/mfa/totp/enroll', { method: 'POST' })
        .then(res => res.json())
        .then(data => setTotpData(data))
        .catch(() => setError('Failed to generate TOTP secret'))
    }
  }, [method, step])

  const handleVerify = async () => {
    setIsLoading(true)
    setError('')
    
    try {
      await onEnroll(verificationCode)
      if (method === 'totp') {
        setStep('backup')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid code')
    } finally {
      setIsLoading(false)
    }
  }

  const copyToClipboard = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const downloadBackupCodes = () => {
    if (!totpData) return
    const content = totpData.backup_codes.join('\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'vault-backup-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
  }

  const methodConfig = {
    totp: {
      icon: Shield,
      title: 'Authenticator App',
      description: 'Use an app like Google Authenticator, Authy, or 1Password',
    },
    email: {
      icon: Mail,
      title: 'Email Verification',
      description: 'Receive codes via email',
    },
    sms: {
      icon: Smartphone,
      title: 'SMS Verification',
      description: 'Receive codes via text message',
    },
  }

  const config = methodConfig[method]
  const Icon = config.icon

  return (
    <div className="w-full max-w-md mx-auto">
      <AnimatePresence mode="wait">
        {step === 'intro' && (
          <motion.div
            key="intro"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="text-center space-y-6"
          >
            <div className="w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto">
              <Icon className="w-8 h-8 text-primary" />
            </div>
            <div>
              <h3 className="text-xl font-semibold">{config.title}</h3>
              <p className="text-sm text-muted-foreground mt-2">
                {config.description}
              </p>
            </div>
            <div className="flex gap-3">
              <Button variant="outline" onClick={onCancel} className="flex-1">
                Cancel
              </Button>
              <Button onClick={() => setStep('setup')} className="flex-1">
                Continue
              </Button>
            </div>
          </motion.div>
        )}

        {step === 'setup' && method === 'totp' && totpData && (
          <motion.div
            key="setup"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            <div className="text-center">
              <h3 className="text-lg font-semibold">Scan QR Code</h3>
              <p className="text-sm text-muted-foreground">
                Open your authenticator app and scan this code
              </p>
            </div>

            <div className="flex justify-center">
              <div className="p-4 bg-white rounded-lg">
                <QRCodeSVG value={totpData.qr_uri} size={200} />
              </div>
            </div>

            <div className="space-y-2">
              <p className="text-xs text-center text-muted-foreground">
                Can't scan? Enter this code manually:
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 p-2 bg-muted rounded text-center text-sm font-mono">
                  {totpData.secret}
                </code>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={copiedSecret ? 'Secret copied' : 'Copy setup secret'}
                  onClick={() => copyToClipboard(totpData.secret, setCopiedSecret)}
                >
                  {copiedSecret ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
            </div>

            <Button onClick={() => setStep('verify')} fullWidth>
              I've scanned the code
            </Button>
          </motion.div>
        )}

        {step === 'verify' && (
          <motion.div
            key="verify"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            <div className="text-center">
              <h3 className="text-lg font-semibold">Verify Setup</h3>
              <p className="text-sm text-muted-foreground">
                Enter the 6-digit code from your {method === 'totp' ? 'authenticator app' : method}
              </p>
            </div>

            <div className="space-y-2">
              <Input
                type="text"
                placeholder="000000"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                className="text-center text-2xl tracking-widest font-mono"
                maxLength={6}
                name="verificationCode"
                autoComplete="one-time-code"
                inputMode="numeric"
                aria-label="Verification code"
                error={error}
              />
            </div>

            <div className="flex gap-3">
              <Button
                variant="outline"
                onClick={() => setStep(method === 'totp' ? 'setup' : 'intro')}
                className="flex-1"
              >
                Back
              </Button>
              <Button
                onClick={handleVerify}
                disabled={verificationCode.length !== 6 || isLoading}
                className="flex-1"
                isLoading={isLoading}
              >
                Verify
              </Button>
            </div>
          </motion.div>
        )}

        {step === 'backup' && totpData && (
          <motion.div
            key="backup"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            <div className="text-center">
              <div className="w-12 h-12 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto mb-4">
                <Check className="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
              <h3 className="text-lg font-semibold">MFA Enabled!</h3>
              <p className="text-sm text-muted-foreground">
                Save these backup codes in a safe place
              </p>
            </div>

            <div className="bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 rounded-lg p-4">
              <p className="text-xs text-amber-800 dark:text-amber-200 mb-3">
                ⚠️ These codes can be used to access your account if you lose your authenticator device. 
                Each code can only be used once.
              </p>
              <div className="grid grid-cols-2 gap-2">
                {totpData.backup_codes.map((code) => (
                  <code key={code} className="text-sm font-mono text-center">
                    {code}
                  </code>
                ))}
              </div>
            </div>

            <div className="flex gap-3">
              <Button
                variant="outline"
                onClick={() => copyToClipboard(totpData.backup_codes.join('\n'), setCopiedCodes)}
                className="flex-1 gap-2"
              >
                {copiedCodes ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                Copy Codes
              </Button>
              <Button
                variant="outline"
                onClick={downloadBackupCodes}
                className="flex-1 gap-2"
              >
                <Download className="h-4 w-4" />
                Download
              </Button>
            </div>

            <Button onClick={onCancel} fullWidth>
              Done
            </Button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
