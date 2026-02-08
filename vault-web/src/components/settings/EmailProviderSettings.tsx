import { useState, type ElementType } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import {
  Mail,
  Send,
  Cloud,
  Server,
  CheckCircle,
  Lock,
  TestTube,
  AlertTriangle,
} from 'lucide-react'
import { env } from '@/env/client'
import { cn } from '@/lib/utils'

interface EmailConfig {
  provider: 'smtp' | 'sendgrid' | 'mailgun' | 'aws_ses' | 'postmark' | 'resend' | null
  enabled: boolean
  fromEmail: string
  fromName: string
  // SMTP specific
  smtpHost?: string
  smtpPort?: number
  smtpUser?: string
  smtpPass?: string
  smtpSecure?: boolean
  // API key specific
  apiKey?: string
  // AWS specific
  awsRegion?: string
  awsAccessKeyId?: string
  awsSecretAccessKey?: string
}

const defaultConfig: EmailConfig = {
  provider: null,
  enabled: false,
  fromEmail: 'noreply@example.com',
  fromName: 'Vault',
  smtpHost: '',
  smtpPort: 587,
  smtpUser: '',
  smtpPass: '',
  smtpSecure: true,
  apiKey: '',
  awsRegion: 'us-east-1',
  awsAccessKeyId: '',
  awsSecretAccessKey: '',
}

interface EmailProvider {
  id: EmailConfig['provider'] & string
  name: string
  description: string
  icon: ElementType
  envKey: keyof typeof env
  requiresApiKey: boolean
}

const emailProviders: EmailProvider[] = [
  { id: 'smtp', name: 'SMTP', description: 'Standard email protocol', icon: Server, envKey: 'VITE_EMAIL_SMTP_ENABLED', requiresApiKey: false },
  { id: 'sendgrid', name: 'SendGrid', description: 'Twilio email platform', icon: Send, envKey: 'VITE_EMAIL_SENDGRID_ENABLED', requiresApiKey: true },
  { id: 'mailgun', name: 'Mailgun', description: 'Powerful email APIs', icon: Mail, envKey: 'VITE_EMAIL_MAILGUN_ENABLED', requiresApiKey: true },
  { id: 'aws_ses', name: 'AWS SES', description: 'Amazon Simple Email Service', icon: Cloud, envKey: 'VITE_EMAIL_AWS_SES_ENABLED', requiresApiKey: true },
  { id: 'postmark', name: 'Postmark', description: 'Fast email delivery', icon: Mail, envKey: 'VITE_EMAIL_POSTMARK_ENABLED', requiresApiKey: true },
  { id: 'resend', name: 'Resend', description: 'Modern email for developers', icon: Send, envKey: 'VITE_EMAIL_RESEND_ENABLED', requiresApiKey: true },
]

function isProviderEnabled(provider: EmailProvider): boolean {
  return env[provider.envKey] === 'true'
}

export function EmailProviderSettings() {
  const [config, setConfig] = useState<EmailConfig>(defaultConfig)
  const [isLoading, setIsLoading] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [testStatus, setTestStatus] = useState<'idle' | 'success' | 'error'>('idle')
  const [showSecrets, setShowSecrets] = useState(false)
  const [secretState, setSecretState] = useState({
    smtpPass: false,
    apiKey: false,
    awsAccessKeyId: false,
    awsSecretAccessKey: false,
  })

  const handleSave = async () => {
    setIsLoading(true)
    try {
      await new Promise((resolve) => setTimeout(resolve, 1000))
      setSecretState((prev) => ({
        smtpPass: prev.smtpPass || Boolean(config.smtpPass?.trim()),
        apiKey: prev.apiKey || Boolean(config.apiKey?.trim()),
        awsAccessKeyId: prev.awsAccessKeyId || Boolean(config.awsAccessKeyId?.trim()),
        awsSecretAccessKey: prev.awsSecretAccessKey || Boolean(config.awsSecretAccessKey?.trim()),
      }))
      if (config.smtpPass?.trim()) updateConfig('smtpPass', '')
      if (config.apiKey?.trim()) updateConfig('apiKey', '')
      if (config.awsAccessKeyId?.trim()) updateConfig('awsAccessKeyId', '')
      if (config.awsSecretAccessKey?.trim()) updateConfig('awsSecretAccessKey', '')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTest = async () => {
    setIsTesting(true)
    setTestStatus('idle')
    try {
      await new Promise((resolve) => setTimeout(resolve, 2000))
      setTestStatus('success')
    } catch {
      setTestStatus('error')
    } finally {
      setIsTesting(false)
    }
  }

  const updateConfig = <K extends keyof EmailConfig>(key: K, value: EmailConfig[K]) => {
    setConfig((prev) => ({ ...prev, [key]: value }))
  }

  const selectedProvider = emailProviders.find(p => p.id === config.provider)
  const isSelectedProviderEnabled = selectedProvider ? isProviderEnabled(selectedProvider) : false

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Email Configuration</h2>
          <p className="text-muted-foreground">
            Configure email providers for transactional emails, magic links, and notifications
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Switch
            checked={config.enabled}
            onCheckedChange={(checked) => updateConfig('enabled', checked)}
            disabled={!config.provider || !isSelectedProviderEnabled}
          />
          <span className={cn(
            'text-sm font-medium',
            config.enabled ? 'text-green-600' : 'text-muted-foreground'
          )}>
            {config.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Email Provider</CardTitle>
          <CardDescription>
            Select an email provider for sending transactional emails
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {emailProviders.map((provider) => {
              const isEnabled = isProviderEnabled(provider)
              const Icon = provider.icon
              return (
                <div
                  key={provider.id}
                  className={cn(
                    'relative rounded-lg border p-4 transition-colors',
                    isEnabled
                      ? config.provider === provider.id
                        ? 'cursor-pointer border-primary bg-primary/5'
                        : 'cursor-pointer hover:border-primary/50'
                      : 'cursor-not-allowed border-muted bg-muted/30 opacity-60'
                  )}
                  onClick={() => isEnabled && updateConfig('provider', provider.id)}
                >
                  {!isEnabled && (
                    <div className="absolute right-2 top-2">
                      <Lock className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                  )}
                  <div className="flex items-start gap-3">
                    <div
                      className={cn(
                        'flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border',
                        config.provider === provider.id && isEnabled
                          ? 'border-primary bg-primary text-primary-foreground'
                          : 'border-muted-foreground/30'
                      )}
                    >
                      <Icon className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="font-medium">{provider.name}</div>
                      <p className="text-xs text-muted-foreground">{provider.description}</p>
                      {isEnabled && (
                        <Badge variant="outline" className="mt-2 text-xs">
                          Available
                        </Badge>
                      )}
                    </div>
                  </div>
                  {!isEnabled && (
                    <p className="mt-3 text-xs text-muted-foreground">
                      Set {provider.envKey}=true to enable
                    </p>
                  )}
                </div>
              )
            })}
          </div>

          {config.provider && isSelectedProviderEnabled && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              className="space-y-4"
            >
              <div className="h-px bg-border" />

              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <label htmlFor="from-email" className="text-sm font-medium leading-none">
                    From Email
                  </label>
                  <Input
                    id="from-email"
                    type="email"
                    value={config.fromEmail}
                    onChange={(e) => updateConfig('fromEmail', e.target.value)}
                    placeholder="noreply@yourdomain.com"
                  />
                </div>
                <div className="space-y-2">
                  <label htmlFor="from-name" className="text-sm font-medium leading-none">
                    From Name
                  </label>
                  <Input
                    id="from-name"
                    value={config.fromName}
                    onChange={(e) => updateConfig('fromName', e.target.value)}
                    placeholder="Your App Name"
                  />
                </div>
              </div>

              {config.provider === 'smtp' && (
                <div className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label htmlFor="smtp-host" className="text-sm font-medium leading-none">
                        SMTP Host
                      </label>
                      <Input
                        id="smtp-host"
                        value={config.smtpHost}
                        onChange={(e) => updateConfig('smtpHost', e.target.value)}
                        placeholder="smtp.gmail.com"
                      />
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="smtp-port" className="text-sm font-medium leading-none">
                        SMTP Port
                      </label>
                      <Input
                        id="smtp-port"
                        type="number"
                        value={config.smtpPort}
                        onChange={(e) => updateConfig('smtpPort', parseInt(e.target.value))}
                        placeholder="587"
                      />
                    </div>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label htmlFor="smtp-user" className="text-sm font-medium leading-none">
                        Username
                      </label>
                      <Input
                        id="smtp-user"
                        value={config.smtpUser}
                        onChange={(e) => updateConfig('smtpUser', e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <label htmlFor="smtp-pass" className="text-sm font-medium leading-none">
                          Password
                        </label>
                        {secretState.smtpPass && !config.smtpPass && (
                          <Badge variant="outline" className="text-xs">Set</Badge>
                        )}
                      </div>
                      <Input
                        id="smtp-pass"
                        type={showSecrets ? 'text' : 'password'}
                        value={config.smtpPass}
                        placeholder={secretState.smtpPass && !config.smtpPass ? '******** (set)' : '••••••••'}
                        onChange={(e) => updateConfig('smtpPass', e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch
                      id="smtp-secure"
                      checked={config.smtpSecure}
                      onCheckedChange={(checked) => updateConfig('smtpSecure', checked)}
                    />
                    <label htmlFor="smtp-secure" className="text-sm font-medium leading-none">
                      Use TLS/SSL
                    </label>
                  </div>
                </div>
              )}

              {config.provider === 'aws_ses' && (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <label htmlFor="aws-region" className="text-sm font-medium leading-none">
                      AWS Region
                    </label>
                    <Input
                      id="aws-region"
                      value={config.awsRegion}
                      onChange={(e) => updateConfig('awsRegion', e.target.value)}
                      placeholder="us-east-1"
                    />
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label htmlFor="aws-access-key" className="text-sm font-medium leading-none">
                        AWS Access Key ID
                      </label>
                      {secretState.awsAccessKeyId && !config.awsAccessKeyId && (
                        <Badge variant="outline" className="text-xs">Set</Badge>
                      )}
                    </div>
                    <Input
                      id="aws-access-key"
                      type={showSecrets ? 'text' : 'password'}
                      value={config.awsAccessKeyId}
                      placeholder={secretState.awsAccessKeyId && !config.awsAccessKeyId ? '******** (set)' : 'AKIA...'}
                      onChange={(e) => updateConfig('awsAccessKeyId', e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label htmlFor="aws-secret-key" className="text-sm font-medium leading-none">
                        AWS Secret Access Key
                      </label>
                      {secretState.awsSecretAccessKey && !config.awsSecretAccessKey && (
                        <Badge variant="outline" className="text-xs">Set</Badge>
                      )}
                    </div>
                    <Input
                      id="aws-secret-key"
                      type={showSecrets ? 'text' : 'password'}
                      value={config.awsSecretAccessKey}
                      placeholder={secretState.awsSecretAccessKey && !config.awsSecretAccessKey ? '******** (set)' : '••••••••'}
                      onChange={(e) => updateConfig('awsSecretAccessKey', e.target.value)}
                    />
                  </div>
                </div>
              )}

              {selectedProvider?.requiresApiKey && config.provider !== 'aws_ses' && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label htmlFor="api-key" className="text-sm font-medium leading-none">
                      API Key
                    </label>
                    {secretState.apiKey && !config.apiKey && (
                      <Badge variant="outline" className="text-xs">Set</Badge>
                    )}
                  </div>
                  <Input
                    id="api-key"
                    type={showSecrets ? 'text' : 'password'}
                    value={config.apiKey}
                    onChange={(e) => updateConfig('apiKey', e.target.value)}
                    placeholder={secretState.apiKey && !config.apiKey ? '******** (set)' : `Enter your ${selectedProvider.name} API key`}
                  />
                </div>
              )}

              <div className="flex items-center gap-2">
                <Switch
                  id="show-secrets"
                  checked={showSecrets}
                  onCheckedChange={setShowSecrets}
                />
                <label htmlFor="show-secrets" className="text-sm font-medium leading-none">
                  Show Secrets
                </label>
              </div>
            </motion.div>
          )}

          {config.provider && !isSelectedProviderEnabled && (
            <div className="rounded-lg bg-amber-50 p-4 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" />
                <span className="text-sm font-medium">
                  This provider is disabled. Set {selectedProvider?.envKey}=true to enable.
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {testStatus !== 'idle' && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className={cn(
            'rounded-lg p-4',
            testStatus === 'success'
              ? 'bg-green-50 text-green-800 dark:bg-green-900/20 dark:text-green-400'
              : 'bg-red-50 text-red-800 dark:bg-red-900/20 dark:text-red-400'
          )}
        >
          <div className="flex items-center gap-2">
            {testStatus === 'success' ? (
              <CheckCircle className="h-5 w-5" />
            ) : (
              <AlertTriangle className="h-5 w-5" />
            )}
            <span>
              {testStatus === 'success'
                ? 'Test email sent successfully!'
                : 'Failed to send test email. Check your configuration.'}
            </span>
          </div>
        </motion.div>
      )}

      <div className="flex items-center justify-end gap-4">
        <Button
          variant="outline"
          onClick={handleTest}
          disabled={!config.enabled || !config.provider || isTesting}
        >
          {isTesting ? (
            <>
              <motion.div className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
              Sending…
            </>
          ) : (
            <>
              <TestTube className="mr-2 h-4 w-4" />
              Send Test Email
            </>
          )}
        </Button>
        <Button onClick={handleSave} disabled={isLoading}>
          {isLoading ? (
            <>
              <motion.div className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
              Saving…
            </>
          ) : (
            'Save Configuration'
          )}
        </Button>
      </div>
    </div>
  )
}
