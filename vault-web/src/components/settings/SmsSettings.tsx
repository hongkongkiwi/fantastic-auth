import { useState, type ElementType } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import {
  Smartphone,
  MessageSquare,
  Cloud,
  Globe,
  CheckCircle,
  Lock,
  TestTube,
} from 'lucide-react'
import { env } from '@/env/client'
import { cn } from '@/lib/utils'

interface SmsConfig {
  provider: 'twilio' | 'message_bird' | 'vonage' | null
  enabled: boolean
  // Twilio
  twilioAccountSid?: string
  twilioAuthToken?: string
  twilioPhoneNumber?: string
  // MessageBird
  messageBirdApiKey?: string
  messageBirdOriginator?: string
  // Vonage
  vonageApiKey?: string
  vonageApiSecret?: string
  vonageFromName?: string
  // Common
  testPhoneNumber?: string
}

const defaultConfig: SmsConfig = {
  provider: null,
  enabled: false,
  twilioAccountSid: '',
  twilioAuthToken: '',
  twilioPhoneNumber: '',
  messageBirdApiKey: '',
  messageBirdOriginator: '',
  vonageApiKey: '',
  vonageApiSecret: '',
  vonageFromName: '',
  testPhoneNumber: '',
}

interface SmsProvider {
  id: SmsConfig['provider'] & string
  name: string
  description: string
  icon: ElementType
  envKey: keyof typeof env
}

const smsProviders: SmsProvider[] = [
  { id: 'twilio', name: 'Twilio', description: 'Leading SMS platform', icon: Smartphone, envKey: 'VITE_SMS_TWILIO_ENABLED' },
  { id: 'message_bird', name: 'MessageBird', description: 'Omnichannel communications', icon: MessageSquare, envKey: 'VITE_SMS_MESSAGE_BIRD_ENABLED' },
  { id: 'vonage', name: 'Vonage', description: 'Global SMS API', icon: Cloud, envKey: 'VITE_SMS_VONAGE_ENABLED' },
]

function isProviderEnabled(provider: SmsProvider): boolean {
  return env[provider.envKey] === 'true'
}

export function SmsSettings() {
  const [config, setConfig] = useState<SmsConfig>(defaultConfig)
  const [isLoading, setIsLoading] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [testStatus, setTestStatus] = useState<'idle' | 'success' | 'error'>('idle')
  const [showSecrets, setShowSecrets] = useState(false)

  const handleSave = async () => {
    setIsLoading(true)
    try {
      await new Promise((resolve) => setTimeout(resolve, 1000))
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

  const updateConfig = <K extends keyof SmsConfig>(key: K, value: SmsConfig[K]) => {
    setConfig((prev) => ({ ...prev, [key]: value }))
  }

  const selectedProvider = smsProviders.find(p => p.id === config.provider)
  const isSelectedProviderEnabled = selectedProvider ? isProviderEnabled(selectedProvider) : false

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">SMS Configuration</h2>
          <p className="text-muted-foreground">
            Configure SMS providers for phone verification and MFA
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
          <CardTitle>SMS Provider</CardTitle>
          <CardDescription>
            Select an SMS provider for sending verification codes
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-3">
            {smsProviders.map((provider) => {
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

              {config.provider === 'twilio' && (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <label htmlFor="twilio-sid" className="text-sm font-medium leading-none">
                      Account SID
                    </label>
                    <Input
                      id="twilio-sid"
                      value={config.twilioAccountSid}
                      onChange={(e) => updateConfig('twilioAccountSid', e.target.value)}
                      placeholder="YOUR_TWILIO_SID"
                    />
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="twilio-token" className="text-sm font-medium leading-none">
                      Auth Token
                    </label>
                    <Input
                      id="twilio-token"
                      type={showSecrets ? 'text' : 'password'}
                      value={config.twilioAuthToken}
                      onChange={(e) => updateConfig('twilioAuthToken', e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="twilio-number" className="text-sm font-medium leading-none">
                      Phone Number
                    </label>
                    <Input
                      id="twilio-number"
                      value={config.twilioPhoneNumber}
                      onChange={(e) => updateConfig('twilioPhoneNumber', e.target.value)}
                      placeholder="+1234567890"
                    />
                  </div>
                </div>
              )}

              {config.provider === 'message_bird' && (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <label htmlFor="mb-api-key" className="text-sm font-medium leading-none">
                      API Key
                    </label>
                    <Input
                      id="mb-api-key"
                      type={showSecrets ? 'text' : 'password'}
                      value={config.messageBirdApiKey}
                      onChange={(e) => updateConfig('messageBirdApiKey', e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="mb-originator" className="text-sm font-medium leading-none">
                      Originator
                    </label>
                    <Input
                      id="mb-originator"
                      value={config.messageBirdOriginator}
                      onChange={(e) => updateConfig('messageBirdOriginator', e.target.value)}
                      placeholder="YourApp"
                    />
                    <p className="text-xs text-muted-foreground">
                      Sender ID displayed on recipient&apos;s phone
                    </p>
                  </div>
                </div>
              )}

              {config.provider === 'vonage' && (
                <div className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <label htmlFor="vonage-key" className="text-sm font-medium leading-none">
                        API Key
                      </label>
                      <Input
                        id="vonage-key"
                        value={config.vonageApiKey}
                        onChange={(e) => updateConfig('vonageApiKey', e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <label htmlFor="vonage-secret" className="text-sm font-medium leading-none">
                        API Secret
                      </label>
                      <Input
                        id="vonage-secret"
                        type={showSecrets ? 'text' : 'password'}
                        value={config.vonageApiSecret}
                        onChange={(e) => updateConfig('vonageApiSecret', e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="vonage-from" className="text-sm font-medium leading-none">
                      From Name
                    </label>
                    <Input
                      id="vonage-from"
                      value={config.vonageFromName}
                      onChange={(e) => updateConfig('vonageFromName', e.target.value)}
                      placeholder="Vault"
                    />
                  </div>
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

              <div className="h-px bg-border" />

              <div className="space-y-2">
                <label htmlFor="test-number" className="text-sm font-medium leading-none">
                  Test Phone Number
                </label>
                <div className="flex gap-2">
                  <Input
                    id="test-number"
                    value={config.testPhoneNumber}
                    onChange={(e) => updateConfig('testPhoneNumber', e.target.value)}
                    placeholder="+1234567890"
                  />
                  <Button
                    variant="outline"
                    onClick={handleTest}
                    disabled={isTesting || !config.testPhoneNumber}
                  >
                    {isTesting ? (
                      <motion.div className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                    ) : (
                      <TestTube className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>
            </motion.div>
          )}

          {config.provider && !isSelectedProviderEnabled && (
            <div className="rounded-lg bg-amber-50 p-4 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400">
              <p className="text-sm font-medium">
                This provider is disabled. Set {selectedProvider?.envKey}=true to enable.
              </p>
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
              <Globe className="h-5 w-5" />
            )}
            <span>
              {testStatus === 'success'
                ? 'Test SMS sent successfully!'
                : 'Failed to send test SMS. Check your configuration.'}
            </span>
          </div>
        </motion.div>
      )}

      <div className="flex items-center justify-end gap-4">
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
