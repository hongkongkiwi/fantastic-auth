import { useState, type ElementType } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import {
  CreditCard,
  Wallet,
  CheckCircle,
  Lock,
  AlertTriangle,
  ExternalLink,
} from 'lucide-react'
import { env } from '@/env/client'
import { cn } from '@/lib/utils'

interface PaymentConfig {
  provider: 'stripe' | 'paddle' | null
  enabled: boolean
  // Stripe
  stripePublishableKey?: string
  stripeSecretKey?: string
  stripeWebhookSecret?: string
  // Paddle
  paddleApiKey?: string
  paddleVendorId?: string
  paddlePublicKey?: string
  // Common
  currency?: string
  defaultPlanId?: string
  trialDays?: number
  allowSelfServeDowngrades?: boolean
}

const defaultConfig: PaymentConfig = {
  provider: null,
  enabled: false,
  stripePublishableKey: '',
  stripeSecretKey: '',
  stripeWebhookSecret: '',
  paddleApiKey: '',
  paddleVendorId: '',
  paddlePublicKey: '',
  currency: 'usd',
  defaultPlanId: '',
  trialDays: 14,
  allowSelfServeDowngrades: true,
}

interface PaymentProvider {
  id: PaymentConfig['provider'] & string
  name: string
  description: string
  icon: ElementType
  envKey: keyof typeof env
  docsUrl: string
}

const paymentProviders: PaymentProvider[] = [
  {
    id: 'stripe',
    name: 'Stripe',
    description: 'Leading payment processing platform',
    icon: CreditCard,
    envKey: 'VITE_PAYMENT_STRIPE_ENABLED',
    docsUrl: 'https://stripe.com/docs',
  },
  {
    id: 'paddle',
    name: 'Paddle',
    description: 'Merchant of record for SaaS',
    icon: Wallet,
    envKey: 'VITE_PAYMENT_PADDLE_ENABLED',
    docsUrl: 'https://developer.paddle.com/',
  },
]

function isProviderEnabled(provider: PaymentProvider): boolean {
  return env[provider.envKey] === 'true'
}

export function PaymentSettings() {
  const [config, setConfig] = useState<PaymentConfig>(defaultConfig)
  const [isLoading, setIsLoading] = useState(false)
  const [showSecrets, setShowSecrets] = useState(false)
  const [secretState, setSecretState] = useState({
    paddleApiKey: false,
    paddlePublicKey: false,
  })

  const hasAnyProviderEnabled = paymentProviders.some(isProviderEnabled)

  const handleSave = async () => {
    setIsLoading(true)
    try {
      await new Promise((resolve) => setTimeout(resolve, 1000))
      setSecretState((prev) => ({
        paddleApiKey: prev.paddleApiKey || Boolean(config.paddleApiKey?.trim()),
        paddlePublicKey: prev.paddlePublicKey || Boolean(config.paddlePublicKey?.trim()),
      }))
      if (config.paddleApiKey?.trim()) updateConfig('paddleApiKey', '')
      if (config.paddlePublicKey?.trim()) updateConfig('paddlePublicKey', '')
    } finally {
      setIsLoading(false)
    }
  }

  const updateConfig = <K extends keyof PaymentConfig>(key: K, value: PaymentConfig[K]) => {
    setConfig((prev) => ({ ...prev, [key]: value }))
  }

  const selectedProvider = paymentProviders.find(p => p.id === config.provider)
  const isSelectedProviderEnabled = selectedProvider ? isProviderEnabled(selectedProvider) : false

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Payment Configuration</h2>
          <p className="text-muted-foreground">
            Configure payment providers for billing and subscriptions
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

      {!hasAnyProviderEnabled && (
        <div className="rounded-lg bg-amber-50 p-4 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            <span className="text-sm">
              No payment providers enabled. Set VITE_PAYMENT_STRIPE_ENABLED=true or VITE_PAYMENT_PADDLE_ENABLED=true
            </span>
          </div>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Payment Provider</CardTitle>
          <CardDescription>
            Select a payment processor for your subscriptions
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2">
            {paymentProviders.map((provider) => {
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
              className="space-y-6"
            >
              <div className="h-px bg-border" />

              {config.provider === 'stripe' && (
                <div className="space-y-4">
                  <h3 className="font-semibold">Stripe Configuration</h3>
                  
                  <div className="rounded-lg bg-blue-50 p-4 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                    <p className="text-sm">
                      Set your webhook endpoint to:{''}
                      <code className="ml-1 rounded bg-blue-100 px-1 text-xs dark:bg-blue-900/40">
                        {typeof window !== 'undefined' ? `${window.location.origin}/api/webhooks/stripe` : ''}
                      </code>
                    </p>
                  </div>

                  <div className="space-y-2">
                    <label htmlFor="stripe-pk" className="text-sm font-medium leading-none">
                      Publishable Key
                    </label>
                    <Input
                      id="stripe-pk"
                      value={config.stripePublishableKey}
                      onChange={(e) => updateConfig('stripePublishableKey', e.target.value)}
                      placeholder="pk_your_stripe_publishable_key"
                    />
                  </div>

                  <div className="space-y-2">
                    <label htmlFor="stripe-sk" className="text-sm font-medium leading-none">
                      Secret Key
                    </label>
                    <Input
                      id="stripe-sk"
                      type={showSecrets ? 'text' : 'password'}
                      value={config.stripeSecretKey}
                      onChange={(e) => updateConfig('stripeSecretKey', e.target.value)}
                      placeholder="sk_your_stripe_secret_key"
                    />
                  </div>

                  <div className="space-y-2">
                    <label htmlFor="stripe-wh" className="text-sm font-medium leading-none">
                      Webhook Secret
                    </label>
                    <Input
                      id="stripe-wh"
                      type={showSecrets ? 'text' : 'password'}
                      value={config.stripeWebhookSecret}
                      onChange={(e) => updateConfig('stripeWebhookSecret', e.target.value)}
                      placeholder="YOUR_STRIPE_WEBHOOK_SECRET"
                    />
                  </div>
                </div>
              )}

              {config.provider === 'paddle' && (
                <div className="space-y-4">
                  <h3 className="font-semibold">Paddle Configuration</h3>
                  
                  <div className="space-y-2">
                    <label htmlFor="paddle-vendor" className="text-sm font-medium leading-none">
                      Vendor ID
                    </label>
                    <Input
                      id="paddle-vendor"
                      value={config.paddleVendorId}
                      onChange={(e) => updateConfig('paddleVendorId', e.target.value)}
                      placeholder="12345"
                    />
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label htmlFor="paddle-api" className="text-sm font-medium leading-none">
                        API Key
                      </label>
                      {secretState.paddleApiKey && !config.paddleApiKey && (
                        <Badge variant="outline" className="text-xs">Set</Badge>
                      )}
                    </div>
                    <Input
                      id="paddle-api"
                      type={showSecrets ? 'text' : 'password'}
                      value={config.paddleApiKey}
                      onChange={(e) => updateConfig('paddleApiKey', e.target.value)}
                      placeholder={secretState.paddleApiKey && !config.paddleApiKey ? '******** (set)' : '••••••••'}
                    />
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label htmlFor="paddle-pk" className="text-sm font-medium leading-none">
                        Public Key
                      </label>
                      {secretState.paddlePublicKey && !config.paddlePublicKey && (
                        <Badge variant="outline" className="text-xs">Set</Badge>
                      )}
                    </div>
                    <Input
                      id="paddle-pk"
                      type={showSecrets ? 'text' : 'password'}
                      value={config.paddlePublicKey}
                      onChange={(e) => updateConfig('paddlePublicKey', e.target.value)}
                      placeholder={secretState.paddlePublicKey && !config.paddlePublicKey ? '******** (set)' : '••••••••'}
                    />
                  </div>
                </div>
              )}

              <div className="h-px bg-border" />

              <div className="space-y-4">
                <h3 className="font-semibold">Billing Settings</h3>
                
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <label htmlFor="currency" className="text-sm font-medium leading-none">
                      Currency
                    </label>
                    <select
                      id="currency"
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                      value={config.currency}
                      onChange={(e) => updateConfig('currency', e.target.value)}
                    >
                      <option value="usd">USD - US Dollar</option>
                      <option value="eur">EUR - Euro</option>
                      <option value="gbp">GBP - British Pound</option>
                      <option value="cad">CAD - Canadian Dollar</option>
                      <option value="aud">AUD - Australian Dollar</option>
                    </select>
                  </div>

                  <div className="space-y-2">
                    <label htmlFor="trial" className="text-sm font-medium leading-none">
                      Trial Period (Days)
                    </label>
                    <Input
                      id="trial"
                      type="number"
                      value={config.trialDays}
                      onChange={(e) => updateConfig('trialDays', parseInt(e.target.value))}
                      min={0}
                      max={90}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <label htmlFor="default-plan" className="text-sm font-medium leading-none">
                    Default Plan ID (Optional)
                  </label>
                  <Input
                    id="default-plan"
                    value={config.defaultPlanId}
                    onChange={(e) => updateConfig('defaultPlanId', e.target.value)}
                    placeholder="price_xxx or plan_xxx"
                  />
                </div>

              <div className="flex items-center gap-2">
                <Switch
                  id="self-serve"
                  checked={config.allowSelfServeDowngrades}
                  onCheckedChange={(checked) => updateConfig('allowSelfServeDowngrades', checked)}
                />
                <label htmlFor="self-serve" className="text-sm font-medium leading-none">
                  Allow self-serve plan changes
                </label>
              </div>
              </div>

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

              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <CheckCircle className="h-4 w-4" />
                <a
                  href={selectedProvider?.docsUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:underline"
                >
                  View {selectedProvider?.name} documentation
                </a>
                <ExternalLink className="h-3 w-3" />
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
