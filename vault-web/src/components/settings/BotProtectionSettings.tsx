import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/Tabs'
import {
  Shield,
  Bot,
  Eye,
  Fingerprint,
  Globe,
  CheckCircle,
  AlertTriangle,
  HelpCircle,
  Lock,
} from 'lucide-react'
import { env } from '@/env/client'
import { cn } from '@/lib/utils'

interface BotProtectionConfig {
  enabled: boolean
  captcha: {
    provider: 'recaptcha_v2' | 'recaptcha_v3' | 'hcaptcha' | 'turnstile' | null
    siteKey: string
    secretKey: string
    v3ScoreThreshold: number
    actions: {
      login: boolean
      register: boolean
      passwordReset: boolean
      apiAccess: boolean
    }
  }
  fingerprinting: {
    enabled: boolean
    fingerprintTimeout: number
  }
  rules: {
    blockHeadlessBrowsers: boolean
    blockDataCenterIps: boolean
    requireUserAgent: boolean
    maxRequestsPerSession: number
  }
}

const defaultConfig: BotProtectionConfig = {
  enabled: true,
  captcha: {
    provider: null,
    siteKey: '',
    secretKey: '',
    v3ScoreThreshold: 0.5,
    actions: {
      login: true,
      register: true,
      passwordReset: true,
      apiAccess: false,
    },
  },
  fingerprinting: {
    enabled: true,
    fingerprintTimeout: 3600,
  },
  rules: {
    blockHeadlessBrowsers: true,
    blockDataCenterIps: false,
    requireUserAgent: true,
    maxRequestsPerSession: 1000,
  },
}

interface CaptchaProvider {
  id: 'recaptcha_v2' | 'recaptcha_v3' | 'hcaptcha' | 'turnstile'
  name: string
  description: string
  envKey: keyof typeof env
}

const captchaProviders: CaptchaProvider[] = [
  { id: 'recaptcha_v2', name: 'reCAPTCHA v2', description: 'Checkbox challenge-based verification', envKey: 'VITE_CAPTCHA_RECAPTCHA_V2_ENABLED' },
  { id: 'recaptcha_v3', name: 'reCAPTCHA v3', description: 'Invisible scoring-based verification', envKey: 'VITE_CAPTCHA_RECAPTCHA_V3_ENABLED' },
  { id: 'hcaptcha', name: 'hCaptcha', description: 'Privacy-focused alternative to reCAPTCHA', envKey: 'VITE_CAPTCHA_HCAPTCHA_ENABLED' },
  { id: 'turnstile', name: 'Cloudflare Turnstile', description: 'Invisible, privacy-preserving CAPTCHA', envKey: 'VITE_CAPTCHA_TURNSTILE_ENABLED' },
]

function isProviderEnabled(provider: CaptchaProvider): boolean {
  return env[provider.envKey] === 'true'
}

export function BotProtectionSettings() {
  const [config, setConfig] = useState<BotProtectionConfig>(defaultConfig)
  const [isLoading, setIsLoading] = useState(false)
  const [showSecret, setShowSecret] = useState(false)
  const [testStatus, setTestStatus] = useState<'idle' | 'success' | 'error'>('idle')
  const [secretSet, setSecretSet] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function loadConfig() {
      const endpoints = ['/api/v1/admin/advanced', '/api/v1/admin/settings/advanced']
      for (const endpoint of endpoints) {
        try {
          const response = await fetch(endpoint, { credentials: 'include' })
          if (!response.ok) continue
          const payload = await response.json() as {
            settings?: { feature_flags?: Record<string, boolean>; jwt_claims?: Record<string, unknown> }
          }
          if (cancelled) return
          const featureFlags = payload.settings?.feature_flags || {}
          const claims = payload.settings?.jwt_claims || {}
          setConfig((prev) => ({
            ...prev,
            enabled: featureFlags.bot_protection_enabled ?? prev.enabled,
            captcha: {
              ...prev.captcha,
              provider: (claims.bot_captcha_provider as BotProtectionConfig['captcha']['provider']) ?? prev.captcha.provider,
              v3ScoreThreshold: Number(claims.bot_v3_threshold ?? prev.captcha.v3ScoreThreshold),
            },
          }))
          return
        } catch {
          // try fallback endpoint
        }
      }
    }
    void loadConfig()
    return () => {
      cancelled = true
    }
  }, [])

  // Check which providers are enabled via env vars

  const handleSave = async () => {
    setIsLoading(true)
    try {
      const endpoints = ['/api/v1/admin/advanced', '/api/v1/admin/settings/advanced']
      let saved = false
      for (const endpoint of endpoints) {
        try {
          const getResponse = await fetch(endpoint, { credentials: 'include' })
          if (!getResponse.ok) continue
          const current = await getResponse.json() as {
            settings?: Record<string, unknown>
          }
          const settings = (current.settings || {}) as Record<string, unknown>
          const featureFlags = (settings.feature_flags as Record<string, boolean> | undefined) || {}
          const jwtClaims = (settings.jwt_claims as Record<string, unknown> | undefined) || {}

          const nextSettings = {
            ...settings,
            feature_flags: {
              ...featureFlags,
              bot_protection_enabled: config.enabled,
              bot_fingerprint_enabled: config.fingerprinting.enabled,
            },
            jwt_claims: {
              ...jwtClaims,
              bot_captcha_provider: config.captcha.provider,
              bot_v3_threshold: config.captcha.v3ScoreThreshold,
              bot_block_headless: config.rules.blockHeadlessBrowsers,
              bot_block_datacenter: config.rules.blockDataCenterIps,
            },
          }

          const patchResponse = await fetch(endpoint, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(nextSettings),
          })
          if (!patchResponse.ok) {
            continue
          }
          saved = true
          break
        } catch {
          // try fallback endpoint
        }
      }
      if (!saved) {
        throw new Error('Failed to save bot protection settings')
      }
      setSaveError(null)
      if (config.captcha.secretKey?.trim()) {
        setSecretSet(true)
        updateConfig('captcha.secretKey', '')
      }
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save bot protection settings')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTest = async () => {
    setTestStatus('idle')
    try {
      const response = await fetch('/api/v1/auth/captcha-site-key')
      if (!response.ok) {
        throw new Error('CAPTCHA endpoint unavailable')
      }
      setTestStatus('success')
    } catch {
      setTestStatus('error')
    }
  }

  const updateConfig = (path: string, value: unknown) => {
    const keys = path.split('.')
    setConfig((prev) => {
      const newConfig = { ...prev }
      let current: Record<string, unknown> = newConfig
      for (let i = 0; i < keys.length - 1; i++) {
        current[keys[i]] = { ...(current[keys[i]] as Record<string, unknown>) }
        current = current[keys[i]] as Record<string, unknown>
      }
      current[keys[keys.length - 1]] = value
      return newConfig
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Bot Protection</h2>
          <p className="text-muted-foreground">
            Protect your application from automated attacks and spam
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Switch
            checked={config.enabled}
            onCheckedChange={(checked) => updateConfig('enabled', checked)}
          />
          <span className={cn('text-sm font-medium', config.enabled ? 'text-green-600' : 'text-muted-foreground')}>
            {config.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
      </div>
      {saveError && (
        <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
          {saveError}
        </div>
      )}

      <Tabs defaultValue="captcha" className="space-y-4">
        <TabsList>
          <TabsTrigger value="captcha" className="gap-2">
            <Shield className="h-4 w-4" />
            CAPTCHA
          </TabsTrigger>
          <TabsTrigger value="fingerprinting" className="gap-2">
            <Fingerprint className="h-4 w-4" />
            Fingerprinting
          </TabsTrigger>
          <TabsTrigger value="rules" className="gap-2">
            <Bot className="h-4 w-4" />
            Rules
          </TabsTrigger>
        </TabsList>

        <TabsContent value="captcha" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>CAPTCHA Provider</CardTitle>
              <CardDescription>
                Choose a CAPTCHA provider to protect your forms and API endpoints
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 sm:grid-cols-2">
                {captchaProviders.map((provider) => {
                  const isEnabled = isProviderEnabled(provider)
                  return (
                    <div key={provider.id} className="space-y-2">
                      <div
                        className={cn(
                          'relative rounded-lg border p-4 transition-colors',
                          isEnabled
                            ? config.captcha.provider === provider.id
                              ? 'cursor-pointer border-primary bg-primary/5'
                              : 'cursor-pointer hover:border-primary/50'
                            : 'cursor-not-allowed border-muted bg-muted/30 opacity-60'
                        )}
                        onClick={() => isEnabled && updateConfig('captcha.provider', provider.id)}
                      >
                        {!isEnabled && (
                          <div className="absolute right-2 top-2">
                            <Lock className="h-3.5 w-3.5 text-muted-foreground" />
                          </div>
                        )}
                        <div className="flex items-start gap-3">
                          <div
                            className={cn(
                              'flex h-5 w-5 shrink-0 items-center justify-center rounded-full border',
                              config.captcha.provider === provider.id && isEnabled
                                ? 'border-primary bg-primary text-primary-foreground'
                                : 'border-muted-foreground'
                            )}
                          >
                            {config.captcha.provider === provider.id && isEnabled && (
                              <CheckCircle className="h-3.5 w-3.5" />
                            )}
                          </div>
                          <div>
                            <div className="font-medium">{provider.name}</div>
                            <p className="text-sm text-muted-foreground">{provider.description}</p>
                          </div>
                        </div>
                      </div>
                      {!isEnabled && (
                        <p className="text-xs text-muted-foreground">
                          Set <code className="font-mono">{provider.envKey}=true</code> to enable.
                        </p>
                      )}
                    </div>
                  )
                })}
                <div
                  className={cn(
                    'cursor-pointer rounded-lg border p-4 transition-colors',
                    config.captcha.provider === null
                      ? 'border-primary bg-primary/5'
                      : 'hover:border-primary/50'
                  )}
                  onClick={() => updateConfig('captcha.provider', null)}
                >
                  <div className="flex items-start gap-3">
                    <div
                      className={cn(
                        'flex h-5 w-5 shrink-0 items-center justify-center rounded-full border',
                        config.captcha.provider === null
                          ? 'border-primary bg-primary text-primary-foreground'
                          : 'border-muted-foreground'
                      )}
                    >
                      {config.captcha.provider === null && <CheckCircle className="h-3.5 w-3.5" />}
                    </div>
                    <div>
                      <div className="font-medium">None</div>
                      <p className="text-sm text-muted-foreground">Disable CAPTCHA protection</p>
                    </div>
                  </div>
                </div>
              </div>

              <AnimatePresence>
                {config.captcha.provider && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="space-y-4"
                  >
                    <div className="h-px bg-border" />

                    <div className="space-y-2">
                      <label className="text-sm font-medium" htmlFor="site-key">Site Key</label>
                      <Input
                        id="site-key"
                        placeholder="Enter your site key"
                        value={config.captcha.siteKey}
                        onChange={(e) => updateConfig('captcha.siteKey', e.target.value)}
                      />
                    </div>

                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <label className="text-sm font-medium" htmlFor="secret-key">Secret Key</label>
                        {secretSet && !config.captcha.secretKey && (
                          <Badge variant="outline" className="text-xs">Set</Badge>
                        )}
                      </div>
                      <div className="flex gap-2">
                        <Input
                          id="secret-key"
                          type={showSecret ? 'text' : 'password'}
                          placeholder={secretSet && !config.captcha.secretKey ? '******** (set)' : 'Enter your secret key'}
                          value={config.captcha.secretKey}
                          onChange={(e) => updateConfig('captcha.secretKey', e.target.value)}
                        />
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => setShowSecret(!showSecret)}
                          aria-label={showSecret ? 'Hide secret key' : 'Show secret key'}
                        >
                          {showSecret ? <Eye className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </Button>
                      </div>
                    </div>

                    {config.captcha.provider === 'recaptcha_v3' && (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <label className="text-sm font-medium">Score Threshold</label>
                          <Badge variant="secondary">{config.captcha.v3ScoreThreshold}</Badge>
                        </div>
                        <input
                          type="range"
                          min="0"
                          max="1"
                          step="0.1"
                          value={config.captcha.v3ScoreThreshold}
                          onChange={(e) => updateConfig('captcha.v3ScoreThreshold', parseFloat(e.target.value))}
                          className="w-full"
                        />
                        <p className="text-xs text-muted-foreground">
                          Scores below this threshold will be challenged. Lower values are more permissive.
                        </p>
                      </div>
                    )}

                    <div className="space-y-2">
                      <label className="text-sm font-medium">Protected Actions</label>
                      <div className="space-y-2 rounded-lg border p-4">
                        {[
                          { key: 'login', label: 'Login', description: 'Protect login forms' },
                          { key: 'register', label: 'Registration', description: 'Protect sign-up forms' },
                          { key: 'passwordReset', label: 'Password Reset', description: 'Protect password reset' },
                          { key: 'apiAccess', label: 'API Access', description: 'Protect API endpoints' },
                        ].map((action) => (
                          <label
                            key={action.key}
                            className="flex cursor-pointer items-center justify-between rounded-md p-2 hover:bg-muted"
                          >
                            <div>
                              <div className="font-medium">{action.label}</div>
                              <p className="text-xs text-muted-foreground">{action.description}</p>
                            </div>
                            <Switch
                              checked={config.captcha.actions[action.key as keyof typeof config.captcha.actions]}
                              onCheckedChange={(checked) =>
                                updateConfig(`captcha.actions.${action.key}`, checked)
                              }
                            />
                          </label>
                        ))}
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="fingerprinting" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Fingerprint className="h-5 w-5" />
                Device Fingerprinting
              </CardTitle>
              <CardDescription>
                Track unique device signatures to detect suspicious behavior
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between rounded-lg border p-4">
                <div className="space-y-0.5">
                  <label className="text-base font-medium">Enable Fingerprinting</label>
                  <p className="text-sm text-muted-foreground">
                    Generate unique fingerprints for each device
                  </p>
                </div>
                <Switch
                  checked={config.fingerprinting.enabled}
                  onCheckedChange={(checked) => updateConfig('fingerprinting.enabled', checked)}
                />
              </div>

              {config.fingerprinting.enabled && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="space-y-4"
                >
                  <div className="rounded-lg bg-blue-50 p-4 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                    <div className="flex items-start gap-2">
                      <HelpCircle className="mt-0.5 h-4 w-4" />
                      <div className="text-sm">
                        Device fingerprinting creates a unique identifier based on browser
                        characteristics. This helps detect when the same device is used across
                        multiple sessions or accounts.
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium" htmlFor="fingerprint-timeout">Fingerprint Timeout (seconds)</label>
                    <Input
                      id="fingerprint-timeout"
                      type="number"
                      value={config.fingerprinting.fingerprintTimeout}
                      onChange={(e) =>
                        updateConfig('fingerprinting.fingerprintTimeout', parseInt(e.target.value))
                      }
                    />
                    <p className="text-xs text-muted-foreground">
                      How long to keep fingerprint data before requiring re-verification
                    </p>
                  </div>
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="rules" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bot className="h-5 w-5" />
                Detection Rules
              </CardTitle>
              <CardDescription>
                Configure automated bot detection rules
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-lg bg-amber-50 p-4 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="mt-0.5 h-4 w-4" />
                  <div className="text-sm">
                    Some rules may block legitimate automated tools. Use with caution and monitor
                    your traffic patterns.
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <label className="flex cursor-pointer items-center justify-between rounded-lg border p-4 hover:bg-muted">
                  <div className="space-y-0.5">
                    <div className="font-medium">Block Headless Browsers</div>
                    <p className="text-sm text-muted-foreground">
                      Block requests from headless browsers like Puppeteer and Playwright
                    </p>
                  </div>
                  <Switch
                    checked={config.rules.blockHeadlessBrowsers}
                    onCheckedChange={(checked) => updateConfig('rules.blockHeadlessBrowsers', checked)}
                  />
                </label>

                <label className="flex cursor-pointer items-center justify-between rounded-lg border p-4 hover:bg-muted">
                  <div className="space-y-0.5">
                    <div className="font-medium">Block Data Center IPs</div>
                    <p className="text-sm text-muted-foreground">
                      Block requests from known hosting providers and data centers
                    </p>
                  </div>
                  <Switch
                    checked={config.rules.blockDataCenterIps}
                    onCheckedChange={(checked) => updateConfig('rules.blockDataCenterIps', checked)}
                  />
                </label>

                <label className="flex cursor-pointer items-center justify-between rounded-lg border p-4 hover:bg-muted">
                  <div className="space-y-0.5">
                    <div className="font-medium">Require User-Agent</div>
                    <p className="text-sm text-muted-foreground">
                      Block requests without a valid User-Agent header
                    </p>
                  </div>
                  <Switch
                    checked={config.rules.requireUserAgent}
                    onCheckedChange={(checked) => updateConfig('rules.requireUserAgent', checked)}
                  />
                </label>

                <div className="space-y-2 rounded-lg border p-4">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium">Max Requests Per Session</label>
                    <Badge variant="secondary">{config.rules.maxRequestsPerSession}</Badge>
                  </div>
                  <input
                    type="range"
                    min="100"
                    max="10000"
                    step="100"
                    value={config.rules.maxRequestsPerSession}
                    onChange={(e) => updateConfig('rules.maxRequestsPerSession', parseInt(e.target.value))}
                    className="w-full"
                  />
                  <p className="text-xs text-muted-foreground">
                    Maximum requests allowed per session before requiring re-authentication
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <AnimatePresence>
        {testStatus !== 'idle' && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
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
                  ? 'Bot protection test passed!'
                  : 'Bot protection test failed. Please check your configuration.'}
              </span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="flex items-center justify-end gap-4">
        <Button
          variant="outline"
          onClick={handleTest}
          disabled={!config.enabled || !config.captcha.provider}
        >
          <Globe className="mr-2 h-4 w-4" />
          Test Configuration
        </Button>
        <Button onClick={handleSave} disabled={isLoading}>
          {isLoading ? (
            <>
              <motion.div
                className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
              />
              Saving…
            </>
          ) : (
            'Save Settings'
          )}
        </Button>
      </div>
    </div>
  )
}
