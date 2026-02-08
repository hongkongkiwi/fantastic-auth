import { useState, type ElementType } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import {
  BarChart3,
  MousePointerClick,
  CheckCircle,
  Lock,
  ExternalLink,
} from 'lucide-react'
import { env } from '@/env/client'
import { cn } from '@/lib/utils'

interface AnalyticsConfig {
  posthog: {
    enabled: boolean
    apiKey: string
    apiHost: string
    autocapture: boolean
    sessionRecording: boolean
  }
  plausible: {
    enabled: boolean
    domain: string
    apiHost: string
    trackOutboundLinks: boolean
  }
}

const defaultConfig: AnalyticsConfig = {
  posthog: {
    enabled: false,
    apiKey: '',
    apiHost: 'https://app.posthog.com',
    autocapture: true,
    sessionRecording: false,
  },
  plausible: {
    enabled: false,
    domain: '',
    apiHost: 'https://plausible.io',
    trackOutboundLinks: true,
  },
}

interface AnalyticsProvider {
  id: keyof AnalyticsConfig
  name: string
  description: string
  icon: ElementType
  envKey: keyof typeof env
  docsUrl: string
}

const analyticsProviders: AnalyticsProvider[] = [
  {
    id: 'posthog',
    name: 'PostHog',
    description: 'Product analytics with autocapture',
    icon: BarChart3,
    envKey: 'VITE_ANALYTICS_POSTHOG_ENABLED',
    docsUrl: 'https://posthog.com/docs',
  },
  {
    id: 'plausible',
    name: 'Plausible',
    description: 'Privacy-focused web analytics',
    icon: MousePointerClick,
    envKey: 'VITE_ANALYTICS_PLAUSIBLE_ENABLED',
    docsUrl: 'https://plausible.io/docs',
  },
]

function isProviderEnabled(provider: AnalyticsProvider): boolean {
  return env[provider.envKey] === 'true'
}

export function AnalyticsSettings() {
  const [config, setConfig] = useState<AnalyticsConfig>(defaultConfig)
  const [isLoading, setIsLoading] = useState(false)
  const [showSecrets, setShowSecrets] = useState(false)
  const [secretState, setSecretState] = useState<Record<string, boolean>>({})

  const handleSave = async () => {
    setIsLoading(true)
    try {
      await new Promise((resolve) => setTimeout(resolve, 1000))
      setSecretState((prev) => ({
        ...prev,
        posthog: prev.posthog || Boolean(config.posthog.apiKey?.trim()),
      }))
      if (config.posthog.apiKey?.trim()) {
        updateProviderConfig('posthog', 'apiKey', '')
      }
    } finally {
      setIsLoading(false)
    }
  }

  const updateProviderConfig = (
    provider: keyof AnalyticsConfig,
    key: string,
    value: unknown
  ) => {
    setConfig((prev) => ({
      ...prev,
      [provider]: { ...prev[provider], [key]: value },
    }))
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Analytics</h2>
        <p className="text-muted-foreground">
          Configure analytics providers to track user behavior and app usage
        </p>
      </div>

      <div className="grid gap-6">
        {analyticsProviders.map((provider) => {
          const isEnabled = isProviderEnabled(provider)
          const providerConfig = config[provider.id]
          const Icon = provider.icon

          return (
            <Card key={provider.id} className={cn(!isEnabled && 'opacity-60')}>
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                      <Icon className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        {provider.name}
                        {!isEnabled && (
                          <Lock className="h-3.5 w-3.5 text-muted-foreground" />
                        )}
                      </CardTitle>
                      <CardDescription>{provider.description}</CardDescription>
                    </div>
                  </div>
                  <Switch
                    checked={providerConfig.enabled}
                    onCheckedChange={(checked) =>
                      updateProviderConfig(provider.id, 'enabled', checked)
                    }
                    disabled={!isEnabled}
                  />
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {!isEnabled ? (
                  <div className="rounded-lg bg-muted p-3 text-sm text-muted-foreground">
                    Set {provider.envKey}=true to enable {provider.name} configuration
                  </div>
                ) : (
                  <>
                          {provider.id === 'posthog' && (
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              className="space-y-4"
                            >
                              <div className="space-y-2">
                                <div className="flex items-center justify-between">
                                  <label htmlFor="posthog-key" className="text-sm font-medium leading-none">
                                    Project API Key
                                  </label>
                                  {secretState.posthog && !config.posthog.apiKey && (
                                    <Badge variant="outline" className="text-xs">Set</Badge>
                                  )}
                                </div>
                                <Input
                                  id="posthog-key"
                                  type={showSecrets ? 'text' : 'password'}
                                  value={config.posthog.apiKey}
                                  onChange={(e) =>
                                    updateProviderConfig('posthog', 'apiKey', e.target.value)
                                  }
                                  placeholder={secretState.posthog && !config.posthog.apiKey ? '******** (set)' : 'phc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'}
                                />
                              </div>

                              <div className="space-y-2">
                                <label htmlFor="posthog-host" className="text-sm font-medium leading-none">
                                  API Host
                                </label>
                                <Input
                                  id="posthog-host"
                                  value={config.posthog.apiHost}
                                  onChange={(e) =>
                                    updateProviderConfig('posthog', 'apiHost', e.target.value)
                                  }
                                  placeholder="https://app.posthog.com"
                                />
                              </div>

                              <div className="h-px bg-border" />

                              <div className="space-y-3">
                                <div className="flex items-center justify-between">
                                  <div className="space-y-0.5">
                                    <span className="text-sm font-medium leading-none">Autocapture</span>
                                    <p className="text-xs text-muted-foreground">
                                      Automatically capture clicks, form submissions, etc.
                                    </p>
                                  </div>
                                  <Switch
                                    checked={config.posthog.autocapture}
                                    onCheckedChange={(checked) =>
                                      updateProviderConfig('posthog', 'autocapture', checked)
                                    }
                                  />
                                </div>

                                <div className="flex items-center justify-between">
                                  <div className="space-y-0.5">
                                    <span className="text-sm font-medium leading-none">Session Recording</span>
                                    <p className="text-xs text-muted-foreground">
                                      Record user sessions for replay
                                    </p>
                                  </div>
                                  <Switch
                                    checked={config.posthog.sessionRecording}
                                    onCheckedChange={(checked) =>
                                      updateProviderConfig('posthog', 'sessionRecording', checked)
                                    }
                                  />
                                </div>
                              </div>
                            </motion.div>
                          )}

                          {provider.id === 'plausible' && (
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              className="space-y-4"
                            >
                              <div className="space-y-2">
                                <label htmlFor="plausible-domain" className="text-sm font-medium leading-none">
                                  Domain
                                </label>
                                <Input
                                  id="plausible-domain"
                                  value={config.plausible.domain}
                                  onChange={(e) =>
                                    updateProviderConfig('plausible', 'domain', e.target.value)
                                  }
                                  placeholder="yourdomain.com"
                                />
                              </div>

                              <div className="space-y-2">
                                <label htmlFor="plausible-host" className="text-sm font-medium leading-none">
                                  API Host
                                </label>
                                <Input
                                  id="plausible-host"
                                  value={config.plausible.apiHost}
                                  onChange={(e) =>
                                    updateProviderConfig('plausible', 'apiHost', e.target.value)
                                  }
                                  placeholder="https://plausible.io"
                                />
                                <p className="text-xs text-muted-foreground">
                                  Use your self-hosted Plausible URL if applicable
                                </p>
                              </div>

                              <div className="h-px bg-border" />

                              <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                  <span className="text-sm font-medium leading-none">
                                    Track Outbound Links
                                  </span>
                                  <p className="text-xs text-muted-foreground">
                                    Track clicks on external links
                                  </p>
                                </div>
                                <Switch
                                  checked={config.plausible.trackOutboundLinks}
                                  onCheckedChange={(checked) =>
                                    updateProviderConfig('plausible', 'trackOutboundLinks', checked)
                                  }
                                />
                              </div>
                            </motion.div>
                          )}

                          <div className="flex items-center gap-2 pt-2">
                            <Switch
                              id={`show-secrets-${provider.id}`}
                              checked={showSecrets}
                              onCheckedChange={setShowSecrets}
                            />
                            <label htmlFor={`show-secrets-${provider.id}`} className="text-sm font-medium leading-none">
                              Show Secrets
                            </label>
                          </div>

                          <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            <CheckCircle className="h-4 w-4" />
                            <a
                              href={provider.docsUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="hover:underline"
                            >
                              View {provider.name} documentation
                            </a>
                            <ExternalLink className="h-3 w-3" />
                          </div>
                  </>
                )}
              </CardContent>
            </Card>
          )
        })}
      </div>

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
