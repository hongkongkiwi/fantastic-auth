import { useState, type ElementType } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import {
  Shield,
  Key,
  Globe,
  CheckCircle,
  Lock,
  ExternalLink,
} from 'lucide-react'
import { env } from '@/env/client'
import { cn } from '@/lib/utils'

interface SecurityServicesConfig {
  hibp: {
    enabled: boolean
    apiKey: string
    checkOnRegistration: boolean
    checkOnPasswordChange: boolean
    warningThreshold: number
  }
  maxmind: {
    enabled: boolean
    accountId: string
    licenseKey: string
    riskThreshold: number
    blockAnonymousProxies: boolean
  }
}

const defaultConfig: SecurityServicesConfig = {
  hibp: {
    enabled: false,
    apiKey: '',
    checkOnRegistration: true,
    checkOnPasswordChange: true,
    warningThreshold: 1,
  },
  maxmind: {
    enabled: false,
    accountId: '',
    licenseKey: '',
    riskThreshold: 50,
    blockAnonymousProxies: true,
  },
}

interface SecurityService {
  id: keyof SecurityServicesConfig
  name: string
  description: string
  icon: ElementType
  envKey: keyof typeof env
  docsUrl: string
}

const securityServices: SecurityService[] = [
  {
    id: 'hibp',
    name: 'Have I Been Pwned',
    description: 'Check passwords against known data breaches',
    icon: Key,
    envKey: 'VITE_SECURITY_HIBP_ENABLED',
    docsUrl: 'https://haveibeenpwned.com/API/v3',
  },
  {
    id: 'maxmind',
    name: 'MaxMind GeoIP',
    description: 'IP geolocation and risk scoring',
    icon: Globe,
    envKey: 'VITE_SECURITY_MAXMIND_ENABLED',
    docsUrl: 'https://dev.maxmind.com/',
  },
]

function isServiceEnabled(service: SecurityService): boolean {
  return env[service.envKey] === 'true'
}

export function SecurityServicesSettings() {
  const [config, setConfig] = useState<SecurityServicesConfig>(defaultConfig)
  const [isLoading, setIsLoading] = useState(false)
  const [showSecrets, setShowSecrets] = useState(false)
  const [secretState, setSecretState] = useState({
    hibpApiKey: false,
    maxmindLicenseKey: false,
  })

  const handleSave = async () => {
    setIsLoading(true)
    try {
      await new Promise((resolve) => setTimeout(resolve, 1000))
      setSecretState((prev) => ({
        hibpApiKey: prev.hibpApiKey || Boolean(config.hibp.apiKey.trim()),
        maxmindLicenseKey: prev.maxmindLicenseKey || Boolean(config.maxmind.licenseKey.trim()),
      }))
      if (config.hibp.apiKey.trim()) updateServiceConfig('hibp', 'apiKey', '')
      if (config.maxmind.licenseKey.trim()) updateServiceConfig('maxmind', 'licenseKey', '')
    } finally {
      setIsLoading(false)
    }
  }

  const updateServiceConfig = (
    service: keyof SecurityServicesConfig,
    key: string,
    value: unknown
  ) => {
    setConfig((prev) => ({
      ...prev,
      [service]: { ...prev[service], [key]: value },
    }))
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Security Services</h2>
        <p className="text-muted-foreground">
          Configure external security services for enhanced protection
        </p>
      </div>

      <div className="grid gap-6">
        {securityServices.map((service) => {
          const isEnabled = isServiceEnabled(service)
          const serviceConfig = config[service.id]
          const Icon = service.icon

          return (
            <Card key={service.id} className={cn(!isEnabled && 'opacity-60')}>
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                      <Icon className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        {service.name}
                        {!isEnabled && (
                          <Lock className="h-3.5 w-3.5 text-muted-foreground" />
                        )}
                      </CardTitle>
                      <CardDescription>{service.description}</CardDescription>
                    </div>
                  </div>
                  <Switch
                    checked={serviceConfig.enabled}
                    onCheckedChange={(checked) =>
                      updateServiceConfig(service.id, 'enabled', checked)
                    }
                    disabled={!isEnabled}
                  />
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {!isEnabled ? (
                  <div className="rounded-lg bg-muted p-3 text-sm text-muted-foreground">
                    Set {service.envKey}=true to enable {service.name} configuration
                  </div>
                ) : (
                  <>
                          {service.id === 'hibp' && (
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              className="space-y-4"
                            >
                              <div className="rounded-lg bg-blue-50 p-4 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                                <div className="flex items-start gap-2">
                                  <Shield className="mt-0.5 h-4 w-4 shrink-0" />
                                  <div className="text-sm">
                                    <p className="font-medium">Password Breach Detection</p>
                                    <p className="mt-1">
                                      Check passwords against the Have I Been Pwned database of known breached passwords.
                                      Requires an API key from{' '}
                                      <a
                                        href="https://haveibeenpwned.com/API/Key"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="underline"
                                      >
                                        HIBP
                                      </a>.
                                    </p>
                                  </div>
                                </div>
                              </div>

                              <div className="space-y-2">
                                <div className="flex items-center justify-between">
                                  <label htmlFor="hibp-key" className="text-sm font-medium leading-none">
                                    API Key
                                  </label>
                                  {secretState.hibpApiKey && !config.hibp.apiKey && (
                                    <Badge variant="outline" className="text-xs">Set</Badge>
                                  )}
                                </div>
                                <Input
                                  id="hibp-key"
                                  type={showSecrets ? 'text' : 'password'}
                                  value={config.hibp.apiKey}
                                  onChange={(event) =>
                                    updateServiceConfig('hibp', 'apiKey', event.target.value)
                                  }
                                  placeholder={secretState.hibpApiKey && !config.hibp.apiKey ? '******** (set)' : 'Enter your HIBP API key'}
                                />
                              </div>

                              <div className="h-px bg-border" />

                              <div className="space-y-3">
                                <div className="flex items-center justify-between">
                                  <div className="space-y-0.5">
                                    <span className="text-sm font-medium leading-none">
                                      Check on Registration
                                    </span>
                                    <p className="text-xs text-muted-foreground">
                                      Check passwords when users sign up
                                    </p>
                                  </div>
                                  <Switch
                                    checked={config.hibp.checkOnRegistration}
                                    onCheckedChange={(checked) =>
                                      updateServiceConfig('hibp', 'checkOnRegistration', checked)
                                    }
                                  />
                                </div>

                                <div className="flex items-center justify-between">
                                  <div className="space-y-0.5">
                                    <span className="text-sm font-medium leading-none">
                                      Check on Password Change
                                    </span>
                                    <p className="text-xs text-muted-foreground">
                                      Check passwords when users change them
                                    </p>
                                  </div>
                                  <Switch
                                    checked={config.hibp.checkOnPasswordChange}
                                    onCheckedChange={(checked) =>
                                      updateServiceConfig('hibp', 'checkOnPasswordChange', checked)
                                    }
                                  />
                                </div>
                              </div>

                              <div className="space-y-2">
                                <label htmlFor="warning-threshold" className="text-sm font-medium leading-none">
                                  Warning Threshold
                                </label>
                                <div className="flex items-center gap-4">
                                  <input
                                    id="warning-threshold"
                                    type="range"
                                    min="1"
                                    max="10"
                                    step="1"
                                    value={config.hibp.warningThreshold}
                                    onChange={(event) =>
                                      updateServiceConfig(
                                        'hibp',
                                        'warningThreshold',
                                        Number.parseInt(event.target.value, 10)
                                      )
                                    }
                                    className="flex-1"
                                  />
                                  <Badge variant="secondary">
                                    {config.hibp.warningThreshold}+ breaches
                                  </Badge>
                                </div>
                                <p className="text-xs text-muted-foreground">
                                  Minimum number of breaches before warning the user
                                </p>
                              </div>
                            </motion.div>
                          )}

                          {service.id === 'maxmind' && (
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              className="space-y-4"
                            >
                              <div className="rounded-lg bg-blue-50 p-4 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                                <div className="flex items-start gap-2">
                                  <Globe className="mt-0.5 h-4 w-4 shrink-0" />
                                  <div className="text-sm">
                                    <p className="font-medium">IP Geolocation & Risk Scoring</p>
                                    <p className="mt-1">
                                      Detect suspicious login locations and assess IP risk scores using MaxMind&apos;s
                                      GeoIP and minFraud services.
                                    </p>
                                  </div>
                                </div>
                              </div>

                              <div className="grid gap-4 md:grid-cols-2">
                                <div className="space-y-2">
                                  <label htmlFor="maxmind-account" className="text-sm font-medium leading-none">
                                    Account ID
                                  </label>
                                  <Input
                                    id="maxmind-account"
                                    value={config.maxmind.accountId}
                                    onChange={(event) =>
                                      updateServiceConfig('maxmind', 'accountId', event.target.value)
                                    }
                                    placeholder="123456"
                                  />
                                </div>
                                <div className="space-y-2">
                                  <div className="flex items-center justify-between">
                                    <label htmlFor="maxmind-key" className="text-sm font-medium leading-none">
                                      License Key
                                    </label>
                                    {secretState.maxmindLicenseKey && !config.maxmind.licenseKey && (
                                      <Badge variant="outline" className="text-xs">Set</Badge>
                                    )}
                                  </div>
                                  <Input
                                    id="maxmind-key"
                                    type={showSecrets ? 'text' : 'password'}
                                    value={config.maxmind.licenseKey}
                                    onChange={(event) =>
                                      updateServiceConfig('maxmind', 'licenseKey', event.target.value)
                                    }
                                    placeholder={secretState.maxmindLicenseKey && !config.maxmind.licenseKey ? '******** (set)' : 'Enter license key'}
                                  />
                                </div>
                              </div>

                              <div className="h-px bg-border" />

                              <div className="space-y-2">
                                <span className="text-sm font-medium leading-none">
                                  Risk Score Threshold
                                </span>
                                <div className="flex items-center gap-4">
                                  <input
                                    type="range"
                                    min="0"
                                    max="100"
                                    step="5"
                                    value={config.maxmind.riskThreshold}
                                    onChange={(event) =>
                                      updateServiceConfig(
                                        'maxmind',
                                        'riskThreshold',
                                        Number.parseInt(event.target.value, 10)
                                      )
                                    }
                                    className="flex-1"
                                  />
                                  <Badge variant="secondary">{config.maxmind.riskThreshold}%</Badge>
                                </div>
                                <p className="text-xs text-muted-foreground">
                                  Block logins from IPs with risk scores above this threshold
                                </p>
                              </div>

                              <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                  <span className="text-sm font-medium leading-none">
                                    Block Anonymous Proxies
                                  </span>
                                  <p className="text-xs text-muted-foreground">
                                    Block VPNs, Tor exit nodes, and anonymous proxies
                                  </p>
                                </div>
                                <Switch
                                  checked={config.maxmind.blockAnonymousProxies}
                                  onCheckedChange={(checked) =>
                                    updateServiceConfig('maxmind', 'blockAnonymousProxies', checked)
                                  }
                                />
                              </div>
                            </motion.div>
                          )}

                          <div className="flex items-center gap-2 pt-2">
                            <Switch
                              id={`show-secrets-${service.id}`}
                              checked={showSecrets}
                              onCheckedChange={setShowSecrets}
                            />
                            <label htmlFor={`show-secrets-${service.id}`} className="text-sm font-medium leading-none">
                              Show Secrets
                            </label>
                          </div>

                          <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            <CheckCircle className="h-4 w-4" />
                            <a
                              href={service.docsUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="hover:underline"
                            >
                              View {service.name} documentation
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
              Saving...
            </>
          ) : (
            'Save Configuration'
          )}
        </Button>
      </div>
    </div>
  )
}
