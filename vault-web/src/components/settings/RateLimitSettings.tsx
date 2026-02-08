import { useState } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import {
  Shield,
  Zap,
  Globe,
  User,
  AlertTriangle,
  Info,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface RateLimitConfig {
  enabled: boolean
  defaultLimits: {
    requestsPerMinute: number
    requestsPerHour: number
    requestsPerDay: number
  }
  authEndpoints: {
    loginAttemptsPerMinute: number
    mfaAttemptsPerMinute: number
    passwordResetPerHour: number
  }
  apiEndpoints: {
    burstLimit: number
    sustainedLimit: number
    windowSeconds: number
  }
  ipBlocking: {
    enabled: boolean
    failedAttemptsThreshold: number
    blockDurationMinutes: number
  }
}

const defaultConfig: RateLimitConfig = {
  enabled: true,
  defaultLimits: {
    requestsPerMinute: 60,
    requestsPerHour: 1000,
    requestsPerDay: 10000,
  },
  authEndpoints: {
    loginAttemptsPerMinute: 5,
    mfaAttemptsPerMinute: 3,
    passwordResetPerHour: 3,
  },
  apiEndpoints: {
    burstLimit: 100,
    sustainedLimit: 1000,
    windowSeconds: 60,
  },
  ipBlocking: {
    enabled: true,
    failedAttemptsThreshold: 10,
    blockDurationMinutes: 30,
  },
}

const presets = [
  { name: 'Strict', description: 'High security, lower limits', config: { ...defaultConfig, defaultLimits: { requestsPerMinute: 30, requestsPerHour: 500, requestsPerDay: 5000 } } },
  { name: 'Standard', description: 'Balanced security and usability', config: defaultConfig },
  { name: 'Relaxed', description: 'Higher limits for high-traffic apps', config: { ...defaultConfig, defaultLimits: { requestsPerMinute: 120, requestsPerHour: 5000, requestsPerDay: 50000 } } },
]

export function RateLimitSettings() {
  const [config, setConfig] = useState<RateLimitConfig>(defaultConfig)
  const [isLoading, setIsLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'general' | 'auth' | 'api' | 'blocking'>('general')

  const handleSave = async () => {
    setIsLoading(true)
    try {
      // TODO: Implement save API call
      await new Promise((resolve) => setTimeout(resolve, 1000))
    } finally {
      setIsLoading(false)
    }
  }

  const applyPreset = (preset: typeof presets[0]) => {
    setConfig(preset.config)
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

  const tabs = [
    { id: 'general', label: 'General', icon: Globe },
    { id: 'auth', label: 'Authentication', icon: User },
    { id: 'api', label: 'API Endpoints', icon: Zap },
    { id: 'blocking', label: 'IP Blocking', icon: Shield },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Rate Limiting</h2>
          <p className="text-muted-foreground">
            Configure rate limits to protect your API from abuse and ensure fair usage
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

      {/* Presets */}
      <div className="grid gap-4 md:grid-cols-3">
        {presets.map((preset) => (
          <Card
            key={preset.name}
            className={cn(
              'cursor-pointer transition-colors hover:border-primary',
            )}
            onClick={() => applyPreset(preset)}
          >
            <CardContent className="p-4">
              <div className="font-semibold">{preset.name}</div>
              <p className="text-sm text-muted-foreground">{preset.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 rounded-lg bg-muted p-1">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as typeof activeTab)}
            className={cn(
              'flex flex-1 items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors',
              activeTab === tab.id
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <tab.icon className="h-4 w-4" />
            <span className="hidden sm:inline">{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2 }}
      >
        {activeTab === 'general' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5" />
                Default Rate Limits
              </CardTitle>
              <CardDescription>
                General rate limits applied to all API requests
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium">Requests Per Minute</label>
                    <Badge variant="secondary">{config.defaultLimits.requestsPerMinute}</Badge>
                  </div>
                  <input
                    type="range"
                    className="w-full"
                    value={config.defaultLimits.requestsPerMinute}
                    onChange={(e) =>
                      updateConfig('defaultLimits.requestsPerMinute', Number(e.target.value))
                    }
                    min={10}
                    max={300}
                    step={10}
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium">Requests Per Hour</label>
                    <Badge variant="secondary">{config.defaultLimits.requestsPerHour}</Badge>
                  </div>
                  <input
                    type="range"
                    className="w-full"
                    value={config.defaultLimits.requestsPerHour}
                    onChange={(e) =>
                      updateConfig('defaultLimits.requestsPerHour', Number(e.target.value))
                    }
                    min={100}
                    max={10000}
                    step={100}
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium">Requests Per Day</label>
                    <Badge variant="secondary">{config.defaultLimits.requestsPerDay.toLocaleString()}</Badge>
                  </div>
                  <input
                    type="range"
                    className="w-full"
                    value={config.defaultLimits.requestsPerDay}
                    onChange={(e) =>
                      updateConfig('defaultLimits.requestsPerDay', Number(e.target.value))
                    }
                    min={1000}
                    max={100000}
                    step={1000}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {activeTab === 'auth' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <User className="h-5 w-5" />
                Authentication Endpoints
              </CardTitle>
              <CardDescription>
                Stricter limits for authentication-related endpoints
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium">Login Attempts Per Minute</label>
                    <Badge variant="secondary">{config.authEndpoints.loginAttemptsPerMinute}</Badge>
                  </div>
                  <input
                    type="range"
                    className="w-full"
                    value={config.authEndpoints.loginAttemptsPerMinute}
                    onChange={(e) =>
                      updateConfig('authEndpoints.loginAttemptsPerMinute', Number(e.target.value))
                    }
                    min={1}
                    max={20}
                    step={1}
                  />
                  <p className="text-xs text-muted-foreground">
                    Maximum login attempts allowed per IP address per minute
                  </p>
                </div>

                <div className="h-px bg-border" />

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium">MFA Attempts Per Minute</label>
                    <Badge variant="secondary">{config.authEndpoints.mfaAttemptsPerMinute}</Badge>
                  </div>
                  <input
                    type="range"
                    className="w-full"
                    value={config.authEndpoints.mfaAttemptsPerMinute}
                    onChange={(e) =>
                      updateConfig('authEndpoints.mfaAttemptsPerMinute', Number(e.target.value))
                    }
                    min={1}
                    max={10}
                    step={1}
                  />
                </div>

                <div className="h-px bg-border" />

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium">Password Reset Per Hour</label>
                    <Badge variant="secondary">{config.authEndpoints.passwordResetPerHour}</Badge>
                  </div>
                  <input
                    type="range"
                    className="w-full"
                    value={config.authEndpoints.passwordResetPerHour}
                    onChange={(e) =>
                      updateConfig('authEndpoints.passwordResetPerHour', Number(e.target.value))
                    }
                    min={1}
                    max={10}
                    step={1}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {activeTab === 'api' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5" />
                API Endpoint Limits
              </CardTitle>
              <CardDescription>
                Token bucket algorithm configuration for burst and sustained traffic
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="rounded-lg bg-blue-50 p-4 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                <div className="flex items-start gap-2">
                  <Info className="mt-0.5 h-4 w-4" />
                  <div className="text-sm">
                    <p className="font-medium">Token Bucket Algorithm</p>
                    <p className="mt-1">
                      Burst limit allows short spikes of traffic, while sustained limit controls
                      long-term usage. The window determines how quickly tokens refill.
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium">Burst Limit</label>
                    <Badge variant="secondary">{config.apiEndpoints.burstLimit}</Badge>
                  </div>
                  <input
                    type="range"
                    className="w-full"
                    value={config.apiEndpoints.burstLimit}
                    onChange={(e) =>
                      updateConfig('apiEndpoints.burstLimit', Number(e.target.value))
                    }
                    min={10}
                    max={500}
                    step={10}
                  />
                  <p className="text-xs text-muted-foreground">
                    Maximum requests allowed in a short burst
                  </p>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium">Sustained Limit</label>
                    <Badge variant="secondary">{config.apiEndpoints.sustainedLimit}</Badge>
                  </div>
                  <input
                    type="range"
                    className="w-full"
                    value={config.apiEndpoints.sustainedLimit}
                    onChange={(e) =>
                      updateConfig('apiEndpoints.sustainedLimit', Number(e.target.value))
                    }
                    min={100}
                    max={10000}
                    step={100}
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-sm font-medium">Window (seconds)</label>
                    <Badge variant="secondary">{config.apiEndpoints.windowSeconds}s</Badge>
                  </div>
                  <input
                    type="range"
                    className="w-full"
                    value={config.apiEndpoints.windowSeconds}
                    onChange={(e) =>
                      updateConfig('apiEndpoints.windowSeconds', Number(e.target.value))
                    }
                    min={10}
                    max={300}
                    step={10}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {activeTab === 'blocking' && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                IP Blocking
              </CardTitle>
              <CardDescription>
                Automatically block IP addresses that exceed rate limits
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between rounded-lg border p-4">
                <div className="space-y-0.5">
                  <label className="text-base font-medium">Enable IP Blocking</label>
                  <p className="text-sm text-muted-foreground">
                    Automatically block IPs that exceed the failed attempt threshold
                  </p>
                </div>
                <Switch
                  checked={config.ipBlocking.enabled}
                  onCheckedChange={(checked) => updateConfig('ipBlocking.enabled', checked)}
                />
              </div>

              {config.ipBlocking.enabled && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className="space-y-4"
                >
                  <div className="rounded-lg bg-amber-50 p-4 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400">
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="mt-0.5 h-4 w-4" />
                      <div className="text-sm">
                        IP blocking helps prevent brute force attacks but may affect legitimate
                        users behind shared IPs (corporate networks, VPNs, etc.).
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label className="text-sm font-medium">Failed Attempts Threshold</label>
                      <Badge variant="secondary">{config.ipBlocking.failedAttemptsThreshold}</Badge>
                    </div>
                    <input
                      type="range"
                      className="w-full"
                      value={config.ipBlocking.failedAttemptsThreshold}
                      onChange={(e) =>
                        updateConfig('ipBlocking.failedAttemptsThreshold', Number(e.target.value))
                      }
                      min={5}
                      max={50}
                      step={5}
                    />
                    <p className="text-xs text-muted-foreground">
                      Number of failed attempts before blocking an IP
                    </p>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label className="text-sm font-medium">Block Duration (minutes)</label>
                      <Badge variant="secondary">{config.ipBlocking.blockDurationMinutes}m</Badge>
                    </div>
                    <input
                      type="range"
                      className="w-full"
                      value={config.ipBlocking.blockDurationMinutes}
                      onChange={(e) =>
                        updateConfig('ipBlocking.blockDurationMinutes', Number(e.target.value))
                      }
                      min={5}
                      max={1440}
                      step={5}
                    />
                  </div>
                </motion.div>
              )}
            </CardContent>
          </Card>
        )}
      </motion.div>

      <div className="flex items-center justify-end gap-4">
        <Button variant="outline" onClick={() => setConfig(defaultConfig)}>
          Reset to Defaults
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
