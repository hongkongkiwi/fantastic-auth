import { useState, type ElementType } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import {
  Github,
  Chrome,
  Apple,
  Building2,
  CheckCircle,
  Lock,
  Globe,
  Copy,
} from 'lucide-react'
import { env } from '@/env/client'
import { cn } from '@/lib/utils'

interface OAuthProviderConfig {
  id: string
  enabled: boolean
  clientId: string
  clientSecret: string
  scopes: string
  allowedDomains: string
}

interface OAuthProvidersState {
  google: OAuthProviderConfig
  github: OAuthProviderConfig
  microsoft: OAuthProviderConfig
  apple: OAuthProviderConfig
}

const defaultProviderConfig: Omit<OAuthProviderConfig, 'id'> = {
  enabled: false,
  clientId: '',
  clientSecret: '',
  scopes: '',
  allowedDomains: '',
}

const defaultConfig: OAuthProvidersState = {
  google: { id: 'google', ...defaultProviderConfig, scopes: 'openid email profile' },
  github: { id: 'github', ...defaultProviderConfig, scopes: 'read:user user:email' },
  microsoft: { id: 'microsoft', ...defaultProviderConfig, scopes: 'openid email profile' },
  apple: { id: 'apple', ...defaultProviderConfig, scopes: 'name email' },
}

interface OAuthProviderDef {
  id: keyof OAuthProvidersState
  name: string
  description: string
  icon: ElementType
  envKey: keyof typeof env
  defaultScopes: string
  docsUrl: string
}

const oauthProviders: OAuthProviderDef[] = [
  {
    id: 'google',
    name: 'Google',
    description: 'Sign in with Google accounts',
    icon: Chrome,
    envKey: 'VITE_OAUTH_GOOGLE_ENABLED',
    defaultScopes: 'openid email profile',
    docsUrl: 'https://developers.google.com/identity/protocols/oauth2',
  },
  {
    id: 'github',
    name: 'GitHub',
    description: 'Sign in with GitHub accounts',
    icon: Github,
    envKey: 'VITE_OAUTH_GITHUB_ENABLED',
    defaultScopes: 'read:user user:email',
    docsUrl: 'https://docs.github.com/en/developers/apps/building-oauth-apps',
  },
  {
    id: 'microsoft',
    name: 'Microsoft',
    description: 'Sign in with Microsoft/Azure AD accounts',
    icon: Building2,
    envKey: 'VITE_OAUTH_MICROSOFT_ENABLED',
    defaultScopes: 'openid email profile',
    docsUrl: 'https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow',
  },
  {
    id: 'apple',
    name: 'Apple',
    description: 'Sign in with Apple ID',
    icon: Apple,
    envKey: 'VITE_OAUTH_APPLE_ENABLED',
    defaultScopes: 'name email',
    docsUrl: 'https://developer.apple.com/documentation/sign_in_with_apple',
  },
]

function isProviderEnabled(provider: OAuthProviderDef): boolean {
  return env[provider.envKey] === 'true'
}

export function OAuthProviderSettings() {
  const [configs, setConfigs] = useState<OAuthProvidersState>(defaultConfig)
  const [isLoading, setIsLoading] = useState(false)
  const [showSecrets, setShowSecrets] = useState(false)
  const [activeProvider, setActiveProvider] = useState<keyof OAuthProvidersState | null>(null)

  const hasAnyProviderEnabled = oauthProviders.some(isProviderEnabled)

  const updateProviderConfig = (
    providerId: keyof OAuthProvidersState,
    key: keyof OAuthProviderConfig,
    value: string | boolean
  ) => {
    setConfigs((prev) => ({
      ...prev,
      [providerId]: { ...prev[providerId], [key]: value },
    }))
  }

  const handleSave = async () => {
    setIsLoading(true)
    try {
      await new Promise((resolve) => setTimeout(resolve, 1000))
    } finally {
      setIsLoading(false)
    }
  }

  const copyRedirectUri = () => {
    navigator.clipboard.writeText(`${window.location.origin}/api/auth/callback`)
  }

  const activeProviderDef = activeProvider ? oauthProviders.find(p => p.id === activeProvider) : null
  const isActiveProviderEnabled = activeProviderDef ? isProviderEnabled(activeProviderDef) : false

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">OAuth Providers</h2>
        <p className="text-muted-foreground">
          Configure social login providers for your application
        </p>
      </div>

      {!hasAnyProviderEnabled && (
        <div className="rounded-lg bg-muted p-4 text-muted-foreground">
          <p className="text-sm">
            No OAuth providers are enabled. Set the corresponding environment variables to enable social login.
          </p>
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        {oauthProviders.map((provider) => {
          const isEnabled = isProviderEnabled(provider)
          const config = configs[provider.id]
          const Icon = provider.icon
          const isActive = activeProvider === provider.id

          return (
            <Card
              key={provider.id}
              className={cn(
                'relative cursor-pointer transition-colors',
                isEnabled
                  ? isActive
                    ? 'border-primary bg-primary/5'
                    : 'hover:border-primary/50'
                  : 'cursor-not-allowed border-muted bg-muted/30 opacity-60'
              )}
              onClick={() => isEnabled && setActiveProvider(provider.id)}
            >
              <CardContent className="p-4">
                {!isEnabled && (
                  <div className="absolute right-3 top-3">
                    <Lock className="h-4 w-4 text-muted-foreground" />
                  </div>
                )}
                <div className="flex items-start gap-3">
                  <div
                    className={cn(
                      'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
                      isActive && isEnabled
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted'
                    )}
                  >
                    <Icon className="h-5 w-5" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold">{provider.name}</span>
                      {config.enabled && isEnabled && (
                        <Badge variant="default" className="text-xs">Active</Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">{provider.description}</p>
                    {isEnabled && config.clientId && (
                      <p className="mt-1 text-xs text-muted-foreground">
                        Client ID: {config.clientId.slice(0, 8)}…
                      </p>
                    )}
                    {!isEnabled && (
                      <p className="mt-2 text-xs text-muted-foreground">
                        Set {provider.envKey}=true to enable
                      </p>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {activeProvider && isActiveProviderEnabled && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {(() => {
                  const Icon = activeProviderDef?.icon || Globe
                  return <Icon className="h-5 w-5" />
                })()}
                {activeProviderDef?.name} Configuration
              </CardTitle>
              <CardDescription>
                Configure your {activeProviderDef?.name} OAuth application credentials
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="rounded-lg bg-blue-50 p-4 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400">
                <div className="flex items-start gap-2">
                  <Globe className="mt-0.5 h-4 w-4 shrink-0" />
                  <div className="text-sm">
                    <p className="font-medium">Redirect URI</p>
                    <p className="mt-1">Add this redirect URI to your {activeProviderDef?.name} OAuth app:</p>
                    <div className="mt-2 flex items-center gap-2">
                      <code className="flex-1 rounded bg-blue-100 px-2 py-1 text-xs dark:bg-blue-900/40">
                        {typeof window !== 'undefined' ? `${window.location.origin}/api/auth/callback` : ''}
                      </code>
                      <Button
                        variant="outline"
                        size="icon"
                        className="h-7 w-7"
                        onClick={copyRedirectUri}
                        aria-label="Copy redirect URI"
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between rounded-lg border p-4">
                <div className="space-y-0.5">
                  <span className="text-base font-medium">
                    Enable {activeProviderDef?.name} Login
                  </span>
                  <p className="text-sm text-muted-foreground">
                    Allow users to sign in with {activeProviderDef?.name}
                  </p>
                </div>
                <Switch
                  checked={configs[activeProvider].enabled}
                  onCheckedChange={(checked) =>
                    updateProviderConfig(activeProvider, 'enabled', checked)
                  }
                />
              </div>

              <div className="h-px bg-border" />

              <div className="space-y-4">
                <div className="space-y-2">
                  <label htmlFor="client-id" className="text-sm font-medium leading-none">
                    Client ID
                  </label>
                  <Input
                    id="client-id"
                    value={configs[activeProvider].clientId}
                    onChange={(e) => updateProviderConfig(activeProvider, 'clientId', e.target.value)}
                    placeholder={`Enter your ${activeProviderDef?.name} Client ID`}
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="client-secret" className="text-sm font-medium leading-none">
                    Client Secret
                  </label>
                  <Input
                    id="client-secret"
                    type={showSecrets ? 'text' : 'password'}
                    value={configs[activeProvider].clientSecret}
                    onChange={(e) => updateProviderConfig(activeProvider, 'clientSecret', e.target.value)}
                    placeholder={`Enter your ${activeProviderDef?.name} Client Secret`}
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="scopes" className="text-sm font-medium leading-none">
                    Scopes
                  </label>
                  <Input
                    id="scopes"
                    value={configs[activeProvider].scopes}
                    onChange={(e) => updateProviderConfig(activeProvider, 'scopes', e.target.value)}
                    placeholder={activeProviderDef?.defaultScopes}
                  />
                  <p className="text-xs text-muted-foreground">
                    Space-separated list of OAuth scopes
                  </p>
                </div>

                <div className="space-y-2">
                  <label htmlFor="allowed-domains" className="text-sm font-medium leading-none">
                    Allowed Domains (Optional)
                  </label>
                  <Input
                    id="allowed-domains"
                    value={configs[activeProvider].allowedDomains}
                    onChange={(e) => updateProviderConfig(activeProvider, 'allowedDomains', e.target.value)}
                    placeholder="example.com, company.org"
                  />
                  <p className="text-xs text-muted-foreground">
                    Restrict login to specific email domains (comma-separated)
                  </p>
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
              </div>

              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <CheckCircle className="h-4 w-4" />
                <a
                  href={activeProviderDef?.docsUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:underline"
                >
                  View {activeProviderDef?.name} OAuth documentation
                </a>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {activeProvider && !isActiveProviderEnabled && (
        <div className="rounded-lg bg-amber-50 p-4 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400">
          <p className="text-sm font-medium">
            This provider is disabled. Set {activeProviderDef?.envKey}=true to enable.
          </p>
        </div>
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
