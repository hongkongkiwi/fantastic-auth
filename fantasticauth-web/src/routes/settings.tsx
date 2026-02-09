import { createFileRoute } from '@tanstack/react-router'
import { useState, useMemo } from 'react'
import { motion, useReducedMotion, AnimatePresence } from 'framer-motion'
import {
  Settings,
  Shield,
  Bell,
  Key,
  Mail,
  CreditCard,
  Lock,
  Webhook,
  Search,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  X,
  BarChart3,
  Server,
} from 'lucide-react'
import { PageHeader } from '../components/layout/Layout'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Switch } from '../components/ui/Switch'
import { Input } from '../components/ui/Input'
import { toast } from '../components/ui/Toaster'
import { Slider } from '../components/ui/Slider'
import { useQuery } from '@tanstack/react-query'
import { getUiConfig } from '../server/internal-api'

export const Route = createFileRoute('/settings')({
  component: SettingsPage,
})

// Settings categories with icons and descriptions
const settingsCategories = [
  {
    id: 'general',
    title: 'General',
    description: 'Basic platform configuration',
    icon: Settings,
    color: 'blue',
    settings: [
      { id: 'siteName', label: 'Site Name', type: 'input', value: 'Vault Admin' },
      { id: 'siteUrl', label: 'Site URL', type: 'input', value: 'https://vault.example.com' },
      { id: 'timezone', label: 'Default Timezone', type: 'select', value: 'UTC' },
      { id: 'language', label: 'Default Language', type: 'select', value: 'en' },
    ],
  },
  {
    id: 'authentication',
    title: 'Authentication',
    description: 'Login methods and security',
    icon: Shield,
    color: 'green',
    href: '/settings/security',
    settings: [
      { id: 'mfa', label: 'Require MFA', type: 'toggle', value: false },
      { id: 'magicLink', label: 'Enable Magic Link', type: 'toggle', value: true },
      { id: 'oauth', label: 'Social Login', type: 'toggle', value: true },
      { id: 'sessionDuration', label: 'Session Duration (hours)', type: 'slider', value: 24, min: 1, max: 168 },
    ],
  },
  {
    id: 'email',
    title: 'Email',
    description: 'Email provider and templates',
    icon: Mail,
    color: 'amber',
    settings: [
      { id: 'provider', label: 'Email Provider', type: 'select', value: 'smtp' },
      { id: 'fromEmail', label: 'From Email', type: 'input', value: 'noreply@vault.example.com' },
      { id: 'templates', label: 'Custom Templates', type: 'toggle', value: false },
    ],
  },
  {
    id: 'billing',
    title: 'Billing',
    description: 'Payment and subscription settings',
    icon: CreditCard,
    color: 'purple',
    settings: [
      { id: 'enabled', label: 'Enable Billing', type: 'toggle', value: true },
      { id: 'provider', label: 'Payment Provider', type: 'select', value: 'stripe' },
      { id: 'trialDays', label: 'Trial Period (days)', type: 'slider', value: 14, min: 0, max: 30 },
    ],
  },
  {
    id: 'notifications',
    title: 'Notifications',
    description: 'Alert preferences and channels',
    icon: Bell,
    color: 'rose',
    settings: [
      { id: 'emailAlerts', label: 'Email Alerts', type: 'toggle', value: true },
      { id: 'slackAlerts', label: 'Slack Integration', type: 'toggle', value: false },
      { id: 'webhookAlerts', label: 'Webhook Alerts', type: 'toggle', value: false },
    ],
  },
  {
    id: 'api',
    title: 'API & Webhooks',
    description: 'API keys and webhook endpoints',
    icon: Webhook,
    color: 'indigo',
    href: '/settings/webhooks',
    settings: [
      { id: 'rateLimit', label: 'Rate Limit (requests/min)', type: 'slider', value: 60, min: 10, max: 1000 },
      { id: 'cors', label: 'CORS Origins', type: 'input', value: '*' },
      { id: 'apiVersion', label: 'API Version', type: 'select', value: 'v1' },
    ],
  },
  {
    id: 'apiKeys',
    title: 'API Keys',
    description: 'Manage programmatic access keys',
    icon: Key,
    color: 'slate',
    href: '/settings/api-keys',
    settings: [
      { id: 'apiKeyRotation', label: 'Key Rotation (days)', type: 'slider', value: 90, min: 30, max: 365 },
      { id: 'apiKeyLimit', label: 'Max Keys per Org', type: 'slider', value: 10, min: 1, max: 50 },
    ],
  },
  {
    id: 'sso',
    title: 'SSO & Integrations',
    description: 'Configure SAML and OAuth providers',
    icon: Shield,
    color: 'emerald',
    href: '/settings/sso',
    settings: [
      { id: 'ssoRequired', label: 'Require SSO', type: 'toggle', value: false },
      { id: 'domainAllowlist', label: 'Domain Allowlist', type: 'input', value: 'example.com' },
    ],
  },
  {
    id: 'security',
    title: 'Security',
    description: 'Advanced security settings',
    icon: Lock,
    color: 'red',
    settings: [
      { id: 'hibp', label: 'Check Breached Passwords', type: 'toggle', value: true },
      { id: 'geoip', label: 'GeoIP Blocking', type: 'toggle', value: false },
      { id: 'captcha', label: 'CAPTCHA Protection', type: 'toggle', value: true },
      { id: 'auditRetention', label: 'Audit Log Retention (days)', type: 'slider', value: 90, min: 30, max: 365 },
    ],
  },
  {
    id: 'analytics',
    title: 'Analytics',
    description: 'Usage tracking and insights',
    icon: BarChart3,
    color: 'cyan',
    settings: [
      { id: 'enabled', label: 'Enable Analytics', type: 'toggle', value: true },
      { id: 'provider', label: 'Analytics Provider', type: 'select', value: 'posthog' },
      { id: 'anonymize', label: 'Anonymize IPs', type: 'toggle', value: true },
    ],
  },
  {
    id: 'system',
    title: 'System',
    description: 'Maintenance and advanced options',
    icon: Server,
    color: 'slate',
    settings: [
      { id: 'maintenance', label: 'Maintenance Mode', type: 'toggle', value: false },
      { id: 'debug', label: 'Debug Mode', type: 'toggle', value: false },
      { id: 'backups', label: 'Auto Backups', type: 'toggle', value: true },
    ],
  },
]

function SettingsPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [activeCategory, setActiveCategory] = useState<string | null>(null)
  const [settings, setSettings] = useState<Record<string, unknown>>({
    // General
    siteName: 'Vault Admin',
    siteUrl: 'https://vault.example.com',
    timezone: 'UTC',
    language: 'en',
    darkMode: false,
    // Auth
    mfa: false,
    magicLink: true,
    oauth: true,
    sessionDuration: 24,
    // Email
    emailProvider: 'smtp',
    fromEmail: 'noreply@vault.example.com',
    templates: false,
    // Billing
    billingEnabled: true,
    paymentProvider: 'stripe',
    trialDays: 14,
    // Notifications
    emailAlerts: true,
    slackAlerts: false,
    webhookAlerts: false,
    // API
    rateLimit: 60,
    cors: '*',
    apiVersion: 'v1',
    // Security
    hibp: true,
    geoip: false,
    captcha: true,
    auditRetention: 90,
    // Analytics
    analyticsEnabled: true,
    analyticsProvider: 'posthog',
    anonymize: true,
    // System
    maintenance: false,
    debug: false,
    backups: true,
  })
  const [hasChanges, setHasChanges] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  
  const { data: uiConfig } = useQuery({
    queryKey: ['ui-config'],
    queryFn: () => getUiConfig(),
  })
  
  const prefersReducedMotion = useReducedMotion()
  
  const internalApiBaseUrl = uiConfig?.internalApiBaseUrl || 'http://localhost:3000/api/v1/internal'
  const hasApiKey = uiConfig?.hasApiKey ?? false

  // Filter categories based on search
  const filteredCategories = useMemo(() => {
    if (!searchQuery.trim()) return settingsCategories
    
    const query = searchQuery.toLowerCase()
    return settingsCategories.filter((category) => {
      // Check category title/description
      if (category.title.toLowerCase().includes(query)) return true
      if (category.description.toLowerCase().includes(query)) return true
      
      // Check settings within category
      return category.settings.some((setting) =>
        setting.label.toLowerCase().includes(query)
      )
    })
  }, [searchQuery])

  const updateSetting = (key: string, value: unknown) => {
    setSettings((prev) => ({ ...prev, [key]: value }))
    setHasChanges(true)
  }

  const handleSave = async () => {
    setIsSaving(true)
    try {
      // Simulate API call
      await new Promise((resolve) => setTimeout(resolve, 1000))
      toast.success('Settings saved successfully')
      setHasChanges(false)
    } catch {
      toast.error('Failed to save settings')
    } finally {
      setIsSaving(false)
    }
  }

  const renderSetting = (setting: typeof settingsCategories[0]['settings'][0]) => {
    const value = settings[setting.id]

    switch (setting.type) {
      case 'toggle':
        return (
          <Switch
            checked={value as boolean}
            onCheckedChange={(checked) => updateSetting(setting.id, checked)}
          />
        )
      case 'input':
        return (
          <Input
            value={value as string}
            onChange={(e) => updateSetting(setting.id, e.target.value)}
            className="max-w-xs"
          />
        )
      case 'select':
        return (
          <select
            value={value as string}
            onChange={(e) => updateSetting(setting.id, e.target.value)}
            className="rounded-md border border-input bg-background px-3 py-2 text-sm max-w-xs"
          >
            <option value="en">English</option>
            <option value="es">Spanish</option>
            <option value="fr">French</option>
            <option value="de">German</option>
          </select>
        )
      case 'slider':
        return (
          <div className="w-48">
            <Slider
              value={[value as number]}
              onValueChange={([v]) => updateSetting(setting.id, v)}
              min={setting.min}
              max={setting.max}
              showValue
            />
          </div>
        )
      default:
        return null
    }
  }

  const activeCategoryData = settingsCategories.find((c) => c.id === activeCategory)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Configure your platform settings"
        breadcrumbs={[{ label: 'Settings' }]}
      />

      {/* Search Bar */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search settings..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-10"
        />
        {searchQuery && (
          <button
            onClick={() => setSearchQuery('')}
            className="absolute right-3 top-1/2 -translate-y-1/2"
          >
            <X className="h-4 w-4 text-muted-foreground" />
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Categories Sidebar */}
        <div className="lg:col-span-1 space-y-2">
          <h3 className="text-sm font-medium text-muted-foreground mb-3">Categories</h3>
          {filteredCategories.map((category) => {
            const Icon = category.icon
            const isActive = activeCategory === category.id
            
            return (
              <button
                key={category.id}
                onClick={() => setActiveCategory(category.id)}
                className={cn(
                  'w-full flex items-center gap-3 p-3 rounded-lg text-left transition-colors',
                  isActive
                    ? 'bg-primary/10 text-primary'
                    : 'hover:bg-muted'
                )}
              >
                <div
                  className={cn(
                    'p-2 rounded-lg',
                    isActive ? 'bg-primary/20' : 'bg-muted'
                  )}
                >
                  <Icon className="h-4 w-4" />
                </div>
                <div className="flex-1">
                  <p className="font-medium text-sm">{category.title}</p>
                  <p className="text-xs text-muted-foreground line-clamp-1">
                    {category.description}
                  </p>
                </div>
                {isActive && <ChevronRight className="h-4 w-4" />}
              </button>
            )
          })}
        </div>

        {/* Settings Content */}
        <div className="lg:col-span-3 space-y-6">
          {activeCategoryData ? (
            <motion.div
              initial={prefersReducedMotion ? false : { opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <Card>
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg bg-${activeCategoryData.color}-100`}>
                      <activeCategoryData.icon className={`h-5 w-5 text-${activeCategoryData.color}-600`} />
                    </div>
                    <div>
                      <CardTitle>{activeCategoryData.title}</CardTitle>
                      <CardDescription>{activeCategoryData.description}</CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-6">
                  {activeCategoryData.settings.map((setting) => (
                    <div
                      key={setting.id}
                      className="flex items-center justify-between py-3 border-b last:border-0"
                    >
                      <div>
                        <p className="font-medium">{setting.label}</p>
                        {setting.type === 'slider' && (
                          <p className="text-sm text-muted-foreground">
                            Current: {settings[setting.id] as number}
                            {setting.id.includes('Duration') && ' hours'}
                            {setting.id.includes('Retention') && ' days'}
                            {setting.id.includes('Limit') && ' requests/min'}
                            {setting.id.includes('trial') && ' days'}
                          </p>
                        )}
                      </div>
                      {renderSetting(setting)}
                    </div>
                  ))}
                </CardContent>
              </Card>
            </motion.div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {filteredCategories.map((category, index) => {
                const Icon = category.icon
                return (
                  <motion.div
                    key={category.id}
                    initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.05 }}
                  >
                    <Card
                      className="cursor-pointer hover:border-primary/50 transition-colors"
                      onClick={() => setActiveCategory(category.id)}
                    >
                      <CardContent className="p-6">
                        <div className="flex items-start gap-4">
                          <div className={`p-3 rounded-lg bg-${category.color}-100`}>
                            <Icon className={`h-5 w-5 text-${category.color}-600`} />
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <h3 className="font-semibold">{category.title}</h3>
                              {category.href && (
                                <Badge variant="outline" className="text-xs">Page</Badge>
                              )}
                            </div>
                            <p className="text-sm text-muted-foreground mt-1">
                              {category.description}
                            </p>
                            <p className="text-xs text-muted-foreground mt-2">
                              {category.settings.length} settings
                            </p>
                          </div>
                          <ChevronRight className="h-5 w-5 text-muted-foreground" />
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                )
              })}
            </div>
          )}

          {/* API Configuration */}
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.3 }}
          >
            <Card>
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-primary/10">
                    <Key className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle>API Configuration</CardTitle>
                    <CardDescription>Manage internal API settings</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-4 rounded-lg bg-muted">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">Internal API URL</span>
                    <Badge variant="outline">Configured</Badge>
                  </div>
                  <code className="text-sm text-muted-foreground">{internalApiBaseUrl}</code>
                </div>
                <div className="flex items-center justify-between p-4 rounded-lg bg-muted">
                  <div>
                    <span className="text-sm font-medium">API Key Status</span>
                    <p className="text-sm text-muted-foreground">
                      {hasApiKey ? 'Key configured' : 'No key set'}
                    </p>
                  </div>
                  <Badge variant={hasApiKey ? 'success' : 'warning'}>
                    {hasApiKey ? 'Active' : 'Missing'}
                  </Badge>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          {/* Danger Zone */}
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.4 }}
          >
            <Card className="border-destructive/20">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-destructive/10">
                    <AlertTriangle className="h-5 w-5 text-destructive" />
                  </div>
                  <div>
                    <CardTitle className="text-destructive">Danger Zone</CardTitle>
                    <CardDescription>Destructive actions that cannot be undone</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between p-4 rounded-lg border border-destructive/20 bg-destructive/5">
                  <div>
                    <p className="font-medium text-destructive">Reset Platform</p>
                    <p className="text-sm text-muted-foreground">
                      Delete all tenant data and reset to factory defaults
                    </p>
                  </div>
                  <Button variant="destructive">Reset</Button>
                </div>
                <div className="flex items-center justify-between p-4 rounded-lg border border-destructive/20 bg-destructive/5">
                  <div>
                    <p className="font-medium text-destructive">Clear Cache</p>
                    <p className="text-sm text-muted-foreground">
                      Clear all cached data and sessions
                    </p>
                  </div>
                  <Button variant="outline" className="border-destructive/50 text-destructive hover:bg-destructive/10">
                    Clear
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>

      {/* Floating Save Bar */}
      <AnimatePresence>
        {hasChanges && (
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 50 }}
            className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50"
          >
            <div className="flex items-center gap-4 px-6 py-3 bg-background border rounded-full shadow-lg">
              <span className="text-sm font-medium">You have unsaved changes</span>
              <div className="flex items-center gap-2">
                <Button variant="ghost" size="sm" onClick={() => setHasChanges(false)}>
                  Discard
                </Button>
                <Button size="sm" onClick={handleSave} isLoading={isSaving}>
                  <CheckCircle className="mr-2 h-4 w-4" />
                  Save Changes
                </Button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// Helper for class merging
function cn(...classes: (string | boolean | undefined)[]) {
  return classes.filter(Boolean).join(' ')
}
