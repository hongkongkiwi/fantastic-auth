import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/Tabs'
import { Shield, Upload, Download, CheckCircle, AlertTriangle, Copy, ExternalLink } from 'lucide-react'
import { cn } from '@/lib/utils'

interface SamlConfig {
  enabled: boolean
  provider: string
  entityId: string
  ssoUrl: string
  certificate: string
  signInUrl: string
  nameIdFormat: string
  allowCreate: boolean
}

const defaultConfig: SamlConfig = {
  enabled: false,
  provider: '',
  entityId: '',
  ssoUrl: '',
  certificate: '',
  signInUrl: '',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  allowCreate: true,
}

const nameIdFormats = [
  { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', label: 'Email Address' },
  { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', label: 'Unspecified' },
  { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', label: 'Persistent' },
  { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient', label: 'Transient' },
]

export function SamlConfiguration() {
  const [config, setConfig] = useState<SamlConfig>(defaultConfig)
  const [isLoading, setIsLoading] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [testStatus, setTestStatus] = useState<'idle' | 'success' | 'error'>('idle')
  const [activeTab, setActiveTab] = useState('general')
  const [connectionId, setConnectionId] = useState<string | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function loadConnection() {
      try {
        const response = await fetch('/api/v1/admin/sso/saml/connections', {
          credentials: 'include',
        })
        if (!response.ok) return
        const payload = await response.json() as { data?: Array<{
          id: string
          name: string
          idp_entity_id?: string
          idp_sso_url?: string
          idp_slo_url?: string
          name_id_format?: string
          jit_provisioning_enabled?: boolean
          status?: string
        }> }
        const first = payload.data?.[0]
        if (!first || cancelled) return
        setConnectionId(first.id)
        setConfig((prev) => ({
          ...prev,
          enabled: first.status === 'active',
          provider: first.name || '',
          entityId: first.idp_entity_id || '',
          ssoUrl: first.idp_sso_url || '',
          signInUrl: first.idp_slo_url || '',
          nameIdFormat: first.name_id_format || prev.nameIdFormat,
          allowCreate: first.jit_provisioning_enabled ?? true,
        }))
      } catch {
        // leave defaults on load failure
      }
    }
    void loadConnection()
    return () => {
      cancelled = true
    }
  }, [])

  const handleSave = async () => {
    setIsLoading(true)
    try {
      const payload = {
        name: config.provider || 'Default SAML',
        idp_entity_id: config.entityId || null,
        idp_sso_url: config.ssoUrl || null,
        idp_slo_url: config.signInUrl || null,
        idp_certificate: config.certificate || null,
        name_id_format: config.nameIdFormat,
        jit_provisioning_enabled: config.allowCreate,
        status: config.enabled ? 'active' : 'inactive',
      }

      const url = connectionId
        ? `/api/v1/admin/sso/saml/connections/${connectionId}`
        : '/api/v1/admin/sso/saml/connections'
      const method = connectionId ? 'PATCH' : 'POST'

      const response = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload),
      })
      if (!response.ok) {
        throw new Error('Failed to save SAML configuration')
      }

      if (!connectionId) {
        const created = await response.json() as { id?: string }
        if (created.id) {
          setConnectionId(created.id)
        }
      }
      setSaveError(null)
      setTestStatus('idle')
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save SAML configuration')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTestConnection = async () => {
    setIsTesting(true)
    setTestStatus('idle')
    try {
      if (!connectionId) {
        throw new Error('Save configuration before testing')
      }
      const response = await fetch(`/api/v1/admin/sso/saml/connections/${connectionId}/test`, {
        method: 'POST',
        credentials: 'include',
      })
      if (!response.ok) {
        throw new Error('Connection test failed')
      }
      setTestStatus('success')
    } catch {
      setTestStatus('error')
    } finally {
      setIsTesting(false)
    }
  }

  const copyMetadataUrl = () => {
    navigator.clipboard.writeText(`${window.location.origin}/api/auth/saml/metadata`)
  }

  const copyAcsUrl = () => {
    navigator.clipboard.writeText(`${window.location.origin}/api/auth/saml/acs`)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">SAML SSO Configuration</h2>
          <p className="text-muted-foreground">
            Configure SAML 2.0 single sign-on integration with your identity provider
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Switch
            checked={config.enabled}
            onCheckedChange={(checked) => setConfig({ ...config, enabled: checked })}
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

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="provider">Identity Provider</TabsTrigger>
          <TabsTrigger value="metadata">Service Provider</TabsTrigger>
        </TabsList>

        <TabsContent value="general" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>General Settings</CardTitle>
              <CardDescription>Basic SAML configuration options</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium" htmlFor="provider-name">Provider Name</label>
                <Input
                  id="provider-name"
                  placeholder="e.g., Okta, Azure AD, OneLogin"
                  value={config.provider}
                  onChange={(e) => setConfig({ ...config, provider: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium" htmlFor="name-id-format">Name ID Format</label>
                <select
                  id="name-id-format"
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  value={config.nameIdFormat}
                  onChange={(e) => setConfig({ ...config, nameIdFormat: e.target.value })}
                >
                  {nameIdFormats.map((format) => (
                    <option key={format.value} value={format.value}>
                      {format.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center justify-between rounded-lg border p-4">
                <div className="space-y-0.5">
                  <label className="text-base font-medium">Allow Account Creation</label>
                  <p className="text-sm text-muted-foreground">
                    Automatically create accounts for new users authenticated via SAML
                  </p>
                </div>
                <Switch
                  checked={config.allowCreate}
                  onCheckedChange={(checked) => setConfig({ ...config, allowCreate: checked })}
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="provider" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Identity Provider Settings</CardTitle>
              <CardDescription>Configure your IdP connection details</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium" htmlFor="entity-id">Entity ID (Issuer)</label>
                <Input
                  id="entity-id"
                  placeholder="https://your-idp.com/saml/metadata"
                  value={config.entityId}
                  onChange={(e) => setConfig({ ...config, entityId: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium" htmlFor="sso-url">SSO URL (Login URL)</label>
                <Input
                  id="sso-url"
                  placeholder="https://your-idp.com/saml/sso"
                  value={config.ssoUrl}
                  onChange={(e) => setConfig({ ...config, ssoUrl: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium" htmlFor="certificate">X.509 Certificate</label>
                <div className="relative">
                  <textarea
                    id="certificate"
                    rows={6}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                    placeholder="-----BEGIN CERTIFICATE-----&#10;MIIDXTCCAkWg…&#10;-----END CERTIFICATE-----"
                    value={config.certificate}
                    onChange={(e) => setConfig({ ...config, certificate: e.target.value })}
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    className="absolute right-2 top-2"
                    onClick={() => document.getElementById('cert-upload')?.click()}
                  >
                    <Upload className="mr-2 h-4 w-4" />
                    Upload
                  </Button>
                  <input
                    id="cert-upload"
                    type="file"
                    accept=".pem,.crt,.cer"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      if (file) {
                        const reader = new FileReader()
                        reader.onload = (ev) => {
                          setConfig({ ...config, certificate: ev.target?.result as string })
                        }
                        reader.readAsText(file)
                      }
                    }}
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <AnimatePresence>
            {testStatus !== 'idle' && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
              >
                {testStatus === 'success' ? (
                  <div className="flex items-center gap-2 rounded-lg bg-green-50 p-4 text-green-800 dark:bg-green-900/20 dark:text-green-400">
                    <CheckCircle className="h-5 w-5" />
                    <span>Connection test successful! SAML SSO is properly configured.</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 rounded-lg bg-red-50 p-4 text-red-800 dark:bg-red-900/20 dark:text-red-400">
                    <AlertTriangle className="h-5 w-5" />
                    <span>Connection test failed. Please verify your configuration.</span>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </TabsContent>

        <TabsContent value="metadata" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Service Provider Metadata</CardTitle>
              <CardDescription>Share these details with your identity provider</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">SP Metadata URL</label>
                <div className="flex gap-2">
                  <code className="flex-1 rounded bg-muted px-3 py-2 text-sm">
                    {typeof window !== 'undefined' ? `${window.location.origin}/api/auth/saml/metadata` : ''}
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    aria-label="Copy SP metadata URL"
                    onClick={copyMetadataUrl}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                  <Button variant="outline" size="icon" aria-label="Open SP metadata" asChild>
                    <a href="/api/auth/saml/metadata" target="_blank" rel="noopener noreferrer">
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">ACS (Assertion Consumer Service) URL</label>
                <div className="flex gap-2">
                  <code className="flex-1 rounded bg-muted px-3 py-2 text-sm">
                    {typeof window !== 'undefined' ? `${window.location.origin}/api/auth/saml/acs` : ''}
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    aria-label="Copy ACS URL"
                    onClick={copyAcsUrl}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">SP Entity ID</label>
                <div className="flex gap-2">
                  <code className="flex-1 rounded bg-muted px-3 py-2 text-sm">
                    vault-saml
                  </code>
                  <Button
                    variant="outline"
                    size="icon"
                    aria-label="Copy SP entity ID"
                    onClick={() => navigator.clipboard.writeText('vault-saml')}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className="pt-4">
                <Button variant="outline" className="w-full">
                  <Download className="mr-2 h-4 w-4" />
                  Download SP Metadata XML
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <div className="flex items-center justify-end gap-4">
        <Button
          variant="outline"
          onClick={handleTestConnection}
          disabled={isTesting || !config.enabled}
        >
          {isTesting ? (
            <>
              <motion.div
                className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
              />
              Testing…
            </>
          ) : (
            <>
              <Shield className="mr-2 h-4 w-4" />
              Test Connection
            </>
          )}
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
            'Save Configuration'
          )}
        </Button>
      </div>
    </div>
  )
}
