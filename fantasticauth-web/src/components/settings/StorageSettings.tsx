import { useState, type ElementType } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Switch } from '@/components/ui/Switch'
import { Badge } from '@/components/ui/Badge'
import {
  HardDrive,
  Cloud,
  Database,
  Lock,
  Upload,
} from 'lucide-react'
import { env } from '@/env/client'
import { cn } from '@/lib/utils'

interface StorageConfig {
  provider: 's3' | 'r2' | 'azure_blob' | null
  enabled: boolean
  // S3 / R2 common
  endpoint?: string
  region?: string
  bucket?: string
  accessKeyId?: string
  secretAccessKey?: string
  // S3 specific
  forcePathStyle?: boolean
  // R2 specific
  accountId?: string
  // Azure specific
  accountName?: string
  accountKey?: string
  containerName?: string
  // Common settings
  maxFileSize?: number
  allowedMimeTypes?: string
  cdnUrl?: string
}

const defaultConfig: StorageConfig = {
  provider: null,
  enabled: false,
  endpoint: '',
  region: 'us-east-1',
  bucket: '',
  accessKeyId: '',
  secretAccessKey: '',
  forcePathStyle: false,
  accountId: '',
  accountName: '',
  accountKey: '',
  containerName: '',
  maxFileSize: 10,
  allowedMimeTypes: 'image/*,application/pdf',
  cdnUrl: '',
}

interface StorageProvider {
  id: StorageConfig['provider'] & string
  name: string
  description: string
  icon: ElementType
  envKey: keyof typeof env
}

const storageProviders: StorageProvider[] = [
  { id: 's3', name: 'AWS S3', description: 'Amazon Simple Storage Service', icon: Database, envKey: 'VITE_STORAGE_S3_ENABLED' },
  { id: 'r2', name: 'Cloudflare R2', description: 'S3-compatible object storage', icon: Cloud, envKey: 'VITE_STORAGE_R2_ENABLED' },
  { id: 'azure_blob', name: 'Azure Blob', description: 'Microsoft Azure object storage', icon: HardDrive, envKey: 'VITE_STORAGE_AZURE_BLOB_ENABLED' },
]

function isProviderEnabled(provider: StorageProvider): boolean {
  return env[provider.envKey] === 'true'
}

export function StorageSettings() {
  const [config, setConfig] = useState<StorageConfig>(defaultConfig)
  const [isLoading, setIsLoading] = useState(false)
  const [showSecrets, setShowSecrets] = useState(false)
  const [secretState, setSecretState] = useState({
    accessKeyId: false,
    secretAccessKey: false,
    accountKey: false,
  })

  const handleSave = async () => {
    setIsLoading(true)
    try {
      await new Promise((resolve) => setTimeout(resolve, 1000))
      setSecretState((prev) => ({
        accessKeyId: prev.accessKeyId || Boolean(config.accessKeyId?.trim()),
        secretAccessKey: prev.secretAccessKey || Boolean(config.secretAccessKey?.trim()),
        accountKey: prev.accountKey || Boolean(config.accountKey?.trim()),
      }))
      if (config.accessKeyId?.trim()) updateConfig('accessKeyId', '')
      if (config.secretAccessKey?.trim()) updateConfig('secretAccessKey', '')
      if (config.accountKey?.trim()) updateConfig('accountKey', '')
    } finally {
      setIsLoading(false)
    }
  }

  const updateConfig = <K extends keyof StorageConfig>(key: K, value: StorageConfig[K]) => {
    setConfig((prev) => ({ ...prev, [key]: value }))
  }

  const selectedProvider = storageProviders.find(p => p.id === config.provider)
  const isSelectedProviderEnabled = selectedProvider ? isProviderEnabled(selectedProvider) : false

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Storage Configuration</h2>
          <p className="text-muted-foreground">
            Configure file storage for avatars, exports, and other uploads
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
          <CardTitle>Storage Provider</CardTitle>
          <CardDescription>
            Select an object storage provider for file uploads
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-3">
            {storageProviders.map((provider) => {
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

              {(config.provider === 's3' || config.provider === 'r2') && (
                <div className="space-y-4">
                  <h3 className="font-semibold">Connection Settings</h3>
                  
                  {config.provider === 'r2' && (
                    <div className="space-y-2">
                      <label htmlFor="r2-account" className="text-sm font-medium leading-none">
                        Cloudflare Account ID
                      </label>
                      <Input
                        id="r2-account"
                        value={config.accountId}
                        onChange={(e) => updateConfig('accountId', e.target.value)}
                        placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                      />
                    </div>
                  )}

                  <div className="space-y-2">
                    <label htmlFor="endpoint" className="text-sm font-medium leading-none">
                      Endpoint URL (Optional for S3)
                    </label>
                    <Input
                      id="endpoint"
                      value={config.endpoint}
                      onChange={(e) => updateConfig('endpoint', e.target.value)}
                      placeholder={config.provider === 'r2' ? 'https://xxxxxxxx.r2.cloudflarestorage.com' : 'https://s3.amazonaws.com'}
                    />
                  </div>

                  {config.provider === 's3' && (
                    <div className="space-y-2">
                      <label htmlFor="region" className="text-sm font-medium leading-none">
                        Region
                      </label>
                      <Input
                        id="region"
                        value={config.region}
                        onChange={(e) => updateConfig('region', e.target.value)}
                        placeholder="us-east-1"
                      />
                    </div>
                  )}

                  <div className="space-y-2">
                    <label htmlFor="bucket" className="text-sm font-medium leading-none">
                      Bucket Name
                    </label>
                    <Input
                      id="bucket"
                      value={config.bucket}
                      onChange={(e) => updateConfig('bucket', e.target.value)}
                      placeholder="my-app-storage"
                    />
                  </div>

                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <label htmlFor="access-key" className="text-sm font-medium leading-none">
                          Access Key ID
                        </label>
                        {secretState.accessKeyId && !config.accessKeyId && (
                          <Badge variant="outline" className="text-xs">Set</Badge>
                        )}
                      </div>
                      <Input
                        id="access-key"
                        type={showSecrets ? 'text' : 'password'}
                        value={config.accessKeyId}
                        placeholder={secretState.accessKeyId && !config.accessKeyId ? '******** (set)' : 'AKIA...'}
                        onChange={(e) => updateConfig('accessKeyId', e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <label htmlFor="secret-key" className="text-sm font-medium leading-none">
                          Secret Access Key
                        </label>
                        {secretState.secretAccessKey && !config.secretAccessKey && (
                          <Badge variant="outline" className="text-xs">Set</Badge>
                        )}
                      </div>
                      <Input
                        id="secret-key"
                        type={showSecrets ? 'text' : 'password'}
                        value={config.secretAccessKey}
                        placeholder={secretState.secretAccessKey && !config.secretAccessKey ? '******** (set)' : '••••••••'}
                        onChange={(e) => updateConfig('secretAccessKey', e.target.value)}
                      />
                    </div>
                  </div>

                  {config.provider === 's3' && (
                    <div className="flex items-center gap-2">
                      <Switch
                        id="path-style"
                        checked={config.forcePathStyle}
                        onCheckedChange={(checked) => updateConfig('forcePathStyle', checked)}
                      />
                      <label htmlFor="path-style" className="text-sm font-medium leading-none">
                        Force Path Style (for MinIO/compatible)
                      </label>
                    </div>
                  )}
                </div>
              )}

              {config.provider === 'azure_blob' && (
                <div className="space-y-4">
                  <h3 className="font-semibold">Connection Settings</h3>
                  
                  <div className="space-y-2">
                    <label htmlFor="azure-account" className="text-sm font-medium leading-none">
                      Storage Account Name
                    </label>
                    <Input
                      id="azure-account"
                      value={config.accountName}
                      onChange={(e) => updateConfig('accountName', e.target.value)}
                      placeholder="mystorageaccount"
                    />
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label htmlFor="azure-key" className="text-sm font-medium leading-none">
                        Account Key
                      </label>
                      {secretState.accountKey && !config.accountKey && (
                        <Badge variant="outline" className="text-xs">Set</Badge>
                      )}
                    </div>
                    <Input
                      id="azure-key"
                      type={showSecrets ? 'text' : 'password'}
                      value={config.accountKey}
                      placeholder={secretState.accountKey && !config.accountKey ? '******** (set)' : '••••••••'}
                      onChange={(e) => updateConfig('accountKey', e.target.value)}
                    />
                  </div>

                  <div className="space-y-2">
                    <label htmlFor="azure-container" className="text-sm font-medium leading-none">
                      Container Name
                    </label>
                    <Input
                      id="azure-container"
                      value={config.containerName}
                      onChange={(e) => updateConfig('containerName', e.target.value)}
                      placeholder="uploads"
                    />
                  </div>
                </div>
              )}

              <div className="h-px bg-border" />

              <div className="space-y-4">
                <h3 className="font-semibold">Upload Settings</h3>
                
                <div className="space-y-2">
                  <label htmlFor="max-size" className="text-sm font-medium leading-none">
                    Max File Size (MB)
                  </label>
                  <Input
                    id="max-size"
                    type="number"
                    value={config.maxFileSize}
                    onChange={(e) => updateConfig('maxFileSize', parseInt(e.target.value))}
                    min={1}
                    max={100}
                  />
                </div>

                <div className="space-y-2">
                  <label htmlFor="mime-types" className="text-sm font-medium leading-none">
                    Allowed MIME Types
                  </label>
                  <Input
                    id="mime-types"
                    value={config.allowedMimeTypes}
                    onChange={(e) => updateConfig('allowedMimeTypes', e.target.value)}
                    placeholder="image/*,application/pdf"
                  />
                  <p className="text-xs text-muted-foreground">
                    Comma-separated list of MIME type patterns
                  </p>
                </div>

              <div className="space-y-2">
                <label htmlFor="cdn-url" className="text-sm font-medium leading-none">
                  CDN URL (Optional)
                </label>
                  <Input
                    id="cdn-url"
                    value={config.cdnUrl}
                    onChange={(e) => updateConfig('cdnUrl', e.target.value)}
                    placeholder="https://cdn.example.com"
                  />
                  <p className="text-xs text-muted-foreground">
                    Custom domain for serving uploaded files
                  </p>
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
            <>
              <Upload className="mr-2 h-4 w-4" />
              Save Configuration
            </>
          )}
        </Button>
      </div>
    </div>
  )
}
