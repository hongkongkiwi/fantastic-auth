import { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Card, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  ConfirmDialog,
} from '@/components/ui/Dialog'
import { Key, Plus, Copy, Eye, EyeOff, Trash2, Clock, Shield } from 'lucide-react'

interface ApiKey {
  id: string
  name: string
  prefix: string
  createdAt: string
  expiresAt: string | null
  lastUsedAt: string | null
  scopes: string[]
}

interface NewKeyResponse {
  key: string
  apiKey: ApiKey
}

const availableScopes = [
  { id: 'read:users', label: 'Read Users', description: 'View user data' },
  { id: 'write:users', label: 'Write Users', description: 'Create and modify users' },
  { id: 'read:tenants', label: 'Read Tenants', description: 'View tenant data' },
  { id: 'write:tenants', label: 'Write Tenants', description: 'Manage tenants' },
  { id: 'read:audit', label: 'Read Audit', description: 'View audit logs' },
  { id: 'admin', label: 'Admin', description: 'Full admin access' },
]

export function ApiKeyManager() {
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([
    {
      id: '1',
      name: 'Production API',
      prefix: 'pk_fake_removed
      createdAt: '2024-01-15T10:00:00Z',
      expiresAt: null,
      lastUsedAt: '2024-02-08T14:30:00Z',
      scopes: ['read:users', 'write:users'],
    },
  ])
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [isRevokeOpen, setIsRevokeOpen] = useState(false)
  const [selectedKey, setSelectedKey] = useState<ApiKey | null>(null)
  const [newKey, setNewKey] = useState<NewKeyResponse | null>(null)
  const [showNewKey, setShowNewKey] = useState(false)
  const [isCreating, setIsCreating] = useState(false)

  // Create form state
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyExpiry, setNewKeyExpiry] = useState('never')
  const [selectedScopes, setSelectedScopes] = useState<string[]>(['read:users'])

  const sortedKeys = useMemo(() => {
    return [...apiKeys].sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    )
  }, [apiKeys])

  const handleCreate = async () => {
    setIsCreating(true)
    try {
      // Simulate API call
      await new Promise((resolve) => setTimeout(resolve, 1000))
      
      const newApiKey: ApiKey = {
        id: Math.random().toString(36).substring(7),
        name: newKeyName,
        prefix: `pk_fake_removed
        createdAt: new Date().toISOString(),
        expiresAt: newKeyExpiry === 'never' ? null : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        lastUsedAt: null,
        scopes: selectedScopes,
      }

      setNewKey({
        key: `pk_fake_removed
        apiKey: newApiKey,
      })
      setApiKeys([newApiKey, ...apiKeys])
    } finally {
      setIsCreating(false)
    }
  }

  const handleRevoke = async () => {
    if (!selectedKey) return
    
    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 500))
    
    setApiKeys(apiKeys.filter((k) => k.id !== selectedKey.id))
    setIsRevokeOpen(false)
    setSelectedKey(null)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const closeCreateDialog = () => {
    setIsCreateOpen(false)
    setNewKey(null)
    setNewKeyName('')
    setNewKeyExpiry('never')
    setSelectedScopes(['read:users'])
    setShowNewKey(false)
  }

  const formatDate = (date: string | null) => {
    if (!date) return 'Never'
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  const toggleScope = (scope: string) => {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">API Keys</h2>
          <p className="text-muted-foreground">
            Manage API keys for programmatic access to the Vault API
          </p>
        </div>
        <Button onClick={() => setIsCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Create API Key
        </Button>
      </div>

      <div className="space-y-4">
        {sortedKeys.map((key) => (
          <motion.div
            key={key.id}
            layout
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <Card>
              <CardContent className="flex items-center justify-between p-6">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                    <Key className="h-5 w-5 text-primary" />
                  </div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold">{key.name}</h3>
                      <Badge variant="outline" className="font-mono text-xs">
                        {key.prefix}...
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        Created {formatDate(key.createdAt)}
                      </span>
                      {key.expiresAt && (
                        <span className="flex items-center gap-1 text-amber-600">
                          <Clock className="h-3 w-3" />
                          Expires {formatDate(key.expiresAt)}
                        </span>
                      )}
                      {key.lastUsedAt && (
                        <span>Last used {formatDate(key.lastUsedAt)}</span>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-1 pt-1">
                      {key.scopes.map((scope) => (
                        <Badge key={scope} variant="secondary" className="text-xs">
                          {scope}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-destructive hover:text-destructive"
                  onClick={() => {
                    setSelectedKey(key)
                    setIsRevokeOpen(true)
                  }}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </CardContent>
            </Card>
          </motion.div>
        ))}

        {apiKeys.length === 0 && (
          <Card className="border-dashed">
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Key className="h-12 w-12 text-muted-foreground/50" />
              <h3 className="mt-4 text-lg font-semibold">No API keys</h3>
              <p className="text-muted-foreground">
                Create an API key to get started with the Vault API
              </p>
              <Button className="mt-4" onClick={() => setIsCreateOpen(true)}>
                <Plus className="mr-2 h-4 w-4" />
                Create API Key
              </Button>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Create Dialog */}
      <Dialog open={isCreateOpen} onOpenChange={closeCreateDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Create API Key</DialogTitle>
            <DialogDescription>
              Create a new API key for programmatic access
            </DialogDescription>
          </DialogHeader>

          <AnimatePresence mode="wait">
            {!newKey ? (
              <motion.div
                key="form"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="space-y-4"
              >
                <div className="space-y-2">
                  <label className="text-sm font-medium" htmlFor="key-name">Key Name</label>
                  <Input
                    id="key-name"
                    placeholder="e.g., Production API, Testing Key"
                    value={newKeyName}
                    onChange={(e) => setNewKeyName(e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium" htmlFor="key-expiry">Expiration</label>
                  <select
                    id="key-expiry"
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    value={newKeyExpiry}
                    onChange={(e) => setNewKeyExpiry(e.target.value)}
                  >
                    <option value="never">Never</option>
                    <option value="30">30 days</option>
                    <option value="90">90 days</option>
                    <option value="365">1 year</option>
                  </select>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Scopes</label>
                  <div className="space-y-2 rounded-lg border p-3">
                    {availableScopes.map((scope) => (
                      <label
                        key={scope.id}
                        className="flex cursor-pointer items-center gap-3 rounded-md p-2 hover:bg-muted"
                      >
                        <input
                          type="checkbox"
                          checked={selectedScopes.includes(scope.id)}
                          onChange={() => toggleScope(scope.id)}
                          className="h-4 w-4 rounded border-primary"
                        />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{scope.label}</span>
                            <code className="text-xs text-muted-foreground">{scope.id}</code>
                          </div>
                          <p className="text-xs text-muted-foreground">{scope.description}</p>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                <DialogFooter>
                  <Button variant="outline" onClick={closeCreateDialog}>
                    Cancel
                  </Button>
                  <Button
                    onClick={handleCreate}
                    disabled={!newKeyName || selectedScopes.length === 0 || isCreating}
                  >
                    {isCreating ? (
                      <>
                        <motion.div
                          className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
                        />
                        Creating…
                      </>
                    ) : (
                      'Create Key'
                    )}
                  </Button>
                </DialogFooter>
              </motion.div>
            ) : (
              <motion.div
                key="success"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="space-y-4"
              >
                <div className="rounded-lg bg-green-50 p-4 text-green-800 dark:bg-green-900/20 dark:text-green-400">
                  <div className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    <span className="font-medium">API Key Created Successfully</span>
                  </div>
                  <p className="mt-1 text-sm">
                    Copy this key now. You won&apos;t be able to see it again!
                  </p>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Your API Key</label>
                  <div className="flex gap-2">
                    <code className="flex-1 overflow-hidden rounded bg-muted px-3 py-2 text-sm">
                      {showNewKey ? newKey.key : '•'.repeat(newKey.key.length)}
                    </code>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => setShowNewKey(!showNewKey)}
                      aria-label={showNewKey ? 'Hide API key' : 'Show API key'}
                    >
                      {showNewKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => copyToClipboard(newKey.key)}
                      aria-label="Copy API key"
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                <DialogFooter>
                  <Button onClick={closeCreateDialog}>
                    I&apos;ve Copied My Key
                  </Button>
                </DialogFooter>
              </motion.div>
            )}
          </AnimatePresence>
        </DialogContent>
      </Dialog>

      {/* Revoke Confirmation */}
      <ConfirmDialog
        isOpen={isRevokeOpen}
        onClose={() => {
          setIsRevokeOpen(false)
          setSelectedKey(null)
        }}
        onConfirm={handleRevoke}
        title="Revoke API Key"
        description={`Are you sure you want to revoke the API key "${selectedKey?.name}"? This action cannot be undone and any applications using this key will immediately stop working.`}
        confirmText="Revoke Key"
        variant="destructive"
      />
    </div>
  )
}
