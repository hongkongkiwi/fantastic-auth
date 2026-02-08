import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, ExternalLink, Trash2, Copy, Check, RefreshCw, Key } from 'lucide-react'
import { cn, copyToClipboard } from '@/lib/utils'
import { useOAuthClients, useDeleteOAuthClient, useRegenerateOAuthSecret } from '@/hooks/useApi'

export function OAuthClients() {
  const navigate = useNavigate()
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null)
  
  const { data: clients, isLoading } = useOAuthClients()
  const deleteMutation = useDeleteOAuthClient()
  const regenerateMutation = useRegenerateOAuthSecret()

  const handleCopy = async (text: string, id: string) => {
    await copyToClipboard(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const handleDelete = (id: string) => {
    if (confirm('Are you sure you want to delete this OAuth client?')) {
      deleteMutation.mutate(id)
    }
  }

  const handleRegenerate = (id: string) => {
    if (confirm('Regenerate client secret? The old secret will be invalidated immediately.')) {
      regenerateMutation.mutate(id, {
        onSuccess: (data) => {
          setRevealedSecret(data.clientSecret)
        },
      })
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">OAuth Clients</h1>
          <p className="text-muted-foreground">Manage OAuth 2.0 applications</p>
        </div>
        <button
          onClick={() => navigate('/oauth-clients/new')}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
        >
          <Plus className="w-4 h-4" />
          Create Client
        </button>
      </div>

      {/* Clients List */}
      {isLoading ? (
        <div className="bg-card rounded-lg border border-border p-8">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto" />
        </div>
      ) : clients?.length === 0 ? (
        <div className="bg-card rounded-lg border border-border p-12 text-center">
          <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center mx-auto mb-4">
            <Key className="w-8 h-8 text-muted-foreground" />
          </div>
          <h3 className="font-semibold mb-2">No OAuth clients</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Create an OAuth client to allow third-party applications to authenticate with Vault
          </p>
          <button
            onClick={() => navigate('/oauth-clients/new')}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
          >
            Create Client
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {clients?.map((client) => (
            <div
              key={client.id}
              className="bg-card rounded-lg border border-border p-6"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="font-semibold">{client.name}</h3>
                    <span
                      className={cn(
                        "px-2 py-0.5 rounded-full text-xs font-medium",
                        client.active
                          ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                          : "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200"
                      )}
                    >
                      {client.active ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                  
                  <div className="space-y-3 mb-4">
                    <div>
                      <label className="text-xs text-muted-foreground uppercase tracking-wider">Client ID</label>
                      <div className="flex items-center gap-2">
                        <code className="text-sm bg-muted px-2 py-1 rounded">{client.clientId}</code>
                        <button
                          onClick={() => handleCopy(client.clientId, client.id)}
                          className="text-muted-foreground hover:text-foreground"
                        >
                          {copiedId === client.id ? (
                            <Check className="w-4 h-4 text-green-500" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>

                    {revealedSecret && (
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wider">Client Secret</label>
                        <div className="flex items-center gap-2">
                          <code className="text-sm bg-muted px-2 py-1 rounded">{revealedSecret}</code>
                          <button
                            onClick={() => handleCopy(revealedSecret, 'secret')}
                            className="text-muted-foreground hover:text-foreground"
                          >
                            {copiedId === 'secret' ? (
                              <Check className="w-4 h-4 text-green-500" />
                            ) : (
                              <Copy className="w-4 h-4" />
                            )}
                          </button>
                        </div>
                        <p className="text-xs text-yellow-600 mt-1">
                          Copy this now - it won't be shown again!
                        </p>
                      </div>
                    )}

                    <div>
                      <label className="text-xs text-muted-foreground uppercase tracking-wider">Redirect URIs</label>
                      <div className="flex flex-wrap gap-2 mt-1">
                        {client.redirectUris.map((uri) => (
                          <code key={uri} className="text-xs bg-muted px-2 py-1 rounded">
                            {uri}
                          </code>
                        ))}
                      </div>
                    </div>

                    <div>
                      <label className="text-xs text-muted-foreground uppercase tracking-wider">Allowed Scopes</label>
                      <div className="flex flex-wrap gap-2 mt-1">
                        {client.allowedScopes.map((scope) => (
                          <span key={scope} className="text-xs px-2 py-1 bg-primary/10 text-primary rounded">
                            {scope}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="text-sm text-muted-foreground">
                    Created {new Date(client.createdAt).toLocaleDateString()}
                  </div>
                </div>

                <div className="flex items-center gap-2 ml-4">
                  <button
                    onClick={() => handleRegenerate(client.id)}
                    disabled={regenerateMutation.isPending}
                    className="p-2 rounded-lg border border-border hover:bg-muted disabled:opacity-50"
                    title="Regenerate secret"
                  >
                    <RefreshCw className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => navigate(`/oauth-clients/${client.id}/edit`)}
                    className="p-2 rounded-lg border border-border hover:bg-muted"
                    title="Edit client"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(client.id)}
                    className="p-2 rounded-lg border border-border hover:bg-muted text-red-600"
                    title="Delete client"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Info */}
      <div className="bg-card rounded-lg border border-border p-6">
        <h3 className="font-semibold mb-4">About OAuth 2.0</h3>
        <p className="text-sm text-muted-foreground mb-4">
          OAuth 2.0 allows third-party applications to obtain limited access to user accounts on your Vault instance.
          Each client represents an application that can request authentication and authorization.
        </p>
        <div className="space-y-2 text-sm">
          <p><strong>Authorization URL:</strong> <code className="bg-muted px-2 py-1 rounded">/oauth/authorize</code></p>
          <p><strong>Token URL:</strong> <code className="bg-muted px-2 py-1 rounded">/oauth/token</code></p>
          <p><strong>Supported flows:</strong> Authorization Code, PKCE</p>
        </div>
      </div>
    </div>
  )
}
