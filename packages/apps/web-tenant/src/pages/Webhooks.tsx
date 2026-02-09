import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, ExternalLink, Play, Trash2, Copy, Check, RefreshCw, AlertCircle } from 'lucide-react'
import { cn, copyToClipboard } from '@/lib/utils'
import { useWebhooks, useDeleteWebhook, useTestWebhook } from '@/hooks/useApi'
import type { Webhook } from '@/types'

export function Webhooks() {
  const navigate = useNavigate()
  const [copiedId, setCopiedId] = useState<string | null>(null)
  
  const { data: webhooks, isLoading } = useWebhooks()
  const deleteMutation = useDeleteWebhook()
  const testMutation = useTestWebhook()

  const handleCopy = async (text: string, id: string) => {
    await copyToClipboard(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const handleTest = (id: string) => {
    testMutation.mutate(id)
  }

  const handleDelete = (id: string) => {
    if (confirm('Are you sure you want to delete this webhook?')) {
      deleteMutation.mutate(id)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Webhooks</h1>
          <p className="text-muted-foreground">Manage webhook endpoints for real-time events</p>
        </div>
        <button type="button"
          onClick={() => navigate('/webhooks/new')}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
        >
          <Plus className="w-4 h-4" />
          Create Webhook
        </button>
      </div>

      {/* Webhooks List */}
      {isLoading ? (
        <div className="bg-card rounded-lg border border-border p-8">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto" />
        </div>
      ) : webhooks?.length === 0 ? (
        <div className="bg-card rounded-lg border border-border p-12 text-center">
          <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center mx-auto mb-4">
            <ExternalLink className="w-8 h-8 text-muted-foreground" />
          </div>
          <h3 className="font-semibold mb-2">No webhooks configured</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Create a webhook to receive real-time notifications when events occur
          </p>
          <button type="button"
            onClick={() => navigate('/webhooks/new')}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
          >
            Create Webhook
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {webhooks?.map((webhook: Webhook) => (
            <div
              key={webhook.id}
              className="bg-card rounded-lg border border-border p-6"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="font-semibold">{webhook.description || 'Untitled Webhook'}</h3>
                    <span
                      className={cn(
                        "px-2 py-0.5 rounded-full text-xs font-medium",
                        webhook.active
                          ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                          : "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200"
                      )}
                    >
                      {webhook.active ? 'Active' : 'Inactive'}
                    </span>
                    {webhook.lastError && (
                      <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                        <AlertCircle className="w-3 h-3" />
                        Error
                      </span>
                    )}
                  </div>
                  
                  <div className="flex items-center gap-2 mb-4">
                    <code className="text-sm bg-muted px-2 py-1 rounded">{webhook.url}</code>
                    <button type="button"
                      onClick={() => handleCopy(webhook.url, webhook.id)}
                      className="text-muted-foreground hover:text-foreground"
                    >
                      {copiedId === webhook.id ? (
                        <Check className="w-4 h-4 text-green-500" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 mb-4">
                    {webhook.events.map((event: string) => (
                      <span
                        key={event}
                        className="px-2 py-1 bg-primary/10 text-primary rounded text-xs"
                      >
                        {event}
                      </span>
                    ))}
                  </div>

                  {webhook.lastError && (
                    <div className="p-3 bg-red-50 dark:bg-red-950 rounded-lg mb-4">
                      <p className="text-sm text-red-800 dark:text-red-200">
                        <AlertCircle className="w-4 h-4 inline mr-1" />
                        {webhook.lastError}
                      </p>
                    </div>
                  )}

                  <div className="flex items-center gap-4 text-sm text-muted-foreground">
                    <span>ID: {webhook.id.slice(0, 8)}...</span>
                    {webhook.lastTriggeredAt && (
                      <span>
                        Last triggered: {new Date(webhook.lastTriggeredAt).toLocaleString()}
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2 ml-4">
                  <button type="button"
                    onClick={() => handleTest(webhook.id)}
                    disabled={testMutation.isPending}
                    className="p-2 rounded-lg border border-border hover:bg-muted disabled:opacity-50"
                    title="Test webhook"
                  >
                    <Play className="w-4 h-4" />
                  </button>
                  <button type="button"
                    onClick={() => navigate(`/webhooks/${webhook.id}/edit`)}
                    className="p-2 rounded-lg border border-border hover:bg-muted"
                    title="Edit webhook"
                  >
                    <RefreshCw className="w-4 h-4" />
                  </button>
                  <button type="button"
                    onClick={() => handleDelete(webhook.id)}
                    className="p-2 rounded-lg border border-border hover:bg-muted text-red-600"
                    title="Delete webhook"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Webhook Events Reference */}
      <div className="bg-card rounded-lg border border-border p-6">
        <h3 className="font-semibold mb-4">Available Events</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { event: 'user.created', description: 'When a new user is created' },
            { event: 'user.updated', description: 'When a user is updated' },
            { event: 'user.deleted', description: 'When a user is deleted' },
            { event: 'user.login', description: 'When a user logs in' },
            { event: 'user.logout', description: 'When a user logs out' },
            { event: 'org.created', description: 'When a new organization is created' },
            { event: 'org.member_added', description: 'When a member is added to an organization' },
            { event: 'org.member_removed', description: 'When a member is removed' },
            { event: 'session.created', description: 'When a new session is created' },
          ].map((item) => (
            <div key={item.event} className="p-3 bg-muted rounded-lg">
              <code className="text-sm text-primary">{item.event}</code>
              <p className="text-xs text-muted-foreground mt-1">{item.description}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
