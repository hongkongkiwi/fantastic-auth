import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Webhook, 
  Plus, 
  Trash2, 
  Edit2, 
  CheckCircle, 
  XCircle,
  Loader2
} from 'lucide-react'
import { Button } from '../ui/Button'
import { Input } from '../ui/Input'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/Dialog'
import { toast } from '../ui/Toaster'

interface WebhookEndpoint {
  id: string
  name: string
  url: string
  events: string[]
  active: boolean
  created_at: string
}

const EVENT_OPTIONS = [
  { value: 'user.created', label: 'User Created' },
  { value: 'user.updated', label: 'User Updated' },
  { value: 'user.deleted', label: 'User Deleted' },
  { value: 'user.login', label: 'User Login' },
  { value: 'user.login_failed', label: 'Login Failed' },
  { value: 'session.created', label: 'Session Created' },
  { value: 'session.revoked', label: 'Session Revoked' },
  { value: 'mfa.enabled', label: 'MFA Enabled' },
  { value: 'mfa.disabled', label: 'MFA Disabled' },
  { value: '*', label: 'All Events' },
]

export function WebhookManager() {
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [editingWebhook, setEditingWebhook] = useState<WebhookEndpoint | null>(null)
  
  const queryClient = useQueryClient()
  
  const { data: webhooks, isLoading } = useQuery({
    queryKey: ['webhooks'],
    queryFn: async () => {
      const res = await fetch('/api/v1/admin/webhooks')
      if (!res.ok) throw new Error('Failed to load webhooks')
      return res.json() as Promise<WebhookEndpoint[]>
    },
  })
  
  const toggleMutation = useMutation({
    mutationFn: async ({ id, active }: { id: string; active: boolean }) => {
      await fetch(`/api/v1/admin/webhooks/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active }),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
    },
  })
  
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await fetch(`/api/v1/admin/webhooks/${id}`, { method: 'DELETE' })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      toast.success('Webhook deleted')
    },
  })
  
  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    )
  }
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium">Webhook Endpoints</h3>
          <p className="text-sm text-muted-foreground">
            Configure endpoints to receive event notifications
          </p>
        </div>
        <Button onClick={() => setIsCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Add Webhook
        </Button>
      </div>
      
      {webhooks?.length === 0 ? (
        <div className="text-center py-12 border rounded-lg">
          <Webhook className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
          <p className="text-muted-foreground">No webhooks configured</p>
          <Button
            variant="outline"
            className="mt-4"
            onClick={() => setIsCreateOpen(true)}
          >
            Create your first webhook
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          {webhooks?.map((webhook) => (
            <div
              key={webhook.id}
              className="p-4 border rounded-lg flex items-center justify-between"
            >
              <div className="flex items-start gap-3">
                <div className={`p-2 rounded-full ${webhook.active ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-600'}`}>
                  <Webhook className="h-4 w-4" />
                </div>
                <div>
                  <p className="font-medium">{webhook.name}</p>
                  <p className="text-sm text-muted-foreground">{webhook.url}</p>
                  <div className="flex items-center gap-2 mt-1">
                    {webhook.events.includes('*') ? (
                      <span className="text-xs px-2 py-0.5 bg-primary/10 rounded">All events</span>
                    ) : (
                      <span className="text-xs text-muted-foreground">
                        {webhook.events.length} event{webhook.events.length !== 1 ? 's' : ''}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => toggleMutation.mutate({ id: webhook.id, active: !webhook.active })}
                >
                  {webhook.active ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-gray-400" />
                  )}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setEditingWebhook(webhook)}
                >
                  <Edit2 className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => deleteMutation.mutate(webhook.id)}
                  disabled={deleteMutation.isPending}
                >
                  <Trash2 className="h-4 w-4 text-destructive" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
      
      <CreateWebhookDialog
        open={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
      />
      
      {editingWebhook && (
        <EditWebhookDialog
          webhook={editingWebhook}
          open={true}
          onClose={() => setEditingWebhook(null)}
        />
      )}
    </div>
  )
}

function CreateWebhookDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [selectedEvents, setSelectedEvents] = useState<string[]>([])
  const queryClient = useQueryClient()
  
  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch('/api/v1/admin/webhooks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          url,
          events: selectedEvents,
        }),
      })
      if (!res.ok) throw new Error('Failed to create webhook')
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      toast.success('Webhook created')
      onClose()
      setName('')
      setUrl('')
      setSelectedEvents([])
    },
    onError: () => toast.error('Failed to create webhook'),
  })
  
  const toggleEvent = (event: string) => {
    if (event === '*') {
      setSelectedEvents(['*'])
    } else {
      setSelectedEvents(prev => {
        const withoutAll = prev.filter(e => e !== '*')
        if (prev.includes(event)) {
          return withoutAll.filter(e => e !== event)
        }
        return [...withoutAll, event]
      })
    }
  }
  
  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Add Webhook Endpoint</DialogTitle>
          <DialogDescription>
            Configure a URL to receive event notifications
          </DialogDescription>
        </DialogHeader>
        
        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Input
              label="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Webhook"
              name="webhookName"
              autoComplete="off"
            />
          </div>
          
          <div className="space-y-2">
            <Input
              label="URL"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/webhook"
              type="url"
              name="webhookUrl"
              autoComplete="url"
            />
          </div>
          
          <div className="space-y-2">
            <label className="text-sm font-medium">Events</label>
            <div className="flex flex-wrap gap-2">
              {EVENT_OPTIONS.map((event) => (
                <button type="button"
                  key={event.value}
                  onClick={() => toggleEvent(event.value)}
                  className={`px-3 py-1 text-xs rounded-full border transition-colors ${
                    selectedEvents.includes(event.value)
                      ? 'bg-primary text-primary-foreground border-primary'
                      : 'bg-background hover:bg-muted'
                  }`}
                >
                  {event.label}
                </button>
              ))}
            </div>
          </div>
        </div>
        
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button 
            onClick={() => createMutation.mutate()}
            disabled={!name || !url || selectedEvents.length === 0 || createMutation.isPending}
            isLoading={createMutation.isPending}
          >
            Create Webhook
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function EditWebhookDialog({ 
  webhook, 
  open, 
  onClose 
}: { 
  webhook: WebhookEndpoint
  open: boolean
  onClose: () => void 
}) {
  // Similar to create but with pre-filled values
  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit Webhook</DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          Editing webhook "{webhook.name}" is not yet implemented
        </p>
        <DialogFooter>
          <Button onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
