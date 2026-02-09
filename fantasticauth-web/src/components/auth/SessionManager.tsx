import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Monitor, 
  Smartphone, 
  Tablet, 
  Laptop,
  MapPin,
  Clock,
  LogOut,
  ShieldCheck,
  Loader2
} from 'lucide-react'
import { Button } from '../ui/Button'
import { toast } from '../ui/Toaster'
import { formatRelativeTime } from '../../lib/utils'

interface Session {
  id: string
  device_info: {
    name: string
    browser: string
    os: string
    device_type: 'desktop' | 'mobile' | 'tablet'
  }
  ip_address: string
  location?: string
  created_at: string
  last_active_at: string
  is_current: boolean
}

interface SessionManagerProps {
  userId?: string // If provided, admin view for specific user
}

export function SessionManager({ userId }: SessionManagerProps) {
  const queryClient = useQueryClient()
  const isAdminView = !!userId
  
  const { data: sessions, isLoading } = useQuery({
    queryKey: ['sessions', userId || 'me'],
    queryFn: async () => {
      const endpoint = isAdminView 
        ? `/api/v1/admin/users/${userId}/sessions`
        : '/api/v1/auth/sessions'
      const res = await fetch(endpoint)
      if (!res.ok) throw new Error('Failed to load sessions')
      return res.json() as Promise<Session[]>
    },
  })
  
  const revokeMutation = useMutation({
    mutationFn: async (sessionId: string) => {
      const endpoint = isAdminView
        ? `/api/v1/admin/users/${userId}/sessions/${sessionId}`
        : `/api/v1/auth/sessions/${sessionId}`
      await fetch(endpoint, { method: 'DELETE' })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions', userId || 'me'] })
      toast.success('Session revoked')
    },
    onError: () => toast.error('Failed to revoke session'),
  })
  
  const revokeAllMutation = useMutation({
    mutationFn: async () => {
      const endpoint = isAdminView
        ? `/api/v1/admin/users/${userId}/sessions/revoke-all`
        : '/api/v1/auth/sessions/revoke-all'
      await fetch(endpoint, { method: 'POST' })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions', userId || 'me'] })
      toast.success('All other sessions revoked')
    },
    onError: () => toast.error('Failed to revoke sessions'),
  })
  
  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }
  
  const currentSession = sessions?.find(s => s.is_current)
  const otherSessions = sessions?.filter(s => !s.is_current) || []
  
  return (
    <div className="space-y-6">
      {/* Current Session */}
      {currentSession && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
            Current Session
          </h4>
          <SessionCard session={currentSession} />
        </div>
      )}
      
      {/* Other Sessions */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
            Other Sessions
          </h4>
          {otherSessions.length > 0 && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => revokeAllMutation.mutate()}
              disabled={revokeAllMutation.isPending}
            >
              <LogOut className="mr-2 h-4 w-4" />
              Revoke All
            </Button>
          )}
        </div>
        
        {otherSessions.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <ShieldCheck className="h-12 w-12 mx-auto mb-2 opacity-50" />
            <p>No other active sessions</p>
          </div>
        ) : (
          <div className="space-y-2">
            {otherSessions.map((session) => (
              <SessionCard
                key={session.id}
                session={session}
                onRevoke={() => revokeMutation.mutate(session.id)}
                isRevoking={revokeMutation.isPending}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function SessionCard({ 
  session, 
  onRevoke, 
  isRevoking 
}: { 
  session: Session
  onRevoke?: () => void
  isRevoking?: boolean
}) {
  const DeviceIcon = {
    desktop: Laptop,
    mobile: Smartphone,
    tablet: Tablet,
  }[session.device_info.device_type] || Monitor
  
  return (
    <div className={`p-4 rounded-lg border ${session.is_current ? 'border-primary bg-primary/5' : 'border-border'}`}>
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-full bg-muted">
            <DeviceIcon className="h-5 w-5" />
          </div>
          
          <div>
            <div className="flex items-center gap-2">
              <span className="font-medium">{session.device_info.name}</span>
              {session.is_current && (
                <span className="px-2 py-0.5 text-xs bg-primary text-primary-foreground rounded-full">
                  Current
                </span>
              )}
            </div>
            
            <div className="mt-1 text-sm text-muted-foreground space-y-1">
              <div className="flex items-center gap-2">
                <span>{session.device_info.browser}</span>
                <span>•</span>
                <span>{session.device_info.os}</span>
              </div>
              
              <div className="flex items-center gap-3 text-xs">
                {session.location && (
                  <span className="flex items-center gap-1">
                    <MapPin className="h-3 w-3" />
                    {session.location}
                  </span>
                )}
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  Active {formatRelativeTime(new Date(session.last_active_at))}
                </span>
              </div>
              
              <span className="font-mono text-xs text-muted-foreground/60">
                {session.ip_address}
              </span>
            </div>
          </div>
        </div>
        
        {!session.is_current && onRevoke && (
          <Button
            variant="ghost"
            size="sm"
            onClick={onRevoke}
            disabled={isRevoking}
          >
            {isRevoking ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <LogOut className="h-4 w-4" />
            )}
          </Button>
        )}
      </div>
    </div>
  )
}
