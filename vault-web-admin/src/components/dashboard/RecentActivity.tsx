import { useMemo } from 'react'
import { 
  UserPlus, LogIn, LogOut, Shield, AlertTriangle, 
  Building2, Key, CheckCircle, XCircle, Clock
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { useAuditLogs } from '@/hooks/useApi'
import { cn, formatDate } from '@/lib/utils'
import type { AuditEventType } from '@/types'

interface RecentActivityProps {
  limit?: number
  className?: string
}

const eventIcons: Record<string, React.ElementType> = {
  'user.created': UserPlus,
  'user.login': LogIn,
  'user.logout': LogOut,
  'user.suspended': AlertTriangle,
  'user.activated': CheckCircle,
  'user.mfa_enabled': Shield,
  'user.mfa_disabled': Shield,
  'user.password_changed': Key,
  'org.created': Building2,
  'org.member_added': UserPlus,
  'org.member_removed': XCircle,
  'session.created': LogIn,
  'session.revoked': LogOut,
}

const eventLabels: Record<string, string> = {
  'user.created': 'User created',
  'user.login': 'User login',
  'user.logout': 'User logout',
  'user.suspended': 'User suspended',
  'user.activated': 'User activated',
  'user.mfa_enabled': 'MFA enabled',
  'user.mfa_disabled': 'MFA disabled',
  'user.password_changed': 'Password changed',
  'org.created': 'Organization created',
  'org.member_added': 'Member added',
  'org.member_removed': 'Member removed',
  'session.created': 'New session',
  'session.revoked': 'Session revoked',
}

const statusColors = {
  success: 'text-green-500 bg-green-50 dark:bg-green-950',
  failure: 'text-red-500 bg-red-50 dark:bg-red-950',
  blocked: 'text-yellow-500 bg-yellow-50 dark:bg-yellow-950',
}

export function RecentActivity({ limit = 10, className }: RecentActivityProps) {
  const { data, isLoading } = useAuditLogs({ limit })

  const activities = useMemo(() => {
    return data?.data || []
  }, [data])

  if (isLoading) {
    return (
      <div className={cn("bg-card rounded-lg border border-border", className)}>
        <div className="p-4 border-b border-border">
          <h3 className="font-semibold">Recent Activity</h3>
        </div>
        <div className="p-4 space-y-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 animate-pulse">
              <div className="w-8 h-8 rounded-full bg-muted" />
              <div className="flex-1 space-y-2">
                <div className="h-4 w-32 bg-muted rounded" />
                <div className="h-3 w-48 bg-muted rounded" />
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className={cn("bg-card rounded-lg border border-border", className)}>
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div>
          <h3 className="font-semibold">Recent Activity</h3>
          <p className="text-sm text-muted-foreground">Latest events across your organization</p>
        </div>
      </div>

      <div className="divide-y divide-border">
        {activities.length === 0 ? (
          <div className="p-8 text-center text-muted-foreground">
            <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p>No recent activity</p>
          </div>
        ) : (
          activities.map((activity) => {
            const Icon = eventIcons[activity.eventType] || Shield
            const label = eventLabels[activity.eventType] || activity.eventType
            const statusColor = statusColors[activity.status] || statusColors.success

            return (
              <div
                key={activity.id}
                className="p-4 flex items-start gap-4 hover:bg-muted/50 transition-colors"
              >
                <div className={cn("p-2 rounded-full flex-shrink-0", statusColor)}>
                  <Icon className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-medium truncate">{label}</p>
                    <span className="text-xs text-muted-foreground whitespace-nowrap">
                      {formatDate(activity.timestamp, 'relative')}
                    </span>
                  </div>
                  <p className="text-sm text-muted-foreground truncate">
                    {activity.actor.email || activity.actor.id || 'System'}
                    {activity.resource.name && (
                      <span className="ml-1">
                        on <span className="font-medium">{activity.resource.name}</span>
                      </span>
                    )}
                  </p>
                  {activity.status !== 'success' && (
                    <span className={cn(
                      "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium mt-1",
                      activity.status === 'failure' && "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
                      activity.status === 'blocked' && "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
                    )}>
                      {activity.status}
                    </span>
                  )}
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
