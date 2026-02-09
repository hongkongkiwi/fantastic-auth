import { createFileRoute } from '@tanstack/react-router'
import { motion, useReducedMotion } from 'framer-motion'
import { Bell, CheckCircle2, AlertCircle, Info, Trash2, Mail } from 'lucide-react'
import { PageHeader } from '../components/layout/Layout'
import { Card } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useServerFn } from '@tanstack/react-start'
import { listNotifications, markNotificationsRead, type NotificationResponse } from '../server/internal-api'
import { toast } from '../components/ui/Toaster'

export const Route = createFileRoute('/notifications')({
  component: NotificationsPage,
})

type NotificationItem = NotificationResponse

const iconMap = {
  info: Info,
  warning: AlertCircle,
  success: CheckCircle2,
}

function NotificationsPage() {
  const queryClient = useQueryClient()
  const listNotificationsFn = useServerFn(listNotifications)
  const markNotificationsReadFn = useServerFn(markNotificationsRead)
  const { data: notifications = [], isLoading } = useQuery({
    queryKey: ['notifications'],
    queryFn: () => listNotificationsFn({ data: {} }),
  })
  const prefersReducedMotion = useReducedMotion()

  const markReadMutation = useMutation({
    mutationFn: async (ids: string[]) => markNotificationsReadFn({ data: { ids } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] })
      toast.success('Notifications updated')
    },
    onError: () => toast.error('Failed to update notifications'),
  })

  const markAllRead = () => {
    const ids = notifications.filter((n) => !n.read).map((n) => n.id)
    if (ids.length === 0) return
    markReadMutation.mutate(ids)
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Notifications"
        description="System alerts and admin notifications"
        breadcrumbs={[{ label: 'Notifications' }]}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={markAllRead}>
              <CheckCircle2 className="mr-2 h-4 w-4" />
              Mark All Read
            </Button>
            <Button>
              <Mail className="mr-2 h-4 w-4" />
              Send Announcement
            </Button>
          </div>
        }
      />

      <div className="space-y-4">
        {notifications.map((notification, index) => {
          const Icon = iconMap[notification.type]
          return (
            <motion.div
              key={notification.id}
              initial={prefersReducedMotion ? false : { opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.05 }}
            >
              <Card className={notification.read ? 'opacity-70' : ''}>
                <div className="p-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                  <div className="flex items-start gap-4">
                    <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                      <Icon className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold">{notification.title}</h3>
                        {!notification.read && <Badge variant="warning">New</Badge>}
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        {notification.description}
                      </p>
                      <p className="text-xs text-muted-foreground mt-2">
                        {new Date(notification.createdAt).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="ghost" size="icon" aria-label="Dismiss notification">
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </Card>
            </motion.div>
          )
        })}
      </div>

      {!isLoading && notifications.length === 0 && (
        <Card className="p-12 text-center">
          <Bell className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
          <h3 className="text-lg font-medium">No notifications</h3>
          <p className="text-sm text-muted-foreground mt-1">
            You&apos;re all caught up.
          </p>
        </Card>
      )}
    </div>
  )
}
