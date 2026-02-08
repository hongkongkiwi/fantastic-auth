import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Bell, CheckCircle2, AlertCircle, Info, Trash2, Mail } from 'lucide-react'
import { PageHeader } from '../components/layout/Layout'
import { Card } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'

export const Route = createFileRoute('/notifications')({
  component: NotificationsPage,
})

interface NotificationItem {
  id: string
  title: string
  description: string
  createdAt: string
  type: 'info' | 'warning' | 'success'
  read: boolean
}

const notificationsMock: NotificationItem[] = [
  {
    id: 'notif-1',
    title: 'Billing webhook failed',
    description: 'Stripe webhook endpoint returned 500 for tenant Acme Inc.',
    createdAt: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
    type: 'warning',
    read: false,
  },
  {
    id: 'notif-2',
    title: 'New admin added',
    description: 'Jamie Liu was granted Platform Admin role.',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
    type: 'success',
    read: false,
  },
  {
    id: 'notif-3',
    title: 'Weekly usage report ready',
    description: 'Download the latest usage export for all tenants.',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
    type: 'info',
    read: true,
  },
]

const iconMap = {
  info: Info,
  warning: AlertCircle,
  success: CheckCircle2,
}

function NotificationsPage() {
  const [notifications, setNotifications] = useState(notificationsMock)
  const prefersReducedMotion = useReducedMotion()

  const markAllRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })))
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

      {notifications.length === 0 && (
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
