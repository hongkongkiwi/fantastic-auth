import { Suspense, lazy } from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { PageHeader } from '../../components/layout/Layout'
import { Card } from '../../components/ui/Card'
import { Skeleton } from '../../components/ui/Skeleton'

export const Route = createFileRoute('/settings/webhooks')({
  component: WebhooksSettingsPage,
})

const WebhookManager = lazy(() =>
  import('../../components/webhooks/WebhookManager').then((mod) => ({
    default: mod.WebhookManager,
  }))
)

function WebhooksSettingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Webhook Settings"
        description="Configure endpoints to receive real-time event notifications"
        breadcrumbs={[
          { label: 'Settings', href: '/settings' },
          { label: 'Webhooks' },
        ]}
      />

      <Card className="p-6">
        <Suspense fallback={<Skeleton className="h-72 w-full" />}>
          <WebhookManager />
        </Suspense>
      </Card>
    </div>
  )
}
