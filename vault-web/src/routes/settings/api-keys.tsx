import { createFileRoute } from '@tanstack/react-router'
import { PageHeader } from '../../components/layout/Layout'
import { Card } from '../../components/ui/Card'
import { ApiKeyManager } from '../../components/settings'

export const Route = createFileRoute('/settings/api-keys')({
  component: ApiKeysSettingsPage,
})

function ApiKeysSettingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="API Keys"
        description="Manage API access tokens"
        breadcrumbs={[
          { label: 'Settings', href: '/settings' },
          { label: 'API Keys' },
        ]}
      />

      <Card className="p-6">
        <ApiKeyManager />
      </Card>
    </div>
  )
}
