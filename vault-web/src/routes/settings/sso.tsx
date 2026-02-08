import { createFileRoute } from '@tanstack/react-router'
import { PageHeader } from '../../components/layout/Layout'
import { Card } from '../../components/ui/Card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/Tabs'
import { SamlConfiguration, OAuthProviderSettings } from '../../components/settings'

export const Route = createFileRoute('/settings/sso')({
  component: SsoSettingsPage,
})

function SsoSettingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="SSO & Integrations"
        description="Configure SAML and OAuth providers"
        breadcrumbs={[
          { label: 'Settings', href: '/settings' },
          { label: 'SSO' },
        ]}
      />

      <Tabs defaultValue="saml" className="space-y-6">
        <TabsList>
          <TabsTrigger value="saml">SAML</TabsTrigger>
          <TabsTrigger value="oauth">OAuth</TabsTrigger>
        </TabsList>

        <TabsContent value="saml" className="space-y-4">
          <Card className="p-6">
            <SamlConfiguration />
          </Card>
        </TabsContent>

        <TabsContent value="oauth" className="space-y-4">
          <Card className="p-6">
            <OAuthProviderSettings />
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
