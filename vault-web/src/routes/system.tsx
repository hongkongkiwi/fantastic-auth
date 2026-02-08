import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Activity, Shield, ToggleLeft, Server, CheckCircle2, AlertCircle } from 'lucide-react'
import { PageHeader } from '../components/layout/Layout'
import { Card } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/Tabs'
import { Switch } from '../components/ui/Switch'

export const Route = createFileRoute('/system')({
  component: SystemPage,
})

interface FeatureFlag {
  id: string
  name: string
  key: string
  description: string
  enabled: boolean
  rollout: number
}

const flagsMock: FeatureFlag[] = [
  {
    id: 'ff-1',
    name: 'New Billing Engine',
    key: 'billing_v2',
    description: 'Enable the new billing pipeline for eligible tenants',
    enabled: true,
    rollout: 25,
  },
  {
    id: 'ff-2',
    name: 'Realtime Audit',
    key: 'audit_stream',
    description: 'Stream audit events to configured destinations',
    enabled: false,
    rollout: 0,
  },
]

const healthChecks = [
  { service: 'API', status: 'healthy', latency: '120ms' },
  { service: 'Auth', status: 'healthy', latency: '95ms' },
  { service: 'Billing', status: 'degraded', latency: '420ms' },
  { service: 'Webhooks', status: 'healthy', latency: '160ms' },
]

function SystemPage() {
  const [flags, setFlags] = useState(flagsMock)
  const prefersReducedMotion = useReducedMotion()

  const toggleFlag = (id: string) => {
    setFlags((prev) => prev.map((flag) => (flag.id === id ? { ...flag, enabled: !flag.enabled } : flag)))
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="System"
        description="Health, feature flags, and maintenance controls"
        breadcrumbs={[{ label: 'System' }]}
        actions={
          <Button variant="outline">
            <Server className="mr-2 h-4 w-4" />
            Run Diagnostics
          </Button>
        }
      />

      <Tabs defaultValue="health" className="space-y-6">
        <TabsList className="flex flex-wrap">
          <TabsTrigger value="health">Health</TabsTrigger>
          <TabsTrigger value="flags">Feature Flags</TabsTrigger>
          <TabsTrigger value="maintenance">Maintenance</TabsTrigger>
        </TabsList>

        <TabsContent value="health" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {healthChecks.map((check, index) => (
              <motion.div
                key={check.service}
                initial={prefersReducedMotion ? false : { opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.05 }}
              >
                <Card className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Activity className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">{check.service}</p>
                        <p className="text-sm text-muted-foreground">Latency {check.latency}</p>
                      </div>
                    </div>
                    <Badge variant={check.status === 'healthy' ? 'success' : 'warning'}>
                      {check.status}
                    </Badge>
                  </div>
                </Card>
              </motion.div>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="flags" className="space-y-4">
          <div className="space-y-4">
            {flags.map((flag) => (
              <Card key={flag.id} className="p-6">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-primary" />
                      <h3 className="font-semibold">{flag.name}</h3>
                      <Badge variant="secondary" className="font-mono text-xs">
                        {flag.key}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mt-2">{flag.description}</p>
                    <p className="text-xs text-muted-foreground mt-2">
                      Rollout: {flag.rollout}%
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={flag.enabled} onCheckedChange={() => toggleFlag(flag.id)} />
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="maintenance" className="space-y-4">
          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-semibold">Maintenance Mode</h3>
                <p className="text-sm text-muted-foreground">Pause logins and API traffic</p>
              </div>
              <Switch />
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                <ToggleLeft className="h-5 w-5 text-primary" />
                <div>
                  <h4 className="font-medium">Background Jobs</h4>
                  <p className="text-sm text-muted-foreground">Queue processing and webhooks</p>
                </div>
              </div>
              <Badge variant="success" className="flex items-center gap-1">
                <CheckCircle2 className="h-3 w-3" />
                Healthy
              </Badge>
            </div>
            <div className="mt-4 flex items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                <AlertCircle className="h-5 w-5 text-amber-500" />
                <div>
                  <h4 className="font-medium">Email Delivery</h4>
                  <p className="text-sm text-muted-foreground">Retry queue delayed</p>
                </div>
              </div>
              <Badge variant="warning">Degraded</Badge>
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
