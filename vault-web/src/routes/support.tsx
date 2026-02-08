import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { HelpCircle, Ticket, AlertTriangle, LifeBuoy, CheckCircle2 } from 'lucide-react'
import { PageHeader } from '../components/layout/Layout'
import { Card } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/Tabs'

export const Route = createFileRoute('/support')({
  component: SupportPage,
})

const ticketsMock = [
  {
    id: 'SUP-1023',
    subject: 'Login failures for tenant Acme Inc',
    status: 'open',
    priority: 'high',
    updatedAt: new Date(Date.now() - 1000 * 60 * 40).toISOString(),
  },
  {
    id: 'SUP-1019',
    subject: 'Webhook retry delays',
    status: 'pending',
    priority: 'medium',
    updatedAt: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
  },
  {
    id: 'SUP-1012',
    subject: 'Billing invoice mismatch',
    status: 'resolved',
    priority: 'low',
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
  },
]

const incidentsMock = [
  {
    id: 'INC-3001',
    title: 'Email delivery delays',
    status: 'monitoring',
    startedAt: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
  },
  {
    id: 'INC-2997',
    title: 'API latency spike',
    status: 'resolved',
    startedAt: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
  },
]

const statusMock = [
  { service: 'API', status: 'operational' },
  { service: 'Auth', status: 'degraded' },
  { service: 'Billing', status: 'operational' },
  { service: 'Webhooks', status: 'operational' },
]

function SupportPage() {
  const [tickets] = useState(ticketsMock)
  const prefersReducedMotion = useReducedMotion()

  return (
    <div className="space-y-6">
      <PageHeader
        title="Support"
        description="Tickets, status, and incident history"
        breadcrumbs={[{ label: 'Support' }]}
        actions={
          <Button>
            <Ticket className="mr-2 h-4 w-4" />
            Create Ticket
          </Button>
        }
      />

      <Tabs defaultValue="tickets" className="space-y-6">
        <TabsList className="flex flex-wrap">
          <TabsTrigger value="tickets">Tickets</TabsTrigger>
          <TabsTrigger value="status">Status</TabsTrigger>
          <TabsTrigger value="incidents">Incidents</TabsTrigger>
        </TabsList>

        <TabsContent value="tickets" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {tickets.map((ticket, index) => (
              <motion.div
                key={ticket.id}
                initial={prefersReducedMotion ? false : { opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.05 }}
              >
                <Card className="p-6">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold">{ticket.subject}</h3>
                        <Badge variant={ticket.priority === 'high' ? 'destructive' : ticket.priority === 'medium' ? 'warning' : 'secondary'}>
                          {ticket.priority}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">{ticket.id}</p>
                    </div>
                    <Badge variant={ticket.status === 'resolved' ? 'success' : ticket.status === 'open' ? 'warning' : 'secondary'}>
                      {ticket.status}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mt-3">
                    Updated {new Date(ticket.updatedAt).toLocaleString()}
                  </p>
                </Card>
              </motion.div>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="status" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {statusMock.map((service) => (
              <Card key={service.service} className="p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <LifeBuoy className="h-5 w-5 text-primary" />
                    <span className="font-medium">{service.service}</span>
                  </div>
                  <Badge variant={service.status === 'operational' ? 'success' : 'warning'}>
                    {service.status}
                  </Badge>
                </div>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="incidents" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {incidentsMock.map((incident) => (
              <Card key={incident.id} className="p-6">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      {incident.status === 'resolved' ? (
                        <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                      ) : (
                        <AlertTriangle className="h-5 w-5 text-amber-500" />
                      )}
                      <h3 className="font-semibold">{incident.title}</h3>
                    </div>
                    <p className="text-xs text-muted-foreground mt-2">{incident.id}</p>
                  </div>
                  <Badge variant={incident.status === 'resolved' ? 'success' : 'warning'}>
                    {incident.status}
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground mt-3">
                  Started {new Date(incident.startedAt).toLocaleString()}
                </p>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>

      {tickets.length === 0 && (
        <Card className="p-12 text-center">
          <HelpCircle className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
          <h3 className="text-lg font-medium">No active support items</h3>
          <p className="text-sm text-muted-foreground mt-1">
            You&apos;re all caught up.
          </p>
        </Card>
      )}
    </div>
  )
}
