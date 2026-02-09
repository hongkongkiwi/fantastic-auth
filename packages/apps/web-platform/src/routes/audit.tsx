import { createFileRoute } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  ClipboardList,
  Download,
  Calendar,
  User,
  Building2,
  CheckCircle2,
  AlertCircle,
  Shield,
  Settings,
  Eye,
  ShieldAlert,
  LogOut,
} from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader } from '../components/layout/Layout'
import { DataTable } from '../components/DataTable'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card'
import { Input } from '../components/ui/Input'
import { Select } from '../components/ui/Select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/Tabs'
import { Alert, AlertDescription, AlertTitle } from '../components/ui/Alert'
import { useServerFn } from '@tanstack/react-start'
import { listAudit, downloadAudit, type AuditLogEvent } from '../server/internal-api'
import { toast } from '../components/ui/Toaster'
import { formatDateTime, formatRelativeTime } from '../lib/utils'
import { cn } from '../lib/utils'
import { env } from '../env/client'

export const Route = createFileRoute('/audit')({
  component: AuditPage,
})

// Platform-level action icons
const actionIcons: Record<string, React.ReactNode> = {
  'tenant.create': <Building2 className="h-4 w-4" aria-hidden="true" />,
  'tenant.update': <Settings className="h-4 w-4" aria-hidden="true" />,
  'tenant.suspend': <AlertCircle className="h-4 w-4" aria-hidden="true" />,
  'tenant.activate': <CheckCircle2 className="h-4 w-4" aria-hidden="true" />,
  'tenant.delete': <AlertCircle className="h-4 w-4" aria-hidden="true" />,
  'user.create': <User className="h-4 w-4" aria-hidden="true" />,
  'auth.login': <Shield className="h-4 w-4" aria-hidden="true" />,
  'auth.logout': <Shield className="h-4 w-4" aria-hidden="true" />,
  // Impersonation actions
  'impersonation.start': <Eye className="h-4 w-4" aria-hidden="true" />,
  'impersonation.end': <LogOut className="h-4 w-4" aria-hidden="true" />,
  'impersonation.action': <ShieldAlert className="h-4 w-4" aria-hidden="true" />,
}

const actionColors: Record<string, string> = {
  'tenant.create': 'bg-blue-500/10 text-blue-600',
  'tenant.update': 'bg-slate-500/10 text-slate-600',
  'tenant.suspend': 'bg-amber-500/10 text-amber-600',
  'tenant.activate': 'bg-green-500/10 text-green-600',
  'tenant.delete': 'bg-red-500/10 text-red-600',
  'user.create': 'bg-purple-500/10 text-purple-600',
  'auth.login': 'bg-emerald-500/10 text-emerald-600',
  'auth.logout': 'bg-gray-500/10 text-gray-600',
  // Impersonation - highlighted in amber
  'impersonation.start': 'bg-amber-500/10 text-amber-600',
  'impersonation.end': 'bg-gray-500/10 text-gray-600',
  'impersonation.action': 'bg-orange-500/10 text-orange-600',
}

const actionLabels: Record<string, string> = {
  'tenant.create': 'Tenant Created',
  'tenant.update': 'Tenant Updated',
  'tenant.suspend': 'Tenant Suspended',
  'tenant.activate': 'Tenant Activated',
  'tenant.delete': 'Tenant Deleted',
  'tenant.migrate': 'Tenant Migrated',
  'user.create': 'User Created',
  'user.update': 'User Updated',
  'user.delete': 'User Deleted',
  'auth.login': 'Login',
  'auth.logout': 'Logout',
  'auth.expired': 'Session Expired',
  'subscription.update': 'Subscription Updated',
  'invoice.generate': 'Invoice Generated',
  // Impersonation labels
  'impersonation.start': 'Support Access Started',
  'impersonation.end': 'Support Access Ended',
  'impersonation.action': 'Action During Support Access',
}

const filterOptions = [
  { value: '', label: 'All Actions' },
  { value: 'tenant', label: 'Tenant Actions' },
  { value: 'user', label: 'User Actions' },
  { value: 'auth', label: 'Authentication' },
  { value: 'subscription', label: 'Billing' },
  { value: 'impersonation', label: 'Support Access' },
]

function AuditPage() {
  const supportImpersonationEnabled =
    env.VITE_ENABLE_SUPPORT_IMPERSONATION === 'true'
  const [events, setEvents] = useState<AuditLogEvent[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [dateRange, setDateRange] = useState({ since: '', until: '' })
  const [activeTab, setActiveTab] = useState('platform')
  const prefersReducedMotion = useReducedMotion()

  const listAuditFn = useServerFn(listAudit)
  const downloadAuditFn = useServerFn(downloadAudit)

  const fetchAudit = async (page = 1) => {
    setIsLoading(true)
    try {
      const result = await listAuditFn({
        data: {
          action: filter || undefined,
          since: dateRange.since || undefined,
          until: dateRange.until || undefined,
          page,
          perPage: 50,
          sort: 'desc',
        },
      })
      setEvents(result.data || [])
    } catch (error) {
      toast.error('Failed to load audit logs')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchAudit()
  }, [filter, dateRange])

  const handleDownload = async () => {
    try {
      const result = await downloadAuditFn({
        data: {
          action: filter || undefined,
          since: dateRange.since || undefined,
          until: dateRange.until || undefined,
        },
      })
      
      // Handle the download
      const blob = new Blob([result as string], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `audit-log-${new Date().toISOString().split('T')[0]}.csv`
      link.click()
      URL.revokeObjectURL(url)
      
      toast.success('Audit log downloaded')
    } catch (error) {
      toast.error('Failed to download audit log')
    }
  }

  const impersonationEvents = events.filter((event) =>
    (event.action || '').startsWith('impersonation'),
  )
  const platformEvents = events.filter(
    (event) => !(event.action || '').startsWith('impersonation'),
  )

  // Filter events based on active tab
  const displayEvents =
    activeTab === 'platform'
      ? platformEvents
      : activeTab === 'impersonation'
        ? impersonationEvents
        : events

  const columns: ColumnDef<AuditLogEvent>[] = [
    {
      accessorKey: 'timestamp',
      header: 'Time',
      cell: ({ getValue }) => {
        const date = getValue() as string
        return (
          <div className="flex flex-col">
            <span className="text-sm">{formatDateTime(date)}</span>
            <span className="text-xs text-muted-foreground">{formatRelativeTime(date)}</span>
          </div>
        )
      },
    },
    {
      accessorKey: 'action',
      header: 'Action',
      cell: ({ getValue }) => {
        const action = getValue() as string
        const icon = actionIcons[action] || <ClipboardList className="h-4 w-4" aria-hidden="true" />
        const colorClass = actionColors[action] || 'bg-gray-500/10 text-gray-600'
        const label = actionLabels[action] || action

        return (
          <div className="flex items-center gap-3">
            <div className={cn('p-2 rounded-full', colorClass)}>{icon}</div>
            <span className="font-medium">{label}</span>
          </div>
        )
      },
    },
    {
      accessorKey: 'actor',
      header: 'Actor',
      cell: ({ row, getValue }) => {
        const actor = getValue() as string
        const isImpersonation = (row.original.action as string)?.startsWith('impersonation')
        return (
          <div className="flex items-center gap-2">
            <span className="text-sm">{actor}</span>
            {isImpersonation && (
              <Badge variant="warning" className="text-xs">Support Access</Badge>
            )}
          </div>
        )
      },
    },
    {
      accessorKey: 'tenantName',
      header: 'Tenant',
      cell: ({ getValue }) => {
        const tenant = getValue() as string
        if (!tenant) return <span className="text-muted-foreground">—</span>
        return (
          <Badge variant="secondary" className="font-mono text-xs">
            {tenant}
          </Badge>
        )
      },
    },
    {
      accessorKey: 'detail',
      header: 'Details',
      cell: ({ getValue }) => (
        <p className="text-sm text-muted-foreground max-w-md truncate">{getValue() as string}</p>
      ),
    },
    {
      accessorKey: 'source',
      header: 'Source',
      cell: ({ getValue }) => {
        const source = getValue() as string
        return (
          <Badge variant={source === 'ui' ? 'default' : 'secondary'}>
            {source?.toUpperCase() || 'API'}
          </Badge>
        )
      },
    },
  ]

  // Mock stats
  const stats = {
    today: 245,
    thisWeek: 1847,
    thisMonth: 8934,
    impersonationSessions: supportImpersonationEnabled
      ? impersonationEvents.filter((e) => e.action === 'impersonation.start').length
      : 0,
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform Audit Logs"
        description="Track all platform administrative actions and support access sessions"
        breadcrumbs={[{ label: 'Platform Audit' }]}
        actions={
          <Button variant="outline" leftIcon={<Download className="h-4 w-4" />} onClick={handleDownload}>
            Export CSV
          </Button>
        }
      />

      {/* Privacy Notice */}
      <Alert>
        <Shield className="h-4 w-4" />
        <AlertTitle>Privacy & Accountability</AlertTitle>
        <AlertDescription>
          This audit log tracks all platform-level actions. Support access sessions (impersonation) are 
          logged separately and include the reason for access and duration. All actions taken during 
          support access are attributed to the platform admin.
        </AlertDescription>
      </Alert>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Today', value: stats.today, icon: Calendar, color: 'blue' },
          { label: 'This Week', value: stats.thisWeek, icon: ClipboardList, color: 'green' },
          { label: 'This Month', value: stats.thisMonth, icon: ClipboardList, color: 'purple' },
          { label: 'Support Sessions', value: stats.impersonationSessions, icon: Eye, color: 'amber' },
        ].map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.1 }}
          >
            <Card className="p-6 card-hover">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">{stat.label}</p>
                  <p className="text-2xl font-bold mt-1">{stat.value.toLocaleString()}</p>
                </div>
                <div className={cn('p-3 rounded-lg', `bg-${stat.color}-500/10`)}>
                  <stat.icon className={cn('h-5 w-5', `text-${stat.color}-600`)} />
                </div>
              </div>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Tabs for different audit views */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList>
          <TabsTrigger value="all">All Events</TabsTrigger>
          <TabsTrigger value="platform">Platform Actions</TabsTrigger>
          {supportImpersonationEnabled ? (
            <TabsTrigger value="impersonation" className="flex items-center gap-2">
              <Eye className="h-4 w-4" />
              Support Access
              {impersonationEvents.length > 0 && (
                <Badge variant="secondary" className="ml-1 text-xs">{impersonationEvents.length}</Badge>
              )}
            </TabsTrigger>
          ) : null}
        </TabsList>

        <TabsContent value="all" className="space-y-6">
          <FiltersCard 
            filter={filter} 
            setFilter={setFilter} 
            dateRange={dateRange} 
            setDateRange={setDateRange}
            onClear={() => { setFilter(''); setDateRange({ since: '', until: '' }) }}
          />
          <AuditTable 
            columns={columns} 
            data={displayEvents} 
            isLoading={isLoading}
            emptyMessage="No audit events found"
          />
        </TabsContent>

        <TabsContent value="platform" className="space-y-6">
          <FiltersCard 
            filter={filter} 
            setFilter={setFilter} 
            dateRange={dateRange} 
            setDateRange={setDateRange}
            onClear={() => { setFilter(''); setDateRange({ since: '', until: '' }) }}
          />
          <AuditTable 
            columns={columns} 
            data={displayEvents} 
            isLoading={isLoading}
            emptyMessage="No platform actions found"
          />
        </TabsContent>

        {supportImpersonationEnabled ? (
          <TabsContent value="impersonation" className="space-y-6">
            <FiltersCard 
              filter={filter} 
              setFilter={setFilter} 
              dateRange={dateRange} 
              setDateRange={setDateRange}
              onClear={() => { setFilter(''); setDateRange({ since: '', until: '' }) }}
            />
            <AuditTable 
              columns={columns} 
              data={displayEvents} 
              isLoading={isLoading}
              emptyMessage="No support access events found"
            />
          </TabsContent>
        ) : null}
      </Tabs>
    </div>
  )
}

// Filter card component
function FiltersCard({ 
  filter, 
  setFilter, 
  dateRange, 
  setDateRange, 
  onClear 
}: { 
  filter: string
  setFilter: (value: string) => void
  dateRange: { since: string; until: string }
  setDateRange: (range: { since: string; until: string }) => void
  onClear: () => void
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Filters</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="w-full sm:w-64">
            <Select
              label="Action Type"
              options={filterOptions}
              value={filter}
              onChange={(value) => setFilter(value)}
              name="actionFilter"
              autoComplete="off"
            />
          </div>
          <div className="w-full sm:w-48">
            <Input
              label="From"
              type="date"
              value={dateRange.since}
              onChange={(e) => setDateRange({ ...dateRange, since: e.target.value })}
              name="sinceDate"
              autoComplete="off"
            />
          </div>
          <div className="w-full sm:w-48">
            <Input
              label="To"
              type="date"
              value={dateRange.until}
              onChange={(e) => setDateRange({ ...dateRange, until: e.target.value })}
              name="untilDate"
              autoComplete="off"
            />
          </div>
          <div className="flex items-end">
            <Button variant="outline" onClick={onClear}>
              Clear Filters
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

// Audit table component
function AuditTable({ 
  columns, 
  data, 
  isLoading,
  emptyMessage
}: { 
  columns: ColumnDef<AuditLogEvent>[]
  data: AuditLogEvent[]
  isLoading: boolean
  emptyMessage: string
}) {
  return (
    <Card>
      {data.length === 0 && !isLoading ? (
        <div className="text-center py-12 text-muted-foreground">
          <ClipboardList className="h-12 w-12 mx-auto mb-3 opacity-50" />
          <p>{emptyMessage}</p>
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={data}
          isLoading={isLoading}
          pagination
          pageSize={50}
          exportable={false}
        />
      )}
    </Card>
  )
}
