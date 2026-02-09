import { createFileRoute, useParams, Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  Users,
  CreditCard,
  Calendar,
  User,
  Activity,
  CheckCircle2,
  AlertCircle,
  Pause,
  Play,
  Trash2,
} from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader, StatCard } from '../../components/layout/Layout'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/Tabs'
import { ConfirmDialog } from '../../components/ui/Dialog'
import { Skeleton } from '../../components/ui/Skeleton'
import { DataTable } from '../../components/DataTable'
import { useServerFn } from '@tanstack/react-start'
import {
  getTenantDetail,
  searchUsers,
  suspendTenant,
  activateTenant,
  deleteTenant,
  type TenantDetail,
  type PlatformUserResponse,
} from '../../server/internal-api'
import { toast } from '../../components/ui/Toaster'
import { formatDate, formatDateTime, formatNumber, formatRelativeTime } from '../../lib/utils'
import { cn } from '../../lib/utils'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

export const Route = createFileRoute('/tenants/$id')({
  component: TenantDetailPage,
})

const usageData = [
  { day: 'Mon', apiCalls: 1200, users: 45 },
  { day: 'Tue', apiCalls: 1800, users: 52 },
  { day: 'Wed', apiCalls: 2400, users: 58 },
  { day: 'Thu', apiCalls: 2100, users: 61 },
  { day: 'Fri', apiCalls: 2800, users: 65 },
  { day: 'Sat', apiCalls: 1500, users: 42 },
  { day: 'Sun', apiCalls: 1200, users: 38 },
]

const now = Date.now()
const recentActivity = [
  { id: 1, action: 'User Login', user: 'john@example.com', timestamp: new Date(now - 2 * 60 * 1000).toISOString(), status: 'success' },
  { id: 2, action: 'API Key Created', user: 'admin', timestamp: new Date(now - 15 * 60 * 1000).toISOString(), status: 'success' },
  { id: 3, action: 'Password Reset', user: 'jane@example.com', timestamp: new Date(now - 60 * 60 * 1000).toISOString(), status: 'success' },
  { id: 4, action: 'Failed Login', user: 'unknown', timestamp: new Date(now - 2 * 60 * 60 * 1000).toISOString(), status: 'error' },
]

const tenantUserColumns: ColumnDef<PlatformUserResponse>[] = [
  {
    accessorKey: 'name',
    header: 'User',
    cell: ({ row }) => (
      <div>
        <p className="font-medium">{row.original.name || 'Unnamed User'}</p>
        <p className="text-sm text-muted-foreground">{row.original.email ?? '—'}</p>
      </div>
    ),
  },
  {
    id: 'role',
    header: 'Role',
    accessorFn: () => 'member',
    cell: ({ getValue }) => <Badge variant="secondary">{getValue() as string}</Badge>,
  },
  {
    id: 'seats',
    header: 'Seats',
    accessorFn: () => 1,
    cell: ({ getValue }) => getValue() as number,
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ getValue }) => (
      <Badge variant={getValue() === 'active' ? 'success' : 'warning'}>{getValue() as string}</Badge>
    ),
  },
]

function TenantDetailPage() {
  const { id } = useParams({ from: '/tenants/$id' })
  const [tenant, setTenant] = useState<TenantDetail | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [tenantUsers, setTenantUsers] = useState<PlatformUserResponse[]>([])
  const [isUsersLoading, setIsUsersLoading] = useState(false)
  const [dialogState, setDialogState] = useState<'suspend' | 'activate' | 'delete' | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const prefersReducedMotion = useReducedMotion()

  const getTenantFn = useServerFn(getTenantDetail)
  const searchUsersFn = useServerFn(searchUsers)
  const suspendTenantFn = useServerFn(suspendTenant)
  const activateTenantFn = useServerFn(activateTenant)
  const deleteTenantFn = useServerFn(deleteTenant)

  useEffect(() => {
    const fetchTenant = async () => {
      try {
        const data = await getTenantFn({ data: { tenantId: id } })
        setTenant(data)
      } catch (error) {
        toast.error('Failed to load tenant details')
      } finally {
        setIsLoading(false)
      }
    }
    fetchTenant()
  }, [id])

  useEffect(() => {
    const fetchTenantUsers = async () => {
      setIsUsersLoading(true)
      try {
        const result = await searchUsersFn({ data: { tenantId: id, page: 1 } })
        setTenantUsers(result.data || [])
      } catch {
        toast.error('Failed to load tenant users')
      } finally {
        setIsUsersLoading(false)
      }
    }
    fetchTenantUsers()
  }, [id])

  const handleAction = async () => {
    if (!tenant || !dialogState) return
    if (!tenant.id) {
      toast.error('Tenant ID is missing')
      return
    }

    setIsSubmitting(true)
    try {
      switch (dialogState) {
        case 'suspend':
          await suspendTenantFn({ data: { tenantId: tenant.id } })
          toast.success('Tenant suspended')
          break
        case 'activate':
          await activateTenantFn({ data: { tenantId: tenant.id } })
          toast.success('Tenant activated')
          break
        case 'delete':
          await deleteTenantFn({ data: { tenantId: tenant.id } })
          toast.success('Tenant deleted')
          window.location.href = '/tenants'
          return
      }
      const updated = await getTenantFn({ data: { tenantId: id } })
      setTenant(updated)
    } catch (error) {
      toast.error(`Failed to ${dialogState} tenant`)
    } finally {
      setIsSubmitting(false)
      setDialogState(null)
    }
  }

  const statusConfig: Record<string, { label: string; variant: 'default' | 'success' | 'warning' | 'destructive'; icon: any }> = {
    active: { label: 'Active', variant: 'success', icon: CheckCircle2 },
    suspended: { label: 'Suspended', variant: 'warning', icon: AlertCircle },
    inactive: { label: 'Inactive', variant: 'destructive', icon: AlertCircle },
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} variant="card" />
          ))}
        </div>
        <Skeleton variant="card" className="h-96" />
      </div>
    )
  }

  if (!tenant) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <AlertCircle className="h-12 w-12 text-muted-foreground mb-4" />
        <h2 className="text-xl font-semibold">Tenant not found</h2>
        <p className="text-muted-foreground mb-4">The tenant you're looking for doesn't exist</p>
        <Button asChild>
          <Link to="/tenants">Back to Tenants</Link>
        </Button>
      </div>
    )
  }

  const statusKey = tenant.status ?? 'inactive'
  const status = statusConfig[statusKey] || statusConfig.inactive
  const StatusIcon = status.icon
  const planKey = tenant.plan ?? 'unknown'
  const planLabel =
    planKey === 'unknown'
      ? 'Unknown'
      : planKey.charAt(0).toUpperCase() + planKey.slice(1)
  const createdAtLabel = tenant.createdAt ? formatDate(tenant.createdAt) : '—'
  const createdAtDateTime = tenant.createdAt ? formatDateTime(tenant.createdAt) : '—'
  const updatedAtDateTime = tenant.updatedAt
    ? formatDateTime(tenant.updatedAt)
    : createdAtDateTime

  return (
    <div className="space-y-6">
      <PageHeader
        title={tenant.name ?? 'Tenant'}
        description={tenant.slug ?? '—'}
        breadcrumbs={[
          { label: 'Tenants', href: '/tenants' },
          { label: tenant.name ?? 'Tenant' },
        ]}
        actions={
          <div className="flex items-center gap-2">
            {tenant.status === 'active' ? (
              <Button variant="outline" onClick={() => setDialogState('suspend')}>
                <Pause className="mr-2 h-4 w-4" />
                Suspend
              </Button>
            ) : (
              <Button variant="outline" onClick={() => setDialogState('activate')}>
                <Play className="mr-2 h-4 w-4" />
                Activate
              </Button>
            )}
            <Button variant="destructive" onClick={() => setDialogState('delete')}>
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </Button>
          </div>
        }
      />

      {/* Status Bar */}
      <Card className={cn('border-l-4', tenant.status === 'active' ? 'border-l-green-500' : 'border-l-amber-500')}>
        <CardContent className="flex items-center justify-between py-4">
          <div className="flex items-center gap-4">
            <div className={cn('p-2 rounded-full', tenant.status === 'active' ? 'bg-green-500/10' : 'bg-amber-500/10')}>
              <StatusIcon className={cn('h-5 w-5', tenant.status === 'active' ? 'text-green-600' : 'text-amber-600')} />
            </div>
            <div>
              <p className="font-medium">{status.label}</p>
              <p className="text-sm text-muted-foreground">
                {tenant.status === 'active' ? 'All services operational' : 'Tenant access restricted'}
              </p>
            </div>
          </div>
          <Badge variant={status.variant} size="lg">
            {status.label}
          </Badge>
        </CardContent>
      </Card>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Users"
          value={formatNumber(tenant.usage?.currentUsers ?? 0)}
          icon={<Users className="h-5 w-5" />}
          color="blue"
        />
        <StatCard
          title="Plan"
          value={planLabel}
          icon={<CreditCard className="h-5 w-5" />}
          color="purple"
        />
        <StatCard
          title="Created"
          value={createdAtLabel}
          icon={<Calendar className="h-5 w-5" />}
          color="green"
        />
        <StatCard
          title="API Calls (24h)"
          value={formatNumber(2450)}
          trend={{ value: 12, isPositive: true }}
          icon={<Activity className="h-5 w-5" />}
          color="amber"
        />
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="usage">Usage</TabsTrigger>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Details Card */}
            <Card>
              <CardHeader>
                <CardTitle>Tenant Details</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-muted-foreground">Tenant ID</p>
                    <p className="font-medium font-mono text-sm">{tenant.id ?? '—'}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Slug</p>
                    <p className="font-medium">{tenant.slug ?? '—'}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Plan</p>
                    <Badge variant={planKey === 'enterprise' ? 'warning' : planKey === 'pro' ? 'success' : 'default'}>
                      {planLabel}
                    </Badge>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Status</p>
                    <Badge variant={status.variant}>{status.label}</Badge>
                  </div>
                  {tenant.customDomain && (
                    <div className="col-span-2">
                      <p className="text-sm text-muted-foreground">Custom Domain</p>
                      <p className="font-medium">{tenant.customDomain}</p>
                    </div>
                  )}
                  <div>
                    <p className="text-sm text-muted-foreground">Created</p>
                    <p className="font-medium">{createdAtDateTime}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Last Updated</p>
                    <p className="font-medium">{updatedAtDateTime}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Owner Card */}
            <Card>
              <CardHeader>
                <CardTitle>Owner Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {tenant.owner ? (
                  <>
                    <div className="flex items-center gap-4">
                      <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center">
                        <User className="h-6 w-6 text-primary" />
                      </div>
                      <div>
                        <p className="font-medium">{tenant.owner.name || 'Unknown'}</p>
                        <p className="text-sm text-muted-foreground">{tenant.owner.email ?? 'unknown'}</p>
                      </div>
                    </div>
                    <div className="pt-4 border-t space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Email Verified</span>
                        <Badge variant="success">Yes</Badge>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Last Login</span>
                        <span>2 hours ago</span>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <User className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>No owner assigned</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="usage" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>API Usage (Last 7 Days)</CardTitle>
              <CardDescription>Daily API calls and active users</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={usageData}>
                    <defs>
                      <linearGradient id="colorApi" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                    <XAxis dataKey="day" stroke="#64748b" fontSize={12} />
                    <YAxis stroke="#64748b" fontSize={12} />
                    <Tooltip />
                    <Area
                      type="monotone"
                      dataKey="apiCalls"
                      stroke="#6366f1"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#colorApi)"
                      name="API Calls"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="pt-6">
                <p className="text-sm text-muted-foreground">API Calls (This Month)</p>
                <p className="text-2xl font-bold mt-1">{formatNumber(45200)}</p>
                <p className="text-sm text-green-600 mt-1">↑ 12% from last month</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <p className="text-sm text-muted-foreground">Storage Used</p>
                <p className="text-2xl font-bold mt-1">2.4 GB</p>
                <p className="text-sm text-muted-foreground mt-1">of 10 GB limit</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <p className="text-sm text-muted-foreground">Active Sessions</p>
                <p className="text-2xl font-bold mt-1">{formatNumber(156)}</p>
                <p className="text-sm text-green-600 mt-1">↑ 5% from yesterday</p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="users" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Tenant Users</CardTitle>
              <CardDescription>Manage members, roles, and seats for this tenant</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={tenantUserColumns}
                data={tenantUsers}
                isLoading={isUsersLoading}
                searchable
                searchPlaceholder="Search users…"
                pagination
                pageSize={5}
                exportable
                exportFileName={`tenant_${tenant.id || 'tenant'}_users`}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="activity" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Recent Activity</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentActivity.map((activity, index) => (
                  <motion.div
                    key={activity.id}
                    initial={prefersReducedMotion ? false : { opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.05 }}
                    className="flex items-start gap-4 p-3 rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <div
                      className={cn(
                        'p-2 rounded-full shrink-0',
                        activity.status === 'success' && 'bg-green-500/10 text-green-600',
                        activity.status === 'error' && 'bg-red-500/10 text-red-600'
                      )}
                    >
                      {activity.status === 'success' ? <CheckCircle2 className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
                    </div>
                    <div className="flex-1">
                      <p className="text-sm font-medium">{activity.action}</p>
                      <p className="text-sm text-muted-foreground">{activity.user}</p>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      <span title={activity.timestamp}>{formatRelativeTime(activity.timestamp)}</span>
                    </span>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Danger Zone</CardTitle>
              <CardDescription>Destructive actions for this tenant</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between p-4 border border-destructive/20 rounded-lg bg-destructive/5">
                <div>
                  <p className="font-medium text-destructive">Delete Tenant</p>
                  <p className="text-sm text-muted-foreground">Permanently delete this tenant and all associated data</p>
                </div>
                <Button variant="destructive" onClick={() => setDialogState('delete')}>
                  Delete
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Confirm Dialogs */}
      <ConfirmDialog
        isOpen={dialogState === 'suspend'}
        onClose={() => setDialogState(null)}
        onConfirm={handleAction}
        title="Suspend Tenant"
        description={`Are you sure you want to suspend "${tenant.name}"? This will prevent users from accessing the tenant.`}
        confirmText="Suspend"
        variant="destructive"
        isLoading={isSubmitting}
      />

      <ConfirmDialog
        isOpen={dialogState === 'activate'}
        onClose={() => setDialogState(null)}
        onConfirm={handleAction}
        title="Activate Tenant"
        description={`Are you sure you want to activate "${tenant.name}"?`}
        confirmText="Activate"
        isLoading={isSubmitting}
      />

      <ConfirmDialog
        isOpen={dialogState === 'delete'}
        onClose={() => setDialogState(null)}
        onConfirm={handleAction}
        title="Delete Tenant"
        description={`Are you sure you want to delete "${tenant.name}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="destructive"
        isLoading={isSubmitting}
      />
    </div>
  )
}
