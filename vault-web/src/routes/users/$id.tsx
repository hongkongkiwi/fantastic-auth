import { createFileRoute, useParams, Link } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  User,
  Mail,
  Shield,
  Key,
  Activity,
  AlertCircle,
  MoreHorizontal,
  Users,
  RefreshCcw,
} from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader } from '../../components/layout/Layout'
import { Card, CardContent } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/Tabs'
import { DataTable } from '../../components/DataTable'
import { Input } from '../../components/ui/Input'
import { Select } from '../../components/ui/Select'
import { Skeleton } from '../../components/ui/Skeleton'
import { toast } from '../../components/ui/Toaster'
import { SessionManager } from '../../components/auth/SessionManager'
import { useServerFn } from '@tanstack/react-start'
import {
  getUser,
  listAudit,
  type PlatformUserDetailResponse,
  type AuditLogEvent,
} from '../../server/internal-api'
import { formatDate, formatDateTime, formatRelativeTime } from '../../lib/utils'
import { cn } from '../../lib/utils'

export const Route = createFileRoute('/users/$id')({
  component: UserDetailPage,
})

type Membership = NonNullable<PlatformUserDetailResponse['tenants']>[number]

const roleHistoryMock = [
  {
    id: 'rh-1',
    role: 'admin',
    scope: 'Tenant: acme-inc',
    grantedBy: 'system',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 14).toISOString(),
  },
  {
    id: 'rh-2',
    role: 'member',
    scope: 'Org: acme-inc',
    grantedBy: 'admin@acme.com',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 45).toISOString(),
  },
]

const auditActionOptions = [
  { value: '', label: 'All Actions' },
  { value: 'user', label: 'User Actions' },
  { value: 'auth', label: 'Authentication' },
  { value: 'ownership', label: 'Ownership Transfers' },
  { value: 'tenant', label: 'Tenant Actions' },
]

const actionIcons: Record<string, React.ReactNode> = {
  'user.create': <User className="h-4 w-4" aria-hidden="true" />,
  'user.update': <User className="h-4 w-4" aria-hidden="true" />,
  'user.delete': <User className="h-4 w-4" aria-hidden="true" />,
  'auth.login': <Shield className="h-4 w-4" aria-hidden="true" />,
  'auth.logout': <Shield className="h-4 w-4" aria-hidden="true" />,
}

const actionColors: Record<string, string> = {
  'user.create': 'bg-blue-500/10 text-blue-600',
  'user.update': 'bg-slate-500/10 text-slate-600',
  'user.delete': 'bg-red-500/10 text-red-600',
  'auth.login': 'bg-emerald-500/10 text-emerald-600',
  'auth.logout': 'bg-gray-500/10 text-gray-600',
}

function UserDetailPage() {
  const { id } = useParams({ from: '/users/$id' })
  const [user, setUser] = useState<PlatformUserDetailResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [auditEvents, setAuditEvents] = useState<AuditLogEvent[]>([])
  const [auditFilter, setAuditFilter] = useState('')
  const [auditQuery, setAuditQuery] = useState('')
  const prefersReducedMotion = useReducedMotion()

  const getUserFn = useServerFn(getUser)
  const listAuditFn = useServerFn(listAudit)

  useEffect(() => {
    const fetchUser = async () => {
      setIsLoading(true)
      try {
        const data = await getUserFn({ data: { userId: id } })
        setUser(data)
      } catch (error) {
        toast.error('Failed to load user details')
      } finally {
        setIsLoading(false)
      }
    }
    fetchUser()
  }, [id])

  useEffect(() => {
    const fetchAudit = async () => {
      try {
        const result = await listAuditFn({
          data: {
            action: auditFilter || undefined,
            page: 1,
            perPage: 200,
            sort: 'desc',
          },
        })
        setAuditEvents(result.data || [])
      } catch {
        toast.error('Failed to load audit events')
      }
    }
    fetchAudit()
  }, [auditFilter])

  const userTokens = useMemo(() => {
    const tokens = [user?.id, user?.email].filter(Boolean) as string[]
    return tokens.map((token) => token.toLowerCase())
  }, [user?.id, user?.email])

  const filteredAuditEvents = useMemo(() => {
    const query = auditQuery.trim().toLowerCase()
    return auditEvents.filter((event) => {
      const detail = (event.detail || '').toLowerCase()
      const matchesUser =
        userTokens.length === 0 || userTokens.some((token) => detail.includes(token))
      const matchesQuery = !query || detail.includes(query)
      return matchesUser && matchesQuery
    })
  }, [auditEvents, auditQuery, userTokens])

  const auditColumns: ColumnDef<AuditLogEvent>[] = [
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
        const icon = actionIcons[action] || <Activity className="h-4 w-4" aria-hidden="true" />
        const colorClass = actionColors[action] || 'bg-gray-500/10 text-gray-600'
        return (
          <div className="flex items-center gap-3">
            <div className={cn('p-2 rounded-full', colorClass)}>{icon}</div>
            <span className="font-medium">{action}</span>
          </div>
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
        return <Badge variant={source === 'ui' ? 'default' : 'secondary'}>{source?.toUpperCase() || 'API'}</Badge>
      },
    },
  ]

  const membershipColumns: ColumnDef<Membership>[] = [
    {
      accessorKey: 'tenantName',
      header: 'Tenant',
      cell: ({ row }) => (
        <div>
          <p className="font-medium">{row.original.tenantName || row.original.tenantSlug || '—'}</p>
          <p className="text-sm text-muted-foreground">{row.original.tenantId || '—'}</p>
        </div>
      ),
    },
    {
      accessorKey: 'role',
      header: 'Role',
      cell: ({ getValue }) => (
        <Badge variant="secondary">{(getValue() as string) || 'member'}</Badge>
      ),
    },
    {
      accessorKey: 'joinedAt',
      header: 'Joined',
      cell: ({ getValue }) => {
        const value = getValue() as string | undefined
        return value ? formatDate(value) : '—'
      },
    },
  ]

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton variant="card" className="h-48" />
        <Skeleton variant="card" className="h-96" />
      </div>
    )
  }

  if (!user) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <AlertCircle className="h-12 w-12 text-muted-foreground mb-4" />
        <h2 className="text-xl font-semibold">User not found</h2>
        <p className="text-muted-foreground mb-4">We couldn&apos;t find this user.</p>
        <Button asChild>
          <Link to="/users">Back to Users</Link>
        </Button>
      </div>
    )
  }

  const status = user.status || 'active'
  const statusVariant =
    status === 'active' ? 'success' : status === 'suspended' ? 'destructive' : 'warning'

  return (
    <div className="space-y-6">
      <PageHeader
        title={user.name || user.email || 'User'}
        description={user.email || user.id || 'User profile'}
        breadcrumbs={[
          { label: 'Users', href: '/users' },
          { label: user.name || user.email || 'User' },
        ]}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => toast.success('Password reset email queued')}
            >
              <Key className="mr-2 h-4 w-4" />
              Reset Password
            </Button>
            <Button
              variant="destructive"
              onClick={() => toast.success('User suspended')}
            >
              Suspend
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="lg:col-span-2"
        >
          <Card className="p-6">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-4">
                <div className="h-14 w-14 rounded-full bg-primary/10 flex items-center justify-center">
                  <User className="h-7 w-7 text-primary" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-xl font-semibold">{user.name || 'Unnamed User'}</h2>
                    <Badge variant={statusVariant}>{status}</Badge>
                  </div>
                  <p className="text-sm text-muted-foreground flex items-center gap-2 mt-1">
                    <Mail className="h-4 w-4" />
                    {user.email}
                  </p>
                </div>
              </div>
              <Button variant="ghost" size="icon" aria-label="User actions">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </div>

            <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">User ID</p>
                <p className="font-mono text-sm">{user.id}</p>
              </div>
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Created</p>
                <p className="text-sm">{user.createdAt ? formatDateTime(user.createdAt) : '—'}</p>
              </div>
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Last Login</p>
                <p className="text-sm">{user.lastLoginAt ? formatDateTime(user.lastLoginAt) : '—'}</p>
              </div>
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">MFA</p>
                <Badge variant={user.mfaEnabled ? 'success' : 'secondary'}>
                  {user.mfaEnabled ? 'Enabled' : 'Not enabled'}
                </Badge>
              </div>
            </div>
          </Card>
        </motion.div>

        <motion.div
          initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.1 }}
        >
          <Card className="p-6 space-y-4">
            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Security Signals</p>
              <div className="mt-3 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Failed logins</span>
                  <Badge variant="secondary">{user.failedLoginAttempts ?? 0}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Email verified</span>
                  <Badge variant={user.emailVerified ? 'success' : 'warning'}>
                    {user.emailVerified ? 'Yes' : 'No'}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Status</span>
                  <Badge variant={statusVariant}>{status}</Badge>
                </div>
              </div>
            </div>

            <div className="border-t pt-4">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Quick Actions</p>
              <div className="mt-3 grid grid-cols-1 gap-2">
                <Button variant="outline" onClick={() => toast.success('MFA reset queued')}>
                  <Shield className="mr-2 h-4 w-4" />
                  Reset MFA
                </Button>
                <Button variant="outline" onClick={() => toast.success('Verification email sent')}>
                  <Mail className="mr-2 h-4 w-4" />
                  Send Verification
                </Button>
                <Button variant="outline" onClick={() => toast.success('User invited to new tenant')}>
                  <Users className="mr-2 h-4 w-4" />
                  Add to Tenant
                </Button>
              </div>
            </div>
          </Card>
        </motion.div>
      </div>

      <Tabs defaultValue="memberships" className="space-y-6">
        <TabsList className="flex flex-wrap">
          <TabsTrigger value="memberships">Memberships</TabsTrigger>
          <TabsTrigger value="sessions">Sessions</TabsTrigger>
          <TabsTrigger value="audit">Audit Log</TabsTrigger>
          <TabsTrigger value="roles">Role History</TabsTrigger>
        </TabsList>

        <TabsContent value="memberships" className="space-y-4">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-lg font-medium">Tenant Memberships</h3>
                  <p className="text-sm text-muted-foreground">All tenants this user belongs to</p>
                </div>
                <Button variant="outline" size="sm">
                  <Users className="mr-2 h-4 w-4" />
                  Assign Tenant
                </Button>
              </div>
              <DataTable
                columns={membershipColumns}
                data={user.tenants || []}
                searchable
                searchPlaceholder="Search tenants…"
                pagination
                pageSize={5}
                exportable
                exportFileName={`user_${user.id || 'user'}_memberships`}
                emptyState={
                  <div className="text-center py-8 text-muted-foreground">
                    No tenant memberships found
                  </div>
                }
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sessions" className="space-y-4">
          <Card className="p-6">
            <SessionManager userId={user.id || id} />
          </Card>
        </TabsContent>

        <TabsContent value="audit" className="space-y-4">
          <Card>
            <CardContent className="p-6 space-y-4">
              <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
                <div>
                  <h3 className="text-lg font-medium">User Audit Log</h3>
                  <p className="text-sm text-muted-foreground">
                    Filtered by matches to user id/email in audit details
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Select
                    value={auditFilter}
                    onChange={setAuditFilter}
                    options={auditActionOptions}
                    className="min-w-[180px]"
                  />
                  <div className="relative">
                    <Input
                      placeholder="Filter details…"
                      value={auditQuery}
                      onChange={(event) => setAuditQuery(event.target.value)}
                      className="w-[200px]"
                      aria-label="Filter audit details"
                    />
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setAuditQuery('')}
                  >
                    <RefreshCcw className="mr-2 h-4 w-4" />
                    Reset
                  </Button>
                </div>
              </div>
              <DataTable
                columns={auditColumns}
                data={filteredAuditEvents}
                searchable={false}
                pagination
                pageSize={10}
                exportable
                exportFileName={`user_${user.id || 'user'}_audit`}
                emptyState={
                  <div className="text-center py-8 text-muted-foreground">
                    No audit events found for this user
                  </div>
                }
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="roles" className="space-y-4">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-lg font-medium">Role History</h3>
                  <p className="text-sm text-muted-foreground">Recent role and permission changes</p>
                </div>
                <Button variant="outline" size="sm">
                  <Shield className="mr-2 h-4 w-4" />
                  Grant Role
                </Button>
              </div>
              <div className="space-y-3">
                {roleHistoryMock.map((entry) => (
                  <div
                    key={entry.id}
                    className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 p-4 border rounded-lg"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <Badge variant="secondary">{entry.role}</Badge>
                        <span className="text-sm font-medium">{entry.scope}</span>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        Granted by {entry.grantedBy}
                      </p>
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {formatDateTime(entry.createdAt)}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
