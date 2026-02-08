import { createFileRoute, useParams, Link } from '@tanstack/react-router'
import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion, useReducedMotion } from 'framer-motion'
import {
  Building2,
  Shield,
  Settings,
  Plus,
  AlertCircle,
  Mail,
  Lock,
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
import { formatDate, formatDateTime } from '../../lib/utils'

export const Route = createFileRoute('/organizations/$id')({
  component: OrganizationDetailPage,
})

interface Organization {
  id: string
  name: string
  slug: string
  member_count: number
  role: 'owner' | 'admin' | 'member'
  sso_enabled: boolean
  created_at: string
}

interface OrgMember {
  id: string
  name: string
  email: string
  role: string
  status: 'active' | 'invited' | 'suspended'
  joinedAt: string
}

const memberStatusVariant: Record<OrgMember['status'], 'success' | 'warning' | 'destructive'> = {
  active: 'success',
  invited: 'warning',
  suspended: 'destructive',
}

const roles = [
  { name: 'Owner', description: 'Full access to organization settings', permissions: 42 },
  { name: 'Admin', description: 'Manage members and billing', permissions: 28 },
  { name: 'Member', description: 'Standard access to projects', permissions: 12 },
]

const membersMock: OrgMember[] = [
  {
    id: 'mem-1',
    name: 'Alex Grant',
    email: 'alex@acme.com',
    role: 'Owner',
    status: 'active',
    joinedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 200).toISOString(),
  },
  {
    id: 'mem-2',
    name: 'Jamie Liu',
    email: 'jamie@acme.com',
    role: 'Admin',
    status: 'active',
    joinedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 80).toISOString(),
  },
  {
    id: 'mem-3',
    name: 'Taylor Reed',
    email: 'taylor@acme.com',
    role: 'Member',
    status: 'invited',
    joinedAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 5).toISOString(),
  },
]

const memberColumns: ColumnDef<OrgMember>[] = [
  {
    accessorKey: 'name',
    header: 'Member',
    cell: ({ row }) => (
      <div>
        <p className="font-medium">{row.original.name}</p>
        <p className="text-sm text-muted-foreground">{row.original.email}</p>
      </div>
    ),
  },
  {
    accessorKey: 'role',
    header: 'Role',
    cell: ({ getValue }) => <Badge variant="secondary">{getValue() as string}</Badge>,
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ getValue }) => {
      const status = getValue() as OrgMember['status']
      return <Badge variant={memberStatusVariant[status]}>{status}</Badge>
    },
  },
  {
    accessorKey: 'joinedAt',
    header: 'Joined',
    cell: ({ getValue }) => formatDate(getValue() as string),
  },
]

function OrganizationDetailPage() {
  const { id } = useParams({ from: '/organizations/$id' })
  const prefersReducedMotion = useReducedMotion()

  const { data, isLoading } = useQuery({
    queryKey: ['organizations'],
    queryFn: async () => {
      const res = await fetch('/api/v1/admin/organizations')
      if (!res.ok) throw new Error('Failed to load organizations')
      return res.json() as Promise<Organization[]>
    },
  })

  const organization = useMemo(() => data?.find((org) => org.id === id), [data, id])

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton variant="card" className="h-48" />
        <Skeleton variant="card" className="h-96" />
      </div>
    )
  }

  if (!organization) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <AlertCircle className="h-12 w-12 text-muted-foreground mb-4" />
        <h2 className="text-xl font-semibold">Organization not found</h2>
        <p className="text-muted-foreground mb-4">We couldn&apos;t find this organization.</p>
        <Button asChild>
          <Link to="/organizations">Back to Organizations</Link>
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={organization.name}
        description={`@${organization.slug}`}
        breadcrumbs={[
          { label: 'Organizations', href: '/organizations' },
          { label: organization.name },
        ]}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline">
              <Settings className="mr-2 h-4 w-4" />
              Organization Settings
            </Button>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Invite Member
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
                <div className="h-14 w-14 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Building2 className="h-7 w-7 text-primary" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-xl font-semibold">{organization.name}</h2>
                    {organization.sso_enabled && (
                      <Badge variant="success">SSO Enabled</Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Created {formatDateTime(organization.created_at)}
                  </p>
                </div>
              </div>
              <Badge variant="secondary">{organization.role}</Badge>
            </div>

            <div className="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Members</p>
                <p className="text-2xl font-semibold">{organization.member_count}</p>
              </div>
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Default Role</p>
                <Badge variant="secondary">Member</Badge>
              </div>
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">SSO</p>
                <Badge variant={organization.sso_enabled ? 'success' : 'secondary'}>
                  {organization.sso_enabled ? 'Enabled' : 'Not configured'}
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
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Quick Actions</p>
              <div className="mt-3 grid gap-2">
                <Button variant="outline">
                  <Mail className="mr-2 h-4 w-4" />
                  Send Announcement
                </Button>
                <Button variant="outline">
                  <Shield className="mr-2 h-4 w-4" />
                  Enforce SSO
                </Button>
                <Button variant="outline">
                  <Lock className="mr-2 h-4 w-4" />
                  Require MFA
                </Button>
              </div>
            </div>
          </Card>
        </motion.div>
      </div>

      <Tabs defaultValue="members" className="space-y-6">
        <TabsList className="flex flex-wrap">
          <TabsTrigger value="members">Members</TabsTrigger>
          <TabsTrigger value="roles">Roles</TabsTrigger>
          <TabsTrigger value="sso">SSO</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="members" className="space-y-4">
          <Card>
            <CardContent className="p-6">
              <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 mb-4">
                <div>
                  <h3 className="text-lg font-medium">Members</h3>
                  <p className="text-sm text-muted-foreground">Manage organization access</p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Input placeholder="Search members…" className="w-[200px]" />
                  <Select
                    options={[
                      { value: '', label: 'All Roles' },
                      { value: 'owner', label: 'Owner' },
                      { value: 'admin', label: 'Admin' },
                      { value: 'member', label: 'Member' },
                    ]}
                    value=""
                    onChange={() => {}}
                    className="min-w-[140px]"
                  />
                  <Button size="sm">
                    <Plus className="mr-2 h-4 w-4" />
                    Invite Member
                  </Button>
                </div>
              </div>
              <DataTable
                columns={memberColumns}
                data={membersMock}
                searchable={false}
                pagination
                pageSize={5}
                exportable
                exportFileName={`org_${organization.id}_members`}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="roles" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {roles.map((role) => (
              <Card key={role.name} className="p-6">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-semibold">{role.name}</h3>
                    <p className="text-sm text-muted-foreground mt-1">{role.description}</p>
                  </div>
                  <Badge variant="secondary">{role.permissions} perms</Badge>
                </div>
                <Button variant="outline" className="mt-4" size="sm">
                  Manage Permissions
                </Button>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="sso" className="space-y-4">
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h3 className="text-lg font-semibold">Single Sign-On</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Configure SAML or OAuth to secure organization access
                </p>
                <div className="flex flex-wrap gap-2 mt-4">
                  <Button variant="outline">Configure SAML</Button>
                  <Button variant="outline">Configure OAuth</Button>
                </div>
              </div>
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="space-y-4">
          <Card className="p-6 space-y-4">
            <div>
              <h3 className="text-lg font-semibold">Organization Settings</h3>
              <p className="text-sm text-muted-foreground">Manage defaults and security policies</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="border rounded-lg p-4">
                <p className="text-sm font-medium">Default Role</p>
                <p className="text-sm text-muted-foreground mt-1">Member</p>
              </div>
              <div className="border rounded-lg p-4">
                <p className="text-sm font-medium">Domain Allowlist</p>
                <p className="text-sm text-muted-foreground mt-1">acme.com</p>
              </div>
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
