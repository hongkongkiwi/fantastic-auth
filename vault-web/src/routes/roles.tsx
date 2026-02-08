import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Shield, Plus, Lock, Users, MoreHorizontal } from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader } from '../components/layout/Layout'
import { Card } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { DataTable } from '../components/DataTable'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../components/ui/DropdownMenu'

export const Route = createFileRoute('/roles')({
  component: RolesPage,
})

interface Role {
  id: string
  name: string
  description: string
  scope: 'platform' | 'tenant' | 'org'
  permissions: number
  members: number
  status: 'active' | 'disabled'
}

const roleData: Role[] = [
  {
    id: 'role-1',
    name: 'Platform Admin',
    description: 'Full access to platform settings and data',
    scope: 'platform',
    permissions: 48,
    members: 4,
    status: 'active',
  },
  {
    id: 'role-2',
    name: 'Tenant Manager',
    description: 'Manage tenants, subscriptions, and usage',
    scope: 'tenant',
    permissions: 28,
    members: 12,
    status: 'active',
  },
  {
    id: 'role-3',
    name: 'Support Agent',
    description: 'Read-only access to users and audit logs',
    scope: 'platform',
    permissions: 12,
    members: 9,
    status: 'disabled',
  },
]

function RolesPage() {
  const [roles] = useState<Role[]>(roleData)
  const prefersReducedMotion = useReducedMotion()

  const columns: ColumnDef<Role>[] = [
    {
      accessorKey: 'name',
      header: 'Role',
      cell: ({ row }) => (
        <div>
          <p className="font-medium">{row.original.name}</p>
          <p className="text-sm text-muted-foreground">{row.original.description}</p>
        </div>
      ),
    },
    {
      accessorKey: 'scope',
      header: 'Scope',
      cell: ({ getValue }) => <Badge variant="secondary">{getValue() as string}</Badge>,
    },
    {
      accessorKey: 'permissions',
      header: 'Permissions',
      cell: ({ getValue }) => (
        <div className="flex items-center gap-2">
          <Lock className="h-4 w-4 text-muted-foreground" />
          <span>{getValue() as number}</span>
        </div>
      ),
    },
    {
      accessorKey: 'members',
      header: 'Members',
      cell: ({ getValue }) => (
        <div className="flex items-center gap-2">
          <Users className="h-4 w-4 text-muted-foreground" />
          <span>{getValue() as number}</span>
        </div>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ getValue }) => (
        <Badge variant={getValue() === 'active' ? 'success' : 'secondary'}>
          {getValue() as string}
        </Badge>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: () => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label="Role actions">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem>Edit role</DropdownMenuItem>
            <DropdownMenuItem>View permissions</DropdownMenuItem>
            <DropdownMenuItem className="text-destructive">Disable role</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Roles & Permissions"
        description="Define access control across the platform"
        breadcrumbs={[{ label: 'Roles' }]}
        actions={
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            Create Role
          </Button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Total Roles', value: roles.length, icon: Shield },
          { label: 'Active Roles', value: roles.filter((r) => r.status === 'active').length, icon: Shield },
          { label: 'Assigned Members', value: roles.reduce((sum, r) => sum + r.members, 0), icon: Users },
        ].map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={prefersReducedMotion ? false : { opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.1 }}
          >
            <Card className="p-6">
              <p className="text-sm text-muted-foreground">{stat.label}</p>
              <p className="text-3xl font-bold mt-1">{stat.value}</p>
            </Card>
          </motion.div>
        ))}
      </div>

      <Card>
        <DataTable
          columns={columns}
          data={roles}
          searchable
          searchPlaceholder="Search roles…"
          pagination
          pageSize={10}
          exportable
          exportFileName="roles"
        />
      </Card>
    </div>
  )
}
