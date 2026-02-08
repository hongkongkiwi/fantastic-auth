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
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/Dialog'
import { Input } from '../components/ui/Input'
import { Checkbox } from '../components/ui/Checkbox'

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

const availablePermissions = [
  { id: 'users.read', label: 'Read Users' },
  { id: 'users.write', label: 'Write Users' },
  { id: 'tenants.read', label: 'Read Tenants' },
  { id: 'tenants.write', label: 'Write Tenants' },
  { id: 'billing.read', label: 'Read Billing' },
  { id: 'billing.write', label: 'Manage Billing' },
  { id: 'audit.read', label: 'Read Audit Logs' },
  { id: 'system.manage', label: 'Manage System' },
]

function RolesPage() {
  const [roles, setRoles] = useState<Role[]>(roleData)
  const [isEditOpen, setIsEditOpen] = useState(false)
  const [editingRole, setEditingRole] = useState<Role | null>(null)
  const [roleName, setRoleName] = useState('')
  const [roleDescription, setRoleDescription] = useState('')
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([])
  const prefersReducedMotion = useReducedMotion()

  const openCreate = () => {
    setEditingRole(null)
    setRoleName('')
    setRoleDescription('')
    setSelectedPermissions([])
    setIsEditOpen(true)
  }

  const openEdit = (role: Role) => {
    setEditingRole(role)
    setRoleName(role.name)
    setRoleDescription(role.description)
    setSelectedPermissions([])
    setIsEditOpen(true)
  }

  const togglePermission = (permissionId: string) => {
    setSelectedPermissions((prev) =>
      prev.includes(permissionId) ? prev.filter((p) => p !== permissionId) : [...prev, permissionId]
    )
  }

  const saveRole = () => {
    if (!roleName.trim()) return
    if (editingRole) {
      setRoles((prev) =>
        prev.map((role) =>
          role.id === editingRole.id
            ? { ...role, name: roleName, description: roleDescription, permissions: selectedPermissions.length || role.permissions }
            : role
        )
      )
    } else {
      setRoles((prev) => [
        {
          id: `role-${Date.now()}`,
          name: roleName,
          description: roleDescription,
          scope: 'platform',
          permissions: selectedPermissions.length || 0,
          members: 0,
          status: 'active',
        },
        ...prev,
      ])
    }
    setIsEditOpen(false)
  }

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
      cell: ({ row }) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label="Role actions">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => openEdit(row.original)}>Edit role</DropdownMenuItem>
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
          <Button onClick={openCreate}>
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

      <Dialog open={isEditOpen} onOpenChange={setIsEditOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{editingRole ? 'Edit Role' : 'Create Role'}</DialogTitle>
            <DialogDescription>
              Define access level and permissions for this role.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Role Name</label>
              <Input value={roleName} onChange={(e) => setRoleName(e.target.value)} placeholder="Role name" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Description</label>
              <Input value={roleDescription} onChange={(e) => setRoleDescription(e.target.value)} placeholder="Describe this role" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Permissions</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {availablePermissions.map((permission) => (
                  <label key={permission.id} className="flex items-center gap-2 border rounded-lg px-3 py-2 text-sm">
                    <Checkbox
                      checked={selectedPermissions.includes(permission.id)}
                      onCheckedChange={() => togglePermission(permission.id)}
                    />
                    {permission.label}
                  </label>
                ))}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setIsEditOpen(false)}>
              Cancel
            </Button>
            <Button onClick={saveRole}>{editingRole ? 'Save Changes' : 'Create Role'}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
