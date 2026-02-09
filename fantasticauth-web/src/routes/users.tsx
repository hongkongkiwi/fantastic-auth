import { createFileRoute, Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  MoreHorizontal,
  Mail,
  Shield,
  Trash2,
  User,
} from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader } from '../components/layout/Layout'
import { DataTable, createSelectColumn } from '../components/DataTable'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { Card } from '../components/ui/Card'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../components/ui/DropdownMenu'
import { useServerFn } from '@tanstack/react-start'
import { searchUsers, type PlatformUserResponse } from '../server/internal-api'
import { toast } from '../components/ui/Toaster'
import { formatNumber } from '../lib/utils'
import { DeleteUserDialog } from '../components/users/DeleteUserDialog'
import { TransferOwnershipDialog } from '../components/users/TransferOwnershipDialog'
import type { User as UserType } from '../hooks/useAuth'

export const Route = createFileRoute('/users')({
  component: UsersPage,
})

const statusConfig: Record<string, { label: string; variant: 'default' | 'success' | 'warning' | 'destructive' }> = {
  active: { label: 'Active', variant: 'success' },
  pending: { label: 'Pending', variant: 'warning' },
  suspended: { label: 'Suspended', variant: 'destructive' },
}

function UsersPage() {
  const [users, setUsers] = useState<PlatformUserResponse[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [userToDelete, setUserToDelete] = useState<UserType | null>(null)
  const [userToTransfer, setUserToTransfer] = useState<UserType | null>(null)
  const [transferTenantId, setTransferTenantId] = useState('')
  const prefersReducedMotion = useReducedMotion()

  const searchUsersFn = useServerFn(searchUsers)

  useEffect(() => {
    const fetchUsers = async () => {
      setIsLoading(true)
      try {
        const result = await searchUsersFn({ data: { page: 1 } })
        setUsers(result.data || [])
      } catch (error) {
        toast.error('Failed to load users')
      } finally {
        setIsLoading(false)
      }
    }
    fetchUsers()
  }, [])

  const columns: ColumnDef<PlatformUserResponse>[] = [
    createSelectColumn<PlatformUserResponse>(),
    {
      accessorKey: 'name',
      header: 'User',
      cell: ({ row }) => {
        const user = row.original
        return (
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
              <span className="text-sm font-medium text-primary">
                {user.name?.[0] || (user.email ? user.email[0].toUpperCase() : '?')}
              </span>
            </div>
            <div>
              <p className="font-medium">{user.name || 'Unnamed User'}</p>
              <p className="text-sm text-muted-foreground">{user.email ?? 'unknown'}</p>
            </div>
          </div>
        )
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ getValue }) => {
        const status = getValue() as string
        const config = statusConfig[status] || { label: status, variant: 'default' }
        return <Badge variant={config.variant}>{config.label}</Badge>
      },
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => {
        const user = row.original
        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon-sm" aria-label="Open user actions">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
              <DropdownMenuItem asChild>
                <Link to={`/users/${user.id ?? ''}`}>
                  <User className="mr-2 h-4 w-4" />
                  View Profile
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem>
                <Mail className="mr-2 h-4 w-4" />
                Send Email
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-destructive"
                onClick={() => setUserToDelete({
                  id: user.id ?? '',
                  email: user.email ?? 'unknown',
                  name: user.name || undefined,
                })}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => {
                  setUserToTransfer({
                    id: user.id ?? '',
                    email: user.email ?? 'unknown',
                    name: user.name || undefined,
                  })
                  setTransferTenantId('tenant-1')
                }}
              >
                <Shield className="mr-2 h-4 w-4" />
                Transfer Ownership
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )
      },
    },
  ]

  // Mock stats
  const stats = {
    total: users.length || 2480,
    active: users.filter((u) => u.status === 'active').length || 2100,
    pending: users.filter((u) => u.status === 'pending').length || 180,
    suspended: users.filter((u) => u.status === 'suspended').length || 45,
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Users"
        description="Manage platform users across all tenants"
        breadcrumbs={[{ label: 'Users' }]}
      />

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Users', value: stats.total, color: 'blue' },
          { label: 'Active', value: stats.active, color: 'green' },
          { label: 'Pending', value: stats.pending, color: 'amber' },
          { label: 'Suspended', value: stats.suspended, color: 'rose' },
        ].map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.1 }}
          >
            <Card className="p-6 card-hover">
              <p className="text-sm text-muted-foreground">{stat.label}</p>
              <p className="text-3xl font-bold mt-1">{formatNumber(stat.value)}</p>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Users Table */}
      <Card>
        <DataTable
          columns={columns}
          data={users}
          isLoading={isLoading}
          searchable
          searchPlaceholder="Search users by name or email…"
          pagination
          pageSize={10}
          exportable
          exportFileName="users"
        />
      </Card>

      {/* Delete User Dialog */}
      <DeleteUserDialog
        user={userToDelete}
        isOpen={!!userToDelete}
        onClose={() => setUserToDelete(null)}
        onSuccess={() => {
          toast.success('User deleted successfully')
          // Refresh users list
          searchUsersFn({ data: { page: 1 } }).then((result) => {
            setUsers(result.data || [])
          })
        }}
        onTransferOwnership={(userId) => {
          const user = users.find((u) => u.id === userId)
          if (user) {
            setUserToTransfer({
              id: user.id ?? '',
              email: user.email ?? 'unknown',
              name: user.name || undefined,
            })
            setTransferTenantId('tenant-1')
          }
        }}
      />

      {/* Transfer Ownership Dialog */}
      <TransferOwnershipDialog
        user={userToTransfer}
        tenantId={transferTenantId}
        isOpen={!!userToTransfer}
        onClose={() => {
          setUserToTransfer(null)
          setTransferTenantId('')
        }}
        onSuccess={() => {
          toast.success('Ownership transfer request sent')
        }}
      />
    </div>
  )
}
