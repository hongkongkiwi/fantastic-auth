import { useState } from 'react'
import { flexRender, getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table'
import { 
  Trash2, Ban, CheckCircle,
  Shield, ChevronLeft, ChevronRight,
  Loader2, ExternalLink
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { cn, formatDate, initials } from '@/lib/utils'
import { useUsers, useSuspendUser, useActivateUser, useDeleteUser } from '@/hooks/useApi'
import type { User, UserListParams } from '@/types'

interface UserTableProps {
  filters?: UserListParams
}

export function UserTable({ filters = {} }: UserTableProps) {
  const navigate = useNavigate()
  const [selectedUsers, setSelectedUsers] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const [limit] = useState(10)

  const params: UserListParams = {
    page,
    limit,
    ...filters,
  }

  const { data, isLoading } = useUsers(params)
  const suspendMutation = useSuspendUser()
  const activateMutation = useActivateUser()
  const deleteMutation = useDeleteUser()

  const users = (data?.data || []) as User[]
  const pagination = data?.pagination

  const columns: ColumnDef<User>[] = [
      {
        id: 'select',
        header: () => (
          <input
            type="checkbox"
            className="rounded border-border"
            checked={selectedUsers.length === users.length && users.length > 0}
            onChange={handleSelectAll}
            aria-label="Select all users"
          />
        ),
        cell: ({ row }) => (
          <input
            type="checkbox"
            className="rounded border-border"
            checked={selectedUsers.includes(row.original.id)}
            onChange={() => handleSelectUser(row.original.id)}
            aria-label={`Select user ${row.original.email}`}
          />
        ),
      },
      {
        id: 'user',
        header: 'User',
        cell: ({ row }) => {
          const user = row.original
          return (
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                {user.avatarUrl ? (
                  <img
                    src={user.avatarUrl}
                    alt={user.email}
                    className="w-8 h-8 rounded-full object-cover"
                  />
                ) : (
                  <span className="text-sm font-medium text-primary">
                    {initials(user.displayName || user.email)}
                  </span>
                )}
              </div>
              <div>
                <p className="font-medium">
                  {user.displayName || (user.firstName && user.lastName)
                    ? `${user.firstName} ${user.lastName}`
                    : user.email}
                </p>
                <p className="text-sm text-muted-foreground">{user.email}</p>
              </div>
            </div>
          )
        },
      },
      {
        id: 'status',
        header: 'Status',
        cell: ({ row }) => (
          <span
            className={cn(
              'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
              row.original.status === 'active' &&
                'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
              row.original.status === 'suspended' &&
                'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
              row.original.status === 'pending' &&
                'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
            )}
          >
            {row.original.status}
          </span>
        ),
      },
      {
        id: 'role',
        header: 'Role',
        cell: ({ row }) => (
          <span className="inline-flex items-center gap-1 text-sm">
            {row.original.role === 'admin' && <Shield className="w-3 h-3" />}
            {row.original.role}
          </span>
        ),
      },
      {
        id: 'mfa',
        header: 'MFA',
        cell: ({ row }) =>
          row.original.mfaEnabled ? (
            <span className="inline-flex items-center gap-1 text-xs text-green-600 dark:text-green-400">
              <CheckCircle className="w-3 h-3" />
              Enabled
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">-</span>
          ),
      },
      {
        id: 'lastLogin',
        header: 'Last Login',
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {row.original.lastLoginAt ? formatDate(row.original.lastLoginAt, 'relative') : 'Never'}
          </span>
        ),
      },
      {
        id: 'joined',
        header: 'Joined',
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">{formatDate(row.original.createdAt, 'short')}</span>
        ),
      },
      {
        id: 'actions',
        header: () => <div className="text-right">Actions</div>,
        cell: ({ row }) => {
          const user = row.original
          return (
            <div className="flex items-center justify-end gap-1">
              <button type="button"
                onClick={() => navigate(`/users/${user.id}`)}
                className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
                title="View details"
              >
                <ExternalLink className="w-4 h-4" />
              </button>
              {user.status === 'active' ? (
                <button type="button"
                  onClick={() => handleSuspend(user.id)}
                  className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-yellow-600"
                  title="Suspend user"
                >
                  <Ban className="w-4 h-4" />
                </button>
              ) : (
                <button type="button"
                  onClick={() => handleActivate(user.id)}
                  className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-green-600"
                  title="Activate user"
                >
                  <CheckCircle className="w-4 h-4" />
                </button>
              )}
              <button type="button"
                onClick={() => handleDelete(user.id)}
                className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-red-600"
                title="Delete user"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          )
        },
      },
    ]

  const table = useReactTable({
    data: users,
    columns,
    getCoreRowModel: getCoreRowModel(),
  })

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedUsers(users.map((u) => u.id))
    } else {
      setSelectedUsers([])
    }
  }

  const handleSelectUser = (userId: string) => {
    setSelectedUsers((prev) =>
      prev.includes(userId)
        ? prev.filter((id) => id !== userId)
        : [...prev, userId]
    )
  }

  const handleSuspend = (userId: string) => {
    if (confirm('Are you sure you want to suspend this user?')) {
      suspendMutation.mutate({ id: userId, reason: 'Suspended by admin' })
    }
  }

  const handleActivate = (userId: string) => {
    activateMutation.mutate(userId)
  }

  const handleDelete = (userId: string) => {
    if (confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
      deleteMutation.mutate(userId)
    }
  }

  if (isLoading) {
    return (
      <div className="bg-card rounded-lg border border-border">
        <div className="p-8 flex items-center justify-center">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
        </div>
      </div>
    )
  }

  return (
    <div className="bg-card rounded-lg border border-border">
      {/* Bulk Actions */}
      {selectedUsers.length > 0 && (
        <div className="px-4 py-3 bg-primary/5 border-b border-border flex items-center gap-4">
          <span className="text-sm font-medium">{selectedUsers.length} selected</span>
          <div className="flex items-center gap-2">
            <button type="button" className="text-sm text-muted-foreground hover:text-foreground">
              Suspend
            </button>
            <button type="button" className="text-sm text-muted-foreground hover:text-foreground">
              Delete
            </button>
            <button type="button" className="text-sm text-muted-foreground hover:text-foreground">
              Export
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-border bg-muted/50">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider"
                  >
                    {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody className="divide-y divide-border">
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                className="hover:bg-muted/50 transition-colors"
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-4 py-3">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pagination && pagination.totalPages > 1 && (
        <div className="px-4 py-3 border-t border-border flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            Showing {((pagination.page - 1) * pagination.limit) + 1} to{' '}
            {Math.min(pagination.page * pagination.limit, pagination.total)} of{' '}
            {pagination.total} users
          </div>
          <div className="flex items-center gap-2">
            <button type="button"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={!pagination.hasPrevPage}
              className="p-2 rounded-lg border border-border hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              aria-label="Previous page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-sm">
              Page {pagination.page} of {pagination.totalPages}
            </span>
            <button type="button"
              onClick={() => setPage((p) => Math.min(pagination.totalPages, p + 1))}
              disabled={!pagination.hasNextPage}
              className="p-2 rounded-lg border border-border hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
              aria-label="Next page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
