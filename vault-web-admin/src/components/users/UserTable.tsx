import { useState } from 'react'
import { 
  MoreHorizontal, Edit, Trash2, Ban, CheckCircle, 
  Mail, Shield, User as UserIcon, ChevronLeft, ChevronRight,
  Loader2, Copy, ExternalLink
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { cn, formatDate, initials } from '@/lib/utils'
import { useUsers, useSuspendUser, useActivateUser, useDeleteUser } from '@/hooks/useApi'
import type { User, UserListParams } from '@/types'

interface UserTableProps {
  filters?: UserListParams
  onFilterChange?: (filters: UserListParams) => void
}

export function UserTable({ filters = {}, onFilterChange }: UserTableProps) {
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

  const users = data?.data || []
  const pagination = data?.pagination

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
            <button className="text-sm text-muted-foreground hover:text-foreground">
              Suspend
            </button>
            <button className="text-sm text-muted-foreground hover:text-foreground">
              Delete
            </button>
            <button className="text-sm text-muted-foreground hover:text-foreground">
              Export
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border bg-muted/50">
              <th className="px-4 py-3 text-left">
                <input
                  type="checkbox"
                  className="rounded border-border"
                  checked={selectedUsers.length === users.length && users.length > 0}
                  onChange={handleSelectAll}
                />
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                User
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Status
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Role
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                MFA
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Last Login
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Joined
              </th>
              <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {users.map((user) => (
              <tr
                key={user.id}
                className="hover:bg-muted/50 transition-colors cursor-pointer"
                onClick={(e) => {
                  if ((e.target as HTMLElement).closest('button, input')) return
                  navigate(`/users/${user.id}`)
                }}
              >
                <td className="px-4 py-3">
                  <input
                    type="checkbox"
                    className="rounded border-border"
                    checked={selectedUsers.includes(user.id)}
                    onChange={() => handleSelectUser(user.id)}
                  />
                </td>
                <td className="px-4 py-3">
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
                        {user.displayName || user.firstName && user.lastName 
                          ? `${user.firstName} ${user.lastName}` 
                          : user.email}
                      </p>
                      <p className="text-sm text-muted-foreground">{user.email}</p>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={cn(
                      "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium",
                      user.status === 'active' && "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
                      user.status === 'suspended' && "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
                      user.status === 'pending' && "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
                    )}
                  >
                    {user.status}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="inline-flex items-center gap-1 text-sm">
                    {user.role === 'admin' && <Shield className="w-3 h-3" />}
                    {user.role}
                  </span>
                </td>
                <td className="px-4 py-3">
                  {user.mfaEnabled ? (
                    <span className="inline-flex items-center gap-1 text-xs text-green-600 dark:text-green-400">
                      <CheckCircle className="w-3 h-3" />
                      Enabled
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">-</span>
                  )}
                </td>
                <td className="px-4 py-3 text-sm text-muted-foreground">
                  {user.lastLoginAt ? formatDate(user.lastLoginAt, 'relative') : 'Never'}
                </td>
                <td className="px-4 py-3 text-sm text-muted-foreground">
                  {formatDate(user.createdAt, 'short')}
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      onClick={() => navigate(`/users/${user.id}`)}
                      className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
                      title="View details"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </button>
                    {user.status === 'active' ? (
                      <button
                        onClick={() => handleSuspend(user.id)}
                        className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-yellow-600"
                        title="Suspend user"
                      >
                        <Ban className="w-4 h-4" />
                      </button>
                    ) : (
                      <button
                        onClick={() => handleActivate(user.id)}
                        className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-green-600"
                        title="Activate user"
                      >
                        <CheckCircle className="w-4 h-4" />
                      </button>
                    )}
                    <button
                      onClick={() => handleDelete(user.id)}
                      className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-red-600"
                      title="Delete user"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </td>
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
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={!pagination.hasPrevPage}
              className="p-2 rounded-lg border border-border hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-sm">
              Page {pagination.page} of {pagination.totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(pagination.totalPages, p + 1))}
              disabled={!pagination.hasNextPage}
              className="p-2 rounded-lg border border-border hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
