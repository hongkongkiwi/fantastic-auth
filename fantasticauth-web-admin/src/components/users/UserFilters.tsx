import { Search, X, Filter, Download } from 'lucide-react'
import { useState } from 'react'
import { cn } from '@/lib/utils'
import type { UserListParams } from '@/types'

interface UserFiltersProps {
  filters: UserListParams
  onChange: (filters: UserListParams) => void
  onExport?: () => void
}

export function UserFilters({ filters, onChange, onExport }: UserFiltersProps) {
  const [search, setSearch] = useState(filters.search || '')

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    onChange({ ...filters, search, page: 1 })
  }

  const handleClear = () => {
    setSearch('')
    onChange({
      page: 1,
      limit: filters.limit,
    })
  }

  const hasActiveFilters = filters.search || filters.status !== 'all' || filters.role !== 'all'

  return (
    <div className="bg-card rounded-lg border border-border p-4 space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        {/* Search */}
        <form onSubmit={handleSearch} className="flex-1 min-w-[200px] max-w-md">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search users..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-10 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
            {search && (
              <button
                type="button"
                onClick={() => { setSearch(''); onChange({ ...filters, search: '', page: 1 }) }}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </form>

        {/* Status Filter */}
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <select
            value={filters.status || 'all'}
            onChange={(e) => onChange({ ...filters, status: e.target.value as UserListParams['status'], page: 1 })}
            className="px-3 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          >
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="suspended">Suspended</option>
            <option value="pending">Pending</option>
            <option value="deleted">Deleted</option>
          </select>
        </div>

        {/* Role Filter */}
        <select
          value={filters.role || 'all'}
          onChange={(e) => onChange({ ...filters, role: e.target.value as UserListParams['role'], page: 1 })}
          className="px-3 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        >
          <option value="all">All Roles</option>
          <option value="admin">Admin</option>
          <option value="user">User</option>
          <option value="super_admin">Super Admin</option>
        </select>

        {/* MFA Filter */}
        <select
          value={filters.mfaEnabled?.toString() || 'all'}
          onChange={(e) => onChange({ 
            ...filters, 
            mfaEnabled: e.target.value === 'all' ? 'all' : e.target.value === 'true',
            page: 1 
          })}
          className="px-3 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        >
          <option value="all">MFA: All</option>
          <option value="true">MFA: Enabled</option>
          <option value="false">MFA: Disabled</option>
        </select>

        {/* Actions */}
        <div className="flex items-center gap-2 ml-auto">
          {hasActiveFilters && (
            <button
              onClick={handleClear}
              className="px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
            >
              Clear filters
            </button>
          )}
          {onExport && (
            <button
              onClick={onExport}
              className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
            >
              <Download className="w-4 h-4" />
              Export
            </button>
          )}
        </div>
      </div>

      {/* Active Filters */}
      {hasActiveFilters && (
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-border">
          <span className="text-xs text-muted-foreground">Active filters:</span>
          {filters.search && (
            <span className="inline-flex items-center gap-1 px-2 py-1 bg-primary/10 text-primary rounded text-xs">
              Search: {filters.search}
              <button onClick={() => { setSearch(''); onChange({ ...filters, search: '', page: 1 }) }}>
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {filters.status && filters.status !== 'all' && (
            <span className="inline-flex items-center gap-1 px-2 py-1 bg-primary/10 text-primary rounded text-xs">
              Status: {filters.status}
              <button onClick={() => onChange({ ...filters, status: 'all', page: 1 })}>
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {filters.role && filters.role !== 'all' && (
            <span className="inline-flex items-center gap-1 px-2 py-1 bg-primary/10 text-primary rounded text-xs">
              Role: {filters.role}
              <button onClick={() => onChange({ ...filters, role: 'all', page: 1 })}>
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
        </div>
      )}
    </div>
  )
}
