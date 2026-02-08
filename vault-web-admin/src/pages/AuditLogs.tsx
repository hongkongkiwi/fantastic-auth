import { useState } from 'react'
import { Download, Filter, Search, Calendar } from 'lucide-react'
import { format } from 'date-fns'
import { useAuditLogs, useExportAuditLogs } from '@/hooks/useApi'
import { cn, formatDate } from '@/lib/utils'
import type { AuditEventType, AuditLog } from '@/types'

const eventTypeFilters: { value: AuditEventType | 'all'; label: string }[] = [
  { value: 'all', label: 'All Events' },
  { value: 'user.created', label: 'User Created' },
  { value: 'user.login', label: 'User Login' },
  { value: 'user.logout', label: 'User Logout' },
  { value: 'user.suspended', label: 'User Suspended' },
  { value: 'user.activated', label: 'User Activated' },
  { value: 'user.mfa_enabled', label: 'MFA Enabled' },
  { value: 'user.password_changed', label: 'Password Changed' },
  { value: 'org.created', label: 'Organization Created' },
  { value: 'org.member_added', label: 'Member Added' },
  { value: 'org.member_removed', label: 'Member Removed' },
  { value: 'session.created', label: 'Session Created' },
  { value: 'session.revoked', label: 'Session Revoked' },
]

const statusFilters = [
  { value: 'all', label: 'All Status' },
  { value: 'success', label: 'Success' },
  { value: 'failure', label: 'Failure' },
  { value: 'blocked', label: 'Blocked' },
]

export function AuditLogs() {
  const [filters, setFilters] = useState({
    eventType: 'all' as AuditEventType | 'all',
    status: 'all' as 'all' | 'success' | 'failure' | 'blocked',
    actorId: '',
    dateFrom: '',
    dateTo: '',
    page: 1,
    limit: 25,
  })

  const { data, isLoading } = useAuditLogs({
    page: filters.page,
    limit: filters.limit,
    eventType: filters.eventType === 'all' ? undefined : filters.eventType,
    status: filters.status === 'all' ? undefined : filters.status,
    actorId: filters.actorId || undefined,
    dateFrom: filters.dateFrom || undefined,
    dateTo: filters.dateTo || undefined,
  })

  const exportMutation = useExportAuditLogs()

  const handleExport = (format: 'csv' | 'json') => {
    exportMutation.mutate(
      { format, filters },
      {
        onSuccess: (blob) => {
          const url = window.URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = `audit-logs-${format}-${new Date().toISOString().split('T')[0]}.${format}`
          document.body.appendChild(a)
          a.click()
          window.URL.revokeObjectURL(url)
          document.body.removeChild(a)
        },
      }
    )
  }

  const getEventColor = (eventType: string) => {
    if (eventType.startsWith('user.')) return 'text-blue-600 bg-blue-50 dark:bg-blue-950 dark:text-blue-400'
    if (eventType.startsWith('org.')) return 'text-purple-600 bg-purple-50 dark:bg-purple-950 dark:text-purple-400'
    if (eventType.startsWith('session.')) return 'text-green-600 bg-green-50 dark:bg-green-950 dark:text-green-400'
    return 'text-gray-600 bg-gray-50 dark:bg-gray-800 dark:text-gray-400'
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Audit Logs</h1>
          <p className="text-muted-foreground">Track all activities across your organization</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleExport('csv')}
            disabled={exportMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border hover:bg-muted text-sm font-medium disabled:opacity-50"
          >
            <Download className="w-4 h-4" />
            Export CSV
          </button>
          <button
            onClick={() => handleExport('json')}
            disabled={exportMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border hover:bg-muted text-sm font-medium disabled:opacity-50"
          >
            <Download className="w-4 h-4" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-card rounded-lg border border-border p-4 space-y-4">
        <div className="flex flex-wrap items-center gap-4">
          {/* Event Type */}
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-muted-foreground" />
            <select
              value={filters.eventType}
              onChange={(e) => setFilters({ ...filters, eventType: e.target.value as AuditEventType | 'all', page: 1 })}
              className="px-3 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              {eventTypeFilters.map((filter) => (
                <option key={filter.value} value={filter.value}>{filter.label}</option>
              ))}
            </select>
          </div>

          {/* Status */}
          <select
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value as typeof filters.status, page: 1 })}
            className="px-3 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          >
            {statusFilters.map((filter) => (
              <option key={filter.value} value={filter.value}>{filter.label}</option>
            ))}
          </select>

          {/* Actor ID */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Actor ID or Email"
              value={filters.actorId}
              onChange={(e) => setFilters({ ...filters, actorId: e.target.value, page: 1 })}
              className="pl-10 pr-4 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>

          {/* Date Range */}
          <div className="flex items-center gap-2">
            <Calendar className="w-4 h-4 text-muted-foreground" />
            <input
              type="date"
              value={filters.dateFrom}
              onChange={(e) => setFilters({ ...filters, dateFrom: e.target.value, page: 1 })}
              className="px-3 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
            <span className="text-muted-foreground">to</span>
            <input
              type="date"
              value={filters.dateTo}
              onChange={(e) => setFilters({ ...filters, dateTo: e.target.value, page: 1 })}
              className="px-3 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-card rounded-lg border border-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Timestamp
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Event
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Actor
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Resource
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Status
                </th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  IP Address
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center">
                    <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto" />
                  </td>
                </tr>
              ) : data?.data.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                    No audit logs found
                  </td>
                </tr>
              ) : (
                data?.data.map((log) => (
                  <tr key={log.id} className="hover:bg-muted/50 transition-colors">
                    <td className="px-4 py-3 text-sm whitespace-nowrap">
                      {formatDate(log.timestamp, 'long')}
                    </td>
                    <td className="px-4 py-3">
                      <span className={cn(
                        "inline-flex items-center px-2 py-1 rounded text-xs font-medium",
                        getEventColor(log.eventType)
                      )}>
                        {log.eventType}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-sm">
                        <p className="font-medium">{log.actor.email || log.actor.id || 'System'}</p>
                        <p className="text-muted-foreground">{log.actor.type}</p>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className="font-medium">{log.resource.type}</span>
                      <span className="text-muted-foreground ml-1">({log.resource.id.slice(0, 8)}...)</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={cn(
                        "inline-flex items-center px-2 py-1 rounded-full text-xs font-medium",
                        log.status === 'success' && "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
                        log.status === 'failure' && "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
                        log.status === 'blocked' && "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
                      )}>
                        {log.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm font-mono">
                      {log.actor.ipAddress}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data?.pagination && data.pagination.totalPages > 1 && (
          <div className="px-4 py-3 border-t border-border flex items-center justify-between">
            <div className="text-sm text-muted-foreground">
              Showing {((data.pagination.page - 1) * data.pagination.limit) + 1} to{' '}
              {Math.min(data.pagination.page * data.pagination.limit, data.pagination.total)} of{' '}
              {data.pagination.total} logs
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setFilters(f => ({ ...f, page: f.page - 1 }))}
                disabled={!data.pagination.hasPrevPage}
                className="px-3 py-1 rounded-lg border border-border hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed text-sm"
              >
                Previous
              </button>
              <span className="text-sm">
                Page {data.pagination.page} of {data.pagination.totalPages}
              </span>
              <button
                onClick={() => setFilters(f => ({ ...f, page: f.page + 1 }))}
                disabled={!data.pagination.hasNextPage}
                className="px-3 py-1 rounded-lg border border-border hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed text-sm"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
