import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Download, Upload } from 'lucide-react'
import { UserTable } from '@/components/users/UserTable'
import { UserFilters } from '@/components/users/UserFilters'
import { useExportUsers } from '@/hooks/useApi'
import type { UserListParams } from '@/types'

export function Users() {
  const navigate = useNavigate()
  const [filters, setFilters] = useState<UserListParams>({
    page: 1,
    limit: 10,
    status: 'all',
    role: 'all',
  })

  const exportMutation = useExportUsers()

  const handleExport = (format: 'csv' | 'json') => {
    exportMutation.mutate(
      { format, filters },
      {
        onSuccess: (blob) => {
          const url = window.URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = `users-export-${new Date().toISOString().split('T')[0]}.${format}`
          document.body.appendChild(a)
          a.click()
          window.URL.revokeObjectURL(url)
          document.body.removeChild(a)
        },
      }
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Users</h1>
          <p className="text-muted-foreground">Manage your users and their access</p>
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
          <button
            onClick={() => navigate('/users/new')}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
          >
            <Plus className="w-4 h-4" />
            Add User
          </button>
        </div>
      </div>

      {/* Filters */}
      <UserFilters 
        filters={filters} 
        onChange={setFilters}
      />

      {/* Table */}
      <UserTable 
        filters={filters} 
        onFilterChange={setFilters}
      />
    </div>
  )
}
