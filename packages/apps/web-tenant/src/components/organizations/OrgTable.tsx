import { useState } from 'react'
import { 
  Edit, Trash2, ChevronLeft, ChevronRight,
  Building2, Users, ExternalLink, CheckCircle, XCircle
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { cn, formatDate } from '@/lib/utils'
import { useOrganizations, useDeleteOrganization } from '@/hooks/useApi'
import type { Organization } from '@/types'

interface OrgTableProps {
  search?: string
}

export function OrgTable({ search }: OrgTableProps) {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [limit] = useState(10)

  const { data, isLoading } = useOrganizations({ page, limit, search })
  const deleteMutation = useDeleteOrganization()

  const organizations = (data?.data || []) as Organization[]
  const pagination = data?.pagination

  const handleDelete = (orgId: string, orgName: string) => {
    if (confirm(`Are you sure you want to delete "${orgName}"? This action cannot be undone.`)) {
      deleteMutation.mutate(orgId)
    }
  }

  if (isLoading) {
    return (
      <div className="bg-card rounded-lg border border-border">
        <div className="p-8 flex items-center justify-center">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      </div>
    )
  }

  return (
    <div className="bg-card rounded-lg border border-border">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border bg-muted/50">
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Organization
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Status
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Plan
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Members
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Domain
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                SSO
              </th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Created
              </th>
              <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {organizations.map((org) => (
              <tr
                key={org.id}
                className="hover:bg-muted/50 transition-colors"
              >
                <td className="px-4 py-3">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                      {org.logoUrl ? (
                        <img
                          src={org.logoUrl}
                          alt={org.name}
                          className="w-10 h-10 rounded-lg object-cover"
                        />
                      ) : (
                        <Building2 className="w-5 h-5 text-primary" />
                      )}
                    </div>
                    <div>
                      <p className="font-medium">{org.name}</p>
                      <p className="text-sm text-muted-foreground">{org.slug}</p>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={cn(
                      "inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium",
                      org.status === 'active' && "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
                      org.status === 'inactive' && "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
                      org.status === 'suspended' && "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                    )}
                  >
                    {org.status === 'active' && <CheckCircle className="w-3 h-3" />}
                    {org.status !== 'active' && <XCircle className="w-3 h-3" />}
                    {org.status}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={cn(
                    "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize",
                    org.plan === 'free' && "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
                    org.plan === 'starter' && "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
                    org.plan === 'pro' && "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
                    org.plan === 'enterprise' && "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200"
                  )}>
                    {org.plan}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1 text-sm">
                    <Users className="w-4 h-4 text-muted-foreground" />
                    {org.memberCount}
                  </div>
                </td>
                <td className="px-4 py-3">
                  {org.domain ? (
                    <div className="flex items-center gap-1">
                      <span className="text-sm">{org.domain}</span>
                      {org.domainVerified ? (
                        <CheckCircle className="w-3 h-3 text-green-500" />
                      ) : (
                        <XCircle className="w-3 h-3 text-yellow-500" />
                      )}
                    </div>
                  ) : (
                    <span className="text-sm text-muted-foreground">-</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {org.ssoEnabled ? (
                    <span className="inline-flex items-center gap-1 text-xs text-green-600 dark:text-green-400">
                      <CheckCircle className="w-3 h-3" />
                      {org.ssoProvider?.toUpperCase()}
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">-</span>
                  )}
                </td>
                <td className="px-4 py-3 text-sm text-muted-foreground">
                  {formatDate(org.createdAt, 'short')}
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-1">
                    <button type="button"
                      onClick={() => navigate(`/organizations/${org.id}`)}
                      className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
                      title="View details"
                      aria-label={`View organization ${org.name}`}
                    >
                      <ExternalLink className="w-4 h-4" />
                    </button>
                    <button type="button"
                      onClick={() => navigate(`/organizations/${org.id}/edit`)}
                      className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
                      title="Edit organization"
                      aria-label={`Edit organization ${org.name}`}
                    >
                      <Edit className="w-4 h-4" />
                    </button>
                    <button type="button"
                      onClick={() => handleDelete(org.id, org.name)}
                      className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-red-600"
                      title="Delete organization"
                      aria-label={`Delete organization ${org.name}`}
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
            {pagination.total} organizations
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
