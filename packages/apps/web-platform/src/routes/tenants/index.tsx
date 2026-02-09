import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  Building2,
  Plus,
  MoreHorizontal,
  Edit,
  Trash2,
  Pause,
  Play,
  FileText,
} from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader } from '../../components/layout/Layout'
import { DataTable, createSelectColumn, createStatusBadge, createDateCell } from '../../components/DataTable'
import { Button } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import { Card } from '../../components/ui/Card'
import { ConfirmDialog } from '../../components/ui/Dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../../components/ui/DropdownMenu'
import { useServerFn } from '@tanstack/react-start'
import {
  listTenants,
  suspendTenant,
  activateTenant,
  deleteTenant,
  type TenantDetail,
} from '../../server/internal-api'
import { toast } from '../../components/ui/Toaster'
import { formatNumber } from '../../lib/utils'

export const Route = createFileRoute('/tenants/')({
  component: TenantsPage,
})

const planColors: Record<string, 'default' | 'secondary' | 'success' | 'warning' | 'destructive' | 'info'> = {
  free: 'secondary',
  starter: 'info',
  pro: 'success',
  enterprise: 'warning',
}

const statusConfig: Record<string, { label: string; variant: 'default' | 'success' | 'warning' | 'destructive' }> = {
  active: { label: 'Active', variant: 'success' },
  suspended: { label: 'Suspended', variant: 'warning' },
  inactive: { label: 'Inactive', variant: 'destructive' },
}

function TenantsPage() {
  const [tenants, setTenants] = useState<TenantDetail[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [selectedTenant, setSelectedTenant] = useState<TenantDetail | null>(null)
  const [dialogState, setDialogState] = useState<'suspend' | 'activate' | 'delete' | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const prefersReducedMotion = useReducedMotion()
  const navigate = useNavigate()

  const listTenantsFn = useServerFn(listTenants)
  const suspendTenantFn = useServerFn(suspendTenant)
  const activateTenantFn = useServerFn(activateTenant)
  const deleteTenantFn = useServerFn(deleteTenant)

  const fetchTenants = async () => {
    setIsLoading(true)
    try {
      const result = await listTenantsFn({ data: { page: 1, perPage: 50 } })
      setTenants(result.data || [])
    } catch (error) {
      toast.error('Failed to load tenants')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchTenants()
  }, [])

  const handleAction = async () => {
    if (!selectedTenant || !dialogState) return
    if (!selectedTenant.id) {
      toast.error('Tenant ID is missing')
      return
    }

    setIsSubmitting(true)
    try {
      switch (dialogState) {
        case 'suspend':
          await suspendTenantFn({ data: { tenantId: selectedTenant.id } })
          toast.success('Tenant suspended successfully')
          break
        case 'activate':
          await activateTenantFn({ data: { tenantId: selectedTenant.id } })
          toast.success('Tenant activated successfully')
          break
        case 'delete':
          await deleteTenantFn({ data: { tenantId: selectedTenant.id } })
          toast.success('Tenant deleted successfully')
          break
      }
      await fetchTenants()
    } catch (error) {
      toast.error(`Failed to ${dialogState} tenant`)
    } finally {
      setIsSubmitting(false)
      setDialogState(null)
      setSelectedTenant(null)
    }
  }

  const columns: ColumnDef<TenantDetail>[] = [
    createSelectColumn<TenantDetail>(),
    {
      accessorKey: 'name',
      header: 'Tenant',
      cell: ({ row }) => {
        const tenant = row.original
        return (
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
              <Building2 className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="font-medium">{tenant.name ?? 'Unnamed tenant'}</p>
              <p className="text-sm text-muted-foreground">{tenant.slug ?? '—'}</p>
            </div>
          </div>
        )
      },
    },
    {
      accessorKey: 'plan',
      header: 'Plan',
      cell: ({ getValue }) => {
        const plan = String(getValue() ?? 'unknown')
        return (
          <Badge variant={planColors[plan] || 'default'}>
            {plan.charAt(0).toUpperCase() + plan.slice(1)}
          </Badge>
        )
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: createStatusBadge(statusConfig),
    },
    {
      accessorKey: 'usage.currentUsers',
      header: 'Users',
      cell: ({ row }) => formatNumber(row.original.usage?.currentUsers ?? 0),
    },
    {
      accessorKey: 'createdAt',
      header: 'Created',
      cell: createDateCell(),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => {
        const tenant = row.original
        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon-sm" aria-label="Open tenant actions">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem asChild>
                <Link to="/tenants/$id" params={{ id: tenant.id ?? '' }}>
                  <FileText className="mr-2 h-4 w-4" />
                  View Details
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link to="/tenants/$id" params={{ id: tenant.id ?? '' }}>
                  <Edit className="mr-2 h-4 w-4" />
                  Edit
                </Link>
              </DropdownMenuItem>
              {tenant.status === 'active' ? (
                <DropdownMenuItem
                  onClick={() => {
                    setSelectedTenant(tenant)
                    setDialogState('suspend')
                  }}
                >
                  <Pause className="mr-2 h-4 w-4" />
                  Suspend
                </DropdownMenuItem>
              ) : (
                <DropdownMenuItem
                  onClick={() => {
                    setSelectedTenant(tenant)
                    setDialogState('activate')
                  }}
                >
                  <Play className="mr-2 h-4 w-4" />
                  Activate
                </DropdownMenuItem>
              )}
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => {
                  setSelectedTenant(tenant)
                  setDialogState('delete')
                }}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )
      },
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Tenants"
        description="Manage your platform tenants and their subscriptions"
        breadcrumbs={[{ label: 'Tenants' }]}
        actions={
          <Button asChild leftIcon={<Plus className="h-4 w-4" />}>
            <Link to="/tenants/create">Create Tenant</Link>
          </Button>
        }
      />

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Tenants', value: tenants.length, color: 'blue' },
          { label: 'Active', value: tenants.filter((t) => t.status === 'active').length, color: 'green' },
          { label: 'Suspended', value: tenants.filter((t) => t.status === 'suspended').length, color: 'amber' },
          { label: 'Enterprise', value: tenants.filter((t) => t.plan === 'enterprise').length, color: 'purple' },
        ].map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.1 }}
          >
            <Card className="p-6 card-hover">
              <p className="text-sm text-muted-foreground">{stat.label}</p>
              <p className="text-3xl font-bold mt-1">{stat.value}</p>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Tenants Table */}
      <Card>
        <DataTable
          columns={columns}
          data={tenants}
          isLoading={isLoading}
          searchable
          searchPlaceholder="Search tenants by name or slug…"
          pagination
          pageSize={10}
          onRowClick={(row) => {
            navigate({ to: `/tenants/${row.id}` })
          }}
          exportable
          exportFileName="tenants"
        />
      </Card>

      {/* Action Dialogs */}
      <ConfirmDialog
        isOpen={dialogState === 'suspend'}
        onClose={() => setDialogState(null)}
        onConfirm={handleAction}
        title="Suspend Tenant"
        description={`Are you sure you want to suspend "${selectedTenant?.name}"? This will prevent users from accessing the tenant.`}
        confirmText="Suspend"
        variant="destructive"
        isLoading={isSubmitting}
      />

      <ConfirmDialog
        isOpen={dialogState === 'activate'}
        onClose={() => setDialogState(null)}
        onConfirm={handleAction}
        title="Activate Tenant"
        description={`Are you sure you want to activate "${selectedTenant?.name}"?`}
        confirmText="Activate"
        isLoading={isSubmitting}
      />

      <ConfirmDialog
        isOpen={dialogState === 'delete'}
        onClose={() => setDialogState(null)}
        onConfirm={handleAction}
        title="Delete Tenant"
        description={`Are you sure you want to delete "${selectedTenant?.name}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="destructive"
        isLoading={isSubmitting}
      />
    </div>
  )
}
