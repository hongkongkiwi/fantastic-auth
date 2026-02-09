import { createFileRoute, Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { FileText, MoreHorizontal, Download } from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader } from '../../components/layout/Layout'
import { Card } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import { DataTable, createStatusBadge, createDateCell } from '../../components/DataTable'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../../components/ui/DropdownMenu'
import { useServerFn } from '@tanstack/react-start'
import { listSubscriptions, type SubscriptionDetail } from '../../server/internal-api'
import { toast } from '../../components/ui/Toaster'
import { formatCurrency } from '../../lib/utils'

export const Route = createFileRoute('/billing/subscriptions')({
  component: BillingSubscriptionsPage,
})

const statusConfig: Record<string, { label: string; variant: 'default' | 'success' | 'warning' | 'destructive' }> = {
  active: { label: 'Active', variant: 'success' },
  past_due: { label: 'Past Due', variant: 'warning' },
  canceled: { label: 'Canceled', variant: 'destructive' },
  trialing: { label: 'Trialing', variant: 'default' },
}

function BillingSubscriptionsPage() {
  const [subscriptions, setSubscriptions] = useState<SubscriptionDetail[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const listSubscriptionsFn = useServerFn(listSubscriptions)

  useEffect(() => {
    const fetchSubscriptions = async () => {
      setIsLoading(true)
      try {
        const result = await listSubscriptionsFn({ data: {} })
        setSubscriptions(result.data || [])
      } catch (error) {
        toast.error('Failed to load subscriptions')
      } finally {
        setIsLoading(false)
      }
    }
    fetchSubscriptions()
  }, [])

  const columns: ColumnDef<SubscriptionDetail>[] = [
    {
      accessorKey: 'tenantId',
      header: 'Tenant',
      cell: ({ row }) => (
        <div>
          <p className="font-medium">{row.getValue('tenantId') || '—'}</p>
          <p className="text-sm text-muted-foreground">{row.original.id ?? '—'}</p>
        </div>
      ),
    },
    {
      accessorKey: 'plan',
      header: 'Plan',
      cell: ({ getValue }) => (
        <Badge variant={getValue() === 'enterprise' ? 'warning' : getValue() === 'pro' ? 'success' : 'default'}>
          {(getValue() as string).charAt(0).toUpperCase() + (getValue() as string).slice(1)}
        </Badge>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: createStatusBadge(statusConfig),
    },
    {
      accessorKey: 'amount',
      header: 'Amount',
      cell: ({ row }) => formatCurrency(row.original.amount?.total ?? 0),
    },
    {
      accessorKey: 'currentPeriodEnd',
      header: 'Renews',
      cell: createDateCell(),
    },
    {
      id: 'actions',
      header: '',
      cell: () => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label="Open subscription actions">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem>
              <FileText className="mr-2 h-4 w-4" />
              View Invoices
            </DropdownMenuItem>
            <DropdownMenuItem>
              <Download className="mr-2 h-4 w-4" />
              Download Statement
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Subscriptions"
        description="Manage active subscriptions"
        breadcrumbs={[
          { label: 'Billing', href: '/billing' },
          { label: 'Subscriptions' },
        ]}
        actions={
          <Button variant="outline" asChild>
            <Link to="/billing">Back to Billing</Link>
          </Button>
        }
      />

      <Card>
        <DataTable
          columns={columns}
          data={subscriptions}
          isLoading={isLoading}
          searchable
          searchPlaceholder="Search subscriptions…"
          pagination
          pageSize={10}
          exportable
          exportFileName="subscriptions"
        />
      </Card>
    </div>
  )
}
