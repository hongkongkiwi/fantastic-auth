import { createFileRoute, Link } from '@tanstack/react-router'
import { useEffect, useMemo, useState } from 'react'
import { FileText, Download, MoreHorizontal } from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader } from '../../components/layout/Layout'
import { Card } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import { Input } from '../../components/ui/Input'
import { DataTable } from '../../components/DataTable'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../../components/ui/DropdownMenu'
import { formatCurrency } from '../../lib/utils'
import { toast } from '../../components/ui/Toaster'
import { useServerFn } from '@tanstack/react-start'
import { listPlatformInvoices, type InvoiceResponse } from '../../server/internal-api'

export const Route = createFileRoute('/billing/invoices')({
  component: BillingInvoicesPage,
})

type Invoice = InvoiceResponse
type InvoiceStatusFilter = 'all' | 'draft' | 'open' | 'paid' | 'uncollectible' | 'void'

function BillingInvoicesPage() {
  const [invoices, setInvoices] = useState<Invoice[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [perPage, setPerPage] = useState(10)
  const [statusFilter, setStatusFilter] = useState<InvoiceStatusFilter>('all')
  const [tenantFilter, setTenantFilter] = useState('')
  const [createdFrom, setCreatedFrom] = useState('')
  const [createdTo, setCreatedTo] = useState('')
  const [pagination, setPagination] = useState({
    page: 1,
    perPage: 10,
    total: 0,
    totalPages: 1,
  })
  const listPlatformInvoicesFn = useServerFn(listPlatformInvoices)
  const pageSizeOptions = useMemo(() => [10, 20, 50, 100], [])

  useEffect(() => {
    const fetchInvoices = async () => {
      setIsLoading(true)
      try {
        const result = await listPlatformInvoicesFn({
          data: {
            page,
            perPage,
            tenantId: tenantFilter.trim() ? tenantFilter.trim() : undefined,
            status: statusFilter === 'all' ? undefined : statusFilter,
            createdFrom: createdFrom || undefined,
            createdTo: createdTo || undefined,
          },
        })
        const response = result as {
          invoices?: Invoice[]
          pagination?: {
            page?: number
            perPage?: number
            total?: number
            totalPages?: number
          }
        }
        setInvoices(response.invoices || [])
        setPagination({
          page: response.pagination?.page ?? page,
          perPage: response.pagination?.perPage ?? perPage,
          total: response.pagination?.total ?? response.invoices?.length ?? 0,
          totalPages:
            response.pagination?.totalPages ??
            Math.max(1, Math.ceil((response.invoices?.length ?? 0) / perPage)),
        })
      } catch {
        toast.error('Failed to load invoices')
      } finally {
        setIsLoading(false)
      }
    }
    fetchInvoices()
  }, [
    page,
    perPage,
    statusFilter,
    tenantFilter,
    createdFrom,
    createdTo,
    listPlatformInvoicesFn,
  ])

  const columns: ColumnDef<Invoice>[] = [
    {
      accessorKey: 'id',
      header: 'Invoice',
      cell: ({ row }) => (
        <div>
          <p className="font-medium">{row.original.id}</p>
          <p className="text-sm text-muted-foreground">{row.original.tenantId}</p>
        </div>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ getValue }) => {
        const status = getValue() as Invoice['status']
        const variant =
          status === 'paid'
            ? 'success'
            : status === 'open' || status === 'draft'
              ? 'warning'
              : 'destructive'
        return <Badge variant={variant}>{status}</Badge>
      },
    },
    {
      accessorKey: 'amount',
      header: 'Amount',
      cell: ({ row }) => formatCurrency(row.original.amount || 0),
    },
    {
      accessorKey: 'createdAt',
      header: 'Date',
      cell: ({ getValue }) => new Date(getValue() as string).toLocaleDateString(),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label="Invoice actions">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem
              onClick={() => {
                const url = row.original.pdfUrl
                if (url) window.open(url, '_blank', 'noopener,noreferrer')
              }}
            >
              <FileText className="mr-2 h-4 w-4" />
              View Invoice
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => {
                const url = row.original.pdfUrl
                if (url) window.open(url, '_blank', 'noopener,noreferrer')
              }}
            >
              <Download className="mr-2 h-4 w-4" />
              Download PDF
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Invoices"
        description="Review invoices across tenants"
        breadcrumbs={[
          { label: 'Billing', href: '/billing' },
          { label: 'Invoices' },
        ]}
        actions={
          <Button variant="outline" asChild>
            <Link to="/billing">Back to Billing</Link>
          </Button>
        }
      />

      <Card>
        <div className="flex flex-col lg:flex-row lg:items-end gap-4 border-b px-4 py-4">
          <div className="flex flex-col gap-1">
            <label className="text-xs uppercase tracking-wide text-muted-foreground">
              Status
            </label>
            <select
              className="h-9 rounded-md border border-input bg-background px-2 text-sm"
              value={statusFilter}
              onChange={(event) => {
                setStatusFilter(event.target.value as InvoiceStatusFilter)
                setPage(1)
              }}
            >
              <option value="all">All statuses</option>
              <option value="draft">Draft</option>
              <option value="open">Open</option>
              <option value="paid">Paid</option>
              <option value="uncollectible">Uncollectible</option>
              <option value="void">Void</option>
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1">
            <label className="text-xs uppercase tracking-wide text-muted-foreground">
              Tenant ID
            </label>
            <Input
              placeholder="Tenant UUID"
              value={tenantFilter}
              onChange={(event) => {
                setTenantFilter(event.target.value)
                setPage(1)
              }}
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs uppercase tracking-wide text-muted-foreground">
              Created From
            </label>
            <Input
              type="date"
              value={createdFrom}
              onChange={(event) => {
                const value = event.target.value
                setCreatedFrom(value ? new Date(value).toISOString() : '')
                setPage(1)
              }}
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs uppercase tracking-wide text-muted-foreground">
              Created To
            </label>
            <Input
              type="date"
              value={createdTo ? createdTo.slice(0, 10) : ''}
              onChange={(event) => {
                const value = event.target.value
                if (value) {
                  const end = new Date(`${value}T23:59:59.999Z`)
                  setCreatedTo(end.toISOString())
                } else {
                  setCreatedTo('')
                }
                setPage(1)
              }}
            />
          </div>
        </div>
        <DataTable
          columns={columns}
          data={invoices}
          isLoading={isLoading}
          searchable
          searchPlaceholder="Search invoices…"
          pagination={false}
          exportable
          exportFileName="invoices"
        />
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 border-t px-4 py-3 text-sm text-muted-foreground">
          <div>
            Showing page {pagination.page} of {pagination.totalPages} · {pagination.total} total
          </div>
          <div className="flex items-center gap-2">
            <span>Rows</span>
            <select
              className="h-8 rounded-md border border-input bg-background px-2 text-sm"
              value={perPage}
              onChange={(event) => {
                const value = Number(event.target.value)
                setPerPage(value)
                setPage(1)
              }}
            >
              {pageSizeOptions.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(1)}
                disabled={page <= 1 || isLoading}
              >
                First
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((prev) => Math.max(1, prev - 1))}
                disabled={page <= 1 || isLoading}
              >
                Prev
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((prev) => Math.min(pagination.totalPages, prev + 1))}
                disabled={page >= pagination.totalPages || isLoading}
              >
                Next
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(pagination.totalPages)}
                disabled={page >= pagination.totalPages || isLoading}
              >
                Last
              </Button>
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}
