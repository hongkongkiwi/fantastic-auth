import { createFileRoute, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { FileText, Download, MoreHorizontal } from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader } from '../../components/layout/Layout'
import { Card } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import { DataTable } from '../../components/DataTable'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../../components/ui/DropdownMenu'
import { formatCurrency } from '../../lib/utils'

export const Route = createFileRoute('/billing/invoices')({
  component: BillingInvoicesPage,
})

interface Invoice {
  id: string
  tenantId: string
  status: 'paid' | 'pending' | 'overdue'
  amount: number
  currency: string
  createdAt: string
}

const invoicesMock: Invoice[] = [
  {
    id: 'INV-1001',
    tenantId: 'tenant_01',
    status: 'paid',
    amount: 12400,
    currency: 'USD',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 5).toISOString(),
  },
  {
    id: 'INV-1002',
    tenantId: 'tenant_02',
    status: 'pending',
    amount: 7800,
    currency: 'USD',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2).toISOString(),
  },
  {
    id: 'INV-1003',
    tenantId: 'tenant_03',
    status: 'overdue',
    amount: 5600,
    currency: 'USD',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 10).toISOString(),
  },
]

function BillingInvoicesPage() {
  const [invoices] = useState(invoicesMock)

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
      cell: ({ getValue }) => (
        <Badge variant={getValue() === 'paid' ? 'success' : getValue() === 'pending' ? 'warning' : 'destructive'}>
          {getValue() as string}
        </Badge>
      ),
    },
    {
      accessorKey: 'amount',
      header: 'Amount',
      cell: ({ row }) => formatCurrency(row.original.amount),
    },
    {
      accessorKey: 'createdAt',
      header: 'Date',
      cell: ({ getValue }) => new Date(getValue() as string).toLocaleDateString(),
    },
    {
      id: 'actions',
      header: '',
      cell: () => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label="Invoice actions">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem>
              <FileText className="mr-2 h-4 w-4" />
              View Invoice
            </DropdownMenuItem>
            <DropdownMenuItem>
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
        <DataTable
          columns={columns}
          data={invoices}
          searchable
          searchPlaceholder="Search invoices…"
          pagination
          pageSize={10}
          exportable
          exportFileName="invoices"
        />
      </Card>
    </div>
  )
}
