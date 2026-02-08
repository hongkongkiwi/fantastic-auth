import { createFileRoute, Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { FileText, Download, MoreHorizontal } from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader } from '../../components/layout/Layout'
import { Card } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import { DataTable } from '../../components/DataTable'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../../components/ui/DropdownMenu'
import { formatCurrency } from '../../lib/utils'
import { toast } from '../../components/ui/Toaster'

export const Route = createFileRoute('/billing/invoices')({
  component: BillingInvoicesPage,
})

interface Invoice {
  id: string
  tenant_id: string
  status: 'draft' | 'open' | 'paid' | 'uncollectible' | 'void'
  total_cents: number
  currency: string
  created_at: string
  invoice_pdf_url?: string | null
  hosted_invoice_url?: string | null
}

function BillingInvoicesPage() {
  const [invoices, setInvoices] = useState<Invoice[]>([])
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const fetchInvoices = async () => {
      setIsLoading(true)
      try {
        const res = await fetch('/api/v1/admin/billing/invoices')
        if (!res.ok) throw new Error('Failed to load invoices')
        const payload = await res.json()
        setInvoices(payload.invoices || [])
      } catch {
        toast.error('Failed to load invoices')
      } finally {
        setIsLoading(false)
      }
    }
    fetchInvoices()
  }, [])

  const columns: ColumnDef<Invoice>[] = [
    {
      accessorKey: 'id',
      header: 'Invoice',
      cell: ({ row }) => (
        <div>
          <p className="font-medium">{row.original.id}</p>
          <p className="text-sm text-muted-foreground">{row.original.tenant_id}</p>
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
      accessorKey: 'total_cents',
      header: 'Amount',
      cell: ({ row }) => formatCurrency((row.original.total_cents || 0) / 100),
    },
    {
      accessorKey: 'created_at',
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
                const url = row.original.hosted_invoice_url || row.original.invoice_pdf_url
                if (url) window.open(url, '_blank', 'noopener,noreferrer')
              }}
            >
              <FileText className="mr-2 h-4 w-4" />
              View Invoice
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => {
                const url = row.original.invoice_pdf_url || row.original.hosted_invoice_url
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
        <DataTable
          columns={columns}
          data={invoices}
          isLoading={isLoading}
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
