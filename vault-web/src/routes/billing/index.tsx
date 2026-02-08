import { createFileRoute, Link } from '@tanstack/react-router'
import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  DollarSign,
  TrendingUp,
  FileText,
  Download,
  MoreHorizontal,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react'
import type { ColumnDef } from '@tanstack/react-table'
import { PageHeader, StatCard } from '../../components/layout/Layout'
import { DataTable, createStatusBadge, createDateCell } from '../../components/DataTable'
import { Button } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/Card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/Tabs'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../../components/ui/DropdownMenu'
import { useServerFn } from '@tanstack/react-start'
import { listSubscriptions, type SubscriptionDetail } from '../../server/internal-api'
import { toast } from '../../components/ui/Toaster'
import { formatCurrency } from '../../lib/utils'
import { cn } from '../../lib/utils'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from 'recharts'

export const Route = createFileRoute('/billing/')({
  component: BillingPage,
})

const revenueData = [
  { month: 'Jan', revenue: 12500, target: 12000 },
  { month: 'Feb', revenue: 14200, target: 13000 },
  { month: 'Mar', revenue: 15800, target: 14000 },
  { month: 'Apr', revenue: 17100, target: 15000 },
  { month: 'May', revenue: 18900, target: 16000 },
  { month: 'Jun', revenue: 21500, target: 18000 },
]

const statusConfig: Record<string, { label: string; variant: 'default' | 'success' | 'warning' | 'destructive' }> = {
  active: { label: 'Active', variant: 'success' },
  past_due: { label: 'Past Due', variant: 'warning' },
  canceled: { label: 'Canceled', variant: 'destructive' },
  trialing: { label: 'Trialing', variant: 'default' },
}

function BillingPage() {
  const [subscriptions, setSubscriptions] = useState<SubscriptionDetail[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('overview')
  const prefersReducedMotion = useReducedMotion()

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

  // Mock stats
  const stats = {
    mrr: 21500,
    arr: 258000,
    growth: 12.5,
    activeSubs: subscriptions.length || 85,
    pastDue: 3,
    trialing: 8,
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Billing"
        description="Manage subscriptions, invoices, and revenue"
        breadcrumbs={[{ label: 'Billing' }]}
      />

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="subscriptions">Subscriptions</TabsTrigger>
          <TabsTrigger value="invoices">Invoices</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {/* Stats Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              title="Monthly Recurring Revenue"
              value={formatCurrency(stats.mrr)}
              trend={{ value: stats.growth, isPositive: true }}
              icon={<DollarSign className="h-5 w-5" />}
              color="green"
            />
            <StatCard
              title="Annual Run Rate"
              value={formatCurrency(stats.arr)}
              icon={<TrendingUp className="h-5 w-5" />}
              color="blue"
            />
            <StatCard
              title="Active Subscriptions"
              value={stats.activeSubs}
              icon={<CheckCircle2 className="h-5 w-5" />}
              color="purple"
            />
            <StatCard
              title="Past Due"
              value={stats.pastDue}
              icon={<AlertCircle className="h-5 w-5" />}
              color="rose"
            />
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Revenue Overview</CardTitle>
                <CardDescription>Monthly recurring revenue vs target</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[300px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={revenueData}>
                      <defs>
                        <linearGradient id="colorRevenue" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis dataKey="month" stroke="#64748b" fontSize={12} />
                      <YAxis stroke="#64748b" fontSize={12} tickFormatter={(v) => `$${Number(v) / 1000}k`} />
                      <Tooltip formatter={(value) => formatCurrency(Number(value ?? 0))} />
                      <Area
                        type="monotone"
                        dataKey="revenue"
                        stroke="#10b981"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#colorRevenue)"
                        name="Revenue"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Plan Distribution</CardTitle>
                <CardDescription>Subscriptions by plan tier</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[300px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={[
                        { name: 'Free', value: 35 },
                        { name: 'Starter', value: 28 },
                        { name: 'Pro', value: 18 },
                        { name: 'Enterprise', value: 4 },
                      ]}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                      <YAxis stroke="#64748b" fontSize={12} />
                      <Tooltip />
                      <Bar dataKey="value" fill="#6366f1" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Recent Activity */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Recent Invoices</CardTitle>
                <CardDescription>Latest billing activity</CardDescription>
              </div>
              <Button variant="outline" size="sm" asChild>
                <Link to="/billing">View All</Link>
              </Button>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {[
                  { id: 'INV-001', tenant: 'Acme Corp', amount: 299, status: 'paid', date: '2024-01-15' },
                  { id: 'INV-002', tenant: 'TechStart Inc', amount: 99, status: 'paid', date: '2024-01-14' },
                  { id: 'INV-003', tenant: 'Beta LLC', amount: 599, status: 'pending', date: '2024-01-13' },
                  { id: 'INV-004', tenant: 'Gamma Co', amount: 99, status: 'overdue', date: '2024-01-10' },
                ].map((invoice, index) => (
                  <motion.div
                    key={invoice.id}
                    initial={prefersReducedMotion ? false : { opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.05 }}
                    className="flex items-center justify-between p-3 rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <div className="flex items-center gap-4">
                      <div className={cn(
                        'p-2 rounded-full',
                        invoice.status === 'paid' && 'bg-green-500/10 text-green-600',
                        invoice.status === 'pending' && 'bg-amber-500/10 text-amber-600',
                        invoice.status === 'overdue' && 'bg-red-500/10 text-red-600'
                      )}>
                        <FileText className="h-4 w-4" />
                      </div>
                      <div>
                        <p className="font-medium">{invoice.id}</p>
                        <p className="text-sm text-muted-foreground">{invoice.tenant}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className="font-medium">{formatCurrency(invoice.amount)}</span>
                      <Badge
                        variant={
                          invoice.status === 'paid'
                            ? 'success'
                            : invoice.status === 'pending'
                            ? 'warning'
                            : 'destructive'
                        }
                      >
                        {invoice.status}
                      </Badge>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="subscriptions" className="space-y-6">
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
        </TabsContent>

        <TabsContent value="invoices" className="space-y-6">
          <Card className="p-12 text-center">
            <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold">Invoice Management</h3>
            <p className="text-muted-foreground mt-1">Full invoice management coming soon</p>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
