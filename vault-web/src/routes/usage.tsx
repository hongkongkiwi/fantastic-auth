import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  BarChart3,
  Activity,
  Users,
  Zap,
  Download,
  TrendingUp,
} from 'lucide-react'
import { PageHeader, StatCard } from '../components/layout/Layout'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { DataTable } from '../components/DataTable'
import type { ColumnDef } from '@tanstack/react-table'
import { formatNumber } from '../lib/utils'
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

export const Route = createFileRoute('/usage')({
  component: UsagePage,
})

interface UsageExport {
  id: string
  type: string
  createdAt: string
  status: 'ready' | 'processing' | 'failed'
  size: string
}

const usageSeries = [
  { day: 'Mon', apiCalls: 32000, activeUsers: 1200 },
  { day: 'Tue', apiCalls: 45000, activeUsers: 1400 },
  { day: 'Wed', apiCalls: 38000, activeUsers: 1350 },
  { day: 'Thu', apiCalls: 52000, activeUsers: 1600 },
  { day: 'Fri', apiCalls: 61000, activeUsers: 1750 },
  { day: 'Sat', apiCalls: 43000, activeUsers: 1500 },
  { day: 'Sun', apiCalls: 37000, activeUsers: 1250 },
]

const tenantUsage = [
  { tenant: 'Acme Inc', calls: 24000, seats: 120, growth: 12 },
  { tenant: 'Oceanic', calls: 18000, seats: 92, growth: 8 },
  { tenant: 'Northwind', calls: 15000, seats: 75, growth: 5 },
  { tenant: 'Umbrella', calls: 12000, seats: 64, growth: -2 },
]

const exportHistory: UsageExport[] = [
  {
    id: 'exp-1',
    type: 'Daily Usage Report',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 3).toISOString(),
    status: 'ready',
    size: '24 MB',
  },
  {
    id: 'exp-2',
    type: 'Tenant Breakdown',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 28).toISOString(),
    status: 'processing',
    size: '—',
  },
]

const exportColumns: ColumnDef<UsageExport>[] = [
  { accessorKey: 'type', header: 'Export', cell: ({ getValue }) => <span className="font-medium">{getValue() as string}</span> },
  { accessorKey: 'createdAt', header: 'Created', cell: ({ getValue }) => new Date(getValue() as string).toLocaleString() },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ getValue }) => (
      <Badge variant={getValue() === 'ready' ? 'success' : getValue() === 'processing' ? 'warning' : 'destructive'}>
        {getValue() as string}
      </Badge>
    ),
  },
  { accessorKey: 'size', header: 'Size', cell: ({ getValue }) => getValue() as string },
]

function UsagePage() {
  const [exports] = useState(exportHistory)
  const prefersReducedMotion = useReducedMotion()

  return (
    <div className="space-y-6">
      <PageHeader
        title="Usage & Analytics"
        description="Platform usage, growth, and exports"
        breadcrumbs={[{ label: 'Usage' }]}
        actions={
          <Button>
            <Download className="mr-2 h-4 w-4" />
            Export Usage
          </Button>
        }
      />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="API Calls (7d)"
          value={formatNumber(usageSeries.reduce((sum, d) => sum + d.apiCalls, 0))}
          icon={<Activity className="h-5 w-5" />}
          color="blue"
        />
        <StatCard
          title="Active Users"
          value={formatNumber(usageSeries[usageSeries.length - 1].activeUsers)}
          icon={<Users className="h-5 w-5" />}
          color="green"
        />
        <StatCard
          title="Peak Throughput"
          value="62k/min"
          icon={<Zap className="h-5 w-5" />}
          color="amber"
        />
        <StatCard
          title="Growth"
          value="+9.4%"
          icon={<TrendingUp className="h-5 w-5" />}
          color="purple"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>API Calls</CardTitle>
            <CardDescription>Daily platform traffic</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={usageSeries}>
                  <defs>
                    <linearGradient id="colorCalls" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="day" stroke="#64748b" fontSize={12} />
                  <YAxis stroke="#64748b" fontSize={12} tickFormatter={(v) => `${Number(v) / 1000}k`} />
                  <Tooltip formatter={(value) => formatNumber(Number(value ?? 0))} />
                  <Area
                    type="monotone"
                    dataKey="apiCalls"
                    stroke="#3b82f6"
                    fillOpacity={1}
                    fill="url(#colorCalls)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Active Users</CardTitle>
            <CardDescription>Daily active users by day</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={usageSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="day" stroke="#64748b" fontSize={12} />
                  <YAxis stroke="#64748b" fontSize={12} />
                  <Tooltip formatter={(value) => formatNumber(Number(value ?? 0))} />
                  <Bar dataKey="activeUsers" fill="#10b981" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Top Tenants</CardTitle>
            <CardDescription>Highest usage in the last 7 days</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {tenantUsage.map((tenant, index) => (
              <motion.div
                key={tenant.tenant}
                initial={prefersReducedMotion ? false : { opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.05 }}
                className="flex items-center justify-between border rounded-lg p-4"
              >
                <div>
                  <p className="font-medium">{tenant.tenant}</p>
                  <p className="text-sm text-muted-foreground">
                    {formatNumber(tenant.calls)} calls • {tenant.seats} seats
                  </p>
                </div>
                <Badge variant={tenant.growth >= 0 ? 'success' : 'destructive'}>
                  {tenant.growth >= 0 ? '+' : ''}{tenant.growth}%
                </Badge>
              </motion.div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Exports</CardTitle>
            <CardDescription>Recent usage exports</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={exportColumns}
              data={exports}
              searchable={false}
              pagination={false}
              exportable={false}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
