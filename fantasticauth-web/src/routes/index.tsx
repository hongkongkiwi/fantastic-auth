import { createFileRoute } from '@tanstack/react-router'
import { Suspense, lazy, useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  Building2,
  Users,
  CreditCard,
  Activity,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react'
import { PageHeader, StatCard } from '../components/layout/Layout'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Skeleton, SkeletonStatCard } from '../components/ui/Skeleton'
import { useServerFn } from '@tanstack/react-start'
import { getPlatformOverview, type PlatformOverview } from '../server/internal-api'
import { clientLogger } from '../lib/client-logger'
import { formatNumber, formatCurrency, formatRelativeTime } from '../lib/utils'

export const Route = createFileRoute('/')({
  component: DashboardPage,
})

const GrowthChart = lazy(() => import('../components/charts/GrowthChart'))
const PlanDistributionChart = lazy(
  () => import('../components/charts/PlanDistributionChart')
)

// Mock data for charts - replace with real data
const tenantGrowthData = [
  { month: 'Jan', tenants: 45, users: 1200 },
  { month: 'Feb', tenants: 52, users: 1450 },
  { month: 'Mar', tenants: 58, users: 1680 },
  { month: 'Apr', tenants: 65, users: 1920 },
  { month: 'May', tenants: 72, users: 2150 },
  { month: 'Jun', tenants: 85, users: 2480 },
]

const planDistribution = [
  { name: 'Free', value: 35, color: '#94a3b8' },
  { name: 'Starter', value: 28, color: '#6366f1' },
  { name: 'Pro', value: 18, color: '#8b5cf6' },
  { name: 'Enterprise', value: 4, color: '#ec4899' },
]

const now = Date.now()
const recentActivity = [
  { id: 1, action: 'Tenant Created', tenant: 'Acme Corp', user: 'John Doe', timestamp: new Date(now - 2 * 60 * 1000).toISOString(), status: 'success' },
  { id: 2, action: 'Subscription Updated', tenant: 'TechStart Inc', user: 'Jane Smith', timestamp: new Date(now - 5 * 60 * 1000).toISOString(), status: 'success' },
  { id: 3, action: 'User Suspended', tenant: 'Beta LLC', user: 'Admin', timestamp: new Date(now - 12 * 60 * 1000).toISOString(), status: 'warning' },
  { id: 4, action: 'Invoice Generated', tenant: 'Gamma Co', user: 'System', timestamp: new Date(now - 15 * 60 * 1000).toISOString(), status: 'success' },
  { id: 5, action: 'Payment Failed', tenant: 'Delta Ltd', user: 'System', timestamp: new Date(now - 23 * 60 * 1000).toISOString(), status: 'error' },
]

function DashboardPage() {
  const [isLoading, setIsLoading] = useState(true)
  const [overview, setOverview] = useState<PlatformOverview | null>(null)
  const getOverview = useServerFn(getPlatformOverview)
  const prefersReducedMotion = useReducedMotion()

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await getOverview({ data: {} })
        setOverview(data)
      } catch (error) {
        clientLogger.error('Failed to fetch overview', error)
      } finally {
        setIsLoading(false)
      }
    }
    fetchData()
  }, [getOverview])

  // Calculate trends (mock data - replace with real calculations)
  const trends = {
    tenants: { value: 12, isPositive: true },
    users: { value: 8.5, isPositive: true },
    mrr: { value: 15.3, isPositive: true },
    apiCalls: { value: 3.2, isPositive: false },
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Dashboard"
        description="Overview of your platform's performance and key metrics"
      />

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {isLoading ? (
          <>
            <SkeletonStatCard />
            <SkeletonStatCard />
            <SkeletonStatCard />
            <SkeletonStatCard />
          </>
        ) : (
          <>
            <StatCard
              title="Total Tenants"
              value={formatNumber(overview?.tenants?.total ?? 85)}
              trend={trends.tenants}
              icon={<Building2 className="h-5 w-5" />}
              color="blue"
            />
            <StatCard
              title="Active Users"
              value={formatNumber(overview?.users?.total ?? 2480)}
              trend={trends.users}
              icon={<Users className="h-5 w-5" />}
              color="green"
            />
            <StatCard
              title="Monthly Revenue"
              value={formatCurrency(overview?.revenue?.mrr ?? 12500)}
              trend={trends.mrr}
              icon={<CreditCard className="h-5 w-5" />}
              color="purple"
            />
            <StatCard
              title="API Calls (24h)"
              value={formatNumber(overview?.system?.totalApiCalls24h ?? 45200)}
              trend={trends.apiCalls}
              icon={<Activity className="h-5 w-5" />}
              color="amber"
            />
          </>
        )}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Chart */}
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>Growth Overview</CardTitle>
              <CardDescription>Tenant and user growth over the last 6 months</CardDescription>
            </div>
            <Badge variant="muted">Last 6 months</Badge>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <Suspense fallback={<Skeleton className="h-[300px] w-full" />}>
                <GrowthChart data={tenantGrowthData} />
              </Suspense>
            </div>
          </CardContent>
        </Card>

        {/* Plan Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Plan Distribution</CardTitle>
            <CardDescription>Breakdown by subscription tier</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[200px]">
              <Suspense fallback={<Skeleton className="h-[200px] w-full" />}>
                <PlanDistributionChart data={planDistribution} />
              </Suspense>
            </div>
            <div className="mt-4 space-y-2">
              {planDistribution.map((plan) => (
                <div key={plan.name} className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-3 h-3 rounded-full"
                      style={{ backgroundColor: plan.color }}
                    />
                    <span className="text-muted-foreground">{plan.name}</span>
                  </div>
                  <span className="font-medium">{plan.value}%</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Activity */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>Latest actions across the platform</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentActivity.map((activity, index) => (
                <motion.div
                  key={activity.id}
                  initial={prefersReducedMotion ? false : { opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.05 }}
                  className="flex items-start gap-4 p-3 rounded-lg hover:bg-muted/50 transition-colors"
                >
                  <div
                    className={cn(
                      'p-2 rounded-full shrink-0',
                      activity.status === 'success' && 'bg-green-500/10 text-green-600',
                      activity.status === 'warning' && 'bg-amber-500/10 text-amber-600',
                      activity.status === 'error' && 'bg-red-500/10 text-red-600'
                    )}
                  >
                    {activity.status === 'success' && <CheckCircle2 className="h-4 w-4" />}
                    {activity.status === 'warning' && <AlertCircle className="h-4 w-4" />}
                    {activity.status === 'error' && <AlertCircle className="h-4 w-4" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium">{activity.action}</p>
                    <p className="text-sm text-muted-foreground">
                      {activity.tenant} • {activity.user}
                    </p>
                  </div>
                  <span className="text-xs text-muted-foreground whitespace-nowrap">
                    <span title={activity.timestamp}>{formatRelativeTime(activity.timestamp)}</span>
                  </span>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* System Status */}
        <Card>
          <CardHeader>
            <CardTitle>System Status</CardTitle>
            <CardDescription>Current platform health</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { name: 'API Gateway', status: 'operational', latency: '45ms' },
                { name: 'Database', status: 'operational', latency: '12ms' },
                { name: 'Auth Service', status: 'operational', latency: '28ms' },
                { name: 'Email Service', status: 'degraded', latency: '340ms' },
              ].map((service) => (
                <div key={service.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div
                      className={cn(
                        'w-2 h-2 rounded-full',
                        service.status === 'operational' && 'bg-green-500',
                        service.status === 'degraded' && 'bg-amber-500',
                        service.status === 'down' && 'bg-red-500'
                      )}
                    />
                    <span className="text-sm font-medium">{service.name}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground">{service.latency}</span>
                    <Badge
                      variant={
                        service.status === 'operational'
                          ? 'success'
                          : service.status === 'degraded'
                          ? 'warning'
                          : 'destructive'
                      }
                      size="sm"
                    >
                      {service.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-6 pt-6 border-t">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Uptime (30d)</span>
                <span className="font-medium">99.98%</span>
              </div>
              <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
                <div className="h-full w-[99.98%] bg-green-500 rounded-full" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

// Helper for class merging
function cn(...classes: (string | boolean | undefined)[]) {
  return classes.filter(Boolean).join(' ')
}
