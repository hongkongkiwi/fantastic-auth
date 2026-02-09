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
  Info,
} from 'lucide-react'
import { PageHeader, StatCard } from '../components/layout/Layout'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Skeleton, SkeletonStatCard } from '../components/ui/Skeleton'
import { useServerFn } from '@tanstack/react-start'
import { getPlatformOverview, type PlatformOverview } from '../server/internal-api'
import { clientLogger } from '../lib/client-logger'
import { formatNumber, formatCurrency, formatRelativeTime, cn } from '../lib/utils'

export const Route = createFileRoute('/')({
  component: DashboardPage,
})

const GrowthChart = lazy(() => import('../components/charts/GrowthChart'))
const PlanDistributionChart = lazy(
  () => import('../components/charts/PlanDistributionChart')
)

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

  // Empty state for when no data is available
  const hasNoData = !isLoading && !overview
  const dashboard = overview as (PlatformOverview & {
    tenants?: { trend?: number }
    users?: { trend?: number }
    revenue?: { trend?: number }
    system?: { apiCallsTrend?: number }
    growth?: Array<{ month: string; tenants: number; users: number }>
    planDistribution?: Array<{ name: string; value: number; color: string }>
    recentActivity?: Array<{
      id: string
      action: string
      tenant: string
      user: string
      timestamp: string
      status: 'success' | 'warning' | 'error'
    }>
    systemStatus?: {
      uptime: number
      services: Array<{
        name: string
        status: 'operational' | 'degraded' | 'down'
        latency?: string
      }>
    }
  }) | null
  const trend = (value?: number) =>
    typeof value === 'number'
      ? {
          value: Math.abs(value),
          isPositive: value >= 0,
        }
      : undefined

  return (
    <div className="space-y-8">
      <PageHeader
        title="Dashboard"
        description="Overview of your platform's performance and key metrics"
      />

      {hasNoData ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Info className="h-12 w-12 text-muted-foreground mb-4" />
            <CardTitle className="text-lg mb-2">No Data Available</CardTitle>
            <CardDescription>
              Platform overview data is not available. Please check back later or contact support.
            </CardDescription>
          </CardContent>
        </Card>
      ) : (
        <>
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
                  value={formatNumber(overview?.tenants?.total ?? 0)}
                  trend={trend(dashboard?.tenants?.trend)}
                  icon={<Building2 className="h-5 w-5" />}
                  color="blue"
                />
                <StatCard
                  title="Active Users"
                  value={formatNumber(overview?.users?.total ?? 0)}
                  trend={trend(dashboard?.users?.trend)}
                  icon={<Users className="h-5 w-5" />}
                  color="green"
                />
                <StatCard
                  title="Monthly Revenue"
                  value={formatCurrency(overview?.revenue?.mrr ?? 0)}
                  trend={trend(dashboard?.revenue?.trend)}
                  icon={<CreditCard className="h-5 w-5" />}
                  color="purple"
                />
                <StatCard
                  title="API Calls (24h)"
                  value={formatNumber(overview?.system?.totalApiCalls24h ?? 0)}
                  trend={trend(dashboard?.system?.apiCallsTrend)}
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
                    {dashboard?.growth?.length ? (
                      <GrowthChart data={dashboard.growth} />
                    ) : (
                      <div className="flex items-center justify-center h-full text-muted-foreground">
                        No growth data available
                      </div>
                    )}
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
                    {dashboard?.planDistribution?.length ? (
                      <PlanDistributionChart data={dashboard.planDistribution} />
                    ) : (
                      <div className="flex items-center justify-center h-full text-muted-foreground">
                        No plan data available
                      </div>
                    )}
                  </Suspense>
                </div>
                {dashboard?.planDistribution?.length ? (
                  <div className="mt-4 space-y-2">
                    {dashboard.planDistribution.map((plan) => (
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
                ) : null}
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
                {dashboard?.recentActivity?.length ? (
                  <div className="space-y-4">
                    {dashboard.recentActivity.map((activity, index) => (
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
                          {(activity.status === 'warning' || activity.status === 'error') && (
                            <AlertCircle className="h-4 w-4" />
                          )}
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
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Info className="h-8 w-8 mx-auto mb-2" />
                    <p>No recent activity</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* System Status */}
            <Card>
              <CardHeader>
                <CardTitle>System Status</CardTitle>
                <CardDescription>Current platform health</CardDescription>
              </CardHeader>
              <CardContent>
                {dashboard?.systemStatus?.services?.length ? (
                  <>
                    <div className="space-y-4">
                      {dashboard.systemStatus.services.map((service) => (
                        <div key={service.name} className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <div
                              className={cn(
                                'w-2 h-2 rounded-full',
                                service.status === 'operational' && 'bg-green-500',
                                service.status === 'degraded' && 'bg-amber-500',
                                service.status === 'down' && 'bg-red-500'
                              )}
                              aria-hidden="true"
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
                        <span className="font-medium">{dashboard.systemStatus.uptime}%</span>
                      </div>
                      <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-green-500 rounded-full" 
                          style={{ width: `${dashboard.systemStatus.uptime}%` }}
                        />
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Info className="h-8 w-8 mx-auto mb-2" />
                    <p>System status unavailable</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
