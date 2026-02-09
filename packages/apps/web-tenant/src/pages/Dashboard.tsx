import { Users, Building2, Activity, Shield, AlertCircle } from 'lucide-react'
import { StatsCard } from '@/components/dashboard/StatsCard'
import { ActivityChart } from '@/components/dashboard/ActivityChart'
import { RecentActivity } from '@/components/dashboard/RecentActivity'
import { useDashboardStats, useSystemHealth } from '@/hooks/useApi'
import { cn } from '@/lib/utils'

export function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useDashboardStats()
  const { data: health } = useSystemHealth()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground">Welcome to Vault Admin</p>
        </div>
        {health && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">System Status:</span>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium",
                health.status === 'healthy' && "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
                health.status === 'degraded' && "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
                health.status === 'down' && "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
              )}
            >
              <span
                className={cn(
                  "w-2 h-2 rounded-full",
                  health.status === 'healthy' && "bg-green-500",
                  health.status === 'degraded' && "bg-yellow-500",
                  health.status === 'down' && "bg-red-500"
                )}
              />
              {health.status === 'healthy' ? 'All Systems Operational' : 
               health.status === 'degraded' ? 'Degraded Performance' : 
               'System Down'}
            </span>
          </div>
        )}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Total Users"
          value={stats?.totalUsers || 0}
          description="Registered users"
          trend={stats ? { value: 12, label: 'vs last month', direction: 'up' } : undefined}
          icon={Users}
          loading={statsLoading}
        />
        <StatsCard
          title="Active Users"
          value={stats?.activeUsers || 0}
          description="Users active in last 30 days"
          trend={stats ? { value: 8, label: 'vs last month', direction: 'up' } : undefined}
          icon={Activity}
          variant="success"
          loading={statsLoading}
        />
        <StatsCard
          title="Organizations"
          value={stats?.totalOrganizations || 0}
          description="Total organizations"
          icon={Building2}
          loading={statsLoading}
        />
        <StatsCard
          title="MFA Adoption"
          value={`${stats?.mfaAdoptionRate || 0}%`}
          description="Users with MFA enabled"
          trend={stats ? { value: 5, label: 'vs last month', direction: 'up' } : undefined}
          icon={Shield}
          loading={statsLoading}
        />
      </div>

      {/* Quick Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-card rounded-lg border border-border p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">New Today</p>
              <p className="text-2xl font-bold">{stats?.newUsersToday || 0}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
              <Users className="w-5 h-5 text-blue-600 dark:text-blue-400" />
            </div>
          </div>
        </div>
        <div className="bg-card rounded-lg border border-border p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">This Week</p>
              <p className="text-2xl font-bold">{stats?.newUsersThisWeek || 0}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900 flex items-center justify-center">
              <Users className="w-5 h-5 text-purple-600 dark:text-purple-400" />
            </div>
          </div>
        </div>
        <div className="bg-card rounded-lg border border-border p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Active Sessions</p>
              <p className="text-2xl font-bold">{stats?.activeSessions || 0}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-green-100 dark:bg-green-900 flex items-center justify-center">
              <Activity className="w-5 h-5 text-green-600 dark:text-green-400" />
            </div>
          </div>
        </div>
        <div className="bg-card rounded-lg border border-border p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Failed Logins</p>
              <p className="text-2xl font-bold">{stats?.failedLoginsToday || 0}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-red-100 dark:bg-red-900 flex items-center justify-center">
              <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
            </div>
          </div>
        </div>
      </div>

      {/* Charts and Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <ActivityChart className="lg:col-span-2" days={30} />
        <RecentActivity />
      </div>

      {/* Service Health */}
      {health && (
        <div className="bg-card rounded-lg border border-border p-6">
          <h2 className="text-lg font-semibold mb-4">Service Health</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {Object.entries(health.services as Record<string, { status: string; latency: number }>).map(([name, service]) => (
              <div key={name} className="flex items-center gap-3 p-3 bg-muted rounded-lg">
                <span
                  className={cn(
                    "w-3 h-3 rounded-full",
                    service.status === 'up' && "bg-green-500",
                    service.status === 'degraded' && "bg-yellow-500",
                    service.status === 'down' && "bg-red-500"
                  )}
                />
                <div>
                  <p className="font-medium capitalize">{name}</p>
                  <p className="text-xs text-muted-foreground">{service.latency}ms</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
