import { useState } from 'react'
import { 
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  Area, AreaChart
} from 'recharts'
import { Users, Globe, Clock, Smartphone } from 'lucide-react'
import { formatNumber } from '@/lib/utils'
import { useDashboardStats } from '@/hooks/useApi'

// Mock data for charts
const userGrowthData = [
  { month: 'Jan', users: 1200, newUsers: 150 },
  { month: 'Feb', users: 1350, newUsers: 180 },
  { month: 'Mar', users: 1500, newUsers: 200 },
  { month: 'Apr', users: 1650, newUsers: 220 },
  { month: 'May', users: 1800, newUsers: 250 },
  { month: 'Jun', users: 2050, newUsers: 300 },
]

const loginMethodsData = [
  { name: 'Password', value: 65, color: '#3b82f6' },
  { name: 'SSO', value: 25, color: '#8b5cf6' },
  { name: 'Magic Link', value: 8, color: '#10b981' },
  { name: 'Social', value: 2, color: '#f59e0b' },
]

const sessionDurationData = [
  { duration: '0-5m', users: 450 },
  { duration: '5-15m', users: 680 },
  { duration: '15-30m', users: 520 },
  { duration: '30-60m', users: 380 },
  { duration: '1-2h', users: 250 },
  { duration: '2h+', users: 120 },
]

const geographicData = [
  { country: 'United States', users: 850, percentage: 35 },
  { country: 'United Kingdom', users: 320, percentage: 13 },
  { country: 'Germany', users: 280, percentage: 12 },
  { country: 'Canada', users: 195, percentage: 8 },
  { country: 'France', users: 168, percentage: 7 },
  { country: 'Others', users: 607, percentage: 25 },
]

const deviceData = [
  { device: 'Desktop', users: 1450, percentage: 58 },
  { device: 'Mobile', users: 780, percentage: 31 },
  { device: 'Tablet', users: 275, percentage: 11 },
]

const browserData = [
  { browser: 'Chrome', users: 1450, percentage: 58 },
  { browser: 'Safari', users: 525, percentage: 21 },
  { browser: 'Firefox', users: 275, percentage: 11 },
  { browser: 'Edge', users: 150, percentage: 6 },
  { browser: 'Others', users: 105, percentage: 4 },
]

export function Analytics() {
  const [timeRange, setTimeRange] = useState('30d')
  const { data: stats } = useDashboardStats()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Analytics</h1>
          <p className="text-muted-foreground">Insights into user behavior and activity</p>
        </div>
        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value)}
          className="px-4 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        >
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
          <option value="90d">Last 90 days</option>
          <option value="1y">Last year</option>
        </select>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-card rounded-lg border border-border p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Total Users</p>
              <p className="text-2xl font-bold">{formatNumber(stats?.totalUsers || 2505)}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
              <Users className="w-5 h-5 text-blue-600 dark:text-blue-400" />
            </div>
          </div>
          <p className="text-xs text-green-600 mt-2">+12% from last period</p>
        </div>

        <div className="bg-card rounded-lg border border-border p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Avg. Session</p>
              <p className="text-2xl font-bold">18m 42s</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-green-100 dark:bg-green-900 flex items-center justify-center">
              <Clock className="w-5 h-5 text-green-600 dark:text-green-400" />
            </div>
          </div>
          <p className="text-xs text-green-600 mt-2">+5% from last period</p>
        </div>

        <div className="bg-card rounded-lg border border-border p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Top Country</p>
              <p className="text-2xl font-bold">United States</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900 flex items-center justify-center">
              <Globe className="w-5 h-5 text-purple-600 dark:text-purple-400" />
            </div>
          </div>
          <p className="text-xs text-muted-foreground mt-2">35% of users</p>
        </div>

        <div className="bg-card rounded-lg border border-border p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Mobile Users</p>
              <p className="text-2xl font-bold">31%</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-orange-100 dark:bg-orange-900 flex items-center justify-center">
              <Smartphone className="w-5 h-5 text-orange-600 dark:text-orange-400" />
            </div>
          </div>
          <p className="text-xs text-green-600 mt-2">+8% from last period</p>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* User Growth */}
        <div className="bg-card rounded-lg border border-border p-6">
          <h3 className="font-semibold mb-4">User Growth</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={userGrowthData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="month" stroke="hsl(var(--muted-foreground))" fontSize={12} />
                <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '6px',
                  }}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="users"
                  name="Total Users"
                  stroke="hsl(var(--primary))"
                  fill="hsl(var(--primary))"
                  fillOpacity={0.2}
                />
                <Area
                  type="monotone"
                  dataKey="newUsers"
                  name="New Users"
                  stroke="hsl(142.1 76.2% 36.3%)"
                  fill="hsl(142.1 76.2% 36.3%)"
                  fillOpacity={0.2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Login Methods */}
        <div className="bg-card rounded-lg border border-border p-6">
          <h3 className="font-semibold mb-4">Login Methods</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={loginMethodsData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {loginMethodsData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '6px',
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Session Duration */}
        <div className="bg-card rounded-lg border border-border p-6">
          <h3 className="font-semibold mb-4">Session Duration Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sessionDurationData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="duration" stroke="hsl(var(--muted-foreground))" fontSize={12} />
                <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: '6px',
                  }}
                />
                <Bar dataKey="users" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Geographic Distribution */}
        <div className="bg-card rounded-lg border border-border p-6">
          <h3 className="font-semibold mb-4">Geographic Distribution</h3>
          <div className="space-y-3">
            {geographicData.map((country) => (
              <div key={country.country} className="flex items-center gap-4">
                <span className="w-32 text-sm truncate">{country.country}</span>
                <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full"
                    style={{ width: `${country.percentage}%` }}
                  />
                </div>
                <span className="w-16 text-sm text-right text-muted-foreground">
                  {country.percentage}%
                </span>
                <span className="w-12 text-sm text-right">
                  {formatNumber(country.users)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Device and Browser Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Device Breakdown */}
        <div className="bg-card rounded-lg border border-border p-6">
          <h3 className="font-semibold mb-4">Device Breakdown</h3>
          <div className="space-y-4">
            {deviceData.map((device) => (
              <div key={device.device} className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
                    {device.device === 'Desktop' && <span className="text-lg">💻</span>}
                    {device.device === 'Mobile' && <span className="text-lg">📱</span>}
                    {device.device === 'Tablet' && <span className="text-lg">📱</span>}
                  </div>
                  <span className="font-medium">{device.device}</span>
                </div>
                <div className="flex items-center gap-4">
                  <div className="w-32 h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary rounded-full"
                      style={{ width: `${device.percentage}%` }}
                    />
                  </div>
                  <span className="text-sm text-muted-foreground w-12 text-right">
                    {device.percentage}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Browser Breakdown */}
        <div className="bg-card rounded-lg border border-border p-6">
          <h3 className="font-semibold mb-4">Browser Breakdown</h3>
          <div className="space-y-4">
            {browserData.map((browser) => (
              <div key={browser.browser} className="flex items-center justify-between">
                <span className="font-medium">{browser.browser}</span>
                <div className="flex items-center gap-4">
                  <div className="w-32 h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary rounded-full"
                      style={{ width: `${browser.percentage}%` }}
                    />
                  </div>
                  <span className="text-sm text-muted-foreground w-12 text-right">
                    {browser.percentage}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
