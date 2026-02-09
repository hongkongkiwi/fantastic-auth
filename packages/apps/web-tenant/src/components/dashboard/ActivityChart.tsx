import { useMemo } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Area,
  AreaChart,
} from 'recharts'
import { format } from 'date-fns'
import { useActivityData } from '@/hooks/useApi'
import { cn } from '@/lib/utils'
import type { ActivityData } from '@/types'

interface ActivityChartProps {
  days?: number
  className?: string
  variant?: 'line' | 'area'
}

export function ActivityChart({ days = 30, className, variant = 'area' }: ActivityChartProps) {
  const { data, isLoading } = useActivityData(days)

  const chartData = useMemo(() => {
    if (!data) return []
    return (data as ActivityData[]).map((item) => ({
      date: format(new Date(item.date), 'MMM dd'),
      logins: item.logins,
      signups: item.signups,
      failedLogins: item.failedLogins,
    }))
  }, [data])

  if (isLoading) {
    return (
      <div className={cn("bg-card rounded-lg border border-border p-6", className)}>
        <div className="h-8 w-48 bg-muted rounded animate-pulse mb-6" />
        <div className="h-64 bg-muted rounded animate-pulse" />
      </div>
    )
  }

  const ChartComponent = variant === 'area' ? AreaChart : LineChart

  return (
    <div className={cn("bg-card rounded-lg border border-border p-6", className)}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-lg font-semibold">Activity Overview</h3>
          <p className="text-sm text-muted-foreground">
            User activity over the last {days} days
          </p>
        </div>
      </div>

      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <ChartComponent data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
            <XAxis 
              dataKey="date" 
              stroke="hsl(var(--muted-foreground))"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <YAxis 
              stroke="hsl(var(--muted-foreground))"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: 'hsl(var(--card))',
                border: '1px solid hsl(var(--border))',
                borderRadius: '6px',
                fontSize: '12px',
              }}
            />
            <Legend wrapperStyle={{ fontSize: '12px' }} />
            
            {variant === 'area' ? (
              <>
                <Area
                  type="monotone"
                  dataKey="logins"
                  name="Logins"
                  stroke="hsl(var(--primary))"
                  fill="hsl(var(--primary))"
                  fillOpacity={0.2}
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="signups"
                  name="Signups"
                  stroke="hsl(142.1 76.2% 36.3%)"
                  fill="hsl(142.1 76.2% 36.3%)"
                  fillOpacity={0.2}
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="failedLogins"
                  name="Failed Logins"
                  stroke="hsl(0 84.2% 60.2%)"
                  fill="hsl(0 84.2% 60.2%)"
                  fillOpacity={0.2}
                  strokeWidth={2}
                />
              </>
            ) : (
              <>
                <Line
                  type="monotone"
                  dataKey="logins"
                  name="Logins"
                  stroke="hsl(var(--primary))"
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="signups"
                  name="Signups"
                  stroke="hsl(142.1 76.2% 36.3%)"
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="failedLogins"
                  name="Failed Logins"
                  stroke="hsl(0 84.2% 60.2%)"
                  strokeWidth={2}
                  dot={false}
                />
              </>
            )}
          </ChartComponent>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
