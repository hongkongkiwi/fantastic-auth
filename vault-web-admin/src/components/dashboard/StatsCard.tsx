import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import { cn, formatNumber } from '@/lib/utils'

interface StatsCardProps {
  title: string
  value: number | string
  description?: string
  trend?: {
    value: number
    label: string
    direction: 'up' | 'down' | 'neutral'
  }
  icon: React.ElementType
  variant?: 'default' | 'primary' | 'success' | 'warning' | 'danger'
  loading?: boolean
}

export function StatsCard({
  title,
  value,
  description,
  trend,
  icon: Icon,
  variant = 'default',
  loading = false,
}: StatsCardProps) {
  const variants = {
    default: 'bg-card',
    primary: 'bg-primary text-primary-foreground',
    success: 'bg-green-500 text-white',
    warning: 'bg-yellow-500 text-white',
    danger: 'bg-red-500 text-white',
  }

  const trendColors = {
    up: 'text-green-600 dark:text-green-400',
    down: 'text-red-600 dark:text-red-400',
    neutral: 'text-gray-600 dark:text-gray-400',
  }

  if (loading) {
    return (
      <div className="bg-card rounded-lg border border-border p-6 animate-pulse">
        <div className="flex items-start justify-between">
          <div className="space-y-3">
            <div className="h-4 w-24 bg-muted rounded" />
            <div className="h-8 w-16 bg-muted rounded" />
          </div>
          <div className="h-10 w-10 bg-muted rounded-lg" />
        </div>
      </div>
    )
  }

  return (
    <div 
      className={cn(
        "rounded-lg border border-border p-6 transition-shadow hover:shadow-md",
        variants[variant]
      )}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <p className={cn(
            "text-sm font-medium",
            variant === 'default' ? "text-muted-foreground" : "opacity-90"
          )}>
            {title}
          </p>
          <div className="flex items-baseline gap-2">
            <h3 className="text-2xl font-bold">
              {typeof value === 'number' ? formatNumber(value) : value}
            </h3>
            {trend && (
              <div className={cn(
                "flex items-center gap-1 text-xs font-medium",
                trend.direction === 'up' && trend.value > 0 
                  ? 'text-green-600 dark:text-green-400'
                  : trend.direction === 'down' && trend.value < 0
                    ? 'text-red-600 dark:text-red-400'
                    : 'text-muted-foreground'
              )}>
                {trend.direction === 'up' && <TrendingUp className="w-3 h-3" />}
                {trend.direction === 'down' && <TrendingDown className="w-3 h-3" />}
                {trend.direction === 'neutral' && <Minus className="w-3 h-3" />}
                <span>{Math.abs(trend.value)}%</span>
              </div>
            )}
          </div>
          {description && (
            <p className={cn(
              "text-xs",
              variant === 'default' ? "text-muted-foreground" : "opacity-75"
            )}>
              {description}
            </p>
          )}
          {trend && (
            <p className={cn(
              "text-xs",
              variant === 'default' ? "text-muted-foreground" : "opacity-75"
            )}>
              {trend.label}
            </p>
          )}
        </div>
        <div className={cn(
          "p-3 rounded-lg",
          variant === 'default' ? "bg-primary/10 text-primary" : "bg-white/20"
        )}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  )
}
