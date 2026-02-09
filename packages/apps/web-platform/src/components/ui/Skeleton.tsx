import { cn } from '../../lib/utils'

interface SkeletonProps {
  className?: string
  variant?: 'default' | 'circle' | 'text' | 'card'
  width?: string | number
  height?: string | number
  lines?: number
}

function Skeleton({
  className,
  variant = 'default',
  width,
  height,
  lines = 1,
}: SkeletonProps) {
  const baseClasses =
    'animate-pulse rounded-md bg-muted motion-reduce:animate-none'

  const style: React.CSSProperties = {
    width: width,
    height: height,
  }

  if (variant === 'circle') {
    return (
      <div
        className={cn(baseClasses, 'rounded-full', className)}
        style={style}
      />
    )
  }

  if (variant === 'text') {
    return (
      <div className="space-y-2 w-full">
        {Array.from({ length: lines }).map((_, i) => (
          <div
            key={i}
            className={cn(
              baseClasses,
              'h-4',
              i === lines - 1 && lines > 1 && 'w-3/4',
              className
            )}
            style={style}
          />
        ))}
      </div>
    )
  }

  if (variant === 'card') {
    return (
      <div className={cn('rounded-xl border bg-card p-6 space-y-4', className)}>
        <div className={cn(baseClasses, 'h-6 w-1/3')} />
        <div className={cn(baseClasses, 'h-4 w-full')} />
        <div className={cn(baseClasses, 'h-4 w-2/3')} />
      </div>
    )
  }

  return (
    <div
      className={cn(baseClasses, className)}
      style={style}
    />
  )
}

// Pre-built skeleton patterns for common UI elements
function SkeletonStatCard() {
  return (
    <div className="rounded-xl border bg-card p-6 space-y-3">
      <div className="flex items-center gap-2">
        <Skeleton variant="circle" width={40} height={40} />
        <Skeleton width={80} height={20} />
      </div>
      <Skeleton width={120} height={32} />
      <Skeleton width={60} height={16} />
    </div>
  )
}

function SkeletonTableRow({ columns = 4 }: { columns?: number }) {
  return (
    <div className="flex items-center gap-4 py-4 border-b">
      {Array.from({ length: columns }).map((_, i) => (
        <Skeleton
          key={i}
          className={i === 0 ? 'flex-1' : 'w-24'}
          height={20}
        />
      ))}
    </div>
  )
}

function SkeletonChart() {
  return (
    <div className="rounded-xl border bg-card p-6">
      <Skeleton width={150} height={24} className="mb-6" />
      <div className="flex items-end gap-2 h-48">
        {Array.from({ length: 12 }).map((_, i) => (
          <Skeleton
            key={i}
            className="flex-1"
            height={`${Math.random() * 60 + 40}%`}
          />
        ))}
      </div>
    </div>
  )
}

export { Skeleton, SkeletonStatCard, SkeletonTableRow, SkeletonChart }
