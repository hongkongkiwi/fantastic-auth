import { cloneElement, isValidElement, type ButtonHTMLAttributes, type HTMLAttributes, type ReactElement, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

interface DropdownMenuProps {
  children: ReactNode
}

export function DropdownMenu({ children }: DropdownMenuProps) {
  return <div className="relative inline-block">{children}</div>
}

interface DropdownMenuTriggerProps {
  asChild?: boolean
  children: ReactNode
}

export function DropdownMenuTrigger({ asChild, children }: DropdownMenuTriggerProps) {
  if (asChild && isValidElement(children)) {
    return cloneElement(children as ReactElement)
  }
  return <button type="button">{children}</button>
}

interface DropdownMenuContentProps extends HTMLAttributes<HTMLDivElement> {
  align?: 'start' | 'center' | 'end'
}

export function DropdownMenuContent({ className, align = 'start', ...props }: DropdownMenuContentProps) {
  const alignClass = align === 'end' ? 'right-0' : align === 'center' ? 'left-1/2 -translate-x-1/2' : 'left-0'
  return (
    <div
      className={cn(
        'absolute top-full z-20 mt-1 min-w-[10rem] rounded-md border border-border bg-card p-1 shadow-lg',
        alignClass,
        className
      )}
      {...props}
    />
  )
}

export function DropdownMenuItem({ className, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type="button"
      className={cn('flex w-full items-center rounded-sm px-2 py-1.5 text-sm hover:bg-muted', className)}
      {...props}
    />
  )
}
