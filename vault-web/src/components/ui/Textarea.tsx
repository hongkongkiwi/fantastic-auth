import * as React from 'react'
import { cn } from '../../lib/utils'

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string
  error?: string
  helperText?: string
  resizable?: boolean
  autoResize?: boolean
}

const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, label, error, helperText, resizable = true, autoResize = false, ...props }, ref) => {
    const textareaRef = React.useRef<HTMLTextAreaElement>(null)
    
    React.useImperativeHandle(ref, () => textareaRef.current!)

    // Auto-resize functionality
    React.useEffect(() => {
      if (!autoResize || !textareaRef.current) return

      const textarea = textareaRef.current
      
      const resize = () => {
        textarea.style.height = 'auto'
        textarea.style.height = `${textarea.scrollHeight}px`
      }

      textarea.addEventListener('input', resize)
      resize() // Initial resize

      return () => textarea.removeEventListener('input', resize)
    }, [autoResize])

    return (
      <div className="w-full space-y-2">
        {label && (
          <label
            htmlFor={props.id}
            className={cn(
              'text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70',
              error && 'text-destructive'
            )}
          >
            {label}
            {props.required && <span className="text-destructive ml-1">*</span>}
          </label>
        )}
        <textarea
          ref={textareaRef}
          className={cn(
            'flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm',
            'ring-offset-background placeholder:text-muted-foreground',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
            'disabled:cursor-not-allowed disabled:opacity-50',
            !resizable && 'resize-none',
            error && 'border-destructive focus-visible:ring-destructive',
            className
          )}
          {...props}
        />
        {(helperText || error) && (
          <p className={cn('text-xs', error ? 'text-destructive' : 'text-muted-foreground')}>
            {error || helperText}
          </p>
        )}
      </div>
    )
  }
)
Textarea.displayName = 'Textarea'

export { Textarea }
