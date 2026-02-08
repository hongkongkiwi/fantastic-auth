import * as React from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '../../lib/utils'

export interface SelectOption {
  value: string
  label: string
  disabled?: boolean
}

export interface SelectProps
  extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'onChange'> {
  options: SelectOption[]
  label?: string
  error?: string
  helperText?: string
  placeholder?: string
  onChange?: (value: string) => void
  fullWidth?: boolean
}

const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  (
    {
      className,
      options,
      label,
      error,
      helperText,
      placeholder,
      onChange,
      fullWidth,
      id,
      ...props
    },
    ref
  ) => {
    const selectId = id || React.useId()
    const hasError = !!error

    return (
      <div className={cn('space-y-1.5', fullWidth && 'w-full')}>
        {label && (
          <label
            htmlFor={selectId}
            className="text-sm font-medium text-foreground"
          >
            {label}
            {props.required && (
              <span className="text-destructive ml-1">*</span>
            )}
          </label>
        )}
        <div className="relative">
          <select
            id={selectId}
            className={cn(
              'flex h-10 w-full appearance-none rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background transition-colors transition-shadow duration-200',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
              'disabled:cursor-not-allowed disabled:opacity-50',
              'hover:border-muted-foreground/30',
              hasError && 'border-destructive focus-visible:ring-destructive',
              className
            )}
            ref={ref}
            onChange={(e) => onChange?.(e.target.value)}
            aria-invalid={hasError}
            aria-describedby={hasError ? `${selectId}-error` : undefined}
            {...props}
          >
            {placeholder && (
              <option value="" disabled>
                {placeholder}
              </option>
            )}
            {options.map((option) => (
              <option
                key={option.value}
                value={option.value}
                disabled={option.disabled}
              >
                {option.label}
              </option>
            ))}
          </select>
          <ChevronDown className="absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground pointer-events-none" aria-hidden="true" />
        </div>
        {hasError ? (
          <p
            id={`${selectId}-error`}
            className="text-sm text-destructive animate-fade-in"
          >
            {error}
          </p>
        ) : helperText ? (
          <p className="text-sm text-muted-foreground">{helperText}</p>
        ) : null}
      </div>
    )
  }
)
Select.displayName = 'Select'

export { Select }
