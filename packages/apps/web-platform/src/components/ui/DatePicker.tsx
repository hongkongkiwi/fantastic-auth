import * as React from 'react'
import { format, isValid, parse, startOfDay, endOfDay, subDays } from 'date-fns'
import { Calendar as CalendarIcon, ChevronLeft, ChevronRight, ChevronDown, ChevronUp, X } from 'lucide-react'
import { DayPicker, DateRange } from 'react-day-picker'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '../../lib/utils'
import { Button } from './Button'
import { Input } from './Input'

export interface DatePickerProps {
  value?: Date
  onChange?: (date: Date | undefined) => void
  label?: string
  placeholder?: string
  error?: string
  helperText?: string
  disabled?: boolean
  minDate?: Date
  maxDate?: Date
  presets?: { label: string; date: Date }[]
}

export function DatePicker({
  value,
  onChange,
  label,
  placeholder = 'Pick a date',
  error,
  helperText,
  disabled,
  minDate,
  maxDate,
  presets,
}: DatePickerProps) {
  const [isOpen, setIsOpen] = React.useState(false)
  const [inputValue, setInputValue] = React.useState('')
  const containerRef = React.useRef<HTMLDivElement>(null)

  // Close on click outside
  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Update input value when date changes
  React.useEffect(() => {
    if (value && isValid(value)) {
      setInputValue(format(value, 'MM/dd/yyyy'))
    } else {
      setInputValue('')
    }
  }, [value])

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value
    setInputValue(newValue)

    // Try to parse the date
    const parsed = parse(newValue, 'MM/dd/yyyy', new Date())
    if (isValid(parsed)) {
      onChange?.(parsed)
    }
  }

  const handleSelect = (date: Date | undefined) => {
    onChange?.(date)
    setIsOpen(false)
  }

  const clearDate = () => {
    onChange?.(undefined)
    setInputValue('')
    setIsOpen(false)
  }

  return (
    <div className="w-full space-y-2" ref={containerRef}>
      {label && (
        <label className={cn('text-sm font-medium leading-none', error && 'text-destructive')}>
          {label}
          {disabled && <span className="ml-1 text-muted-foreground">(disabled)</span>}
        </label>
      )}
      <div className="relative">
        <Input
          value={inputValue}
          onChange={handleInputChange}
          onFocus={() => setIsOpen(true)}
          placeholder={placeholder}
          disabled={disabled}
          error={error}
          leftIcon={<CalendarIcon className="h-4 w-4 text-muted-foreground" />}
          rightIcon={
            value && !disabled ? (
              <button type="button"
                onClick={clearDate}
                className="text-muted-foreground hover:text-foreground"
              >
                <X className="h-4 w-4" />
              </button>
            ) : undefined
          }
        />

        <AnimatePresence>
          {isOpen && !disabled && (
            <motion.div
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 4 }}
              className="absolute z-50 mt-1 bg-popover border rounded-md shadow-lg p-3"
            >
              {presets && presets.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-3 pb-3 border-b">
                  {presets.map((preset) => (
                    <Button
                      key={preset.label}
                      variant="ghost"
                      size="sm"
                      onClick={() => handleSelect(preset.date)}
                    >
                      {preset.label}
                    </Button>
                  ))}
                </div>
              )}
              <DayPicker
                mode="single"
                selected={value}
                onSelect={handleSelect}
                disabled={(date) => {
                  if (minDate && date < startOfDay(minDate)) return true
                  if (maxDate && date > endOfDay(maxDate)) return true
                  return false
                }}
                className={cn('p-0')}
                classNames={{
                  months: 'flex flex-col sm:flex-row space-y-4 sm:space-x-4 sm:space-y-0',
                  month: 'space-y-4',
                  caption: 'flex justify-center pt-1 relative items-center',
                  caption_label: 'text-sm font-medium',
                  nav: 'space-x-1 flex items-center',
                  nav_button: cn(
                    'h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100 inline-flex items-center justify-center rounded-md border border-input'
                  ),
                  nav_button_previous: 'absolute left-1',
                  nav_button_next: 'absolute right-1',
                  table: 'w-full border-collapse space-y-1',
                  head_row: 'flex',
                  head_cell: 'text-muted-foreground rounded-md w-9 font-normal text-[0.8rem]',
                  row: 'flex w-full mt-2',
                  cell: 'h-9 w-9 text-center text-sm p-0 relative [&:has([aria-selected])]:bg-accent first:[&:has([aria-selected])]:rounded-l-md last:[&:has([aria-selected])]:rounded-r-md focus-within:relative focus-within:z-20',
                  day: cn(
                    'h-9 w-9 p-0 font-normal aria-selected:opacity-100 inline-flex items-center justify-center rounded-md hover:bg-accent hover:text-accent-foreground'
                  ),
                  day_selected:
                    'bg-primary text-primary-foreground hover:bg-primary hover:text-primary-foreground focus:bg-primary focus:text-primary-foreground',
                  day_today: 'bg-accent text-accent-foreground',
                  day_outside: 'text-muted-foreground opacity-50',
                  day_disabled: 'text-muted-foreground opacity-50',
                  day_hidden: 'invisible',
                }}
                components={{
                  Chevron: ({ orientation, className }) => {
                    const Icon =
                      orientation === 'left'
                        ? ChevronLeft
                        : orientation === 'right'
                          ? ChevronRight
                          : orientation === 'up'
                            ? ChevronUp
                            : ChevronDown
                    return <Icon className={cn('h-4 w-4', className)} />
                  },
                }}
              />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      {helperText && !error && (
        <p className="text-xs text-muted-foreground">{helperText}</p>
      )}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  )
}

// Date Range Picker
export interface DateRangePickerProps {
  value?: DateRange
  onChange?: (range: DateRange | undefined) => void
  label?: string
  placeholder?: string
  error?: string
  helperText?: string
  disabled?: boolean
  minDate?: Date
  maxDate?: Date
  presets?: { label: string; range: DateRange }[]
}

export function DateRangePicker({
  value,
  onChange,
  label,
  placeholder = 'Select date range',
  error,
  helperText,
  disabled,
  minDate,
  maxDate,
  presets,
}: DateRangePickerProps) {
  const [isOpen, setIsOpen] = React.useState(false)
  const containerRef = React.useRef<HTMLDivElement>(null)

  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const displayValue = React.useMemo(() => {
    if (value?.from && value?.to) {
      return `${format(value.from, 'MM/dd/yyyy')} - ${format(value.to, 'MM/dd/yyyy')}`
    }
    if (value?.from) {
      return `${format(value.from, 'MM/dd/yyyy')} - ...`
    }
    return ''
  }, [value])

  const defaultPresets: { label: string; range: DateRange }[] = [
    { label: 'Today', range: { from: new Date(), to: new Date() } },
    { label: 'Yesterday', range: { from: subDays(new Date(), 1), to: subDays(new Date(), 1) } },
    { label: 'Last 7 days', range: { from: subDays(new Date(), 7), to: new Date() } },
    { label: 'Last 30 days', range: { from: subDays(new Date(), 30), to: new Date() } },
    { label: 'This month', range: { from: new Date(new Date().getFullYear(), new Date().getMonth(), 1), to: new Date() } },
  ]

  return (
    <div className="w-full space-y-2" ref={containerRef}>
      {label && (
        <label className={cn('text-sm font-medium leading-none', error && 'text-destructive')}>
          {label}
          {disabled && <span className="ml-1 text-muted-foreground">(disabled)</span>}
        </label>
      )}
      <div className="relative">
        <button type="button"
          onClick={() => !disabled && setIsOpen(!isOpen)}
          disabled={disabled}
          className={cn(
            'w-full flex items-center justify-between px-3 py-2 text-sm border rounded-md bg-background',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
            'disabled:cursor-not-allowed disabled:opacity-50',
            error && 'border-destructive',
            !displayValue && 'text-muted-foreground'
          )}
        >
          <div className="flex items-center gap-2">
            <CalendarIcon className="h-4 w-4 text-muted-foreground" />
            <span>{displayValue || placeholder}</span>
          </div>
          {value?.from && !disabled && (
            <button type="button"
              onClick={(e) => {
                e.stopPropagation()
                onChange?.(undefined)
              }}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </button>

        <AnimatePresence>
          {isOpen && !disabled && (
            <motion.div
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 4 }}
              className="absolute z-50 mt-1 bg-popover border rounded-md shadow-lg p-3"
            >
              <div className="flex flex-wrap gap-1 mb-3 pb-3 border-b">
                {(presets || defaultPresets).map((preset) => (
                  <Button
                    key={preset.label}
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      onChange?.(preset.range)
                      setIsOpen(false)
                    }}
                  >
                    {preset.label}
                  </Button>
                ))}
              </div>
              <DayPicker
                mode="range"
                selected={value}
                onSelect={(range) => {
                  onChange?.(range)
                  if (range?.from && range?.to) {
                    setIsOpen(false)
                  }
                }}
                numberOfMonths={2}
                disabled={(date) => {
                  if (minDate && date < startOfDay(minDate)) return true
                  if (maxDate && date > endOfDay(maxDate)) return true
                  return false
                }}
                classNames={{
                  months: 'flex flex-col sm:flex-row space-y-4 sm:space-x-4 sm:space-y-0',
                  month: 'space-y-4',
                  caption: 'flex justify-center pt-1 relative items-center',
                  caption_label: 'text-sm font-medium',
                  nav: 'space-x-1 flex items-center',
                  nav_button: cn(
                    'h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100 inline-flex items-center justify-center rounded-md border border-input'
                  ),
                  nav_button_previous: 'absolute left-1',
                  nav_button_next: 'absolute right-1',
                  table: 'w-full border-collapse space-y-1',
                  head_row: 'flex',
                  head_cell: 'text-muted-foreground rounded-md w-9 font-normal text-[0.8rem]',
                  row: 'flex w-full mt-2',
                  cell: 'h-9 w-9 text-center text-sm p-0 relative [&:has([aria-selected])]:bg-accent first:[&:has([aria-selected])]:rounded-l-md last:[&:has([aria-selected])]:rounded-r-md focus-within:relative focus-within:z-20',
                  day: cn(
                    'h-9 w-9 p-0 font-normal aria-selected:opacity-100 inline-flex items-center justify-center rounded-md hover:bg-accent hover:text-accent-foreground'
                  ),
                  day_selected:
                    'bg-primary text-primary-foreground hover:bg-primary hover:text-primary-foreground focus:bg-primary focus:text-primary-foreground',
                  day_today: 'bg-accent text-accent-foreground',
                  day_outside: 'text-muted-foreground opacity-50',
                  day_disabled: 'text-muted-foreground opacity-50',
                  day_range_middle: 'aria-selected:bg-accent aria-selected:text-accent-foreground',
                  day_hidden: 'invisible',
                }}
                components={{
                  Chevron: ({ orientation, className }) => {
                    const Icon =
                      orientation === 'left'
                        ? ChevronLeft
                        : orientation === 'right'
                          ? ChevronRight
                          : orientation === 'up'
                            ? ChevronUp
                            : ChevronDown
                    return <Icon className={cn('h-4 w-4', className)} />
                  },
                }}
              />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      {helperText && !error && (
        <p className="text-xs text-muted-foreground">{helperText}</p>
      )}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  )
}
