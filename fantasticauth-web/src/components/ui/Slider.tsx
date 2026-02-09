import * as React from 'react'
import * as SliderPrimitive from '@radix-ui/react-slider'
import { cn } from '../../lib/utils'

export interface SliderProps extends React.ComponentPropsWithoutRef<typeof SliderPrimitive.Root> {
  label?: string
  description?: string
  showValue?: boolean
  valueFormatter?: (value: number) => string
  min?: number
  max?: number
  step?: number
}

const Slider = React.forwardRef<
  React.ElementRef<typeof SliderPrimitive.Root>,
  SliderProps
>(
  (
    {
      className,
      label,
      description,
      showValue = true,
      valueFormatter = (v) => String(v),
      min = 0,
      max = 100,
      step = 1,
      value,
      defaultValue,
      ...props
    },
    ref
  ) => {
    const currentValue = value ?? defaultValue ?? [min]
    const displayValue = Array.isArray(currentValue) ? currentValue[0] : currentValue

    return (
      <div className={cn('w-full space-y-3', className)}>
        {(label || showValue) && (
          <div className="flex items-center justify-between">
            {label && (
              <label className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                {label}
              </label>
            )}
            {showValue && (
              <span className="text-sm text-muted-foreground font-mono">
                {valueFormatter(displayValue)}
              </span>
            )}
          </div>
        )}
        <SliderPrimitive.Root
          ref={ref}
          min={min}
          max={max}
          step={step}
          value={value}
          defaultValue={defaultValue}
          className={cn(
            'relative flex w-full touch-none select-none items-center',
            className
          )}
          {...props}
        >
          <SliderPrimitive.Track className="relative h-2 w-full grow overflow-hidden rounded-full bg-secondary">
            <SliderPrimitive.Range className="absolute h-full bg-primary" />
          </SliderPrimitive.Track>
          <SliderPrimitive.Thumb
            className={cn(
              'block h-5 w-5 rounded-full border-2 border-primary bg-background',
              'ring-offset-background transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
              'disabled:pointer-events-none disabled:opacity-50',
              'active:scale-110 transition-transform'
            )}
          />
        </SliderPrimitive.Root>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
        {/* Min/Max labels */}
        <div className="flex justify-between text-xs text-muted-foreground">
          <span>{valueFormatter(min)}</span>
          <span>{valueFormatter(max)}</span>
        </div>
      </div>
    )
  }
)
Slider.displayName = SliderPrimitive.Root.displayName

// Multi-value slider for ranges
export interface RangeSliderProps extends Omit<SliderProps, 'value' | 'defaultValue' | 'onValueChange'> {
  value?: [number, number]
  defaultValue?: [number, number]
  onValueChange?: (value: [number, number]) => void
}

const RangeSlider = React.forwardRef<
  React.ElementRef<typeof SliderPrimitive.Root>,
  RangeSliderProps
>(
  (
    {
      className,
      label,
      description,
      showValue = true,
      valueFormatter = (v) => String(v),
      min = 0,
      max = 100,
      step = 1,
      value,
      defaultValue,
      onValueChange,
      ...props
    },
    ref
  ) => {
    const currentValue: [number, number] = value ?? defaultValue ?? [min, max]

    return (
      <div className={cn('w-full space-y-3', className)}>
        {(label || showValue) && (
          <div className="flex items-center justify-between">
            {label && (
              <label className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                {label}
              </label>
            )}
            {showValue && (
              <span className="text-sm text-muted-foreground font-mono">
                {valueFormatter(currentValue[0])} - {valueFormatter(currentValue[1])}
              </span>
            )}
          </div>
        )}
        <SliderPrimitive.Root
          ref={ref}
          min={min}
          max={max}
          step={step}
          value={currentValue}
          onValueChange={onValueChange as (value: number[]) => void}
          className={cn(
            'relative flex w-full touch-none select-none items-center',
            className
          )}
          {...props}
        >
          <SliderPrimitive.Track className="relative h-2 w-full grow overflow-hidden rounded-full bg-secondary">
            <SliderPrimitive.Range className="absolute h-full bg-primary" />
          </SliderPrimitive.Track>
          <SliderPrimitive.Thumb
            className={cn(
              'block h-5 w-5 rounded-full border-2 border-primary bg-background',
              'ring-offset-background transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
              'disabled:pointer-events-none disabled:opacity-50',
              'active:scale-110 transition-transform'
            )}
          />
          <SliderPrimitive.Thumb
            className={cn(
              'block h-5 w-5 rounded-full border-2 border-primary bg-background',
              'ring-offset-background transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
              'disabled:pointer-events-none disabled:opacity-50',
              'active:scale-110 transition-transform'
            )}
          />
        </SliderPrimitive.Root>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
        <div className="flex justify-between text-xs text-muted-foreground">
          <span>{valueFormatter(min)}</span>
          <span>{valueFormatter(max)}</span>
        </div>
      </div>
    )
  }
)
RangeSlider.displayName = 'RangeSlider'

export { Slider, RangeSlider }
