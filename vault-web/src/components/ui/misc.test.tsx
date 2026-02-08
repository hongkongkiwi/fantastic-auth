import { describe, it, expect, vi } from 'vitest'

const sonnerToastMock = vi.hoisted(() => ({
  success: vi.fn(),
  error: vi.fn(),
  warning: vi.fn(),
  info: vi.fn(),
  loading: vi.fn(),
  promise: vi.fn(),
}))

vi.mock('sonner', () => ({
  Toaster: (props: { className?: string; theme?: string }) => (
    <div data-testid="sonner" data-theme={props.theme} data-classname={props.className} />
  ),
  toast: sonnerToastMock,
}))

import { render, screen } from '@testing-library/react'
import { beforeEach } from 'vitest'
import userEvent from '@testing-library/user-event'
import { Alert, AlertDescription, AlertTitle } from './Alert'
import { Badge } from './Badge'
import { Label } from './Label'
import { RadioGroup, RadioGroupItem } from './RadioGroup'
import { Select } from './Select'
import { Skeleton, SkeletonChart, SkeletonStatCard, SkeletonTableRow } from './Skeleton'
import { Switch } from './Switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './Tabs'
import { Toaster, toast } from './Toaster'
import { toast as sonnerToast } from 'sonner'

const mockedSonnerToast = vi.mocked(sonnerToast)

beforeEach(() => {
  Object.values(sonnerToastMock).forEach((mock) => mock.mockClear())
})

describe('Alert', () => {
  it('renders title and description with variant classes', () => {
    render(
      <Alert variant="destructive">
        <AlertTitle>Heads up</AlertTitle>
        <AlertDescription>Something went wrong</AlertDescription>
      </Alert>
    )

    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByText('Heads up')).toBeInTheDocument()
    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
  })
})

describe('Badge', () => {
  it('renders a dot when enabled', () => {
    const { container } = render(
      <Badge dot dotColor="bg-red-500">
        New
      </Badge>
    )

    expect(screen.getByText('New')).toBeInTheDocument()
    expect(container.querySelector('span')).toBeInTheDocument()
  })

  it('uses default dot color when not provided', () => {
    const { container } = render(<Badge dot>Default</Badge>)
    const dot = container.querySelector('span')
    expect(dot).toBeInTheDocument()
    expect(dot?.className).toContain('bg-current')
  })
})

describe('Label', () => {
  it('associates with input', () => {
    render(
      <div>
        <Label htmlFor="field">Name</Label>
        <input id="field" />
      </div>
    )

    expect(screen.getByLabelText('Name')).toBeInTheDocument()
  })
})

describe('RadioGroup', () => {
  it('calls onValueChange when selection changes', async () => {
    const user = userEvent.setup()
    const onValueChange = vi.fn()

    render(
      <RadioGroup defaultValue="one" onValueChange={onValueChange}>
        <RadioGroupItem id="one" value="one" label="One" description="First" />
        <RadioGroupItem id="two" value="two" label="Two" description="Second" />
      </RadioGroup>
    )

    await user.click(screen.getByText('Two'))
    expect(onValueChange).toHaveBeenCalledWith('two')
  })

  it('renders items without label or description', () => {
    render(
      <RadioGroup defaultValue="one">
        <RadioGroupItem id="one" value="one" />
      </RadioGroup>
    )
    expect(screen.getByRole('radio')).toBeInTheDocument()
  })
})

describe('Select', () => {
  it('renders options and emits value on change', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()

    render(
      <Select
        label="Plan"
        placeholder="Choose"
        options={[
          { value: 'free', label: 'Free' },
          { value: 'pro', label: 'Pro' },
        ]}
        onChange={onChange}
      />
    )

    const select = screen.getByLabelText('Plan') as HTMLSelectElement
    expect(screen.getByText('Choose')).toBeInTheDocument()
    await user.selectOptions(select, 'pro')

    expect(onChange).toHaveBeenCalledWith('pro')
    expect(select.value).toBe('pro')
  })

  it('shows error text when provided', () => {
    render(
      <Select
        label="Plan"
        options={[{ value: 'free', label: 'Free' }]}
        error="Required"
      />
    )

    expect(screen.getByText('Required')).toBeInTheDocument()
  })

  it('shows helper text when no error', () => {
    render(
      <Select
        label="Plan"
        options={[{ value: 'free', label: 'Free' }]}
        helperText="Pick a plan"
      />
    )

    expect(screen.getByText('Pick a plan')).toBeInTheDocument()
  })
})

describe('Skeleton', () => {
  it('renders different variants', () => {
    const { container } = render(
      <div>
        <Skeleton />
        <Skeleton variant="circle" width={40} height={40} />
        <Skeleton variant="text" lines={2} />
        <Skeleton variant="card" />
      </div>
    )

    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
    expect(container.querySelector('.rounded-full')).toBeInTheDocument()
    expect(container.querySelectorAll('.h-4').length).toBeGreaterThan(0)
  })

  it('renders prebuilt skeleton patterns', () => {
    render(
      <div>
        <SkeletonStatCard />
        <SkeletonTableRow columns={3} />
        <SkeletonChart />
      </div>
    )

    expect(document.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0)
  })
})

describe('Switch', () => {
  it('toggles checked state', async () => {
    const user = userEvent.setup()
    render(<Switch />)

    const toggle = screen.getByRole('switch')
    await user.click(toggle)

    expect(toggle.getAttribute('data-state')).toBe('checked')
  })
})

describe('Tabs', () => {
  it('switches content on tab click', async () => {
    const user = userEvent.setup()

    render(
      <Tabs defaultValue="one">
        <TabsList>
          <TabsTrigger value="one">One</TabsTrigger>
          <TabsTrigger value="two">Two</TabsTrigger>
        </TabsList>
        <TabsContent value="one">First</TabsContent>
        <TabsContent value="two">Second</TabsContent>
      </Tabs>
    )

    expect(screen.getByText('First')).toBeInTheDocument()
    await user.click(screen.getByText('Two'))
    expect(screen.getByText('Second')).toBeInTheDocument()
  })
})

describe('Toaster', () => {
  it('renders the Sonner toaster', () => {
    render(<Toaster />)
    expect(screen.getByTestId('sonner')).toBeInTheDocument()
  })

  it('forwards toast helpers to sonner', async () => {
    toast.success('Saved', 'All good')
    toast.error('Failed', 'Nope')
    toast.warning('Warn', 'Heads up')
    toast.info('Info', 'FYI')
    toast.loading('Loading')

    const promise = Promise.resolve('ok')
    toast.promise(promise, { loading: 'Loading', success: 'Done', error: 'Err' })

    await new Promise((resolve) => setTimeout(resolve, 0))

    expect(mockedSonnerToast.success).toHaveBeenCalledWith('Saved', { description: 'All good' })
  })
})
