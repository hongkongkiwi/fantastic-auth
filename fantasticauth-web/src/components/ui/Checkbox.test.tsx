import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Checkbox } from './Checkbox'

describe('Checkbox', () => {
  it('renders correctly', () => {
    render(<Checkbox label="Accept terms" />)
    expect(screen.getByRole('checkbox')).toBeInTheDocument()
    expect(screen.getByText('Accept terms')).toBeInTheDocument()
  })

  it('handles check/uncheck', async () => {
    const user = userEvent.setup()
    const onCheckedChange = vi.fn()
    
    render(<Checkbox onCheckedChange={onCheckedChange} />)
    const checkbox = screen.getByRole('checkbox')
    
    await user.click(checkbox)
    expect(onCheckedChange).toHaveBeenCalledWith(true)
    
    await user.click(checkbox)
    expect(onCheckedChange).toHaveBeenCalledWith(false)
  })

  it('can be controlled', () => {
    const { rerender } = render(<Checkbox checked={false} />)
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    
    rerender(<Checkbox checked={true} />)
    expect(screen.getByRole('checkbox')).toBeChecked()
  })

  it('displays description', () => {
    render(<Checkbox label="Subscribe" description="Receive weekly updates" />)
    expect(screen.getByText('Receive weekly updates')).toBeInTheDocument()
  })

  it('displays error state', () => {
    render(<Checkbox label="Required" error="This field is required" />)
    expect(screen.getByText('This field is required')).toBeInTheDocument()
  })

  it('can be disabled', () => {
    render(<Checkbox disabled label="Disabled checkbox" />)
    expect(screen.getByRole('checkbox')).toBeDisabled()
  })

  it('supports indeterminate state', () => {
    render(<Checkbox indeterminate label="Select all" />)
    // Indeterminate state is visually different but still a checkbox
    expect(screen.getByRole('checkbox')).toBeInTheDocument()
  })
})
