import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Input } from './Input'

describe('Input', () => {
  it('renders correctly', () => {
    render(<Input placeholder="Enter text" />)
    expect(screen.getByPlaceholderText('Enter text')).toBeInTheDocument()
  })

  it('handles user input', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    
    render(<Input onChange={onChange} />)
    const input = screen.getByRole('textbox')
    
    await user.type(input, 'Hello')
    expect(onChange).toHaveBeenCalledTimes(5)
  })

  it('displays error state', () => {
    render(<Input error="This field is required" />)
    expect(screen.getByText('This field is required')).toBeInTheDocument()
  })

  it('displays label', () => {
    render(<Input label="Email" id="email" />)
    expect(screen.getByLabelText('Email')).toBeInTheDocument()
  })

  it('can be disabled', () => {
    render(<Input disabled />)
    expect(screen.getByRole('textbox')).toBeDisabled()
  })

  it('supports different types', () => {
    const { rerender } = render(<Input type="text" label="Field" id="type-test" />)
    expect(screen.getByLabelText('Field')).toHaveAttribute('type', 'text')

    rerender(<Input type="password" label="Field" id="type-test" />)
    expect(screen.getByLabelText('Field')).toHaveAttribute('type', 'password')

    rerender(<Input type="email" label="Field" id="type-test" />)
    expect(screen.getByLabelText('Field')).toHaveAttribute('type', 'email')
  })

  it('displays helper text', () => {
    render(<Input helperText="Enter your email address" />)
    expect(screen.getByText('Enter your email address')).toBeInTheDocument()
  })

  it('forwards ref correctly', () => {
    const ref = { current: null as HTMLInputElement | null }
    render(<Input ref={ref} />)
    expect(ref.current).toBeInstanceOf(HTMLInputElement)
  })
})
