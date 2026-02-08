import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Textarea } from './Textarea'

describe('Textarea', () => {
  it('renders correctly', () => {
    render(<Textarea placeholder="Enter description" />)
    expect(screen.getByPlaceholderText('Enter description')).toBeInTheDocument()
  })

  it('displays label', () => {
    render(<Textarea label="Description" id="desc" />)
    expect(screen.getByLabelText('Description')).toBeInTheDocument()
  })

  it('shows required indicator', () => {
    render(<Textarea label="Description" required />)
    expect(screen.getByText('*')).toBeInTheDocument()
  })

  it('handles text input', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    
    render(<Textarea onChange={handleChange} />)
    const textarea = screen.getByRole('textbox')
    
    await user.type(textarea, 'Hello world')
    expect(handleChange).toHaveBeenCalled()
  })

  it('displays error message', () => {
    render(<Textarea error="This field is required" />)
    expect(screen.getByText('This field is required')).toBeInTheDocument()
  })

  it('displays helper text when no error', () => {
    render(<Textarea helperText="Max 500 characters" />)
    expect(screen.getByText('Max 500 characters')).toBeInTheDocument()
  })

  it('can be disabled', () => {
    render(<Textarea disabled />)
    expect(screen.getByRole('textbox')).toBeDisabled()
  })

  it('is not resizable when resizable is false', () => {
    render(<Textarea resizable={false} />)
    expect(screen.getByRole('textbox')).toHaveClass('resize-none')
  })

  it('auto-resizes when autoResize is true', async () => {
    const user = userEvent.setup()
    
    render(<Textarea autoResize data-testid="textarea" />)
    const textarea = screen.getByRole('textbox')
    
    // Add multiple lines
    await user.type(textarea, 'Line 1\nLine 2\nLine 3\nLine 4\nLine 5')
    
    // The textarea should have been resized (min-height is 80px)
    expect(textarea).toHaveStyle({ minHeight: '80px' })
  })

  it('forwards ref correctly', () => {
    const ref = { current: null as HTMLTextAreaElement | null }
    render(<Textarea ref={ref} />)
    expect(ref.current).toBeInstanceOf(HTMLTextAreaElement)
  })
})
