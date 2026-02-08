import { describe, it, expect, vi, beforeAll } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Slider, RangeSlider } from './Slider'

beforeAll(() => {
  if (!HTMLElement.prototype.setPointerCapture) {
    HTMLElement.prototype.setPointerCapture = () => {}
  }
  if (!HTMLElement.prototype.releasePointerCapture) {
    HTMLElement.prototype.releasePointerCapture = () => {}
  }
  if (!HTMLElement.prototype.hasPointerCapture) {
    HTMLElement.prototype.hasPointerCapture = () => false
  }
})

describe('Slider', () => {
  it('renders correctly', () => {
    render(<Slider label="Volume" value={[50]} />)
    expect(screen.getByRole('slider')).toBeInTheDocument()
    expect(screen.getByText('Volume')).toBeInTheDocument()
  })

  it('displays current value', () => {
    render(<Slider label="Volume" value={[50]} showValue />)
    expect(screen.getByText('50')).toBeInTheDocument()
  })

  it('displays formatted value', () => {
    render(
      <Slider
        label="Price"
        value={[1000]}
        showValue
        valueFormatter={(v) => `$${v}`}
      />
    )
    expect(screen.getByText('$1000')).toBeInTheDocument()
  })

  it('calls onValueChange when value changes', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    
    render(<Slider value={[50]} onValueChange={handleChange} />)
    const slider = screen.getByRole('slider')
    
    slider.focus()
    await user.keyboard('{ArrowRight}')
    expect(handleChange).toHaveBeenCalled()
  })

  it('shows min and max labels', () => {
    render(<Slider min={0} max={100} showValue={false} />)
    expect(screen.getByText('0')).toBeInTheDocument()
    expect(screen.getByText('100')).toBeInTheDocument()
  })

  it('displays description', () => {
    render(<Slider label="Volume" description="Adjust the volume level" />)
    expect(screen.getByText('Adjust the volume level')).toBeInTheDocument()
  })

  it('is disabled when disabled prop is true', () => {
    render(<Slider disabled />)
    expect(screen.getByRole('slider')).toHaveAttribute('data-disabled')
  })

  it('hides value when showValue is false', () => {
    render(<Slider value={[10]} showValue={false} />)
    expect(screen.queryByText('10')).not.toBeInTheDocument()
  })
})

describe('RangeSlider', () => {
  it('renders correctly', () => {
    render(<RangeSlider label="Price Range" value={[20, 80]} />)
    // Range slider has two thumbs
    expect(screen.getAllByRole('slider')).toHaveLength(2)
  })

  it('displays current range', () => {
    render(<RangeSlider label="Price" value={[20, 80]} showValue />)
    expect(screen.getByText('20 - 80')).toBeInTheDocument()
  })

  it('calls onValueChange with range values', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    
    render(<RangeSlider value={[20, 80]} onValueChange={handleChange} />)
    const sliders = screen.getAllByRole('slider')
    
    sliders[0].focus()
    await user.keyboard('{ArrowRight}')
    expect(handleChange).toHaveBeenCalled()
  })

  it('can hide range values', () => {
    render(<RangeSlider value={[20, 80]} showValue={false} />)
    expect(screen.queryByText('20 - 80')).not.toBeInTheDocument()
  })
})
