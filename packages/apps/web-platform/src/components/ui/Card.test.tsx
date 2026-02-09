import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from './Card'

describe('Card', () => {
  it('renders all card parts', () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Card Title</CardTitle>
          <CardDescription>Card description</CardDescription>
        </CardHeader>
        <CardContent>Card content</CardContent>
        <CardFooter>Card footer</CardFooter>
      </Card>
    )
    
    expect(screen.getByText('Card Title')).toBeInTheDocument()
    expect(screen.getByText('Card description')).toBeInTheDocument()
    expect(screen.getByText('Card content')).toBeInTheDocument()
    expect(screen.getByText('Card footer')).toBeInTheDocument()
  })

  it('applies custom className', () => {
    render(<Card className="custom-class">Content</Card>)
    expect(screen.getByText('Content')).toHaveClass('custom-class')
  })

  it('is accessible', () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Accessible Card</CardTitle>
        </CardHeader>
        <CardContent>Content</CardContent>
      </Card>
    )
    
    // Card should have proper heading structure
    expect(screen.getByRole('heading', { level: 3 })).toHaveTextContent('Accessible Card')
  })

  it('supports variants, hover, and padding', () => {
    const { rerender } = render(
      <Card variant="glass" hover padding="lg">
        Card
      </Card>
    )
    const card = screen.getByText('Card')
    expect(card).toHaveClass('glass')
    expect(card).toHaveClass('card-hover')
    expect(card).toHaveClass('p-8')

    rerender(
      <Card variant="outline" padding="sm">
        Card
      </Card>
    )
    expect(screen.getByText('Card')).toHaveClass('bg-transparent')
    expect(screen.getByText('Card')).toHaveClass('p-4')
  })
})
