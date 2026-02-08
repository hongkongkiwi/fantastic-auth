import * as React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const locationRef = vi.hoisted(() => ({ current: { pathname: '/' } }))

vi.mock('@tanstack/react-router', () => ({
  useLocation: () => locationRef.current,
  Link: ({ to, children, ...props }: any) => (
    <a href={typeof to === 'string' ? to : '#'} {...props}>
      {children}
    </a>
  ),
}))

const reducedMotion = vi.hoisted(() => ({ value: true }))

vi.mock('framer-motion', async () => {
  const ReactImport = await import('react')
  const strip = (props: any) => {
    const { initial, animate, exit, transition, whileHover, ...rest } = props
    return rest
  }
  const create = (tag: string) =>
    ReactImport.forwardRef(({ children, ...props }: any, ref) =>
      ReactImport.createElement(tag, { ref, ...strip(props) }, children)
    )
  return {
    motion: new Proxy({}, { get: (_target, prop) => create(String(prop)) }),
    AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    useReducedMotion: () => reducedMotion.value,
  }
})

import { MobileNav, MobileBottomNav } from './MobileNav'

describe('MobileNav', () => {
  it('renders menu when open and closes on overlay click', async () => {
    reducedMotion.value = false
    const user = userEvent.setup()
    const onClose = vi.fn()

    render(<MobileNav isOpen onClose={onClose} />)

    await user.click(screen.getAllByLabelText('Close navigation menu')[0])
    expect(onClose).toHaveBeenCalled()

    expect(screen.getByText('Vault Admin')).toBeInTheDocument()
  })

  it('triggers logout', async () => {
    const user = userEvent.setup()
    const onLogout = vi.fn()

    render(
      <MobileNav
        isOpen
        onClose={() => {}}
        onLogout={onLogout}
        user={{ name: 'Sam', email: 'sam@example.com' }}
      />
    )

    await user.click(screen.getByText('Logout'))
    expect(onLogout).toHaveBeenCalled()
    expect(screen.getByText('Sam')).toBeInTheDocument()
  })

  it('renders closed state button', () => {
    render(<MobileNav isOpen={false} onClose={() => {}} />)
    expect(screen.getByLabelText('Open navigation menu')).toBeInTheDocument()
  })
})

describe('MobileBottomNav', () => {
  it('renders primary nav items and highlights active route', () => {
    locationRef.current = { pathname: '/' }
    render(<MobileBottomNav />)

    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    const dashboardLink = screen.getByText('Dashboard').closest('a')
    expect(dashboardLink).toHaveClass('text-primary')
  })
})
