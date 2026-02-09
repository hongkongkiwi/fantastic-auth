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

import { Sidebar } from './Sidebar'

describe('Sidebar', () => {
  it('renders navigation and user info', () => {
    reducedMotion.value = false
    render(
      <Sidebar
        isCollapsed={false}
        onToggle={() => {}}
        user={{ name: 'Alex', email: 'alex@example.com' }}
      />
    )

    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Alex')).toBeInTheDocument()
    expect(screen.getByText('alex@example.com')).toBeInTheDocument()
  })

  it('toggles a group with children', async () => {
    const user = userEvent.setup()
    render(<Sidebar isCollapsed={false} onToggle={() => {}} />)

    const tenantsButton = screen.getByRole('button', { name: 'Tenants' })
    expect(screen.getByText('All Tenants')).toBeInTheDocument()
    await user.click(tenantsButton)
    expect(screen.queryByText('All Tenants')).not.toBeInTheDocument()
  })

  it('indicates active route', () => {
    locationRef.current = { pathname: '/tenants' }
    render(<Sidebar isCollapsed={false} onToggle={() => {}} />)

    expect(screen.getByText('Tenants').closest('button')).toHaveClass('bg-sidebar-accent')
  })

  it('supports collapsed state and logout', async () => {
    const user = userEvent.setup()
    const onToggle = vi.fn()
    const onLogout = vi.fn()

    render(
      <Sidebar
        isCollapsed
        onToggle={onToggle}
        onLogout={onLogout}
        user={{ email: 'admin@vault.local' }}
      />
    )

    await user.click(screen.getByLabelText('Expand sidebar'))
    expect(onToggle).toHaveBeenCalled()

    await user.click(screen.getByLabelText('Log out'))
    expect(onLogout).toHaveBeenCalled()
  })

  it('renders badges when provided', () => {
    render(
      <Sidebar
        isCollapsed={false}
        onToggle={() => {}}
        items={[
          { title: 'Dashboard', href: '/', icon: (() => null) as any, badge: 'New' },
        ]}
      />
    )

    expect(screen.getByText('New')).toBeInTheDocument()
  })
})
