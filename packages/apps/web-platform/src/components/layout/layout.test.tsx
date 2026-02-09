import * as React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const useAuthMock = vi.hoisted(() => ({
  logout: vi.fn(),
  user: { name: 'Admin', email: 'admin@vault.local' } as
    | { name: string; email: string }
    | null,
}))

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => useAuthMock,
}))

vi.mock('../../hooks/useTheme', () => ({
  ThemeToggle: () => <div data-testid="theme-toggle" />,
}))

vi.mock('../GlobalSearch', () => ({
  GlobalSearch: () => <div data-testid="global-search" />,
}))

vi.mock('../CommandPalette', () => ({
  CommandPalette: ({ open }: { open: boolean }) => (
    <div data-testid="command-palette" data-open={open} />
  ),
}))

vi.mock('../Announcer', () => ({
  Announcer: () => <div data-testid="announcer" />,
}))

vi.mock('../SkipLinks', () => ({
  SkipLinks: () => <div data-testid="skip-links" />,
}))

vi.mock('./Sidebar', () => ({
  Sidebar: (props: { isCollapsed: boolean; onToggle: () => void }) => (
    <div data-testid="sidebar" data-collapsed={props.isCollapsed}>
      <button type="button" onClick={props.onToggle}>Toggle</button>
    </div>
  ),
}))

vi.mock('./MobileNav', () => ({
  MobileNav: ({ isOpen }: { isOpen: boolean }) => (
    <div data-testid="mobile-nav" data-open={isOpen} />
  ),
  MobileBottomNav: () => <div data-testid="mobile-bottom" />,
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

import { Layout, PageHeader, StatCard } from './Layout'

describe('Layout', () => {
  beforeEach(() => {
    localStorage.clear()
    useAuthMock.logout.mockReset()
    useAuthMock.user = { name: 'Admin', email: 'admin@vault.local' }
    reducedMotion.value = true
  })

  it('renders layout chrome and children', () => {
    reducedMotion.value = false
    render(
      <Layout>
        <div>Content</div>
      </Layout>
    )

    expect(screen.getByTestId('skip-links')).toBeInTheDocument()
    expect(screen.getByTestId('sidebar')).toBeInTheDocument()
    expect(screen.getByTestId('mobile-nav')).toBeInTheDocument()
    expect(screen.getByTestId('mobile-bottom')).toBeInTheDocument()
    expect(screen.getByTestId('command-palette')).toBeInTheDocument()
    expect(screen.getByText('Content')).toBeInTheDocument()
  })

  it('opens the mobile menu and command palette', async () => {
    const user = userEvent.setup()
    render(
      <Layout>
        <div>Content</div>
      </Layout>
    )

    await user.click(screen.getByLabelText('Open navigation menu'))
    expect(screen.getByTestId('mobile-nav')).toHaveAttribute('data-open', 'true')

    await user.click(screen.getByText('Search...'))
    expect(screen.getByTestId('command-palette')).toHaveAttribute('data-open', 'true')
  })

  it('persists sidebar collapsed state', async () => {
    localStorage.setItem('sidebar-collapsed', 'true')
    const user = userEvent.setup()

    render(
      <Layout>
        <div>Content</div>
      </Layout>
    )

    expect(screen.getByTestId('sidebar')).toHaveAttribute('data-collapsed', 'true')
    await user.click(screen.getByText('Toggle'))
    expect(localStorage.getItem('sidebar-collapsed')).toBe('false')
  })

  it('closes mobile menu on desktop resize', async () => {
    const user = userEvent.setup()
    render(
      <Layout>
        <div>Content</div>
      </Layout>
    )

    await user.click(screen.getByLabelText('Open navigation menu'))
    expect(screen.getByTestId('mobile-nav')).toHaveAttribute('data-open', 'true')

    act(() => {
      Object.defineProperty(window, 'innerWidth', { value: 1200, configurable: true })
      window.dispatchEvent(new Event('resize'))
    })

    await waitFor(() => {
      expect(screen.getByTestId('mobile-nav')).toHaveAttribute('data-open', 'false')
    })
  })

  it('renders without a user session', () => {
    useAuthMock.user = null
    render(
      <Layout>
        <div>Content</div>
      </Layout>
    )
    expect(screen.getByText('Content')).toBeInTheDocument()
  })
})

describe('PageHeader', () => {
  it('renders breadcrumbs, description, and actions', () => {
    reducedMotion.value = false
    render(
      <PageHeader
        title="Dashboard"
        description="Overview"
        actions={<button type="button">Action</button>}
        breadcrumbs={[
          { label: 'Home', href: '/' },
          { label: 'Dashboard' },
        ]}
      />
    )

    expect(screen.getByText('Home')).toHaveAttribute('href', '/')
    expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument()
    expect(screen.getByText('Overview')).toBeInTheDocument()
    expect(screen.getByText('Action')).toBeInTheDocument()
  })

  it('renders without optional sections', () => {
    render(<PageHeader title="Settings" />)
    expect(screen.getByRole('heading', { name: 'Settings' })).toBeInTheDocument()
    expect(screen.queryByText('Overview')).not.toBeInTheDocument()
  })

  it('renders optional sections with reduced motion enabled', () => {
    reducedMotion.value = true
    render(
      <PageHeader
        title="Billing"
        description="Manage invoices"
        actions={<button type="button">Pay</button>}
        breadcrumbs={[{ label: 'Billing', href: '/billing' }]}
      />
    )

    expect(screen.getByText('Manage invoices')).toBeInTheDocument()
    expect(screen.getByText('Pay')).toBeInTheDocument()
  })
})

describe('StatCard', () => {
  it('renders with trend and color', () => {
    reducedMotion.value = false
    render(
      <StatCard
        title="Revenue"
        value="$10k"
        trend={{ value: 12, isPositive: true }}
        icon={<span>Icon</span>}
        color="green"
      />
    )

    expect(screen.getByText('Revenue')).toBeInTheDocument()
    expect(screen.getByText('$10k')).toBeInTheDocument()
    expect(screen.getByText('↑ 12%')).toBeInTheDocument()
  })

  it('renders without trend', () => {
    render(
      <StatCard
        title="Users"
        value={120}
        icon={<span>Icon</span>}
        color="rose"
      />
    )

    expect(screen.getByText('Users')).toBeInTheDocument()
    expect(screen.queryByText('↑')).not.toBeInTheDocument()
  })

  it('renders negative trend', () => {
    render(
      <StatCard
        title="Churn"
        value="2%"
        trend={{ value: 5, isPositive: false }}
        icon={<span>Icon</span>}
        color="amber"
      />
    )

    expect(screen.getByText('↓ 5%')).toBeInTheDocument()
  })
})
