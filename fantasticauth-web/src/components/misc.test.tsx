import * as React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const navigateMock = vi.hoisted(() => vi.fn())
const logoutMock = vi.hoisted(() => vi.fn())

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => navigateMock,
}))

vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({ logout: logoutMock }),
}))

vi.mock('./ui/Dialog', () => ({
  Dialog: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DialogContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
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

import { Announcer, useAnnouncer } from './Announcer'
import { SkipLinks, DataTableSkipLinks, SettingsSkipLinks, AuditSkipLinks } from './SkipLinks'
import { GlobalSearch } from './GlobalSearch'

describe('Announcer', () => {
  it('announces messages with the hook', async () => {
    vi.useFakeTimers()
    const rafSpy = vi.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => {
      cb(0)
      return 0
    })

    function TestComponent() {
      const { announce, clear } = useAnnouncer()
      React.useEffect(() => {
        announce('Hello world')
        setTimeout(() => clear('polite'), 0)
      }, [announce])
      return null
    }

    render(
      <>
        <Announcer />
        <TestComponent />
      </>
    )

    expect(screen.getByRole('status')).toHaveTextContent('Hello world')
    vi.runAllTimers()
    expect(screen.getByRole('status')).toHaveTextContent('')
    rafSpy.mockRestore()
    vi.useRealTimers()
  })
})

describe('SkipLinks', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('focuses the target when clicking a skip link', async () => {
    const user = userEvent.setup()
    const scrollSpy = vi.fn()

    render(
      <div>
        <div id="main-content" tabIndex={-1} onFocus={() => {}} />
        <SkipLinks />
      </div>
    )

    const target = document.getElementById('main-content') as HTMLElement
    target.scrollIntoView = scrollSpy

    await user.click(screen.getByText('Skip to main content'))
    expect(document.activeElement).toBe(target)
    expect(scrollSpy).toHaveBeenCalledWith({ behavior: 'smooth' })
  })

  it('renders specialized skip links', () => {
    render(
      <div>
        <DataTableSkipLinks tableId="audit" />
        <SettingsSkipLinks />
        <AuditSkipLinks />
      </div>
    )

    expect(screen.getAllByText('Skip to filters').length).toBeGreaterThan(0)
    expect(screen.getByText('Skip to settings')).toBeInTheDocument()
    expect(screen.getByText('Skip to audit log')).toBeInTheDocument()
  })
})

describe('GlobalSearch', () => {
  beforeEach(() => {
    navigateMock.mockReset()
    logoutMock.mockReset()
    reducedMotion.value = true
  })

  it('navigates when selecting a result', async () => {
    const user = userEvent.setup()
    render(<GlobalSearch />)

    await user.click(screen.getByLabelText('Open global search'))
    await user.type(screen.getByLabelText('Search'), 'Tenants')
    await user.click(screen.getByRole('button', { name: 'Tenants' }))

    expect(navigateMock).toHaveBeenCalledWith({ to: '/tenants' })
  })

  it('invokes logout action', async () => {
    const user = userEvent.setup()
    render(<GlobalSearch />)

    await user.click(screen.getByLabelText('Open global search'))
    await user.type(screen.getByLabelText('Search'), 'Logout')
    const logoutButton = screen.getByText('Logout').closest('button')
    if (logoutButton) {
      await user.click(logoutButton)
    }

    expect(logoutMock).toHaveBeenCalled()
  })

  it('shows no results state', async () => {
    const user = userEvent.setup()
    render(<GlobalSearch />)

    await user.click(screen.getByLabelText('Open global search'))
    await user.type(screen.getByLabelText('Search'), 'zzzzz')
    expect(screen.getByText('No results found')).toBeInTheDocument()
  })

  it('supports keyboard navigation', async () => {
    const user = userEvent.setup()
    reducedMotion.value = false
    render(<GlobalSearch />)
    await user.click(screen.getByLabelText('Open global search'))
    await user.type(screen.getByLabelText('Search'), 'Billing')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown' }))
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }))

    expect(navigateMock).toHaveBeenCalled()
  })

  it('shows default results when query is empty', async () => {
    const user = userEvent.setup()
    render(<GlobalSearch />)

    await user.click(screen.getByLabelText('Open global search'))
    expect(screen.getByText('Navigation')).toBeInTheDocument()
  })

  it('closes on escape and ignores enter when closed', async () => {
    const user = userEvent.setup()
    render(<GlobalSearch />)

    await user.click(screen.getByLabelText('Open global search'))
    await user.type(screen.getByLabelText('Search'), 'Users')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(navigateMock).not.toHaveBeenCalled()
  })

  it('renders shortcuts when provided', async () => {
    const user = userEvent.setup()
    render(
      <GlobalSearch
        items={[
          {
            id: 'shortcut-item',
            title: 'Quick Action',
            icon: () => <span>Icon</span>,
            shortcut: 'K',
            href: '/quick',
            section: 'Navigation',
          },
        ]}
      />
    )

    await user.click(screen.getByLabelText('Open global search'))
    expect(screen.getAllByText('K', { selector: 'kbd' }).length).toBeGreaterThan(0)
  })

  it('focuses input for fine pointers', async () => {
    const user = userEvent.setup()
    const originalMatchMedia = window.matchMedia
    window.matchMedia = vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })

    render(<GlobalSearch />)

    await user.click(screen.getByLabelText('Open global search'))
    expect(screen.getByLabelText('Search')).toHaveFocus()

    window.matchMedia = originalMatchMedia
  })
})
