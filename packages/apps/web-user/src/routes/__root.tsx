import { HeadContent, Scripts, createRootRoute, Outlet, Link, useRouterState } from '@tanstack/react-router'
import { useEffect, useMemo, useState, useRef } from 'react'
import {
  User,
  Shield,
  Smartphone,
  Lock,
  FileText,
  Activity,
  Menu,
  X,
  ChevronRight,
  LogOut,
  Moon,
  Sun,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Toaster } from '@/components/ui/Toaster'
import { AuthProvider, useAuth } from '@/auth/context'
import { features } from '@/lib/features'
import { sanitizeRedirectPath } from '@/lib/redirect'
import appCss from '../styles.css?url'

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      {
        name: 'viewport',
        content: 'width=device-width, initial-scale=1, maximum-scale=5, viewport-fit=cover',
      },
      {
        name: 'description',
        content: 'Vault User Portal - Manage your account, security, and privacy settings',
      },
      { name: 'theme-color', content: '#4f46e5' },
    ],
    links: [
      { rel: 'stylesheet', href: appCss },
    ],
  }),
  component: RootComponent,
})

type NavItem = {
  name: string
  href: string
  icon: LucideIcon
}

const buildNavigation = (): NavItem[] => {
  const items: NavItem[] = [{ name: 'Profile', href: '/', icon: User }]

  if (features.security) items.push({ name: 'Security', href: '/security', icon: Shield })
  if (features.devices) items.push({ name: 'Devices', href: '/devices', icon: Smartphone })
  if (features.sessions) items.push({ name: 'Sessions', href: '/sessions', icon: Lock })
  if (features.privacy) items.push({ name: 'Privacy', href: '/privacy', icon: FileText })
  if (features.activity) items.push({ name: 'Activity', href: '/activity', icon: Activity })

  return items
}

function RootComponent() {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body className="h-full bg-background text-foreground">
        <AuthProvider>
          <AppShell />
        </AuthProvider>
        <Toaster position="top-right" richColors closeButton />
        <Scripts />
      </body>
    </html>
  )
}

// SkipLink component for keyboard navigation accessibility
function SkipLink() {
  return (
    <a
      href="#main-content"
      className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2"
    >
      Skip to main content
    </a>
  )
}

function AppShell() {
  const [isDark, setIsDark] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const mobileMenuRef = useRef<HTMLDivElement>(null)
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null)
  const { pathname } = useRouterState({ select: (state) => state.location })
  const { isAuthenticated, isLoading, logout } = useAuth()
  const navigation = useMemo(() => buildNavigation(), [])
  const isLoginRoute = pathname === '/login'

  // Handle focus when mobile menu opens/closes
  useEffect(() => {
    if (mobileMenuOpen) {
      // Focus first focusable element in menu when opened
      const firstLink = mobileMenuRef.current?.querySelector('a, button') as HTMLElement
      firstLink?.focus()
    }
  }, [mobileMenuOpen])

  // Handle escape key to close mobile menu
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && mobileMenuOpen) {
        setMobileMenuOpen(false)
        mobileMenuButtonRef.current?.focus()
      }
    }
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [mobileMenuOpen])

  useEffect(() => {
    if (isLoading) return

    if (!isAuthenticated && !isLoginRoute) {
      const redirect = encodeURIComponent(pathname || '/')
      window.location.replace(`/login?redirect=${redirect}`)
      return
    }

    if (isAuthenticated && isLoginRoute) {
      const redirect = sanitizeRedirectPath(
        new URLSearchParams(window.location.search).get('redirect'),
      )
      window.location.replace(redirect)
    }
  }, [isAuthenticated, isLoading, isLoginRoute, pathname])

  const toggleTheme = () => {
    setIsDark((prev) => !prev)
    document.documentElement.classList.toggle('dark')
  }

  const handleSignOut = async () => {
    await logout()
    window.location.replace('/login')
  }

  if (isLoading && !isLoginRoute) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="h-8 w-8 border-4 border-primary border-t-transparent rounded-full animate-spin" role="status" aria-label="Loading">
          <span className="sr-only">Loading...</span>
        </div>
      </div>
    )
  }

  if (isLoginRoute) {
    return <Outlet />
  }

  if (!isAuthenticated) {
    return null
  }

  return (
    <div className="min-h-screen flex">
      <SkipLink />
      
      <aside className="hidden lg:flex w-64 flex-col border-r bg-card" aria-label="Main navigation">
        <div className="p-6">
          <h1 className="text-xl font-bold">Vault Portal</h1>
          <p className="text-xs text-muted-foreground mt-1">User Self-Service</p>
        </div>

        <nav className="flex-1 px-4 space-y-1" aria-label="Sidebar navigation">
          {navigation.map((item) => (
            <Link
              key={item.name}
              to={item.href}
              className="flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground [&.active]:bg-primary [&.active]:text-primary-foreground"
              activeOptions={{ exact: item.href === '/' }}
            >
              <item.icon className="h-4 w-4" aria-hidden="true" />
              {item.name}
            </Link>
          ))}
        </nav>

        <div className="p-4 border-t space-y-2">
          <Button
            variant="ghost"
            className="w-full justify-start gap-3"
            onClick={toggleTheme}
          >
            {isDark ? <Sun className="h-4 w-4" aria-hidden="true" /> : <Moon className="h-4 w-4" aria-hidden="true" />}
            {isDark ? 'Light mode' : 'Dark mode'}
          </Button>
          <Button
            variant="ghost"
            className="w-full justify-start gap-3 text-destructive"
            onClick={() => {
              void handleSignOut()
            }}
          >
            <LogOut className="h-4 w-4" aria-hidden="true" />
            Sign out
          </Button>
        </div>
      </aside>

      <div className="lg:hidden fixed top-0 left-0 right-0 z-50 border-b bg-background">
        <div className="flex items-center justify-between p-4">
          <h1 className="text-lg font-bold">Vault Portal</h1>
          <Button
            ref={mobileMenuButtonRef}
            variant="ghost"
            size="icon"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label={mobileMenuOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={mobileMenuOpen}
            aria-controls="mobile-menu"
          >
            {mobileMenuOpen ? <X className="h-5 w-5" aria-hidden="true" /> : <Menu className="h-5 w-5" aria-hidden="true" />}
          </Button>
        </div>

        {mobileMenuOpen && (
          <nav 
            ref={mobileMenuRef}
            id="mobile-menu"
            className="border-t p-4 space-y-1"
            aria-label="Mobile navigation"
          >
            {navigation.map((item) => (
              <Link
                key={item.name}
                to={item.href}
                className="flex items-center justify-between px-3 py-3 rounded-md text-sm font-medium transition-colors hover:bg-accent [&.active]:bg-primary [&.active]:text-primary-foreground"
                onClick={() => setMobileMenuOpen(false)}
                activeOptions={{ exact: item.href === '/' }}
              >
                <span className="flex items-center gap-3">
                  <item.icon className="h-4 w-4" aria-hidden="true" />
                  {item.name}
                </span>
                <ChevronRight className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
              </Link>
            ))}
            <div className="pt-4 mt-4 border-t space-y-2">
              <Button
                variant="ghost"
                className="w-full justify-start gap-3"
                onClick={toggleTheme}
              >
                {isDark ? <Sun className="h-4 w-4" aria-hidden="true" /> : <Moon className="h-4 w-4" aria-hidden="true" />}
                {isDark ? 'Light mode' : 'Dark mode'}
              </Button>
              <Button
                variant="ghost"
                className="w-full justify-start gap-3 text-destructive"
                onClick={() => {
                  void handleSignOut()
                }}
              >
                <LogOut className="h-4 w-4" aria-hidden="true" />
                Sign out
              </Button>
            </div>
          </nav>
        )}
      </div>

      <main id="main-content" className="flex-1 lg:ml-0" tabIndex={-1}>
        <div className="lg:p-8 p-4 pt-20 lg:pt-8 max-w-5xl mx-auto">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
