import { Link, useLocation } from '@tanstack/react-router'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import {
  LayoutDashboard,
  Building2,
  Users,
  CreditCard,
  ClipboardList,
  Settings,
  Menu,
  X,
  Shield,
  LogOut,
  ChevronRight,
  type LucideIcon,
} from 'lucide-react'
import { cn } from '../../lib/utils'
import { Button } from '../ui/Button'

interface NavItem {
  title: string
  href: string
  icon: LucideIcon
  children?: { title: string; href: string }[]
}

const navItems: NavItem[] = [
  {
    title: 'Dashboard',
    href: '/',
    icon: LayoutDashboard,
  },
  {
    title: 'Tenants',
    href: '/tenants',
    icon: Building2,
  },
  {
    title: 'Users',
    href: '/users',
    icon: Users,
  },
  {
    title: 'Billing',
    href: '/billing',
    icon: CreditCard,
  },
  {
    title: 'Audit',
    href: '/audit',
    icon: ClipboardList,
  },
  {
    title: 'Settings',
    href: '/settings',
    icon: Settings,
  },
]

interface MobileNavProps {
  isOpen: boolean
  onClose: () => void
  onLogout?: () => void
  user?: {
    name?: string
    email?: string
  }
}

export function MobileNav({ isOpen, onClose, onLogout, user }: MobileNavProps) {
  const location = useLocation()
  const prefersReducedMotion = useReducedMotion()

  const isActive = (href: string) => {
    if (href === '/') {
      return location.pathname === '/'
    }
    return location.pathname === href || location.pathname.startsWith(`${href}/`)
  }

  return (
    <>
      {/* Mobile Menu Button */}
      <button
        onClick={() => (isOpen ? onClose() : null)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-background border shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        aria-label={isOpen ? 'Close navigation menu' : 'Open navigation menu'}
      >
        {isOpen ? <X className="h-5 w-5" aria-hidden="true" /> : <Menu className="h-5 w-5" aria-hidden="true" />}
      </button>

      {/* Overlay */}
      <AnimatePresence>
        {isOpen && (
          <motion.button
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden"
            aria-label="Close navigation menu"
            type="button"
            transition={prefersReducedMotion ? { duration: 0 } : { duration: 0.2 }}
          />
        )}
      </AnimatePresence>

      {/* Drawer */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ x: '-100%' }}
            animate={{ x: 0 }}
            exit={{ x: '-100%' }}
            transition={
              prefersReducedMotion
                ? { duration: 0 }
                : { type: 'spring', damping: 25, stiffness: 200 }
            }
            className="fixed left-0 top-0 z-50 h-full w-72 bg-sidebar border-r lg:hidden"
          >
            {/* Header */}
            <div className="flex h-16 items-center justify-between px-4 border-b border-sidebar-border">
              <Link to="/" preload="intent" className="flex items-center gap-3" onClick={onClose}>
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary">
                  <Shield className="h-5 w-5 text-primary-foreground" />
                </div>
                <span className="font-semibold text-sidebar-foreground">
                  Vault Admin
                </span>
              </Link>
              <button
                onClick={onClose}
                className="p-2 rounded-lg text-sidebar-foreground hover:bg-sidebar-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                aria-label="Close navigation menu"
              >
                <X className="h-5 w-5" aria-hidden="true" />
              </button>
            </div>

            {/* Navigation */}
            <nav className="flex-1 overflow-y-auto py-4 px-3">
              <ul className="space-y-1">
                {navItems.map((item) => {
                  const active = isActive(item.href)

                  return (
                    <li key={item.title}>
                      <Link
                        to={item.href}
                        preload="intent"
                        onClick={onClose}
                        className={cn(
                          'flex items-center gap-3 rounded-lg px-3 py-3 text-sm font-medium transition-colors',
                          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary',
                          active
                            ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                            : 'text-sidebar-foreground hover:bg-sidebar-accent/50'
                        )}
                      >
                        <item.icon className="h-5 w-5 shrink-0" aria-hidden="true" />
                        <span>{item.title}</span>
                        <ChevronRight className="h-4 w-4 ml-auto opacity-50" aria-hidden="true" />
                      </Link>
                    </li>
                  )
                })}
              </ul>
            </nav>

            {/* Footer */}
            <div className="border-t border-sidebar-border p-4 space-y-3">
              {/* User */}
              <div className="flex items-center gap-3 rounded-lg px-3 py-2">
                <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
                  <span className="text-sm font-medium text-primary">
                    {user?.name?.[0] || user?.email?.[0] || 'A'}
                  </span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-sidebar-foreground truncate">
                    {user?.name || 'Admin User'}
                  </p>
                  <p className="text-xs text-sidebar-foreground/60 truncate">
                    {user?.email || 'admin@vault.local'}
                  </p>
                </div>
              </div>

              {/* Logout */}
              {onLogout && (
                <Button
                  variant="ghost"
                  onClick={onLogout}
                  className="w-full justify-start text-destructive hover:text-destructive hover:bg-destructive/10"
                  leftIcon={<LogOut className="h-4 w-4" />}
                >
                  Logout
                </Button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}

// Mobile Bottom Navigation (for quick access on mobile)
export function MobileBottomNav() {
  const location = useLocation()
  const prefersReducedMotion = useReducedMotion()

  const isActive = (href: string) => {
    if (href === '/') {
      return location.pathname === '/'
    }
    return location.pathname === href || location.pathname.startsWith(`${href}/`)
  }

  const mainItems = navItems.slice(0, 5) // Show first 5 items

  return (
    <motion.nav
      className="lg:hidden fixed bottom-0 left-0 right-0 z-40 bg-background border-t safe-area-pb"
      initial={prefersReducedMotion ? false : { y: 20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={prefersReducedMotion ? { duration: 0 } : { duration: 0.2 }}
    >
      <div className="flex items-center justify-around">
        {mainItems.map((item) => {
          const active = isActive(item.href)

          return (
            <Link
              key={item.title}
              to={item.href}
              preload="intent"
              className={cn(
                'flex flex-col items-center justify-center py-2 px-3 min-w-[60px]',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary',
                active ? 'text-primary' : 'text-muted-foreground'
              )}
            >
              <item.icon className={cn('h-5 w-5', active && 'stroke-[2.5px]')} aria-hidden="true" />
              <span className="text-[10px] mt-1 font-medium">{item.title}</span>
            </Link>
          )
        })}
      </div>
    </motion.nav>
  )
}
