import * as React from 'react'
import { Link, useLocation } from '@tanstack/react-router'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import {
  LayoutDashboard,
  Building2,
  Users,
  CreditCard,
  ClipboardList,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight,
  LogOut,
  Building,
  type LucideIcon,
} from 'lucide-react'
import { cn } from '../../lib/utils'
import { Button } from '../ui/Button'

interface NavItem {
  title: string
  href: string
  icon: LucideIcon
  badge?: string
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
    children: [
      { title: 'All Tenants', href: '/tenants' },
      { title: 'Create Tenant', href: '/tenants/create' },
    ],
  },
  {
    title: 'Organizations',
    href: '/organizations',
    icon: Building,
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
    children: [
      { title: 'Subscriptions', href: '/billing/subscriptions' },
      { title: 'Invoices', href: '/billing/invoices' },
    ],
  },
  {
    title: 'Audit Logs',
    href: '/audit',
    icon: ClipboardList,
  },
  {
    title: 'Settings',
    href: '/settings',
    icon: Settings,
    children: [
      { title: 'General', href: '/settings' },
      { title: 'Security', href: '/settings/security' },
      { title: 'Webhooks', href: '/settings/webhooks' },
    ],
  },
]

interface SidebarProps {
  isCollapsed: boolean
  onToggle: () => void
  onLogout?: () => void
  user?: {
    name?: string
    email?: string
    avatar?: string
  }
}

export function Sidebar({ isCollapsed, onToggle, onLogout, user }: SidebarProps) {
  const location = useLocation()
  const [expandedItems, setExpandedItems] = React.useState<string[]>(['Tenants'])
  const prefersReducedMotion = useReducedMotion()

  const toggleExpand = (title: string) => {
    setExpandedItems((prev) =>
      prev.includes(title) ? prev.filter((t) => t !== title) : [...prev, title]
    )
  }

  const isActive = (href: string) => {
    if (href === '/') {
      return location.pathname === '/'
    }
    return location.pathname === href || location.pathname.startsWith(`${href}/`)
  }

  return (
    <motion.aside
      initial={false}
      animate={{ width: isCollapsed ? 80 : 260 }}
      transition={
        prefersReducedMotion
          ? { duration: 0 }
          : { duration: 0.3, ease: [0.34, 1.56, 0.64, 1] }
      }
      className={cn(
        'fixed left-0 top-0 z-40 h-screen border-r bg-sidebar flex flex-col',
        isCollapsed && 'items-center'
      )}
    >
      {/* Header */}
      <div className="flex h-16 items-center justify-between px-4 border-b border-sidebar-border">
        <Link to="/" preload="intent" className="flex items-center gap-3 overflow-hidden">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary">
            <Shield className="h-5 w-5 text-primary-foreground" />
          </div>
          <AnimatePresence mode="wait">
            {!isCollapsed && (
              <motion.span
                initial={prefersReducedMotion ? false : { opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={prefersReducedMotion ? { opacity: 0 } : { opacity: 0, x: -10 }}
                className="font-semibold text-sidebar-foreground whitespace-nowrap"
              >
                Vault Admin
              </motion.span>
            )}
          </AnimatePresence>
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-3">
        <ul className="space-y-1">
          {navItems.map((item) => {
            const active = isActive(item.href)
            const hasChildren = item.children && item.children.length > 0
            const isExpanded = expandedItems.includes(item.title)

            return (
              <li key={item.title}>
                {hasChildren && !isCollapsed ? (
                  <div className="space-y-1">
                    <button
                      onClick={() => toggleExpand(item.title)}
                      className={cn(
                        'w-full flex items-center justify-between gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary',
                        active
                          ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                          : 'text-sidebar-foreground hover:bg-sidebar-accent/50'
                      )}
                    >
                      <div className="flex items-center gap-3">
                        <item.icon className="h-5 w-5 shrink-0" aria-hidden="true" />
                        <span>{item.title}</span>
                      </div>
                      <motion.div
                        animate={{ rotate: isExpanded ? 90 : 0 }}
                        transition={prefersReducedMotion ? { duration: 0 } : { duration: 0.2 }}
                      >
                        <ChevronRight className="h-4 w-4" aria-hidden="true" />
                      </motion.div>
                    </button>
                    <AnimatePresence>
                      {isExpanded && (
                        <motion.ul
                          initial={prefersReducedMotion ? false : { height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={prefersReducedMotion ? { opacity: 0 } : { height: 0, opacity: 0 }}
                          transition={prefersReducedMotion ? { duration: 0 } : { duration: 0.2 }}
                          className="overflow-hidden pl-10 space-y-1"
                        >
                          {item.children?.map((child) => (
                            <li key={child.href}>
                              <Link
                                to={child.href}
                                preload="intent"
                                className={cn(
                                  'block rounded-lg px-3 py-2 text-sm transition-colors',
                                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary',
                                  isActive(child.href)
                                    ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                                    : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground'
                                )}
                              >
                                {child.title}
                              </Link>
                            </li>
                          ))}
                        </motion.ul>
                      )}
                    </AnimatePresence>
                  </div>
                ) : (
                  <Link
                    to={item.href}
                    preload="intent"
                    className={cn(
                      'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary',
                      active
                        ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                        : 'text-sidebar-foreground hover:bg-sidebar-accent/50',
                      isCollapsed && 'justify-center'
                    )}
                    title={isCollapsed ? item.title : undefined}
                    aria-label={isCollapsed ? item.title : undefined}
                  >
                    <item.icon className="h-5 w-5 shrink-0" aria-hidden="true" />
                    <AnimatePresence mode="wait">
                      {!isCollapsed && (
                        <motion.span
                          initial={prefersReducedMotion ? false : { opacity: 0, width: 0 }}
                          animate={{ opacity: 1, width: 'auto' }}
                          exit={prefersReducedMotion ? { opacity: 0 } : { opacity: 0, width: 0 }}
                          className="whitespace-nowrap overflow-hidden"
                        >
                          {item.title}
                        </motion.span>
                      )}
                    </AnimatePresence>
                    {item.badge && !isCollapsed && (
                      <span className="ml-auto text-xs bg-primary text-primary-foreground px-2 py-0.5 rounded-full">
                        {item.badge}
                      </span>
                    )}
                  </Link>
                )}
              </li>
            )
          })}
        </ul>
      </nav>

      {/* Footer */}
      <div className="border-t border-sidebar-border p-3 space-y-3">
        {/* User */}
        <div
          className={cn(
            'flex items-center gap-3 rounded-lg px-3 py-2',
            isCollapsed && 'justify-center px-2'
          )}
        >
          <div className="h-8 w-8 shrink-0 rounded-full bg-primary/10 flex items-center justify-center">
            <span className="text-sm font-medium text-primary">
              {user?.name?.[0] || user?.email?.[0] || 'A'}
            </span>
          </div>
          <AnimatePresence mode="wait">
            {!isCollapsed && (
              <motion.div
                initial={prefersReducedMotion ? false : { opacity: 0, width: 0 }}
                animate={{ opacity: 1, width: 'auto' }}
                exit={prefersReducedMotion ? { opacity: 0 } : { opacity: 0, width: 0 }}
                className="flex-1 min-w-0 overflow-hidden"
              >
                <p className="text-sm font-medium text-sidebar-foreground truncate">
                  {user?.name || 'Admin User'}
                </p>
                <p className="text-xs text-sidebar-foreground/60 truncate">
                  {user?.email || 'admin@vault.local'}
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Collapse Toggle */}
        <Button
          variant="ghost"
          size={isCollapsed ? 'icon' : 'default'}
          onClick={onToggle}
          className={cn(
            'w-full',
            isCollapsed && 'justify-center'
          )}
          aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          leftIcon={isCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        >
          {!isCollapsed && 'Collapse'}
        </Button>

        {/* Logout */}
        {onLogout && (
          <Button
            variant="ghost"
            size={isCollapsed ? 'icon' : 'default'}
            onClick={onLogout}
            className={cn(
              'w-full text-destructive hover:text-destructive hover:bg-destructive/10',
              isCollapsed && 'justify-center'
            )}
            aria-label={isCollapsed ? 'Log out' : undefined}
            leftIcon={<LogOut className="h-4 w-4" />}
          >
            {!isCollapsed && 'Logout'}
          </Button>
        )}
      </div>
    </motion.aside>
  )
}
