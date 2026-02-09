import { NavLink, useLocation } from 'react-router-dom'
import { 
  LayoutDashboard, Users, Building2, Shield, Settings, 
  FileText, BarChart3, Lock, ChevronLeft, ChevronRight,
  LogOut, ChevronDown, Fingerprint, Smartphone,
  Eye, Database, Activity
} from 'lucide-react'
import { useState } from 'react'
import { cn } from '@/lib/utils'
import { useUIStore, useAuthStore } from '@/store'
import { useAuth } from '@/hooks/useAuth'
import { features } from '@/lib/features'

interface NavItem {
  name: string
  href: string
  icon: React.ElementType
  badge?: string
  badgeVariant?: 'default' | 'secondary' | 'destructive' | 'success' | 'warning'
  children?: { name: string; href: string; icon?: React.ElementType; badge?: string; badgeVariant?: 'default' | 'secondary' | 'destructive' | 'success' | 'warning' }[]
}

const buildNavigation = (): NavItem[] => {
  const securityChildren: NonNullable<NavItem['children']> = [
    { name: 'Security Settings', href: '/security', icon: Lock },
  ]

  if (features.securityDashboard) {
    securityChildren.unshift({
      name: 'Security Dashboard',
      href: '/security-dashboard',
      icon: Activity,
    })
  }
  if (features.selfServiceDevices) {
    securityChildren.push({ name: 'Device Management', href: '/devices', icon: Smartphone })
  }
  if (features.selfServiceSessions) {
    securityChildren.push({ name: 'Active Sessions', href: '/sessions', icon: Eye })
  }

  const items: NavItem[] = [
    { name: 'Dashboard', href: '/', icon: LayoutDashboard },
    { name: 'Users', href: '/users', icon: Users },
    { name: 'Organizations', href: '/organizations', icon: Building2 },
    {
      name: 'Security',
      href: '#',
      icon: Shield,
      badge: 'Zero Trust',
      badgeVariant: 'success',
      children: securityChildren,
    },
    {
      name: 'Integrations',
      href: '#',
      icon: Lock,
      children: [
        { name: 'OAuth Clients', href: '/oauth-clients' },
        { name: 'SAML Connections', href: '/saml-connections' },
        { name: 'Webhooks', href: '/webhooks' },
      ],
    },
    { name: 'Audit Logs', href: '/audit-logs', icon: FileText },
    { name: 'Analytics', href: '/analytics', icon: BarChart3 },
    { name: 'Settings', href: '/settings', icon: Settings },
  ]

  if (features.selfServicePrivacy) {
    items.splice(4, 0, {
      name: 'Privacy',
      href: '/privacy',
      icon: Database,
      badge: 'GDPR',
      badgeVariant: 'secondary',
    })
  }

  return items
}

export function Sidebar({
  isOpen = false,
  onClose = () => {},
}: {
  isOpen?: boolean
  onClose?: () => void
}) {
  const location = useLocation()
  const { sidebarCollapsed, toggleSidebar } = useUIStore()
  const { user } = useAuthStore()
  const { logout } = useAuth()
  const [expandedItems, setExpandedItems] = useState<string[]>(['Security', 'Integrations'])
  const navigation = buildNavigation()

  const toggleExpanded = (name: string) => {
    setExpandedItems(prev => 
      prev.includes(name) 
        ? prev.filter(item => item !== name)
        : [...prev, name]
    )
  }

  const isActive = (href: string) => {
    if (href === '/') {
      return location.pathname === '/'
    }
    return location.pathname.startsWith(href)
  }

  // Check if any child route is active
  const isGroupActive = (item: NavItem) => {
    if (!item.children) return false
    return item.children.some(child => location.pathname.startsWith(child.href))
  }

  return (
    <>
      {/* Mobile overlay */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}
      
      <aside
        role="navigation"
        aria-label="Main navigation"
        className={cn(
          "fixed left-0 top-0 z-50 h-screen bg-card border-r border-border transition-[left,right,width] duration-300",
          sidebarCollapsed ? "w-16" : "w-64",
          isOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        )}
      >
        {/* Logo */}
        <div className="flex h-16 items-center justify-between px-4 border-b border-border">
          <div className={cn("flex items-center gap-2", sidebarCollapsed && "justify-center w-full")}>
            <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center flex-shrink-0">
              <Fingerprint className="w-5 h-5 text-primary-foreground" />
            </div>
            {!sidebarCollapsed && (
              <span className="font-semibold text-lg">Vault Admin</span>
            )}
          </div>
          {!sidebarCollapsed && (
            <button type="button"
              onClick={toggleSidebar}
              className="p-1 rounded-md hover:bg-muted transition-colors"
              aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
              title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Collapse Button (when collapsed) */}
        {sidebarCollapsed && (
          <button type="button"
            onClick={toggleSidebar}
            className="absolute -right-3 top-20 w-6 h-6 bg-primary text-primary-foreground rounded-full flex items-center justify-center shadow-md hover:bg-primary/90"
            aria-label="Expand sidebar"
            title="Expand sidebar"
          >
            <ChevronRight className="w-3 h-3" />
          </button>
        )}

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-4 px-2 scrollbar-thin">
          <ul className="space-y-1" role="menubar">
            {navigation.map((item) => {
              const Icon = item.icon
              const active = isActive(item.href) || isGroupActive(item)
              const expanded = expandedItems.includes(item.name)
              const hasChildren = item.children && item.children.length > 0

              if (sidebarCollapsed) {
                return (
                  <li key={item.name} role="none">
                    <NavLink
                      to={item.href}
                      role="menuitem"
                      className={cn(
                        "flex items-center justify-center p-2 rounded-lg transition-colors relative",
                        active 
                          ? "bg-primary text-primary-foreground" 
                          : "text-muted-foreground hover:bg-muted hover:text-foreground"
                      )}
                      aria-label={item.name}
                      title={item.name}
                      onClick={() => onClose()}
                    >
                      <Icon className="w-5 h-5" aria-hidden="true" />
                      {item.badge && (
                        <span 
                          className={cn(
                            "absolute -top-1 -right-1 w-2 h-2 rounded-full",
                            item.badgeVariant === 'destructive' && "bg-red-500",
                            item.badgeVariant === 'success' && "bg-green-500",
                            item.badgeVariant === 'warning' && "bg-yellow-500",
                            item.badgeVariant === 'secondary' && "bg-gray-500",
                            !item.badgeVariant && "bg-primary"
                          )}
                          aria-hidden="true"
                        />
                      )}
                    </NavLink>
                  </li>
                )
              }

              return (
                <li key={item.name} role="none">
                  {hasChildren ? (
                    <>
                      <button type="button"
                        onClick={() => toggleExpanded(item.name)}
                        className={cn(
                          "w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors",
                          active || isGroupActive(item)
                            ? "bg-primary text-primary-foreground" 
                            : "text-muted-foreground hover:bg-muted hover:text-foreground"
                        )}
                        aria-expanded={expanded}
                        aria-haspopup="true"
                        aria-label={`${item.name} submenu`}
                      >
                        <div className="flex items-center gap-3">
                          <Icon className="w-5 h-5" aria-hidden="true" />
                          <span className="text-sm font-medium">{item.name}</span>
                          {item.badge && (
                            <span className={cn(
                              "text-[10px] px-1.5 py-0.5 rounded-full",
                              item.badgeVariant === 'destructive' && "bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-200",
                              item.badgeVariant === 'success' && "bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-200",
                              item.badgeVariant === 'warning' && "bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-200",
                              item.badgeVariant === 'secondary' && "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-200",
                              !item.badgeVariant && "bg-primary/20 text-primary"
                            )}>
                              {item.badge}
                            </span>
                          )}
                        </div>
                        <ChevronDown 
                          className={cn(
                            "w-4 h-4 transition-transform",
                            expanded && "rotate-180"
                          )} 
                          aria-hidden="true"
                        />
                      </button>
                      {expanded && (
                        <ul 
                          className="mt-1 ml-4 pl-4 border-l border-border space-y-1"
                          role="menu"
                          aria-label={`${item.name} submenu`}
                        >
                          {item.children?.map((child) => (
                            <li key={child.name} role="none">
                              <NavLink
                                to={child.href}
                                role="menuitem"
                                className={({ isActive }) => cn(
                                  "block px-3 py-2 rounded-lg text-sm transition-colors",
                                  isActive
                                    ? "bg-primary/10 text-primary font-medium"
                                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                                )}
                                onClick={() => onClose()}
                              >
                                <div className="flex items-center justify-between">
                                  <span>{child.name}</span>
                                  {child.badge && (
                                    <span className={cn(
                                      "text-[10px] px-1.5 py-0.5 rounded-full",
                                      child.badgeVariant === 'destructive' && "bg-red-100 text-red-700",
                                      child.badgeVariant === 'success' && "bg-green-100 text-green-700",
                                      child.badgeVariant === 'warning' && "bg-yellow-100 text-yellow-700",
                                      !child.badgeVariant && "bg-primary/20 text-primary"
                                    )}>
                                      {child.badge}
                                    </span>
                                  )}
                                </div>
                              </NavLink>
                            </li>
                          ))}
                        </ul>
                      )}
                    </>
                  ) : (
                    <NavLink
                      to={item.href}
                      role="menuitem"
                      className={({ isActive }) => cn(
                        "flex items-center gap-3 px-3 py-2 rounded-lg transition-colors",
                        isActive
                          ? "bg-primary text-primary-foreground"
                          : "text-muted-foreground hover:bg-muted hover:text-foreground"
                      )}
                      onClick={() => onClose()}
                    >
                      <Icon className="w-5 h-5" aria-hidden="true" />
                      <span className="text-sm font-medium">{item.name}</span>
                      {item.badge && (
                        <span className={cn(
                          "ml-auto text-[10px] px-1.5 py-0.5 rounded-full",
                          item.badgeVariant === 'destructive' && "bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-200",
                          item.badgeVariant === 'success' && "bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-200",
                          item.badgeVariant === 'warning' && "bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-200",
                          item.badgeVariant === 'secondary' && "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-200",
                          !item.badgeVariant && "bg-primary/20 text-primary"
                        )}>
                          {item.badge}
                        </span>
                      )}
                    </NavLink>
                  )}
                </li>
              )
            })}
          </ul>
        </nav>

        {/* User */}
        {!sidebarCollapsed && user && (
          <div className="border-t border-border p-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                <span className="text-sm font-medium text-primary">
                  {user.firstName?.[0] || user.email[0].toUpperCase()}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">
                  {user.firstName && user.lastName 
                    ? `${user.firstName} ${user.lastName}` 
                    : user.email}
                </p>
                <p className="text-xs text-muted-foreground truncate">{user.email}</p>
              </div>
              <button type="button" 
                onClick={() => {
                  void logout()
                }}
                className="p-1.5 rounded-md hover:bg-muted text-muted-foreground"
                aria-label="Log out"
                title="Log out"
              >
                <LogOut className="w-4 h-4" aria-hidden="true" />
              </button>
            </div>
          </div>
        )}
      </aside>
    </>
  )
}
