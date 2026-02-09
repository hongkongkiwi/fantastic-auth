import { NavLink, useLocation } from 'react-router-dom'
import { 
  LayoutDashboard, Users, Building2, Shield, Settings, 
  Webhook, FileText, BarChart3, Lock, ChevronLeft, ChevronRight,
  LogOut, ChevronDown, Fingerprint
} from 'lucide-react'
import { useState } from 'react'
import { cn } from '@/lib/utils'
import { useUIStore, useAuthStore } from '@/store'

interface NavItem {
  name: string
  href: string
  icon: React.ElementType
  children?: { name: string; href: string }[]
}

const navigation: NavItem[] = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Users', href: '/users', icon: Users },
  { name: 'Organizations', href: '/organizations', icon: Building2 },
  { name: 'Security', href: '/security', icon: Shield },
  { 
    name: 'Integrations', 
    href: '#', 
    icon: Lock,
    children: [
      { name: 'OAuth Clients', href: '/oauth-clients' },
      { name: 'SAML Connections', href: '/saml-connections' },
      { name: 'Webhooks', href: '/webhooks' },
    ]
  },
  { name: 'Audit Logs', href: '/audit-logs', icon: FileText },
  { name: 'Analytics', href: '/analytics', icon: BarChart3 },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export function Sidebar() {
  const location = useLocation()
  const { sidebarCollapsed, toggleSidebar } = useUIStore()
  const { user } = useAuthStore()
  const [expandedItems, setExpandedItems] = useState<string[]>([])

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

  return (
    <aside
      className={cn(
        "fixed left-0 top-0 z-40 h-screen bg-card border-r border-border transition-all duration-300",
        sidebarCollapsed ? "w-16" : "w-64"
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
          <button
            onClick={toggleSidebar}
            className="p-1 rounded-md hover:bg-muted transition-colors"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Collapse Button (when collapsed) */}
      {sidebarCollapsed && (
        <button
          onClick={toggleSidebar}
          className="absolute -right-3 top-20 w-6 h-6 bg-primary text-primary-foreground rounded-full flex items-center justify-center shadow-md hover:bg-primary/90"
        >
          <ChevronRight className="w-3 h-3" />
        </button>
      )}

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-2 scrollbar-thin">
        <ul className="space-y-1">
          {navigation.map((item) => {
            const Icon = item.icon
            const active = isActive(item.href)
            const expanded = expandedItems.includes(item.name)
            const hasChildren = item.children && item.children.length > 0

            if (sidebarCollapsed) {
              return (
                <li key={item.name}>
                  <NavLink
                    to={item.href}
                    className={cn(
                      "flex items-center justify-center p-2 rounded-lg transition-colors",
                      active 
                        ? "bg-primary text-primary-foreground" 
                        : "text-muted-foreground hover:bg-muted hover:text-foreground"
                    )}
                    title={item.name}
                  >
                    <Icon className="w-5 h-5" />
                  </NavLink>
                </li>
              )
            }

            return (
              <li key={item.name}>
                {hasChildren ? (
                  <>
                    <button
                      onClick={() => toggleExpanded(item.name)}
                      className={cn(
                        "w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors",
                        active 
                          ? "bg-primary text-primary-foreground" 
                          : "text-muted-foreground hover:bg-muted hover:text-foreground"
                      )}
                    >
                      <div className="flex items-center gap-3">
                        <Icon className="w-5 h-5" />
                        <span className="text-sm font-medium">{item.name}</span>
                      </div>
                      <ChevronDown 
                        className={cn(
                          "w-4 h-4 transition-transform",
                          expanded && "rotate-180"
                        )} 
                      />
                    </button>
                    {expanded && (
                      <ul className="mt-1 ml-4 pl-4 border-l border-border space-y-1">
                        {item.children?.map((child) => (
                          <li key={child.name}>
                            <NavLink
                              to={child.href}
                              className={({ isActive }) => cn(
                                "block px-3 py-2 rounded-lg text-sm transition-colors",
                                isActive
                                  ? "bg-primary/10 text-primary font-medium"
                                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
                              )}
                            >
                              {child.name}
                            </NavLink>
                          </li>
                        ))}
                      </ul>
                    )}
                  </>
                ) : (
                  <NavLink
                    to={item.href}
                    className={({ isActive }) => cn(
                      "flex items-center gap-3 px-3 py-2 rounded-lg transition-colors",
                      isActive
                        ? "bg-primary text-primary-foreground"
                        : "text-muted-foreground hover:bg-muted hover:text-foreground"
                    )}
                  >
                    <Icon className="w-5 h-5" />
                    <span className="text-sm font-medium">{item.name}</span>
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
          </div>
        </div>
      )}
    </aside>
  )
}
