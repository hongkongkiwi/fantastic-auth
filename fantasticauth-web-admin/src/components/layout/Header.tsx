import { useState } from 'react'
import { 
  Search, Bell, Moon, Sun, Monitor, Menu, X,
  Check, AlertCircle
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useUIStore, useAuthStore, useNotificationStore } from '@/store'
import type { Theme } from '@/types'

export function Header() {
  const navigate = useNavigate()
  const { theme, setTheme, sidebarCollapsed } = useUIStore()
  const { logout } = useAuthStore()
  const { notifications, removeNotification, clearNotifications } = useNotificationStore()
  const [showSearch, setShowSearch] = useState(false)
  const [showNotifications, setShowNotifications] = useState(false)
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      navigate(`/users?search=${encodeURIComponent(searchQuery)}`)
      setShowSearch(false)
      setSearchQuery('')
    }
  }

  const unreadCount = notifications.filter(n => !n.read).length

  const themeOptions: { value: Theme; icon: React.ElementType; label: string }[] = [
    { value: 'light', icon: Sun, label: 'Light' },
    { value: 'dark', icon: Moon, label: 'Dark' },
    { value: 'system', icon: Monitor, label: 'System' },
  ]

  return (
    <header 
      className={cn(
        "fixed top-0 right-0 z-30 h-16 bg-card border-b border-border transition-all duration-300",
        sidebarCollapsed ? "left-16" : "left-64"
      )}
    >
      <div className="h-full px-4 flex items-center justify-between gap-4">
        {/* Search */}
        <div className="flex-1 max-w-xl">
          {showSearch ? (
            <form onSubmit={handleSearch} className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search users, organizations..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-10 py-2 bg-muted rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                autoFocus
              />
              <button
                type="button"
                onClick={() => setShowSearch(false)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                <X className="w-4 h-4" />
              </button>
            </form>
          ) : (
            <button
              onClick={() => setShowSearch(true)}
              className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
            >
              <Search className="w-4 h-4" />
              <span className="text-sm hidden sm:inline">Search...</span>
              <kbd className="hidden sm:inline-flex h-5 items-center gap-1 rounded border bg-muted px-1.5 font-mono text-xs font-medium">
                <span>⌘</span>K
              </kbd>
            </button>
          )}
        </div>

        {/* Right Actions */}
        <div className="flex items-center gap-2">
          {/* Theme Toggle */}
          <div className="relative">
            <button
              onClick={() => {
                const nextTheme = theme === 'light' ? 'dark' : theme === 'dark' ? 'system' : 'light'
                setTheme(nextTheme)
              }}
              className="p-2 rounded-lg hover:bg-muted transition-colors"
              title={`Theme: ${theme}`}
            >
              {theme === 'light' && <Sun className="w-4 h-4" />}
              {theme === 'dark' && <Moon className="w-4 h-4" />}
              {theme === 'system' && <Monitor className="w-4 h-4" />}
            </button>
          </div>

          {/* Notifications */}
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-2 rounded-lg hover:bg-muted transition-colors"
            >
              <Bell className="w-4 h-4" />
              {unreadCount > 0 && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
              )}
            </button>

            {/* Notifications Dropdown */}
            {showNotifications && (
              <>
                <div 
                  className="fixed inset-0 z-40" 
                  onClick={() => setShowNotifications(false)} 
                />
                <div className="absolute right-0 top-full mt-2 w-80 bg-card border border-border rounded-lg shadow-lg z-50 animate-in">
                  <div className="flex items-center justify-between p-3 border-b border-border">
                    <span className="font-medium">Notifications</span>
                    <button
                      onClick={clearNotifications}
                      className="text-xs text-muted-foreground hover:text-foreground"
                    >
                      Clear all
                    </button>
                  </div>
                  <div className="max-h-64 overflow-y-auto">
                    {notifications.length === 0 ? (
                      <div className="p-4 text-center text-sm text-muted-foreground">
                        No notifications
                      </div>
                    ) : (
                      notifications.map((notification) => (
                        <div
                          key={notification.id}
                          className={cn(
                            "p-3 border-b border-border last:border-0 hover:bg-muted/50 transition-colors",
                            !notification.read && "bg-primary/5"
                          )}
                        >
                          <div className="flex items-start gap-2">
                            {notification.type === 'success' && (
                              <Check className="w-4 h-4 text-green-500 mt-0.5" />
                            )}
                            {notification.type === 'error' && (
                              <AlertCircle className="w-4 h-4 text-red-500 mt-0.5" />
                            )}
                            {notification.type === 'warning' && (
                              <AlertCircle className="w-4 h-4 text-yellow-500 mt-0.5" />
                            )}
                            {notification.type === 'info' && (
                              <Bell className="w-4 h-4 text-blue-500 mt-0.5" />
                            )}
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium">{notification.title}</p>
                              {notification.message && (
                                <p className="text-xs text-muted-foreground mt-0.5">
                                  {notification.message}
                                </p>
                              )}
                            </div>
                            <button
                              onClick={() => removeNotification(notification.id)}
                              className="text-muted-foreground hover:text-foreground"
                            >
                              <X className="w-3 h-3" />
                            </button>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}
