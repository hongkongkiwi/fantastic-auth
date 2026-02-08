import * as React from 'react'
import { useNavigate } from '@tanstack/react-router'
import { motion, useReducedMotion } from 'framer-motion'
import {
  Search,
  Command,
  LayoutDashboard,
  Building2,
  Users,
  CreditCard,
  ClipboardList,
  Settings,
  ArrowRight,
  Plus,
  LogOut,
} from 'lucide-react'
import { Dialog, DialogContent } from './ui/Dialog'
import { cn } from '../lib/utils'
import { useAuth } from '../hooks/useAuth'

interface SearchItem {
  id: string
  title: string
  subtitle?: string
  icon: React.ElementType
  shortcut?: string
  action?: () => void
  href?: string
  section: string
}

export function GlobalSearch() {
  const [isOpen, setIsOpen] = React.useState(false)
  const [query, setQuery] = React.useState('')
  const [selectedIndex, setSelectedIndex] = React.useState(0)
  const navigate = useNavigate()
  const { logout } = useAuth()
  const prefersReducedMotion = useReducedMotion()
  const inputRef = React.useRef<HTMLInputElement | null>(null)
  const deferredQuery = React.useDeferredValue(query)

  // Keyboard shortcut ⌘K or Ctrl+K
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setIsOpen(true)
      }
      if (e.key === 'Escape') {
        setIsOpen(false)
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  const searchItems: SearchItem[] = [
    // Navigation
    {
      id: 'dashboard',
      title: 'Dashboard',
      icon: LayoutDashboard,
      href: '/',
      section: 'Navigation',
    },
    {
      id: 'tenants',
      title: 'Tenants',
      icon: Building2,
      href: '/tenants',
      section: 'Navigation',
    },
    {
      id: 'create-tenant',
      title: 'Create New Tenant',
      subtitle: 'Add a new tenant to the platform',
      icon: Plus,
      href: '/tenants/create',
      section: 'Navigation',
    },
    {
      id: 'users',
      title: 'Users',
      icon: Users,
      href: '/users',
      section: 'Navigation',
    },
    {
      id: 'billing',
      title: 'Billing',
      icon: CreditCard,
      href: '/billing',
      section: 'Navigation',
    },
    {
      id: 'audit',
      title: 'Audit Logs',
      icon: ClipboardList,
      href: '/audit',
      section: 'Navigation',
    },
    {
      id: 'settings',
      title: 'Settings',
      icon: Settings,
      href: '/settings',
      section: 'Navigation',
    },
    // Actions
    {
      id: 'logout',
      title: 'Logout',
      subtitle: 'Sign out of your account',
      icon: LogOut,
      action: () => logout(),
      section: 'Actions',
    },
  ]

  const filteredItems = React.useMemo(() => {
    if (!deferredQuery.trim()) return searchItems

    const lowerQuery = deferredQuery.toLowerCase()
    return searchItems.filter(
      (item) =>
        item.title.toLowerCase().includes(lowerQuery) ||
        item.subtitle?.toLowerCase().includes(lowerQuery)
    )
  }, [deferredQuery])

  const groupedItems = React.useMemo(() => {
    const groups: Record<string, SearchItem[]> = {}
    filteredItems.forEach((item) => {
      if (!groups[item.section]) groups[item.section] = []
      groups[item.section].push(item)
    })
    return groups
  }, [filteredItems])

  const flatItems = React.useMemo(() => {
    return Object.values(groupedItems).flat()
  }, [groupedItems])

  const handleSelect = (item: SearchItem) => {
    setIsOpen(false)
    setQuery('')
    
    if (item.action) {
      item.action()
    } else if (item.href) {
      navigate({ to: item.href })
    }
  }

  // Keyboard navigation
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return
      
      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault()
          setSelectedIndex((prev) => 
            prev < flatItems.length - 1 ? prev + 1 : prev
          )
          break
        case 'ArrowUp':
          e.preventDefault()
          setSelectedIndex((prev) => (prev > 0 ? prev - 1 : prev))
          break
        case 'Enter':
          e.preventDefault()
          if (flatItems[selectedIndex]) {
            handleSelect(flatItems[selectedIndex])
          }
          break
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, flatItems, selectedIndex])

  // Reset selection when query changes
  React.useEffect(() => {
    setSelectedIndex(0)
  }, [query])

  React.useEffect(() => {
    if (!isOpen) return
    const isFinePointer = window.matchMedia?.('(pointer: fine)').matches ?? false
    if (isFinePointer) {
      inputRef.current?.focus()
    }
  }, [isOpen])

  return (
    <>
      {/* Search Trigger Button */}
      <button
        onClick={() => setIsOpen(true)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg bg-muted hover:bg-accent transition-colors text-sm text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        type="button"
        aria-label="Open global search"
      >
        <Search className="h-4 w-4" aria-hidden="true" />
        <span className="hidden sm:inline">Search…</span>
        <kbd className="hidden sm:inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-background text-xs font-mono">
          <Command className="h-3 w-3" aria-hidden="true" />
          <span>K</span>
        </kbd>
      </button>

      {/* Search Dialog */}
      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogContent className="max-w-2xl p-0 gap-0 overflow-hidden" showClose={false}>
          {/* Search Input */}
          <div className="flex items-center gap-3 px-4 py-4 border-b">
            <Search className="h-5 w-5 text-muted-foreground" aria-hidden="true" />
            <input
              type="text"
              placeholder="Search commands, pages, or actions…"
              className="flex-1 bg-transparent text-lg placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Search"
              name="global-search"
              autoComplete="off"
              ref={inputRef}
            />
            <kbd className="hidden sm:inline-flex items-center gap-1 px-2 py-1 rounded bg-muted text-xs font-mono">
              ESC
            </kbd>
          </div>

          {/* Results */}
          <div className="max-h-[400px] overflow-y-auto py-2">
            {flatItems.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <Search className="h-12 w-12 text-muted-foreground/50 mb-4" aria-hidden="true" />
                <p className="text-muted-foreground">No results found</p>
                <p className="text-sm text-muted-foreground/70">
                  Try searching for something else
                </p>
              </div>
            ) : (
              Object.entries(groupedItems).map(([section, items]) => (
                <div key={section} className="px-2">
                  <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                    {section}
                  </div>
                  {items.map((item, index) => {
                    const globalIndex = flatItems.findIndex((i) => i.id === item.id)
                    const isSelected = globalIndex === selectedIndex
                    
                    return (
                      <motion.button
                        key={item.id}
                        onClick={() => handleSelect(item)}
                        onMouseEnter={() => setSelectedIndex(globalIndex)}
                        className={cn(
                          'w-full flex items-center gap-3 px-3 py-3 rounded-lg text-left transition-colors',
                          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary',
                          isSelected
                            ? 'bg-primary text-primary-foreground'
                            : 'hover:bg-accent'
                        )}
                        initial={prefersReducedMotion ? false : { opacity: 0, y: 5 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={prefersReducedMotion ? { duration: 0 } : { delay: index * 0.02 }}
                      >
                        <item.icon
                          className={cn(
                            'h-5 w-5',
                            isSelected ? 'text-primary-foreground' : 'text-muted-foreground'
                          )}
                          aria-hidden="true"
                        />
                        <div className="flex-1 min-w-0">
                          <p className={cn('font-medium', isSelected && 'text-primary-foreground')}>
                            {item.title}
                          </p>
                          {item.subtitle && (
                            <p
                              className={cn(
                                'text-sm truncate',
                                isSelected
                                  ? 'text-primary-foreground/80'
                                  : 'text-muted-foreground'
                              )}
                            >
                              {item.subtitle}
                            </p>
                          )}
                        </div>
                        {item.shortcut && (
                          <kbd
                            className={cn(
                              'px-2 py-1 rounded text-xs font-mono',
                              isSelected ? 'bg-primary-foreground/20' : 'bg-muted'
                            )}
                          >
                            {item.shortcut}
                          </kbd>
                        )}
                        {isSelected && <ArrowRight className="h-4 w-4" aria-hidden="true" />}
                      </motion.button>
                    )
                  })}
                </div>
              ))
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-between px-4 py-3 border-t bg-muted/50 text-xs text-muted-foreground">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1">
                <kbd className="px-1.5 py-0.5 rounded bg-background border">↑</kbd>
                <kbd className="px-1.5 py-0.5 rounded bg-background border">↓</kbd>
                <span>to navigate</span>
              </span>
              <span className="flex items-center gap-1">
                <kbd className="px-1.5 py-0.5 rounded bg-background border">↵</kbd>
                <span>to select</span>
              </span>
            </div>
            <span>{flatItems.length} results</span>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
