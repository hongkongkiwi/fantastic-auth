import * as React from 'react'
import { useNavigate } from '@tanstack/react-router'
import { Command } from 'cmdk'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Search,
  Home,
  Building2,
  Users,
  CreditCard,
  ClipboardList,
  Settings,
  Shield,
  LogOut,
  Bell,
  Key,
  Webhook,
  Plus,
  ExternalLink,
  Moon,
  Command as CommandIcon,
} from 'lucide-react'
import { cn } from '../lib/utils'
import { useAuth } from '../hooks/useAuth'

interface CommandItem {
  id: string
  title: string
  subtitle?: string
  icon?: React.ReactNode
  shortcut?: string[]
  action?: () => void
  href?: string
  keywords?: string[]
  section: string
}

interface CommandPaletteProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const navigate = useNavigate()
  const { logout } = useAuth()
  const [search, setSearch] = React.useState('')
  const [pages, setPages] = React.useState<string[]>([])
  const activePage = pages[pages.length - 1]
  const inputRef = React.useRef<HTMLInputElement>(null)

  // Focus input when opened
  React.useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 100)
    }
  }, [open])

  // Keyboard shortcut to open
  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        onOpenChange(!open)
      }
    }
    document.addEventListener('keydown', down)
    return () => document.removeEventListener('keydown', down)
  }, [open, onOpenChange])

  const pushPage = (page: string) => {
    setPages([...pages, page])
  }

  const popPage = () => {
    setPages(pages.slice(0, -1))
  }

  const goTo = (href: string) => {
    navigate({ to: href })
    onOpenChange(false)
    setSearch('')
    setPages([])
  }

  const mainCommands: CommandItem[] = [
    // Navigation
    {
      id: 'dashboard',
      title: 'Dashboard',
      subtitle: 'Go to dashboard',
      icon: <Home className="h-4 w-4" />,
      shortcut: ['G', 'D'],
      href: '/',
      section: 'Navigation',
    },
    {
      id: 'tenants',
      title: 'Tenants',
      subtitle: 'Manage platform tenants',
      icon: <Building2 className="h-4 w-4" />,
      shortcut: ['G', 'T'],
      href: '/tenants',
      section: 'Navigation',
    },
    {
      id: 'users',
      title: 'Users',
      subtitle: 'Manage platform users',
      icon: <Users className="h-4 w-4" />,
      shortcut: ['G', 'U'],
      href: '/users',
      section: 'Navigation',
    },
    {
      id: 'billing',
      title: 'Billing',
      subtitle: 'Subscriptions and invoices',
      icon: <CreditCard className="h-4 w-4" />,
      shortcut: ['G', 'B'],
      href: '/billing',
      section: 'Navigation',
    },
    {
      id: 'audit',
      title: 'Audit Logs',
      subtitle: 'View platform activity',
      icon: <ClipboardList className="h-4 w-4" />,
      shortcut: ['G', 'A'],
      href: '/audit',
      section: 'Navigation',
    },
    {
      id: 'settings',
      title: 'Settings',
      subtitle: 'Configure platform',
      icon: <Settings className="h-4 w-4" />,
      shortcut: ['G', 'S'],
      href: '/settings',
      section: 'Navigation',
    },

    // Quick Actions
    {
      id: 'create-tenant',
      title: 'Create Tenant',
      subtitle: 'Add a new tenant to the platform',
      icon: <Plus className="h-4 w-4" />,
      shortcut: ['C', 'T'],
      href: '/tenants/create',
      section: 'Quick Actions',
    },
    {
      id: 'api-keys',
      title: 'API Keys',
      subtitle: 'Manage API access tokens',
      icon: <Key className="h-4 w-4" />,
      action: () => pushPage('api-keys'),
      section: 'Quick Actions',
    },
    {
      id: 'webhooks',
      title: 'Webhooks',
      subtitle: 'Configure webhook endpoints',
      icon: <Webhook className="h-4 w-4" />,
      href: '/settings/webhooks',
      section: 'Quick Actions',
    },
    {
      id: 'notifications',
      title: 'Notifications',
      subtitle: 'View recent notifications',
      icon: <Bell className="h-4 w-4" />,
      action: () => pushPage('notifications'),
      section: 'Quick Actions',
    },

    // Settings
    {
      id: 'security-settings',
      title: 'Security Settings',
      subtitle: 'MFA, sessions, password',
      icon: <Shield className="h-4 w-4" />,
      href: '/settings/security',
      section: 'Settings',
    },
    {
      id: 'theme',
      title: 'Toggle Theme',
      subtitle: 'Switch between light and dark mode',
      icon: <Moon className="h-4 w-4" />,
      shortcut: ['T', 'T'],
      action: () => {
        // Toggle theme logic would go here
        onOpenChange(false)
      },
      section: 'Settings',
    },

    // Account
    {
      id: 'logout',
      title: 'Logout',
      subtitle: 'Sign out of your account',
      icon: <LogOut className="h-4 w-4" />,
      shortcut: ['⇧', 'Q'],
      action: () => {
        logout()
        onOpenChange(false)
      },
      section: 'Account',
    },
  ]

  const apiKeyCommands: CommandItem[] = [
    {
      id: 'back',
      title: 'Back',
      subtitle: 'Return to main menu',
      icon: <CommandIcon className="h-4 w-4" />,
      action: popPage,
      section: 'Navigation',
    },
    {
      id: 'view-api-keys',
      title: 'View API Keys',
      subtitle: 'See all configured API keys',
      icon: <Key className="h-4 w-4" />,
      action: () => {
        navigate({ to: '/settings' })
        onOpenChange(false)
      },
      section: 'API Keys',
    },
    {
      id: 'generate-key',
      title: 'Generate New Key',
      subtitle: 'Create a new API key',
      icon: <Plus className="h-4 w-4" />,
      action: () => {
        navigate({ to: '/settings' })
        onOpenChange(false)
      },
      section: 'API Keys',
    },
  ]

  const commands = activePage === 'api-keys' ? apiKeyCommands : mainCommands

  const sections = [...new Set(commands.map((c) => c.section))]

  const handleKeyDown = (e: React.KeyboardEvent) => {
    // Handle keyboard shortcuts
    if (!activePage) {
      for (const cmd of mainCommands) {
        if (cmd.shortcut && cmd.shortcut.length === 2) {
          const [, second] = cmd.shortcut
          if (e.key.toUpperCase() === second && e.shiftKey) {
            // Check if first key was pressed recently (simplified)
            if (cmd.href) {
              goTo(cmd.href)
              return
            } else if (cmd.action) {
              cmd.action()
              return
            }
          }
        }
      }
    }

    if (e.key === 'Backspace' && !search && activePage) {
      e.preventDefault()
      popPage()
    }
  }

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => onOpenChange(false)}
            className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
          />

          {/* Command Palette */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 10 }}
            transition={{ duration: 0.15 }}
            className="fixed left-1/2 top-[20%] z-50 w-full max-w-2xl -translate-x-1/2"
          >
            <Command
              className="overflow-hidden rounded-xl border bg-popover shadow-2xl"
              onKeyDown={handleKeyDown}
            >
              {/* Search Input */}
              <div className="flex items-center border-b px-4">
                <Search className="mr-2 h-4 w-4 shrink-0 text-muted-foreground" />
                <Command.Input
                  ref={inputRef}
                  value={search}
                  onValueChange={setSearch}
                  placeholder={activePage ? 'Search...' : 'Type a command or search...'}
                  className="flex h-12 w-full rounded-md bg-transparent py-3 text-sm outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50"
                />
                {activePage && (
                  <div className="flex items-center gap-1 text-xs text-muted-foreground">
                    <kbd className="rounded bg-muted px-1.5 py-0.5">←</kbd>
                    <span>Back</span>
                  </div>
                )}
              </div>

              {/* Results */}
              <Command.List className="max-h-[60vh] overflow-y-auto p-2">
                <Command.Empty className="py-6 text-center text-sm text-muted-foreground">
                  No results found for &quot;{search}&quot;
                </Command.Empty>

                {sections.map((section) => {
                  const sectionCommands = commands.filter((c) => c.section === section)
                  if (sectionCommands.length === 0) return null

                  return (
                    <Command.Group
                      key={section}
                      heading={section}
                      className="overflow-hidden p-1 text-foreground"
                    >
                      <div className="px-2 py-1.5 text-xs font-medium text-muted-foreground">
                        {section}
                      </div>
                      {sectionCommands.map((cmd) => (
                        <Command.Item
                          key={cmd.id}
                          value={`${cmd.title} ${cmd.subtitle} ${cmd.keywords?.join(' ') || ''}`}
                          onSelect={() => {
                            if (cmd.action) {
                              cmd.action()
                            } else if (cmd.href) {
                              goTo(cmd.href)
                            }
                          }}
                          className={cn(
                            'relative flex cursor-pointer select-none items-center rounded-sm px-2 py-2.5 text-sm outline-none',
                            'data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground',
                            'hover:bg-accent hover:text-accent-foreground'
                          )}
                        >
                          <div className="flex flex-1 items-center gap-3">
                            {cmd.icon && (
                              <div className="flex h-8 w-8 items-center justify-center rounded-md bg-muted">
                                {cmd.icon}
                              </div>
                            )}
                            <div className="flex flex-col">
                              <span className="font-medium">{cmd.title}</span>
                              {cmd.subtitle && (
                                <span className="text-xs text-muted-foreground">
                                  {cmd.subtitle}
                                </span>
                              )}
                            </div>
                          </div>
                          {cmd.shortcut && (
                            <div className="flex items-center gap-1">
                              {cmd.shortcut.map((key, i) => (
                                <kbd
                                  key={i}
                                  className="rounded bg-muted px-1.5 py-0.5 text-xs font-mono"
                                >
                                  {key}
                                </kbd>
                              ))}
                            </div>
                          )}
                          {cmd.href && !cmd.shortcut && (
                            <ExternalLink className="h-3 w-3 text-muted-foreground" />
                          )}
                        </Command.Item>
                      ))}
                    </Command.Group>
                  )
                })}
              </Command.List>

              {/* Footer */}
              <div className="flex items-center justify-between border-t px-4 py-2 text-xs text-muted-foreground">
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-1">
                    <kbd className="rounded bg-muted px-1.5 py-0.5">↑↓</kbd>
                    <span>Navigate</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <kbd className="rounded bg-muted px-1.5 py-0.5">↵</kbd>
                    <span>Select</span>
                  </div>
                  {activePage && (
                    <div className="flex items-center gap-1">
                      <kbd className="rounded bg-muted px-1.5 py-0.5">←</kbd>
                      <span>Back</span>
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-1">
                  <kbd className="rounded bg-muted px-1.5 py-0.5">⌘</kbd>
                  <kbd className="rounded bg-muted px-1.5 py-0.5">K</kbd>
                  <span>to open</span>
                </div>
              </div>
            </Command>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}
