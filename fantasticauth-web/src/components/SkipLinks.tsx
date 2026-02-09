import { cn } from '../lib/utils'

interface SkipLink {
  id: string
  label: string
}

interface SkipLinksProps {
  links?: SkipLink[]
  className?: string
}

const defaultLinks: SkipLink[] = [
  { id: 'main-content', label: 'Skip to main content' },
  { id: 'navigation', label: 'Skip to navigation' },
]

export function SkipLinks({ links = defaultLinks, className }: SkipLinksProps) {
  return (
    <nav
      aria-label="Skip links"
      className={cn(
        'sr-only focus-within:not-sr-only focus-within:absolute focus-within:top-4 focus-within:left-4 focus-within:z-[100]',
        className
      )}
    >
      <ul className="flex flex-col gap-2">
        {links.map((link) => (
          <li key={link.id}>
            <a
              href={`#${link.id}`}
              className={cn(
                'block px-4 py-2 bg-primary text-primary-foreground rounded-md',
                'font-medium text-sm',
                'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary',
                'transition-transform hover:translate-x-1'
              )}
              onClick={(e) => {
                e.preventDefault()
                const target = document.getElementById(link.id)
                if (target) {
                  target.focus()
                  target.scrollIntoView({ behavior: 'smooth' })
                }
              }}
            >
              {link.label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  )
}

// Page-specific skip links
export function DataTableSkipLinks({ tableId }: { tableId: string }) {
  return (
    <SkipLinks
      links={[
        { id: 'main-content', label: 'Skip to main content' },
        { id: `${tableId}-filters`, label: 'Skip to filters' },
        { id: `${tableId}-results`, label: 'Skip to results' },
        { id: `${tableId}-pagination`, label: 'Skip to pagination' },
      ]}
    />
  )
}

export function SettingsSkipLinks() {
  return (
    <SkipLinks
      links={[
        { id: 'main-content', label: 'Skip to main content' },
        { id: 'settings-search', label: 'Skip to settings search' },
        { id: 'settings-categories', label: 'Skip to categories' },
        { id: 'settings-content', label: 'Skip to settings' },
      ]}
    />
  )
}

export function AuditSkipLinks() {
  return (
    <SkipLinks
      links={[
        { id: 'main-content', label: 'Skip to main content' },
        { id: 'audit-filters', label: 'Skip to filters' },
        { id: 'audit-table', label: 'Skip to audit log' },
      ]}
    />
  )
}
