import { useState, useEffect } from 'react'

export function SkipLinks() {
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Tab') {
        setIsVisible(true)
      }
    }

    const handleClick = () => {
      setIsVisible(false)
    }

    window.addEventListener('keydown', handleKeyDown)
    window.addEventListener('click', handleClick)
    
    return () => {
      window.removeEventListener('keydown', handleKeyDown)
      window.removeEventListener('click', handleClick)
    }
  }, [])

  const handleSkipToMain = () => {
    const mainContent = document.getElementById('main-content')
    if (mainContent) {
      mainContent.focus()
      mainContent.scrollIntoView({ behavior: 'smooth' })
      setIsVisible(false)
    }
  }

  const handleSkipToNav = () => {
    const nav = document.querySelector('nav[role="navigation"]') as HTMLElement
    if (nav) {
      nav.focus()
      setIsVisible(false)
    }
  }

  if (!isVisible) {
    return (
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded-md focus:shadow-lg"
        onClick={(e) => {
          e.preventDefault()
          handleSkipToMain()
        }}
      >
        Skip to main content
      </a>
    )
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-background border-b shadow-lg p-4 flex gap-4">
      <button type="button"
        onClick={handleSkipToMain}
        className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-ring"
      >
        Skip to main content
      </button>
      <button type="button"
        onClick={handleSkipToNav}
        className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md hover:bg-secondary/90 focus:outline-none focus:ring-2 focus:ring-ring"
      >
        Skip to navigation
      </button>
    </div>
  )
}

export function DataTableSkipLinks({ tableId }: { tableId?: string }) {
  void tableId
  return (
    <div className="sr-only focus-within:not-sr-only">
      <a href="#table-filters" className="focus:not-sr-only">
        Skip to filters
      </a>
    </div>
  )
}

export function SettingsSkipLinks() {
  return (
    <div className="sr-only focus-within:not-sr-only">
      <a href="#settings-main" className="focus:not-sr-only">
        Skip to settings
      </a>
    </div>
  )
}

export function AuditSkipLinks() {
  return (
    <div className="sr-only focus-within:not-sr-only">
      <a href="#audit-log" className="focus:not-sr-only">
        Skip to audit log
      </a>
    </div>
  )
}
