import * as React from 'react'

interface FocusTrapOptions {
  enabled?: boolean
  onEscape?: () => void
  initialFocus?: boolean
  returnFocus?: boolean
}

export function useFocusTrap(
  containerRef: React.RefObject<HTMLElement>,
  options: FocusTrapOptions = {}
) {
  const { enabled = true, onEscape, initialFocus = true, returnFocus = true } = options
  const previousActiveElement = React.useRef<HTMLElement | null>(null)
  const focusableElementsRef = React.useRef<HTMLElement[]>([])

  const getFocusableElements = React.useCallback(() => {
    const container = containerRef.current
    if (!container) return []

    const selectors = [
      'button:not([disabled])',
      'a[href]',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      '[tabindex]:not([tabindex="-1"])',
      '[contenteditable]',
    ].join(', ')

    return Array.from(container.querySelectorAll<HTMLElement>(selectors))
      .filter((el) => {
        // Check visibility
        const style = window.getComputedStyle(el)
        return style.display !== 'none' && style.visibility !== 'hidden'
      })
      .sort((a, b) => {
        const aTabIndex = parseInt(a.tabIndex.toString()) || 0
        const bTabIndex = parseInt(b.tabIndex.toString()) || 0
        return aTabIndex - bTabIndex
      })
  }, [containerRef])

  // Store previous focus and set initial focus
  React.useEffect(() => {
    if (!enabled) return

    previousActiveElement.current = document.activeElement as HTMLElement

    if (initialFocus) {
      // Small delay to ensure DOM is ready
      const timer = setTimeout(() => {
        const focusableElements = getFocusableElements()
        focusableElementsRef.current = focusableElements

        if (focusableElements.length > 0) {
          // Try to find autofocus element first
          const autoFocusElement = containerRef.current?.querySelector<HTMLElement>('[autofocus]')
          if (autoFocusElement) {
            autoFocusElement.focus()
          } else {
            focusableElements[0].focus()
          }
        }
      }, 50)

      return () => clearTimeout(timer)
    }
  }, [enabled, initialFocus, getFocusableElements, containerRef])

  // Return focus on unmount
  React.useEffect(() => {
    return () => {
      if (returnFocus && previousActiveElement.current && document.contains(previousActiveElement.current)) {
        previousActiveElement.current.focus()
      }
    }
  }, [returnFocus])

  // Handle tab key
  const handleTabKey = React.useCallback(
    (event: KeyboardEvent) => {
      if (!enabled || event.key !== 'Tab') return

      const focusableElements = focusableElementsRef.current
      if (focusableElements.length === 0) return

      const firstElement = focusableElements[0]
      const lastElement = focusableElements[focusableElements.length - 1]
      const activeElement = document.activeElement

      // Shift + Tab
      if (event.shiftKey) {
        if (activeElement === firstElement || !containerRef.current?.contains(activeElement)) {
          event.preventDefault()
          lastElement.focus()
        }
      } else {
        // Tab
        if (activeElement === lastElement || !containerRef.current?.contains(activeElement)) {
          event.preventDefault()
          firstElement.focus()
        }
      }
    },
    [enabled, containerRef]
  )

  // Handle escape key
  const handleEscapeKey = React.useCallback(
    (event: KeyboardEvent) => {
      if (event.key === 'Escape' && onEscape) {
        onEscape()
      }
    },
    [onEscape]
  )

  // Update focusable elements when content changes
  React.useEffect(() => {
    if (!enabled) return

    const observer = new MutationObserver(() => {
      focusableElementsRef.current = getFocusableElements()
    })

    if (containerRef.current) {
      observer.observe(containerRef.current, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['tabindex', 'disabled', 'hidden'],
      })
    }

    return () => observer.disconnect()
  }, [enabled, containerRef, getFocusableElements])

  // Attach keyboard listeners
  React.useEffect(() => {
    if (!enabled) return

    const container = containerRef.current
    if (!container) return

    container.addEventListener('keydown', handleTabKey)
    container.addEventListener('keydown', handleEscapeKey)

    return () => {
      container.removeEventListener('keydown', handleTabKey)
      container.removeEventListener('keydown', handleEscapeKey)
    }
  }, [enabled, containerRef, handleTabKey, handleEscapeKey])

  return {
    focusFirst: () => {
      const elements = getFocusableElements()
      if (elements.length > 0) elements[0].focus()
    },
    focusLast: () => {
      const elements = getFocusableElements()
      if (elements.length > 0) elements[elements.length - 1].focus()
    },
  }
}

// Hook to manage focus within a specific scope
export function useFocusScope(scopeName: string) {
  const scopeRef = React.useRef<HTMLElement | null>(null)

  const register = React.useCallback((element: HTMLElement | null) => {
    scopeRef.current = element
    if (element) {
      element.dataset.focusScope = scopeName
    }
  }, [scopeName])

  const focusWithin = React.useCallback(() => {
    if (scopeRef.current) {
      const focusable = scopeRef.current.querySelector<HTMLElement>(
        'button, a, input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )
      focusable?.focus()
    }
  }, [])

  return { register, focusWithin, scopeRef }
}

// Hook to announce changes to screen readers
export function useAnnouncer() {
  const announce = React.useCallback((message: string, priority: 'polite' | 'assertive' = 'polite') => {
    const announcer = document.getElementById(`aria-announcer-${priority}`)
    if (announcer) {
      announcer.textContent = message
      // Clear after announcement
      setTimeout(() => {
        announcer.textContent = ''
      }, 1000)
    }
  }, [])

  return { announce }
}
