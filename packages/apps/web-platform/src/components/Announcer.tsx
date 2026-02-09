import * as React from 'react'

// Global announcer for screen reader notifications
export function Announcer() {
  return (
    <>
      {/* Polite announcements - won't interrupt */}
      <div
        id="aria-announcer-polite"
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className="sr-only"
      />
      {/* Assertive announcements - will interrupt */}
      <div
        id="aria-announcer-assertive"
        role="alert"
        aria-live="assertive"
        aria-atomic="true"
        className="sr-only"
      />
    </>
  )
}

// Hook to make announcements
export function useAnnouncer() {
  const announce = React.useCallback((message: string, priority: 'polite' | 'assertive' = 'polite') => {
    const announcer = document.getElementById(`aria-announcer-${priority}`)
    if (announcer) {
      // Clear first to ensure announcement
      announcer.textContent = ''
      // Use requestAnimationFrame for better screen reader support
      requestAnimationFrame(() => {
        announcer.textContent = message
      })
    }
  }, [])

  const clear = React.useCallback((priority: 'polite' | 'assertive' = 'polite') => {
    const announcer = document.getElementById(`aria-announcer-${priority}`)
    if (announcer) {
      announcer.textContent = ''
    }
  }, [])

  return { announce, clear }
}
