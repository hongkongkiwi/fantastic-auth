import { useState, useRef, useEffect } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { SkipLink } from './SkipLink'

export function Layout() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const location = useLocation()
  const mainRef = useRef<HTMLDivElement>(null)

  // Reset focus and scroll on route change
  useEffect(() => {
    if (mainRef.current) {
      mainRef.current.focus()
      mainRef.current.scrollTop = 0
    }
  }, [location.pathname])

  return (
    <div className="min-h-screen bg-background">
      <SkipLink />
      
      {/* Header */}
      <Header 
        onMenuClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        isMobileMenuOpen={isMobileMenuOpen}
      />
      
      <div className="flex pt-16">
        {/* Sidebar Navigation */}
        <Sidebar 
          isOpen={isMobileMenuOpen}
          onClose={() => setIsMobileMenuOpen(false)}
        />
        
        {/* Main Content */}
        <main
          ref={mainRef}
          id="main-content"
          tabIndex={-1}
          role="main"
          aria-label="Main content"
          className="flex-1 min-h-[calc(100vh-4rem)] p-6 lg:p-8 outline-none"
        >
          <Outlet />
        </main>
      </div>
    </div>
  )
}
