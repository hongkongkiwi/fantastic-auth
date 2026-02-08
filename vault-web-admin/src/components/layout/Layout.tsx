import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { cn } from '@/lib/utils'
import { useUIStore } from '@/store'
import { Toaster } from 'react-hot-toast'

export function Layout() {
  const { sidebarCollapsed } = useUIStore()

  return (
    <div className="min-h-screen bg-background">
      <Sidebar />
      <Header />
      
      <main 
        className={cn(
          "pt-16 transition-all duration-300 min-h-screen",
          sidebarCollapsed ? "pl-16" : "pl-64"
        )}
      >
        <div className="p-6">
          <Outlet />
        </div>
      </main>

      <Toaster 
        position="top-right"
        toastOptions={{
          duration: 5000,
          style: {
            background: 'hsl(var(--card))',
            color: 'hsl(var(--card-foreground))',
            border: '1px solid hsl(var(--border))',
          },
          success: {
            iconTheme: {
              primary: 'hsl(var(--status-active))',
              secondary: 'hsl(var(--card))',
            },
          },
          error: {
            iconTheme: {
              primary: 'hsl(var(--status-error))',
              secondary: 'hsl(var(--card))',
            },
          },
        }}
      />
    </div>
  )
}
