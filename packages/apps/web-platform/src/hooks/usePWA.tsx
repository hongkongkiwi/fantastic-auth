import * as React from 'react'
import { toast } from '../components/ui/Toaster'

interface PWAContextValue {
  isInstalled: boolean
  canInstall: boolean
  install: () => Promise<void>
  isOnline: boolean
  updateAvailable: boolean
  applyUpdate: () => void
}

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>
}

const PWAContext = React.createContext<PWAContextValue | null>(null)

export function PWAProvider({ children }: { children: React.ReactNode }) {
  const [isInstalled, setIsInstalled] = React.useState(false)
  const [canInstall, setCanInstall] = React.useState(false)
  const [deferredPrompt, setDeferredPrompt] = React.useState<BeforeInstallPromptEvent | null>(null)
  const [isOnline, setIsOnline] = React.useState(navigator.onLine)
  const [updateAvailable, setUpdateAvailable] = React.useState(false)
  const [waitingWorker, setWaitingWorker] = React.useState<ServiceWorker | null>(null)

  // Check if already installed
  React.useEffect(() => {
    if (window.matchMedia('(display-mode: standalone)').matches) {
      setIsInstalled(true)
    }
  }, [])

  // Listen for install prompt
  React.useEffect(() => {
    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault()
      setDeferredPrompt(e as BeforeInstallPromptEvent)
      setCanInstall(true)
    }

    const handleAppInstalled = () => {
      setIsInstalled(true)
      setCanInstall(false)
      setDeferredPrompt(null)
      toast.success('Vault Admin installed successfully!')
    }

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt)
    window.addEventListener('appinstalled', handleAppInstalled)

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt)
      window.removeEventListener('appinstalled', handleAppInstalled)
    }
  }, [])

  // Online/offline detection
  React.useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true)
      toast.success('You are back online')
    }

    const handleOffline = () => {
      setIsOnline(false)
      toast.info('You are offline. Some features may be limited.')
    }

    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)

    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
    }
  }, [])

  // Service Worker registration and updates
  React.useEffect(() => {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.ready.then((registration) => {
        // Check for waiting worker
        if (registration.waiting) {
          setUpdateAvailable(true)
          setWaitingWorker(registration.waiting)
        }

        // Listen for new updates
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing
          
          if (newWorker) {
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                setUpdateAvailable(true)
                setWaitingWorker(newWorker)
                toast.info('Update available! Refresh to apply.')
              }
            })
          }
        })
      })

      // Listen for messages from SW
      navigator.serviceWorker.addEventListener('message', (event) => {
        if (event.data?.type === 'UPDATE_AVAILABLE') {
          setUpdateAvailable(true)
          toast.info('A new version is available!')
        }
      })
    }
  }, [])

  const install = async () => {
    if (!deferredPrompt) return

    deferredPrompt.prompt()
    const { outcome } = await deferredPrompt.userChoice

    if (outcome === 'accepted') {
      setDeferredPrompt(null)
      setCanInstall(false)
    }
  }

  const applyUpdate = () => {
    if (waitingWorker) {
      waitingWorker.postMessage({ type: 'SKIP_WAITING' })
      window.location.reload()
    }
  }

  const value: PWAContextValue = {
    isInstalled,
    canInstall,
    install,
    isOnline,
    updateAvailable,
    applyUpdate,
  }

  return <PWAContext.Provider value={value}>{children}</PWAContext.Provider>
}

export function usePWA() {
  const context = React.useContext(PWAContext)
  if (!context) {
    throw new Error('usePWA must be used within a PWAProvider')
  }
  return context
}

// Install Prompt Component
export function InstallPrompt() {
  const { canInstall, install, isInstalled } = usePWA()
  const [isVisible, setIsVisible] = React.useState(false)

  React.useEffect(() => {
    if (canInstall && !isInstalled) {
      // Show after a delay
      const timer = setTimeout(() => setIsVisible(true), 3000)
      return () => clearTimeout(timer)
    }
  }, [canInstall, isInstalled])

  const handleDismiss = () => {
    setIsVisible(false)
    localStorage.setItem('install-prompt-dismissed', Date.now().toString())
  }

  if (!isVisible) return null

  return (
    <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 animate-slide-up">
      <div className="bg-background border rounded-lg shadow-lg p-4 flex items-center gap-4 max-w-sm">
        <div className="p-2 bg-primary/10 rounded-lg">
          <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
          </svg>
        </div>
        <div className="flex-1">
          <p className="font-medium">Install Vault Admin</p>
          <p className="text-sm text-muted-foreground">Add to home screen for quick access</p>
        </div>
        <button type="button"
          onClick={install}
          className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90"
        >
          Install
        </button>
        <button type="button"
          onClick={handleDismiss}
          className="p-1 text-muted-foreground hover:text-foreground"
          aria-label="Dismiss"
        >
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
    </div>
  )
}

// Offline Indicator
export function OfflineIndicator() {
  const { isOnline } = usePWA()

  if (isOnline) return null

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-amber-500 text-white text-center py-1 text-sm">
      You are offline. Some features may be limited.
    </div>
  )
}

// Update Notification
export function UpdateNotification() {
  const { updateAvailable, applyUpdate } = usePWA()

  if (!updateAvailable) return null

  return (
    <div className="fixed bottom-4 right-4 z-50 animate-slide-up">
      <div className="bg-background border rounded-lg shadow-lg p-4 flex items-center gap-4">
        <div className="p-2 bg-blue-100 rounded-lg">
          <svg className="h-5 w-5 text-blue-600" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </div>
        <div>
          <p className="font-medium">Update Available</p>
          <p className="text-sm text-muted-foreground">Refresh to get the latest version</p>
        </div>
        <button type="button"
          onClick={applyUpdate}
          className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90"
        >
          Update
        </button>
      </div>
    </div>
  )
}

// Register service worker
export function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker
        .register('/sw.js')
        .then((registration) => {
          console.log('SW registered:', registration)
        })
        .catch((error) => {
          console.log('SW registration failed:', error)
        })
    })
  }
}
