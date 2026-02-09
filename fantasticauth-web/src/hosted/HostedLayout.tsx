/**
 * Hosted UI Layout Component
 * 
 * Shared layout for all hosted authentication pages with theming support.
 */

import { useEffect, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Shield, AlertCircle, Loader2 } from 'lucide-react'
import { HostedConfigProvider, useHostedConfig } from './useHostedConfig'
import type { HostedUIConfig } from './types'
import { Alert, AlertTitle, AlertDescription } from '../components/ui/Alert'
import appCss from '../styles.css?url'

interface HostedLayoutProps {
  children: React.ReactNode
  searchParams: URLSearchParams
  title?: string
  description?: string
}

export function HostedLayout({ children, searchParams, title, description }: HostedLayoutProps) {
  return (
    <HostedConfigProvider searchParams={searchParams}>
      <HostedLayoutInner title={title} description={description}>
        {children}
      </HostedLayoutInner>
    </HostedConfigProvider>
  )
}

interface HostedLayoutInnerProps {
  children: React.ReactNode
  title?: string
  description?: string
}

function HostedLayoutInner({ children, title, description }: HostedLayoutInnerProps) {
  const { config, isLoading, error, tenantId } = useHostedConfig()
  const prefersReducedMotion = useReducedMotion()
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  // Loading state
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted p-4">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-muted-foreground text-sm">Loading...</p>
        </div>
      </div>
    )
  }

  // Error state
  if (error || !tenantId) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted p-4">
        <div className="w-full max-w-md">
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Configuration Error</AlertTitle>
            <AlertDescription>
              {error || 'Missing tenant_id parameter. Please check your URL and try again.'}
            </AlertDescription>
          </Alert>
        </div>
      </div>
    )
  }

  const companyName = config?.companyName || 'Vault'
  const pageTitle = title || config?.signInTitle || `Sign in to ${companyName}`
  const pageDescription = description || 'Secure authentication powered by Vault'

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-background via-background to-muted">
      {/* Background decoration */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div 
          className="absolute -top-1/2 -right-1/2 w-full h-full rounded-full blur-3xl opacity-30"
          style={{ 
            backgroundColor: config?.primaryColor ? `${config.primaryColor}20` : 'hsl(var(--primary) / 0.05)' 
          }}
        />
        <div 
          className="absolute -bottom-1/2 -left-1/2 w-full h-full rounded-full blur-3xl opacity-30"
          style={{ 
            backgroundColor: config?.primaryColor ? `${config.primaryColor}10` : 'hsl(var(--secondary) / 0.05)' 
          }}
        />
      </div>

      {/* Header */}
      <header className="relative z-10 w-full p-4 sm:p-6">
        <div className="max-w-md mx-auto flex items-center justify-center">
          <HostedLogo />
        </div>
      </header>

      {/* Main content */}
      <main className="relative z-10 flex-1 flex items-center justify-center p-4 sm:p-6">
        <motion.div
          initial={prefersReducedMotion ? false : { opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={prefersReducedMotion ? { duration: 0 } : { duration: 0.5 }}
          className="w-full max-w-md"
        >
          {mounted && (
            <>
              {/* Page title */}
              {(title || description) && (
                <div className="text-center mb-6">
                  <h1 className="text-2xl font-bold">{pageTitle}</h1>
                  {pageDescription && (
                    <p className="text-muted-foreground mt-1">{pageDescription}</p>
                  )}
                </div>
              )}
              
              {children}
            </>
          )}
        </motion.div>
      </main>

      {/* Footer */}
      <footer className="relative z-10 w-full p-4 sm:p-6">
        <div className="max-w-md mx-auto text-center">
          <p className="text-xs text-muted-foreground">
            Secured by{' '}
            <a 
              href="https://vault.dev" 
              target="_blank" 
              rel="noopener noreferrer"
              className="hover:text-foreground transition-colors"
            >
              Vault
            </a>
          </p>
          {(config?.termsUrl || config?.privacyUrl) && (
            <div className="flex items-center justify-center gap-4 mt-2">
              {config.termsUrl && (
                <a 
                  href={config.termsUrl}
                  className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  Terms
                </a>
              )}
              {config.privacyUrl && (
                <a 
                  href={config.privacyUrl}
                  className="text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  Privacy
                </a>
              )}
            </div>
          )}
        </div>
      </footer>
    </div>
  )
}

/**
 * Hosted Logo Component
 * 
 * Displays tenant logo or default Vault logo
 */
function HostedLogo() {
  const { config } = useHostedConfig()
  const prefersReducedMotion = useReducedMotion()

  if (config?.logoUrl) {
    return (
      <motion.div
        initial={prefersReducedMotion ? false : { scale: 0.8 }}
        animate={{ scale: 1 }}
        transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.2, type: 'spring' }}
        className="flex items-center gap-3"
      >
        <img 
          src={config.logoUrl} 
          alt={config.companyName}
          className="h-12 w-auto object-contain"
        />
        <span className="text-xl font-semibold">{config.companyName}</span>
      </motion.div>
    )
  }

  return (
    <motion.div
      initial={prefersReducedMotion ? false : { scale: 0.8 }}
      animate={{ scale: 1 }}
      transition={prefersReducedMotion ? { duration: 0 } : { delay: 0.2, type: 'spring' }}
      className="flex items-center gap-3"
    >
      <div 
        className="h-12 w-12 rounded-xl flex items-center justify-center shadow-lg"
        style={{ backgroundColor: config?.primaryColor || 'hsl(var(--primary))' }}
      >
        <Shield className="h-7 w-7 text-white" />
      </div>
      <span className="text-xl font-semibold">{config?.companyName || 'Vault'}</span>
    </motion.div>
  )
}

/**
 * Get head content for hosted pages
 */
export function getHostedHeadContent(config?: HostedUIConfig | null) {
  return {
    meta: [
      { charSet: 'utf-8' },
      { 
        name: 'viewport', 
        content: 'width=device-width, initial-scale=1, maximum-scale=5, viewport-fit=cover' 
      },
      { 
        name: 'description', 
        content: config?.signInTitle || `Sign in to ${config?.companyName || 'Vault'}` 
      },
      { 
        name: 'theme-color', 
        content: config?.primaryColor || '#4f46e5' 
      },
    ],
    links: [
      { rel: 'stylesheet', href: appCss },
      ...(config?.faviconUrl 
        ? [{ rel: 'icon', type: 'image/png', href: config.faviconUrl }]
        : []
      ),
    ],
  }
}
