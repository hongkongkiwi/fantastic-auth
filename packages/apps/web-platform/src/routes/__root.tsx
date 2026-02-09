import {
  HeadContent,
  Scripts,
  createRootRoute,
  Outlet,
  useRouterState,
} from '@tanstack/react-router'
import { useEffect, useRef } from 'react'
import { AuthProvider } from '../hooks/useAuth'
import { ThemeProvider } from '../hooks/useTheme'
import { RealtimeProvider } from '../hooks/useRealtime'
import { PWAProvider, InstallPrompt, OfflineIndicator, UpdateNotification } from '../hooks/usePWA'
import { Layout } from '../components/layout/Layout'
import { SkipLinks } from '../components/SkipLinks'
import { Toaster } from '../components/ui/Toaster'
import { ImpersonationBanner } from '../components/auth/ImpersonationBanner'
import { Sentry } from '../lib/sentry'
import { env } from '../env/client'
import appCss from '../styles.css?url'

export const Route = createRootRoute({
  head: () => ({
    meta: [
      {
        charSet: 'utf-8',
      },
      {
        name: 'viewport',
        content: 'width=device-width, initial-scale=1, maximum-scale=5, viewport-fit=cover',
      },
      {
        name: 'description',
        content: 'Internal admin console for Vault multi-tenant platform',
      },
      {
        name: 'theme-color',
        content: '#4f46e5',
      },
      // Security meta tags
      {
        'http-equiv': 'Content-Security-Policy',
        content: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self';",
      },
      {
        'http-equiv': 'X-Content-Type-Options',
        content: 'nosniff',
      },
      {
        'http-equiv': 'Referrer-Policy',
        content: 'strict-origin-when-cross-origin',
      },
      // PWA meta tags
      {
        name: 'apple-mobile-web-app-capable',
        content: 'yes',
      },
      {
        name: 'apple-mobile-web-app-status-bar-style',
        content: 'default',
      },
      {
        name: 'apple-mobile-web-app-title',
        content: 'Vault Admin',
      },
      {
        name: 'format-detection',
        content: 'telephone=no',
      },
      {
        name: 'mobile-web-app-capable',
        content: 'yes',
      },
    ],
    links: [
      {
        rel: 'stylesheet',
        href: appCss,
      },
      // PWA links
      {
        rel: 'manifest',
        href: '/manifest.json',
      },
      {
        rel: 'apple-touch-icon',
        href: '/logo192.png',
      },
      {
        rel: 'icon',
        type: 'image/png',
        href: '/logo192.png',
      },
    ],
  }),
  component: RootComponent,
})

function RootComponent() {
  const { pathname } = useRouterState({ select: (state) => state.location })
  const isHostedRoute = pathname.startsWith('/hosted')

  return (
    <html lang="en" className="h-full" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body className="h-full">
        <ThemeProvider defaultTheme="system">
          {isHostedRoute ? (
            <AppContent withAdminShell={false} />
          ) : (
            <AuthProvider>
              <RealtimeProvider>
                <PWAProvider>
                  <AppContent withAdminShell />
                </PWAProvider>
              </RealtimeProvider>
            </AuthProvider>
          )}
        </ThemeProvider>
        <Scripts />
      </body>
    </html>
  )
}

function AppContent({ withAdminShell }: { withAdminShell: boolean }) {
  const { pathname } = useRouterState({ select: (state) => state.location })
  const supportImpersonationEnabled =
    env.VITE_ENABLE_SUPPORT_IMPERSONATION === 'true'
  const useShell = withAdminShell && pathname !== '/login' && !pathname.startsWith('/hosted')
  const mainRef = useRef<HTMLDivElement>(null)

  // Reset focus on route change for accessibility
  useEffect(() => {
    if (mainRef.current) {
      mainRef.current.focus()
      mainRef.current.scrollIntoView({ behavior: 'auto', block: 'start' })
    }
  }, [pathname])

  return (
    <Sentry.ErrorBoundary fallback={<div>Something went wrong.</div>}>
      {useShell && <SkipLinks />}
      {supportImpersonationEnabled && useShell ? <ImpersonationBanner /> : null}
      {useShell ? <OfflineIndicator /> : null}
      <div
        ref={mainRef}
        id="main-content"
        tabIndex={-1}
        role="main"
        aria-label="Main content"
      >
        {useShell ? (
          <Layout>
            <Outlet />
          </Layout>
        ) : (
          <Outlet />
        )}
      </div>
      {useShell ? <InstallPrompt /> : null}
      {useShell ? <UpdateNotification /> : null}
      <Toaster position="top-right" richColors closeButton />
    </Sentry.ErrorBoundary>
  )
}
