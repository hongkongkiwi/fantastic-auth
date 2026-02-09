import { HeadContent, Scripts, createRootRoute, Outlet } from '@tanstack/react-router'
import { AuthProvider } from '../hooks/useAuth'
import { ThemeProvider } from '../hooks/useTheme'
import { RealtimeProvider } from '../hooks/useRealtime'
import { PWAProvider, InstallPrompt, OfflineIndicator, UpdateNotification } from '../hooks/usePWA'
import { Layout } from '../components/layout/Layout'
import { Toaster } from '../components/ui/Toaster'
import { ImpersonationBanner } from '../components/auth/ImpersonationBanner'
import { Sentry } from '../lib/sentry'
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
        href: '/icons/icon-192x192.png',
      },
      {
        rel: 'icon',
        type: 'image/png',
        href: '/icons/icon-192x192.png',
      },
    ],
  }),
  component: RootComponent,
})

function RootComponent() {
  return (
    <html lang="en" className="h-full" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body className="h-full">
        <ThemeProvider defaultTheme="system">
          <AuthProvider>
            <RealtimeProvider>
              <PWAProvider>
                <AppContent />
              </PWAProvider>
            </RealtimeProvider>
          </AuthProvider>
        </ThemeProvider>
        <Scripts />
      </body>
    </html>
  )
}

function AppContent() {
  return (
    <Sentry.ErrorBoundary fallback={<div>Something went wrong.</div>}>
      <ImpersonationBanner />
      <OfflineIndicator />
      <Layout>
        <Outlet />
      </Layout>
      <InstallPrompt />
      <UpdateNotification />
      <Toaster position="top-right" richColors closeButton />
    </Sentry.ErrorBoundary>
  )
}
