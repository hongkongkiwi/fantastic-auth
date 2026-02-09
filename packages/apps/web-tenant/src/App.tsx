import { Suspense, lazy } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from './services/api'
import { Layout } from './components/layout/Layout'
import { RequireAuth } from './components/auth/RequireAuth'
import { ErrorBoundary } from './components/ErrorBoundary'
import { LoadingScreen } from './components/LoadingScreen'

// Lazy load pages for better performance
const Dashboard = lazy(() =>
  import('./pages/Dashboard').then((m) => ({ default: m.Dashboard })),
)
const Users = lazy(() => import('./pages/Users').then((m) => ({ default: m.Users })))
const UserDetail = lazy(() =>
  import('./pages/UserDetail').then((m) => ({ default: m.UserDetail })),
)
const Organizations = lazy(() =>
  import('./pages/Organizations').then((m) => ({ default: m.Organizations })),
)
const OrgDetail = lazy(() =>
  import('./pages/OrgDetail').then((m) => ({ default: m.OrgDetail })),
)
const Security = lazy(() =>
  import('./pages/Security').then((m) => ({ default: m.Security })),
)
const SecurityDashboard = lazy(() =>
  import('./pages/SecurityDashboard').then((m) => ({
    default: m.SecurityDashboard,
  })),
)
const AuditLogs = lazy(() =>
  import('./pages/AuditLogs').then((m) => ({ default: m.AuditLogs })),
)
const Settings = lazy(() =>
  import('./pages/Settings').then((m) => ({ default: m.Settings })),
)
const Analytics = lazy(() =>
  import('./pages/Analytics').then((m) => ({ default: m.Analytics })),
)
const Webhooks = lazy(() =>
  import('./pages/Webhooks').then((m) => ({ default: m.Webhooks })),
)
const OAuthClients = lazy(() =>
  import('./pages/OAuthClients').then((m) => ({ default: m.OAuthClients })),
)
const SAMLConnections = lazy(() =>
  import('./pages/SAMLConnections').then((m) => ({
    default: m.SAMLConnections,
  })),
)
const Login = lazy(() => import('./pages/Login').then((m) => ({ default: m.Login })))
const Mfa = lazy(() => import('./pages/Mfa').then((m) => ({ default: m.Mfa })))
const DeviceManagement = lazy(() =>
  import('./pages/self-service/DeviceManagement').then((m) => ({
    default: m.DeviceManagement,
  })),
)
const DataPrivacy = lazy(() =>
  import('./pages/self-service/DataPrivacy').then((m) => ({
    default: m.DataPrivacy,
  })),
)

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <Routes>
            {/* Public routes */}
            <Route
              path="/login"
              element={
                <Suspense fallback={<LoadingScreen />}>
                  <Login />
                </Suspense>
              }
            />
            <Route
              path="/mfa"
              element={
                <Suspense fallback={<LoadingScreen />}>
                  <Mfa />
                </Suspense>
              }
            />

            {/* Protected routes */}
            <Route
              element={
                <RequireAuth>
                  <Layout />
                </RequireAuth>
              }
            >
              <Route
                path="/"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <Dashboard />
                  </Suspense>
                }
              />
              <Route
                path="/users"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <Users />
                  </Suspense>
                }
              />
              <Route
                path="/users/:id"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <UserDetail />
                  </Suspense>
                }
              />
              <Route
                path="/organizations"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <Organizations />
                  </Suspense>
                }
              />
              <Route
                path="/organizations/:id"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <OrgDetail />
                  </Suspense>
                }
              />
              <Route
                path="/security"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <Security />
                  </Suspense>
                }
              />
              <Route
                path="/security-dashboard"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <SecurityDashboard />
                  </Suspense>
                }
              />
              <Route
                path="/audit-logs"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <AuditLogs />
                  </Suspense>
                }
              />
              <Route
                path="/analytics"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <Analytics />
                  </Suspense>
                }
              />
              <Route
                path="/settings"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <Settings />
                  </Suspense>
                }
              />
              <Route
                path="/webhooks"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <Webhooks />
                  </Suspense>
                }
              />
              <Route
                path="/oauth-clients"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <OAuthClients />
                  </Suspense>
                }
              />
              <Route
                path="/saml-connections"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <SAMLConnections />
                  </Suspense>
                }
              />
              <Route
                path="/devices"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <DeviceManagement />
                  </Suspense>
                }
              />
              <Route
                path="/privacy"
                element={
                  <Suspense fallback={<LoadingScreen />}>
                    <DataPrivacy />
                  </Suspense>
                }
              />
            </Route>

            {/* Catch all */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}

export default App
