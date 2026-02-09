import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import { Layout } from '@/components/layout/Layout'
import { Dashboard } from '@/pages/Dashboard'
import { Users } from '@/pages/Users'
import { UserDetail } from '@/pages/UserDetail'
import { Organizations } from '@/pages/Organizations'
import { OrgDetail } from '@/pages/OrgDetail'
import { Settings } from '@/pages/Settings'
import { Security } from '@/pages/Security'
import { Webhooks } from '@/pages/Webhooks'
import { OAuthClients } from '@/pages/OAuthClients'
import { SAMLConnections } from '@/pages/SAMLConnections'
import { AuditLogs } from '@/pages/AuditLogs'
import { Analytics } from '@/pages/Analytics'

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="users" element={<Users />} />
            <Route path="users/:id" element={<UserDetail />} />
            <Route path="users/new" element={<Users />} />
            <Route path="organizations" element={<Organizations />} />
            <Route path="organizations/:id" element={<OrgDetail />} />
            <Route path="organizations/:id/edit" element={<OrgDetail />} />
            <Route path="organizations/new" element={<Organizations />} />
            <Route path="settings" element={<Settings />} />
            <Route path="security" element={<Security />} />
            <Route path="webhooks" element={<Webhooks />} />
            <Route path="webhooks/new" element={<Webhooks />} />
            <Route path="webhooks/:id/edit" element={<Webhooks />} />
            <Route path="oauth-clients" element={<OAuthClients />} />
            <Route path="oauth-clients/new" element={<OAuthClients />} />
            <Route path="oauth-clients/:id/edit" element={<OAuthClients />} />
            <Route path="saml-connections" element={<SAMLConnections />} />
            <Route path="saml-connections/new" element={<SAMLConnections />} />
            <Route path="saml-connections/:id/edit" element={<SAMLConnections />} />
            <Route path="audit-logs" element={<AuditLogs />} />
            <Route path="analytics" element={<Analytics />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
