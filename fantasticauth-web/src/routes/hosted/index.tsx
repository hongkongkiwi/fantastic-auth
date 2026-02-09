/**
 * Hosted UI Index Page
 * 
 * Redirects to sign-in page with tenant_id parameter.
 * URL: /hosted?tenant_id=xxx
 */

import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useEffect } from 'react'
import { Loader2 } from 'lucide-react'

export const Route = createFileRoute('/hosted/' as any)({
  component: HostedIndexPage,
})

function HostedIndexPage() {
  const navigate = useNavigate()
  
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const tenantId = params.get('tenant_id')
    const redirectUrl = params.get('redirect_url')
    const organizationId = params.get('organization_id')
    
    // Redirect to sign-in with all params preserved
    navigate({
      to: '/hosted/sign-in' as any,
      search: {
        tenant_id: tenantId || '',
        redirect_url: redirectUrl || undefined,
        organization_id: organizationId || undefined,
      } as any,
    })
  }, [navigate])

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted p-4">
      <div className="flex flex-col items-center gap-4">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-muted-foreground text-sm">Redirecting...</p>
      </div>
    </div>
  )
}
