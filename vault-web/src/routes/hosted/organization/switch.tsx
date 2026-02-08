/**
 * Hosted Organization Switch Page
 * 
 * Pre-built hosted page for switching between organizations.
 * URL: /hosted/organization/switch?tenant_id=xxx&redirect_url=xxx
 */

import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState, useEffect } from 'react'
import { motion, useReducedMotion, AnimatePresence } from 'framer-motion'
import { Building2, ArrowRight, AlertCircle, Plus, Check, Crown, Users } from 'lucide-react'
import { Button } from '../../../components/ui/Button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../../components/ui/Card'
import { Alert, AlertDescription } from '../../../components/ui/Alert'
import { HostedLayout } from '../../../hosted/HostedLayout'
import { useHostedConfig } from '../../../hosted/useHostedConfig'
import { hostedListOrganizations, hostedSwitchOrganization } from '../../../hosted/api'
import type { Organization } from '../../../hosted/types'

export const Route = createFileRoute('/hosted/organization/switch' as any)({
  component: HostedOrganizationSwitchPage,
})

function HostedOrganizationSwitchPage() {
  return (
    <HostedLayout 
      searchParams={new URLSearchParams(window.location.search)}
    >
      <OrganizationSwitchContent />
    </HostedLayout>
  )
}

function OrganizationSwitchContent() {
  const navigate = useNavigate()
  const { config, tenantId, redirectUrl, organizationId } = useHostedConfig()
  const prefersReducedMotion = useReducedMotion()
  
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [switchingOrgId, setSwitchingOrgId] = useState<string | null>(null)

  // Get session token from storage or cookie
  const getSessionToken = () => {
    // In a real implementation, this would get the token from secure storage
    return sessionStorage.getItem('hosted_session_token') || ''
  }

  // Fetch organizations on mount
  useEffect(() => {
    if (!tenantId) return

    const fetchOrganizations = async () => {
      const sessionToken = getSessionToken()
      if (!sessionToken) {
        setError('You must be signed in to view organizations')
        setIsLoading(false)
        return
      }

      try {
        const result = await hostedListOrganizations({
          data: { tenantId, sessionToken },
        })
        setOrganizations(result.organizations)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load organizations')
      } finally {
        setIsLoading(false)
      }
    }

    void fetchOrganizations()
  }, [tenantId])

  if (!config || !tenantId) {
    return null
  }

  const handleSwitch = async (orgId: string) => {
    const sessionToken = getSessionToken()
    if (!sessionToken) {
      setError('Session expired. Please sign in again.')
      return
    }

    setSwitchingOrgId(orgId)
    setError(null)

    try {
      const result = await hostedSwitchOrganization({
        data: {
          organizationId: orgId,
          tenantId,
          sessionToken,
        },
      })

      // Redirect to the specified URL
      window.location.href = redirectUrl || result.redirectUrl
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to switch organization')
      setSwitchingOrgId(null)
    }
  }

  const handleCreateNew = () => {
    navigate({
      to: '/hosted/organization/create' as any,
      search: { tenant_id: tenantId, redirect_url: redirectUrl || undefined } as any,
    })
  }

  return (
    <Card className="shadow-elevated">
      <CardHeader className="space-y-1">
        <div className="mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-2">
          <Building2 className="h-6 w-6 text-primary" />
        </div>
        <CardTitle className="text-2xl text-center">Switch Organization</CardTitle>
        <CardDescription className="text-center">
          Select an organization to continue
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Error Alert */}
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Loading State */}
        {isLoading ? (
          <div className="py-8 text-center">
            <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-sm text-muted-foreground">Loading organizations...</p>
          </div>
        ) : organizations.length === 0 ? (
          /* Empty State */
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-center py-8 space-y-4"
          >
            <div className="w-16 h-16 bg-muted rounded-full flex items-center justify-center mx-auto">
              <Building2 className="h-8 w-8 text-muted-foreground" />
            </div>
            <div>
              <p className="text-muted-foreground">You don&apos;t have any organizations yet.</p>
              <p className="text-sm text-muted-foreground">Create one to get started.</p>
            </div>
            <Button onClick={handleCreateNew} className="gap-2">
              <Plus className="h-4 w-4" />
              Create Organization
            </Button>
          </motion.div>
        ) : (
          /* Organization List */
          <div className="space-y-2">
            <AnimatePresence mode="popLayout">
              {organizations.map((org, index) => (
                <motion.div
                  key={org.id}
                  initial={prefersReducedMotion ? false : { opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  transition={{ delay: prefersReducedMotion ? 0 : index * 0.05 }}
                >
                  <button
                    onClick={() => handleSwitch(org.id)}
                    disabled={switchingOrgId === org.id}
                    className={`w-full flex items-center gap-4 p-4 rounded-lg border transition-all text-left ${
                      organizationId === org.id
                        ? 'border-primary bg-primary/5'
                        : 'border-border hover:border-primary/50 hover:bg-muted/50'
                    }`}
                  >
                    {/* Organization Avatar */}
                    <div className="flex-shrink-0">
                      {org.logoUrl ? (
                        <img
                          src={org.logoUrl}
                          alt={org.name}
                          className="w-12 h-12 rounded-lg object-cover"
                        />
                      ) : (
                        <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                          <Building2 className="h-6 w-6 text-primary" />
                        </div>
                      )}
                    </div>

                    {/* Organization Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <h4 className="font-semibold truncate">{org.name}</h4>
                        {org.role === 'owner' && (
                          <Crown className="h-4 w-4 text-amber-500 flex-shrink-0" />
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">/{org.slug}</p>
                    </div>

                    {/* Status/Action */}
                    <div className="flex-shrink-0">
                      {switchingOrgId === org.id ? (
                        <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                      ) : organizationId === org.id ? (
                        <div className="flex items-center gap-1 text-primary text-sm">
                          <Check className="h-4 w-4" />
                          <span className="hidden sm:inline">Current</span>
                        </div>
                      ) : (
                        <ArrowRight className="h-5 w-5 text-muted-foreground" />
                      )}
                    </div>
                  </button>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}

        {/* Create New Organization */}
        {!isLoading && organizations.length > 0 && (
          <div className="pt-4 border-t">
            <Button
              variant="outline"
              fullWidth
              onClick={handleCreateNew}
              className="gap-2"
            >
              <Plus className="h-4 w-4" />
              Create New Organization
            </Button>
          </div>
        )}

        {/* Personal Account Option */}
        {!isLoading && organizations.length > 0 && (
          <div className="text-center">
            <button
              onClick={() => handleSwitch('personal')}
              disabled={switchingOrgId === 'personal'}
              className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <Users className="h-4 w-4" />
              Continue with personal account
              {switchingOrgId === 'personal' && (
                <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
              )}
            </button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
