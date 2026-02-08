/**
 * Hosted Organization Create Page
 * 
 * Pre-built hosted page for creating new organizations.
 * URL: /hosted/organization/create?tenant_id=xxx&redirect_url=xxx
 */

import { createFileRoute, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Building2, ArrowRight, AlertCircle, ArrowLeft, CheckCircle } from 'lucide-react'
import { Button } from '../../../components/ui/Button'
import { Input } from '../../../components/ui/Input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../../components/ui/Card'
import { Alert, AlertDescription } from '../../../components/ui/Alert'
import { useForm } from '@tanstack/react-form'
import { HostedLayout } from '../../../hosted/HostedLayout'
import { useHostedConfig } from '../../../hosted/useHostedConfig'
import { hostedCreateOrganization } from '../../../hosted/api'

export const Route = createFileRoute('/hosted/organization/create' as any)({
  component: HostedOrganizationCreatePage,
})

function HostedOrganizationCreatePage() {
  return (
    <HostedLayout 
      searchParams={new URLSearchParams(window.location.search)}
    >
      <OrganizationCreateContent />
    </HostedLayout>
  )
}

function OrganizationCreateContent() {
  const { config, tenantId, redirectUrl } = useHostedConfig()
  const prefersReducedMotion = useReducedMotion()
  
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isSuccess, setIsSuccess] = useState(false)
  const [createdOrg, setCreatedOrg] = useState<{ name: string; slug: string } | null>(null)

  // Get session token from storage or cookie
  const getSessionToken = () => {
    // In a real implementation, this would get the token from secure storage
    return sessionStorage.getItem('hosted_session_token') || ''
  }

  const form = useForm({
    defaultValues: {
      name: '',
      slug: '',
    },
    onSubmit: async ({ value }) => {
      if (!tenantId) return
      
      const sessionToken = getSessionToken()
      if (!sessionToken) {
        setError('You must be signed in to create an organization')
        return
      }

      setIsLoading(true)
      setError(null)
      
      try {
        const result = await hostedCreateOrganization({
          data: {
            name: value.name,
            slug: value.slug,
            tenantId,
            sessionToken,
          },
        })

        setCreatedOrg({ name: result.name, slug: result.slug })
        setIsSuccess(true)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to create organization')
      } finally {
        setIsLoading(false)
      }
    },
  })

  // Auto-generate slug from name
  const handleNameChange = (name: string) => {
    form.setFieldValue('name', name)
    
    // Only auto-generate slug if user hasn't manually edited it
    const currentSlug = form.getFieldValue('slug')
    const autoSlug = name
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .slice(0, 50)
    
    if (!currentSlug || currentSlug === form.getFieldValue('name').toLowerCase().replace(/[^a-z0-9\s-]/g, '').replace(/\s+/g, '-').slice(0, 50)) {
      form.setFieldValue('slug', autoSlug)
    }
  }

  if (!config || !tenantId) {
    return null
  }

  const handleContinue = () => {
    const targetUrl = redirectUrl || config.afterSignInUrl || '/dashboard'
    window.location.href = targetUrl
  }

  if (isSuccess && createdOrg) {
    return (
      <Card className="shadow-elevated">
        <CardContent className="pt-6">
          <motion.div
            initial={prefersReducedMotion ? false : { opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="text-center space-y-6 py-8"
          >
            <div className="w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto">
              <CheckCircle className="w-8 h-8 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <h3 className="text-xl font-semibold">Organization created!</h3>
              <p className="text-sm text-muted-foreground mt-2">
                <strong>{createdOrg.name}</strong> has been created successfully.
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                Organization slug: {createdOrg.slug}
              </p>
            </div>
            <Button onClick={handleContinue} fullWidth rightIcon={<ArrowRight className="h-4 w-4" />}>
              Continue
            </Button>
          </motion.div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="shadow-elevated">
      <CardHeader className="space-y-1">
        <div className="mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-2">
          <Building2 className="h-6 w-6 text-primary" />
        </div>
        <CardTitle className="text-2xl text-center">Create Organization</CardTitle>
        <CardDescription className="text-center">
          Set up a new organization for your team
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

        <form
          onSubmit={(e) => {
            e.preventDefault()
            e.stopPropagation()
            void form.handleSubmit()
          }}
          className="space-y-4"
        >
          <form.Field
            name="name"
            validators={{
              onChange: ({ value }: { value: string }) => {
                if (!value.trim()) return 'Organization name is required'
                if (value.trim().length < 2) return 'Name must be at least 2 characters'
                if (value.trim().length > 50) return 'Name must be less than 50 characters'
                return undefined
              },
            }}
          >
            {(field: any) => (
              <Input
                label="Organization Name"
                type="text"
                placeholder="Acme Inc."
                value={field.state.value}
                onChange={(e) => handleNameChange(e.target.value)}
                onBlur={field.handleBlur}
                error={field.state.meta.isTouched ? field.state.meta.errors[0] : undefined}
                leftIcon={<Building2 className="h-4 w-4 text-muted-foreground" />}
                autoComplete="organization"
                required
                disabled={isLoading}
              />
            )}
          </form.Field>

          <form.Field
            name="slug"
            validators={{
              onChange: ({ value }: { value: string }) => {
                if (!value.trim()) return 'Organization slug is required'
                if (!/^[a-z0-9-]+$/.test(value)) {
                  return 'Slug can only contain lowercase letters, numbers, and hyphens'
                }
                if (value.length < 2) return 'Slug must be at least 2 characters'
                if (value.length > 50) return 'Slug must be less than 50 characters'
                return undefined
              },
            }}
          >
            {(field: any) => (
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-foreground">
                  Organization Slug
                  <span className="text-destructive ml-1">*</span>
                </label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-sm">
                    /
                  </span>
                  <input
                    type="text"
                    value={field.state.value}
                    onChange={(e) => field.handleChange(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))}
                    onBlur={field.handleBlur}
                    placeholder="acme-inc"
                    className={`flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 pl-6 text-sm ring-offset-background transition-colors transition-shadow duration-200 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 hover:border-muted-foreground/30 ${
                      field.state.meta.isTouched && field.state.meta.errors[0] 
                        ? 'border-destructive focus-visible:ring-destructive' 
                        : ''
                    }`}
                    required
                    disabled={isLoading}
                  />
                </div>
                {field.state.meta.isTouched && field.state.meta.errors[0] && (
                  <p className="text-sm text-destructive animate-fade-in">
                    {field.state.meta.errors[0]}
                  </p>
                )}
                <p className="text-xs text-muted-foreground">
                  This will be used in URLs and cannot be changed later
                </p>
              </div>
            )}
          </form.Field>

          <Button
            type="submit"
            fullWidth
            size="lg"
            isLoading={isLoading}
            rightIcon={<ArrowRight className="h-4 w-4" />}
          >
            Create Organization
          </Button>
        </form>

        {/* Back Link */}
        <div className="text-center pt-4 border-t">
          <Link
            to={'/hosted/organization/switch' as any}
            search={{ tenant_id: tenantId, redirect_url: redirectUrl || undefined } as any}
            className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Organizations
          </Link>
        </div>
      </CardContent>
    </Card>
  )
}
