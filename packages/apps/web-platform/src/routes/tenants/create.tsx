import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import {
  ArrowLeft,
  Check,
} from 'lucide-react'
import { PageHeader } from '../../components/layout/Layout'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { Input } from '../../components/ui/Input'
import { Badge } from '../../components/ui/Badge'
import { useServerFn } from '@tanstack/react-start'
import { createTenant } from '../../server/internal-api'
import { toast } from '../../components/ui/Toaster'
import { cn } from '../../lib/utils'

export const Route = createFileRoute('/tenants/create')({
  component: CreateTenantPage,
})

const plans = [
  { value: 'free', label: 'Free' },
  { value: 'starter', label: 'Starter' },
  { value: 'pro', label: 'Pro' },
  { value: 'enterprise', label: 'Enterprise' },
]

function CreateTenantPage() {
  const navigate = useNavigate()
  const createTenantFn = useServerFn(createTenant)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [step, setStep] = useState(1)
  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    plan: 'starter',
    ownerEmail: '',
    ownerName: '',
    customDomain: '',
  })
  const [errors, setErrors] = useState<Record<string, string>>({})
  const prefersReducedMotion = useReducedMotion()

  const validateStep = (currentStep: number): boolean => {
    const newErrors: Record<string, string> = {}

    if (currentStep === 1) {
      if (!formData.name.trim()) {
        newErrors.name = 'Tenant name is required'
      }
      if (!formData.slug.trim()) {
        newErrors.slug = 'Slug is required'
      } else if (!/^[a-z0-9-]+$/.test(formData.slug)) {
        newErrors.slug = 'Slug can only contain lowercase letters, numbers, and hyphens'
      }
    }

    if (currentStep === 2) {
      if (formData.ownerEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.ownerEmail)) {
        newErrors.ownerEmail = 'Please enter a valid email'
      }
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleNext = () => {
    if (validateStep(step)) {
      setStep(step + 1)
    }
  }

  const handleBack = () => {
    setStep(step - 1)
  }

  const handleSubmit = async () => {
    if (!validateStep(step)) return

    setIsSubmitting(true)
    try {
      await createTenantFn({
        data: {
          name: formData.name,
          slug: formData.slug,
          plan: formData.plan as 'free' | 'starter' | 'pro' | 'enterprise',
          ownerEmail: formData.ownerEmail || undefined,
          ownerName: formData.ownerName || undefined,
          customDomain: formData.customDomain || undefined,
        },
      })
      toast.success('Tenant created successfully')
      navigate({ to: '/tenants' })
    } catch (error) {
      toast.error('Failed to create tenant')
    } finally {
      setIsSubmitting(false)
    }
  }

  const steps = [
    { number: 1, title: 'Basic Info', description: 'Tenant name and slug' },
    { number: 2, title: 'Plan', description: 'Select subscription tier' },
    { number: 3, title: 'Owner', description: 'Set up owner details' },
  ]

  return (
    <div className="space-y-6 max-w-3xl">
      <PageHeader
        title="Create Tenant"
        description="Set up a new tenant on your platform"
        breadcrumbs={[
          { label: 'Tenants', href: '/tenants' },
          { label: 'Create' },
        ]}
        actions={
          <Button variant="outline" asChild>
            <Link to="/tenants">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Tenants
            </Link>
          </Button>
        }
      />

      {/* Progress Steps */}
      <Card className="p-6">
        <div className="flex items-center justify-between">
          {steps.map((s, index) => (
            <div key={s.number} className="flex items-center">
              <div className="flex flex-col items-center">
                <div
                  className={cn(
                    'w-10 h-10 rounded-full flex items-center justify-center font-semibold transition-colors',
                    step > s.number && 'bg-green-500 text-white',
                    step === s.number && 'bg-primary text-primary-foreground',
                    step < s.number && 'bg-muted text-muted-foreground'
                  )}
                >
                  {step > s.number ? <Check className="h-5 w-5" /> : s.number}
                </div>
                <div className="mt-2 text-center hidden sm:block">
                  <p className={cn('text-sm font-medium', step >= s.number ? 'text-foreground' : 'text-muted-foreground')}>
                    {s.title}
                  </p>
                  <p className="text-xs text-muted-foreground">{s.description}</p>
                </div>
              </div>
              {index < steps.length - 1 && (
                <div
                  className={cn(
                    'w-24 h-0.5 mx-4 hidden sm:block',
                    step > s.number ? 'bg-green-500' : 'bg-muted'
                  )}
                />
              )}
            </div>
          ))}
        </div>
      </Card>

      {/* Form */}
      <motion.div
        key={step}
        initial={prefersReducedMotion ? false : { opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        exit={{ opacity: 0, x: -20 }}
        transition={prefersReducedMotion ? { duration: 0 } : { duration: 0.2 }}
      >
        <Card>
          <CardHeader>
            <CardTitle>{steps[step - 1].title}</CardTitle>
            <CardDescription>{steps[step - 1].description}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {step === 1 && (
              <div className="space-y-4">
                <Input
                  label="Tenant Name"
                  placeholder="Acme Corporation"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  error={errors.name}
                  name="tenantName"
                  autoComplete="off"
                  required
                />
                <Input
                  label="Slug"
                  placeholder="acme-corp"
                  value={formData.slug}
                  onChange={(e) => setFormData({ ...formData, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') })}
                  error={errors.slug}
                  helperText="Used in URLs and API calls. Lowercase letters, numbers, and hyphens only."
                  name="tenantSlug"
                  autoComplete="off"
                  required
                />
                <Input
                  label="Custom Domain (Optional)"
                  type="url"
                  placeholder="auth.acme.com"
                  value={formData.customDomain}
                  onChange={(e) => setFormData({ ...formData, customDomain: e.target.value })}
                  name="customDomain"
                  autoComplete="off"
                />
              </div>
            )}

            {step === 2 && (
              <div className="space-y-4">
                <label className="text-sm font-medium">Select Plan</label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {plans.map((plan) => (
                    <button type="button"
                      key={plan.value}
                      onClick={() => setFormData({ ...formData, plan: plan.value })}
                      className={cn(
                        'p-4 rounded-lg border-2 text-left transition-colors transition-shadow focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary',
                        formData.plan === plan.value
                          ? 'border-primary bg-primary/5'
                          : 'border-muted hover:border-muted-foreground/30'
                      )}
                      aria-pressed={formData.plan === plan.value}
                    >
                      <div className="flex items-center justify-between">
                        <Badge variant={plan.value === 'enterprise' ? 'warning' : plan.value === 'pro' ? 'success' : 'default'}>
                          {plan.label}
                        </Badge>
                        {formData.plan === plan.value && (
                          <div className="h-5 w-5 rounded-full bg-primary flex items-center justify-center">
                            <Check className="h-3 w-3 text-primary-foreground" />
                          </div>
                        )}
                      </div>
                      <p className="mt-2 text-sm text-muted-foreground">
                        {plan.value === 'free' && 'Up to 100 users, basic features'}
                        {plan.value === 'starter' && 'Up to 1,000 users, advanced features'}
                        {plan.value === 'pro' && 'Up to 10,000 users, priority support'}
                        {plan.value === 'enterprise' && 'Unlimited users, dedicated support'}
                      </p>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {step === 3 && (
              <div className="space-y-4">
                <Input
                  label="Owner Name (Optional)"
                  placeholder="John Doe"
                  value={formData.ownerName}
                  onChange={(e) => setFormData({ ...formData, ownerName: e.target.value })}
                  name="ownerName"
                  autoComplete="off"
                />
                <Input
                  label="Owner Email (Optional)"
                  type="email"
                  placeholder="john@example.com"
                  value={formData.ownerEmail}
                  onChange={(e) => setFormData({ ...formData, ownerEmail: e.target.value })}
                  error={errors.ownerEmail}
                  name="ownerEmail"
                  autoComplete="email"
                  inputMode="email"
                  spellCheck={false}
                />

                {/* Summary */}
                <div className="mt-6 p-4 bg-muted rounded-lg">
                  <h4 className="font-medium mb-3">Summary</h4>
                  <dl className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <dt className="text-muted-foreground">Tenant Name</dt>
                      <dd className="font-medium">{formData.name}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-muted-foreground">Slug</dt>
                      <dd className="font-medium">{formData.slug}</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-muted-foreground">Plan</dt>
                      <dd>
                        <Badge variant={formData.plan === 'enterprise' ? 'warning' : formData.plan === 'pro' ? 'success' : 'default'}>
                          {formData.plan.charAt(0).toUpperCase() + formData.plan.slice(1)}
                        </Badge>
                      </dd>
                    </div>
                    {formData.ownerName && (
                      <div className="flex justify-between">
                        <dt className="text-muted-foreground">Owner</dt>
                        <dd className="font-medium">{formData.ownerName}</dd>
                      </div>
                    )}
                  </dl>
                </div>
              </div>
            )}

            {/* Navigation Buttons */}
            <div className="flex justify-between pt-4">
              {step === 1 ? (
                <Button variant="outline" asChild>
                  <Link to="/tenants">Cancel</Link>
                </Button>
              ) : (
                <Button variant="outline" onClick={handleBack}>
                  Back
                </Button>
              )}
              <Button
                onClick={step === 3 ? handleSubmit : handleNext}
                isLoading={isSubmitting}
              >
                {step === 3 ? 'Create Tenant' : 'Continue'}
              </Button>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  )
}
