import { createFileRoute } from '@tanstack/react-router'
import { Suspense, lazy, useState } from 'react'
import { 
  Shield, 
  Key, 
  Smartphone, 
  Mail, 
  Trash2,
  CheckCircle,
  AlertCircle
} from 'lucide-react'
import { motion } from 'framer-motion'
import { PageHeader } from '../../components/layout/Layout'
import { Card } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/Tabs'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '../../components/ui/Dialog'
import { Skeleton } from '../../components/ui/Skeleton'
import { Input } from '../../components/ui/Input'
import { useForm } from '@tanstack/react-form'

export const Route = createFileRoute('/settings/security')({
  component: SecuritySettingsPage,
})

const MfaEnroll = lazy(() =>
  import('../../components/auth/MfaEnroll').then((mod) => ({
    default: mod.MfaEnroll,
  }))
)
const SessionManager = lazy(() =>
  import('../../components/auth/SessionManager').then((mod) => ({
    default: mod.SessionManager,
  }))
)

interface MfaMethod {
  type: 'totp' | 'email' | 'sms' | 'webauthn'
  name: string
  enabled: boolean
  created_at: string
}

function SecuritySettingsPage() {
  const [activeTab, setActiveTab] = useState('mfa')
  const [isEnrollOpen, setIsEnrollOpen] = useState(false)
  const [enrollMethod, setEnrollMethod] = useState<'totp' | 'email' | 'sms'>('totp')
  const [isUpdatingPassword, setIsUpdatingPassword] = useState(false)

  const passwordForm = useForm({
    defaultValues: {
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    },
    onSubmit: async () => {
      setIsUpdatingPassword(true)
      try {
        await new Promise((resolve) => setTimeout(resolve, 500))
      } finally {
        setIsUpdatingPassword(false)
      }
    },
  })

  // Mock data - in real app, fetch from API
  const mfaMethods: MfaMethod[] = [
    { type: 'totp', name: 'Authenticator App', enabled: true, created_at: '2024-01-15' },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Settings"
        description="Manage your account security and authentication methods"
        breadcrumbs={[
          { label: 'Settings', href: '/settings' },
          { label: 'Security' },
        ]}
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-3 lg:w-auto">
          <TabsTrigger value="mfa" className="gap-2">
            <Shield className="h-4 w-4" />
            <span className="hidden sm:inline">MFA</span>
          </TabsTrigger>
          <TabsTrigger value="sessions" className="gap-2">
            <Key className="h-4 w-4" />
            <span className="hidden sm:inline">Sessions</span>
          </TabsTrigger>
          <TabsTrigger value="password" className="gap-2">
            <Shield className="h-4 w-4" />
            <span className="hidden sm:inline">Password</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="mfa" className="space-y-6">
          <Card className="p-6">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-lg font-medium">Multi-Factor Authentication</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Add an extra layer of security to your account
                </p>
              </div>
              <Badge variant="success">Enabled</Badge>
            </div>

            <div className="mt-6 space-y-3">
              {mfaMethods.map((method) => (
                <motion.div
                  key={method.type}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="flex items-center justify-between p-4 border rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-primary/10 rounded-lg">
                      {method.type === 'totp' && <Shield className="h-5 w-5 text-primary" />}
                      {method.type === 'email' && <Mail className="h-5 w-5 text-primary" />}
                      {method.type === 'sms' && <Smartphone className="h-5 w-5 text-primary" />}
                    </div>
                    <div>
                      <p className="font-medium">{method.name}</p>
                      <p className="text-xs text-muted-foreground">
                        Added {new Date(method.created_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="success" className="gap-1">
                      <CheckCircle className="h-3 w-3" />
                      Active
                    </Badge>
                    <Button variant="ghost" size="icon" aria-label="Remove MFA method">
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                </motion.div>
              ))}

              {/* Add MFA Method */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4">
                <Button
                  variant="outline"
                  className="h-auto py-4 flex-col items-center gap-2"
                  onClick={() => {
                    setEnrollMethod('totp')
                    setIsEnrollOpen(true)
                  }}
                >
                  <Shield className="h-6 w-6" />
                  <span className="text-sm">Authenticator App</span>
                </Button>
                <Button
                  variant="outline"
                  className="h-auto py-4 flex-col items-center gap-2"
                  onClick={() => {
                    setEnrollMethod('email')
                    setIsEnrollOpen(true)
                  }}
                >
                  <Mail className="h-6 w-6" />
                  <span className="text-sm">Email OTP</span>
                </Button>
                <Button
                  variant="outline"
                  className="h-auto py-4 flex-col items-center gap-2"
                  onClick={() => {
                    setEnrollMethod('sms')
                    setIsEnrollOpen(true)
                  }}
                >
                  <Smartphone className="h-6 w-6" />
                  <span className="text-sm">SMS OTP</span>
                </Button>
              </div>
            </div>
          </Card>

          {/* Recovery Codes */}
          <Card className="p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 bg-amber-100 dark:bg-amber-900/20 rounded-lg">
                <AlertCircle className="h-6 w-6 text-amber-600 dark:text-amber-400" />
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-medium">Backup Codes</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Generate backup codes to access your account if you lose your MFA device
                </p>
                <Button variant="outline" className="mt-4">
                  Generate New Codes
                </Button>
              </div>
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="sessions">
          <Card className="p-6">
            <Suspense fallback={<Skeleton className="h-64 w-full" />}>
              <SessionManager />
            </Suspense>
          </Card>
        </TabsContent>

        <TabsContent value="password">
          <Card className="p-6">
            <h3 className="text-lg font-medium mb-4">Change Password</h3>
            <form
              onSubmit={(event) => {
                event.preventDefault()
                event.stopPropagation()
                void passwordForm.handleSubmit()
              }}
              className="space-y-4 max-w-md"
            >
              <div className="space-y-2">
                <label className="text-sm font-medium">Current Password</label>
                <passwordForm.Field
                  name="currentPassword"
                  validators={{
                    onChange: ({ value }) => {
                      if (!value) return 'Current password is required'
                      return undefined
                    },
                  }}
                >
                  {(field) => (
                    <Input
                      type="password"
                      placeholder="Enter current password"
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      onBlur={field.handleBlur}
                      error={
                        field.state.meta.isTouched ? field.state.meta.errors[0] : undefined
                      }
                    />
                  )}
                </passwordForm.Field>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">New Password</label>
                <passwordForm.Field
                  name="newPassword"
                  validators={{
                    onChange: ({ value }) => {
                      if (!value) return 'New password is required'
                      if (value.length < 8) return 'Password must be at least 8 characters'
                      return undefined
                    },
                  }}
                >
                  {(field) => (
                    <Input
                      type="password"
                      placeholder="Enter new password"
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      onBlur={field.handleBlur}
                      error={
                        field.state.meta.isTouched ? field.state.meta.errors[0] : undefined
                      }
                    />
                  )}
                </passwordForm.Field>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Confirm New Password</label>
                <passwordForm.Field
                  name="confirmPassword"
                  validators={{
                    onChange: ({ value }) => {
                      if (!value) return 'Please confirm your new password'
                      return undefined
                    },
                  }}
                >
                  {(field) => (
                    <Input
                      type="password"
                      placeholder="Confirm new password"
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      onBlur={field.handleBlur}
                      error={
                        field.state.meta.isTouched ? field.state.meta.errors[0] : undefined
                      }
                    />
                  )}
                </passwordForm.Field>
                <passwordForm.Subscribe
                  selector={(state) => ({
                    newPassword: state.values.newPassword,
                    confirmPassword: state.values.confirmPassword,
                  })}
                >
                  {({ newPassword, confirmPassword }) =>
                    confirmPassword && newPassword && confirmPassword !== newPassword ? (
                      <p className="text-sm text-destructive">
                        Passwords do not match
                      </p>
                    ) : null
                  }
                </passwordForm.Subscribe>
              </div>
              <Button type="submit" isLoading={isUpdatingPassword}>
                Update Password
              </Button>
            </form>
          </Card>
        </TabsContent>
      </Tabs>

      {/* MFA Enrollment Dialog */}
      <Dialog open={isEnrollOpen} onOpenChange={setIsEnrollOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Set Up {enrollMethod === 'totp' ? 'Authenticator App' : enrollMethod === 'email' ? 'Email OTP' : 'SMS OTP'}</DialogTitle>
            <DialogDescription>
              Add an extra layer of security to your account
            </DialogDescription>
          </DialogHeader>
          <Suspense fallback={<Skeleton className="h-72 w-full" />}>
            <MfaEnroll
              method={enrollMethod}
              onEnroll={async (_code) => {
                // API call to verify and enroll
                await new Promise((resolve) => setTimeout(resolve, 1000))
              }}
              onCancel={() => setIsEnrollOpen(false)}
            />
          </Suspense>
        </DialogContent>
      </Dialog>
    </div>
  )
}
