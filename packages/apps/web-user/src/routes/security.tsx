import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import {
  Shield,
  Key,
  Smartphone,
  Fingerprint,
  Plus,
  Trash2,
  Loader2,
  AlertTriangle,
  Info,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Badge } from '@/components/ui/Badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/Tabs'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/Dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/Alert'
import { FeatureUnavailable } from '@/components/FeatureUnavailable'
import { features } from '@/lib/features'
import { toast } from 'sonner'
import { formatDate } from '@/lib/utils'
import {
  useMfaFactors,
  useDisableMfa,
  useSecurityKeys,
  useRemoveSecurityKey,
  useChangePassword,
} from '@/lib/api'

export const Route = createFileRoute('/security')({
  component: SecurityPage,
})

function SecurityPage() {
  if (!features.security) {
    return (
      <FeatureUnavailable
        title="Security Controls Disabled"
        description="Security controls are disabled until live MFA and WebAuthn APIs are integrated."
      />
    )
  }

  const [passwordData, setPasswordData] = useState({
    current: '',
    new: '',
    confirm: '',
  })

  // MFA hooks
  const { data: mfaFactorsData, isLoading: isLoadingMfa } = useMfaFactors()
  const disableMfaMutation = useDisableMfa()

  // Security keys hooks
  const { data: securityKeysData, isLoading: isLoadingKeys } = useSecurityKeys()
  const removeKeyMutation = useRemoveSecurityKey()

  const mfaFactors = mfaFactorsData?.factors || []
  const securityKeys = securityKeysData?.keys || []

  const handleRemoveMfa = async (id: string) => {
    try {
      await disableMfaMutation.mutateAsync({ factorId: id, code: '' })
      toast.success('MFA method removed')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to remove MFA')
    }
  }

  const handleRemoveKey = async (id: string) => {
    try {
      await removeKeyMutation.mutateAsync(id)
      toast.success('Security key removed')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to remove security key')
    }
  }

  const changePasswordMutation = useChangePassword()

  const handleChangePassword = async () => {
    if (passwordData.new !== passwordData.confirm) {
      toast.error('New passwords do not match')
      return
    }
    
    try {
      await changePasswordMutation.mutateAsync({
        currentPassword: passwordData.current,
        newPassword: passwordData.new,
      })
      setPasswordData({ current: '', new: '', confirm: '' })
      toast.success('Password changed successfully')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to change password')
    }
  }

  const getMfaIcon = (type: string) => {
    switch (type) {
      case 'totp':
        return <Smartphone className="h-5 w-5" aria-hidden="true" />
      case 'sms':
        return <Smartphone className="h-5 w-5" aria-hidden="true" />
      default:
        return <Key className="h-5 w-5" aria-hidden="true" />
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Security</h1>
        <p className="text-muted-foreground mt-2">
          Manage your password, two-factor authentication, and security keys
        </p>
      </div>

      <Tabs defaultValue="password" className="space-y-6">
        <TabsList aria-label="Security settings tabs">
          <TabsTrigger value="password">Password</TabsTrigger>
          <TabsTrigger value="mfa">Two-Factor Auth</TabsTrigger>
          <TabsTrigger value="keys">Security Keys</TabsTrigger>
        </TabsList>

        {/* Password Tab */}
        <TabsContent value="password" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" aria-hidden="true" />
                Change Password
              </CardTitle>
              <CardDescription>
                Update your password to keep your account secure
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="current">Current Password</Label>
                <Input
                  id="current"
                  type="password"
                  value={passwordData.current}
                  onChange={(e) =>
                    setPasswordData({ ...passwordData, current: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new">New Password</Label>
                <Input
                  id="new"
                  type="password"
                  value={passwordData.new}
                  onChange={(e) =>
                    setPasswordData({ ...passwordData, new: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirm">Confirm New Password</Label>
                <Input
                  id="confirm"
                  type="password"
                  value={passwordData.confirm}
                  onChange={(e) =>
                    setPasswordData({ ...passwordData, confirm: e.target.value })
                  }
                />
              </div>
              <Button
                onClick={handleChangePassword}
                disabled={
                  changePasswordMutation.isPending ||
                  !passwordData.current ||
                  !passwordData.new ||
                  !passwordData.confirm
                }
              >
                {changePasswordMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                    Updating...
                  </>
                ) : (
                  'Change Password'
                )}
              </Button>
            </CardContent>
          </Card>

          <Alert>
            <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            <AlertTitle>Password Requirements</AlertTitle>
            <AlertDescription>
              <ul className="list-disc list-inside text-sm mt-2 space-y-1">
                <li>At least 12 characters long</li>
                <li>Contains uppercase and lowercase letters</li>
                <li>Contains at least one number</li>
                <li>Contains at least one special character</li>
              </ul>
            </AlertDescription>
          </Alert>
        </TabsContent>

        {/* MFA Tab */}
        <TabsContent value="mfa" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Smartphone className="h-5 w-5" aria-hidden="true" />
                    Two-Factor Authentication
                  </CardTitle>
                  <CardDescription>
                    Add an extra layer of security to your account
                  </CardDescription>
                </div>
                <Dialog>
                  <DialogTrigger asChild>
                    <Button aria-label="Add two-factor authentication method">
                      <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
                      Add Method
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Add Two-Factor Authentication</DialogTitle>
                      <DialogDescription>
                        Choose a method to secure your account
                      </DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                      <Button
                        variant="outline"
                        className="justify-start h-auto py-4"
                        onClick={() => {
                          toast.info('Authenticator app setup coming soon')
                        }}
                        aria-label="Set up authenticator app"
                      >
                        <Smartphone className="mr-3 h-5 w-5" aria-hidden="true" />
                        <div className="text-left">
                          <div className="font-medium">Authenticator App</div>
                          <div className="text-sm text-muted-foreground">
                            Google Authenticator, Authy, etc.
                          </div>
                        </div>
                      </Button>
                      <Button
                        variant="outline"
                        className="justify-start h-auto py-4"
                        onClick={() => {
                          toast.info('SMS setup coming soon')
                        }}
                        aria-label="Set up SMS authentication"
                      >
                        <Smartphone className="mr-3 h-5 w-5" aria-hidden="true" />
                        <div className="text-left">
                          <div className="font-medium">SMS</div>
                          <div className="text-sm text-muted-foreground">
                            Receive codes via text message
                          </div>
                        </div>
                      </Button>
                    </div>
                  </DialogContent>
                </Dialog>
              </div>
            </CardHeader>
            <CardContent>
              {isLoadingMfa ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : mfaFactors.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Info className="h-12 w-12 mx-auto mb-3 opacity-50" aria-hidden="true" />
                  <p>No two-factor methods configured</p>
                  <p className="text-sm">Add a method to protect your account</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {mfaFactors.map((method) => (
                    <div
                      key={method.id}
                      className="flex items-center justify-between p-4 rounded-lg border"
                    >
                      <div className="flex items-center gap-4">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
                          {getMfaIcon(method.type)}
                        </div>
                        <div>
                          <p className="font-medium">{method.name}</p>
                          <p className="text-sm text-muted-foreground">
                            {method.type.toUpperCase()}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            Added {formatDate(method.createdAt)}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="success">Active</Badge>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-destructive"
                          onClick={() => handleRemoveMfa(method.id)}
                          disabled={disableMfaMutation.isPending}
                          aria-label={`Remove ${method.name} MFA method`}
                        >
                          <Trash2 className="h-4 w-4" aria-hidden="true" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Keys Tab */}
        <TabsContent value="keys" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Fingerprint className="h-5 w-5" aria-hidden="true" />
                    Security Keys
                  </CardTitle>
                  <CardDescription>
                    Manage hardware security keys for passwordless login
                  </CardDescription>
                </div>
                <Button
                  onClick={() => toast.info('Security key registration coming soon')}
                  aria-label="Register new security key"
                >
                  <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
                  Register Key
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {isLoadingKeys ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : securityKeys.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Info className="h-12 w-12 mx-auto mb-3 opacity-50" aria-hidden="true" />
                  <p>No security keys registered</p>
                  <p className="text-sm">Add a security key for enhanced protection</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {securityKeys.map((key) => (
                    <div
                      key={key.id}
                      className="flex items-center justify-between p-4 rounded-lg border"
                    >
                      <div className="flex items-center gap-4">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
                          <Key className="h-5 w-5" aria-hidden="true" />
                        </div>
                        <div>
                          <p className="font-medium">{key.name}</p>
                          <p className="text-sm text-muted-foreground">
                            Last used {key.lastUsed ? formatDate(key.lastUsed) : 'Never'}
                          </p>
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="text-destructive"
                        onClick={() => handleRemoveKey(key.id)}
                        disabled={removeKeyMutation.isPending}
                        aria-label={`Remove security key ${key.name}`}
                      >
                        <Trash2 className="h-4 w-4" aria-hidden="true" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
