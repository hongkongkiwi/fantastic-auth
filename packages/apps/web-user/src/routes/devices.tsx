import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import {
  Smartphone,
  Laptop,
  Tablet,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Shield,
  Trash2,
  Loader2,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Switch } from '@/components/ui/Switch'
import { Label } from '@/components/ui/Label'
import { Progress } from '@/components/ui/Progress'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/Dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/Alert'
import { FeatureUnavailable } from '@/components/FeatureUnavailable'
import { features } from '@/lib/features'
import { toast } from 'sonner'
import { formatRelativeTime, getTrustScoreColor } from '@/lib/utils'
import {
  useDevices,
  useDeviceStats,
  useDevicePolicy,
  useUpdateDeviceTrust,
  useRevokeDevice,
  useUpdateDevicePolicy,
  type DeviceInfo,
} from '@/lib/api'

export const Route = createFileRoute('/devices')({
  component: DevicesPage,
})

function DevicesPage() {
  if (!features.devices) {
    return (
      <FeatureUnavailable
        title="Device Management Disabled"
        description="This section is disabled until device APIs are fully verified in production."
      />
    )
  }

  const [deviceToRevoke, setDeviceToRevoke] = useState<string | null>(null)
  
  const { data: devicesData, isLoading: isLoadingDevices, error: devicesError } = useDevices()
  const { data: stats, isLoading: isLoadingStats } = useDeviceStats()
  const { data: policy, isLoading: isLoadingPolicy } = useDevicePolicy()
  
  const updateTrustMutation = useUpdateDeviceTrust()
  const revokeMutation = useRevokeDevice()
  const updatePolicyMutation = useUpdateDevicePolicy()

  const handleRevokeDevice = async () => {
    if (!deviceToRevoke) return
    
    try {
      await revokeMutation.mutateAsync(deviceToRevoke)
      setDeviceToRevoke(null)
      toast.success('Device access revoked')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to revoke device')
    }
  }

  const handleToggleTrust = async (device: DeviceInfo) => {
    try {
      await updateTrustMutation.mutateAsync({
        deviceId: device.id,
        data: {
          trustScore: device.trustScore,
          isTrusted: !device.isTrusted,
        },
      })
      toast.success(`Device ${device.isTrusted ? 'untrusted' : 'trusted'}`)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to update trust')
    }
  }

  const handlePolicyChange = async (updates: Partial<typeof policy>) => {
    if (!policy) return
    
    try {
      await updatePolicyMutation.mutateAsync({ ...policy, ...updates })
      toast.success('Device policy updated')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to update policy')
    }
  }

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'mobile':
        return <Smartphone className="h-5 w-5" aria-hidden="true" />
      case 'tablet':
        return <Tablet className="h-5 w-5" aria-hidden="true" />
      default:
        return <Laptop className="h-5 w-5" aria-hidden="true" />
    }
  }

  const devices = devicesData?.devices || []
  const averageTrustScore = stats ? Math.round(stats.avgTrustScore) : 0

  if (devicesError) {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" aria-hidden="true" />
        <AlertTitle>Error loading devices</AlertTitle>
        <AlertDescription>
          {devicesError instanceof Error ? devicesError.message : 'Please try again later'}
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Device Management</h1>
        <p className="text-muted-foreground mt-2">
          Manage your registered devices and trust settings
        </p>
      </div>

      {/* Trust Score Overview */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Average Trust Score</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? (
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" aria-hidden="true" />
            ) : (
              <>
                <div className={`text-3xl font-bold ${getTrustScoreColor(averageTrustScore)}`}>
                  {averageTrustScore}/100
                </div>
                <Progress value={averageTrustScore} className="mt-2" aria-label={`Trust score: ${averageTrustScore} out of 100`} />
              </>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Trusted Devices</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? (
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" aria-hidden="true" />
            ) : (
              <>
                <div className="text-3xl font-bold">{stats?.trustedDevices || 0}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  of {stats?.totalDevices || 0} total devices
                </p>
              </>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Current Device</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-green-500" aria-hidden="true" />
              <span className="font-medium">This Device</span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {navigator.userAgent.split(')')[0].split('(')[1] || 'Unknown'}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Device Trust Policy */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" aria-hidden="true" />
            Device Trust Policy
          </CardTitle>
          <CardDescription>
            Configure requirements for device access to your account
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {isLoadingPolicy ? (
            <div className="flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              <span className="text-sm text-muted-foreground">Loading policy...</span>
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="require-trusted">Require Trusted Device</Label>
                  <p className="text-sm text-muted-foreground">
                    Only allow login from devices marked as trusted
                  </p>
                </div>
                <Switch
                  id="require-trusted"
                  checked={policy?.autoRevokeUntrusted || false}
                  onCheckedChange={(checked) => handlePolicyChange({ autoRevokeUntrusted: checked })}
                  disabled={updatePolicyMutation.isPending}
                />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Location Mismatch Action</Label>
                  <p className="text-sm text-muted-foreground">
                    How to handle logins from unusual locations
                  </p>
                </div>
                <select
                  className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                  value={policy?.locationMismatchAction || 'prompt'}
                  onChange={(e) => handlePolicyChange({ locationMismatchAction: e.target.value })}
                  disabled={updatePolicyMutation.isPending}
                >
                  <option value="prompt">Prompt</option>
                  <option value="block">Block</option>
                  <option value="allow">Allow</option>
                </select>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Devices List */}
      <Card>
        <CardHeader>
          <CardTitle>Your Devices</CardTitle>
          <CardDescription>
            View and manage all devices with access to your account
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoadingDevices ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : devices.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              No devices found
            </div>
          ) : (
            <div className="space-y-4">
              {devices.map((device) => (
                <div
                  key={device.id}
                  className="p-4 rounded-lg border"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4">
                      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted">
                        {getDeviceIcon(device.deviceType)}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <p className="font-medium">{device.deviceName}</p>
                          {device.isTrusted ? (
                            <Badge variant="default" className="bg-green-500">Trusted</Badge>
                          ) : (
                            <Badge variant="secondary">Untrusted</Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {device.deviceType} • {device.ipAddress}
                        </p>
                        {device.location && (
                          <p className="text-sm text-muted-foreground">
                            {device.location}
                          </p>
                        )}
                        <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            {device.encryptionStatus === 'encrypted' ? (
                              <CheckCircle2 className="h-3 w-3 text-green-500" />
                            ) : (
                              <XCircle className="h-3 w-3 text-red-500" />
                            )}
                            Encrypted
                          </span>
                          <span className="flex items-center gap-1">
                            {device.mfaStatus === 'enabled' ? (
                              <CheckCircle2 className="h-3 w-3 text-green-500" />
                            ) : (
                              <XCircle className="h-3 w-3 text-red-500" />
                            )}
                            MFA
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`text-sm font-medium ${getTrustScoreColor(device.trustScore)}`}>
                          Trust: {device.trustScore}
                        </span>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-destructive"
                          onClick={() => setDeviceToRevoke(device.id)}
                          disabled={revokeMutation.isPending}
                          aria-label={`Revoke access for ${device.deviceName}`}
                        >
                          <Trash2 className="h-4 w-4" aria-hidden="true" />
                        </Button>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Last active {formatRelativeTime(device.lastSeenAt)}
                      </p>
                      <div className="flex items-center gap-2 mt-1">
                        <Switch
                          checked={device.isTrusted}
                          onCheckedChange={() => handleToggleTrust(device)}
                          disabled={updateTrustMutation.isPending}
                        />
                        <span className="text-xs">Trusted</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Warning for untrusted devices */}
      {devices.some((d) => !d.isTrusted) && (
        <Alert variant="warning">
          <AlertTriangle className="h-4 w-4" aria-hidden="true" />
          <AlertTitle>Untrusted Devices Detected</AlertTitle>
          <AlertDescription>
            You have untrusted devices with access to your account. Consider revoking access for devices you no longer use.
          </AlertDescription>
        </Alert>
      )}

      {/* Revoke Dialog */}
      <Dialog open={!!deviceToRevoke} onOpenChange={() => setDeviceToRevoke(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke Device Access</DialogTitle>
            <DialogDescription>
              Are you sure you want to revoke access for this device? The device will be signed out immediately.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeviceToRevoke(null)}>
              Cancel
            </Button>
            <Button 
              variant="destructive" 
              onClick={handleRevokeDevice}
              disabled={revokeMutation.isPending}
            >
              {revokeMutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" aria-hidden="true" />
                  Revoking...
                </>
              ) : (
                'Revoke Access'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
