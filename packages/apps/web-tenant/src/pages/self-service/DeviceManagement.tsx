//! Device Management - Zero Trust Device Trust
//! 
//! This page allows users to:
//! - View all registered devices
//! - See device trust scores
//! - Revoke device access
//! - Configure device trust policies
//! - View device details (OS, browser, location, last seen)

import { useState } from 'react'
import { 
  Laptop, 
  Smartphone, 
  Tablet, 
  Shield, 
  ShieldAlert, 
  ShieldCheck,
  Trash2,
  Info,
  Check,
  X,
  MoreHorizontal
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { 
  Dialog, 
  DialogContent, 
  DialogDescription, 
  DialogFooter, 
  DialogHeader, 
  DialogTitle 
} from '@/components/ui/Dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/DropdownMenu'
import { Switch } from '@/components/ui/Switch'
import { useNotificationStore } from '@/store'

// Types
interface Device {
  id: string
  name: string
  type: 'desktop' | 'mobile' | 'tablet'
  os: string
  browser: string
  ipAddress: string
  location: string
  lastSeen: Date
  registeredAt: Date
  trustScore: number
  isTrusted: boolean
  isCurrentDevice: boolean
  encryptionStatus: 'enabled' | 'disabled' | 'unknown'
  hasPassword: boolean
  biometricSupport: boolean
}

interface DeviceTrustPolicy {
  requireTrustedDevice: boolean
  requireEncryption: boolean
  requirePassword: boolean
  maxDeviceAge: number // days
  allowedDeviceTypes: ('desktop' | 'mobile' | 'tablet')[]
  autoRevokeInactiveDays: number
}

// Mock data - replace with API call
const mockDevices: Device[] = [
  {
    id: 'dev_1',
    name: 'MacBook Pro - Chrome',
    type: 'desktop',
    os: 'macOS Sonoma 14.2',
    browser: 'Chrome 120.0',
    ipAddress: '192.168.1.100',
    location: 'San Francisco, CA, USA',
    lastSeen: new Date(),
    registeredAt: new Date('2024-01-15'),
    trustScore: 95,
    isTrusted: true,
    isCurrentDevice: true,
    encryptionStatus: 'enabled',
    hasPassword: true,
    biometricSupport: true,
  },
  {
    id: 'dev_2',
    name: 'iPhone 15 Pro - Safari',
    type: 'mobile',
    os: 'iOS 17.2',
    browser: 'Safari',
    ipAddress: '203.0.113.45',
    location: 'San Francisco, CA, USA',
    lastSeen: new Date(Date.now() - 3600000), // 1 hour ago
    registeredAt: new Date('2024-01-10'),
    trustScore: 88,
    isTrusted: true,
    isCurrentDevice: false,
    encryptionStatus: 'enabled',
    hasPassword: true,
    biometricSupport: true,
  },
  {
    id: 'dev_3',
    name: 'Windows PC - Edge',
    type: 'desktop',
    os: 'Windows 11',
    browser: 'Edge 118.0',
    ipAddress: '198.51.100.22',
    location: 'New York, NY, USA',
    lastSeen: new Date(Date.now() - 86400000 * 5), // 5 days ago
    registeredAt: new Date('2023-12-01'),
    trustScore: 45,
    isTrusted: false,
    isCurrentDevice: false,
    encryptionStatus: 'unknown',
    hasPassword: false,
    biometricSupport: false,
  },
]

const defaultPolicy: DeviceTrustPolicy = {
  requireTrustedDevice: false,
  requireEncryption: true,
  requirePassword: true,
  maxDeviceAge: 90,
  allowedDeviceTypes: ['desktop', 'mobile', 'tablet'],
  autoRevokeInactiveDays: 30,
}

function DeviceIcon({ type, className }: { type: Device['type']; className?: string }) {
  switch (type) {
    case 'mobile':
      return <Smartphone className={className} />
    case 'tablet':
      return <Tablet className={className} />
    default:
      return <Laptop className={className} />
  }
}

function TrustScoreBadge({ score }: { score: number }) {
  if (score >= 80) {
    return (
      <Badge variant="success" className="gap-1">
        <ShieldCheck className="w-3 h-3" />
        {score} - Trusted
      </Badge>
    )
  } else if (score >= 50) {
    return (
      <Badge variant="warning" className="gap-1">
        <Shield className="w-3 h-3" />
        {score} - Needs Review
      </Badge>
    )
  } else {
    return (
      <Badge variant="destructive" className="gap-1">
        <ShieldAlert className="w-3 h-3" />
        {score} - Untrusted
      </Badge>
    )
  }
}

function EncryptionBadge({ status }: { status: Device['encryptionStatus'] }) {
  if (status === 'enabled') {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-green-600">
        <Check className="w-3 h-3" />
        Encrypted
      </span>
    )
  } else if (status === 'disabled') {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-red-600">
        <X className="w-3 h-3" />
        Not Encrypted
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
      <Info className="w-3 h-3" />
      Unknown
    </span>
  )
}

function formatRelativeTime(date: Date): string {
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  const seconds = Math.floor(diff / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)

  if (seconds < 60) return 'Just now'
  if (minutes < 60) return `${minutes}m ago`
  if (hours < 24) return `${hours}h ago`
  if (days < 30) return `${days}d ago`
  return date.toLocaleDateString()
}

export function DeviceManagement() {
  const [devices, setDevices] = useState<Device[]>(mockDevices)
  const [policy, setPolicy] = useState<DeviceTrustPolicy>(defaultPolicy)
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)
  const [showRevokeDialog, setShowRevokeDialog] = useState(false)
  const [showDetailsDialog, setShowDetailsDialog] = useState(false)
  const { addNotification } = useNotificationStore()

  const handleRevoke = (device: Device) => {
    if (device.isCurrentDevice) {
      addNotification({
        type: 'error',
        title: 'Cannot revoke current device',
        message: 'You cannot revoke the device you are currently using.',
      })
      return
    }

    setSelectedDevice(device)
    setShowRevokeDialog(true)
  }

  const confirmRevoke = () => {
    if (!selectedDevice) return

    setDevices(devices.filter(d => d.id !== selectedDevice.id))
    addNotification({
      type: 'success',
      title: 'Device revoked',
      message: `${selectedDevice.name} has been revoked and will no longer have access.`,
    })
    setShowRevokeDialog(false)
    setSelectedDevice(null)
  }

  const handleTrustToggle = (deviceId: string, trusted: boolean) => {
    setDevices(devices.map(d => 
      d.id === deviceId 
        ? { ...d, isTrusted: trusted, trustScore: trusted ? Math.max(d.trustScore, 80) : Math.min(d.trustScore, 50) }
        : d
    ))
    
    addNotification({
      type: 'success',
      title: trusted ? 'Device trusted' : 'Device untrusted',
      message: trusted 
        ? 'This device is now trusted for authentication.'
        : 'This device has been marked as untrusted.',
    })
  }

  const handlePolicyUpdate = (updates: Partial<DeviceTrustPolicy>) => {
    setPolicy({ ...policy, ...updates })
    addNotification({
      type: 'success',
      title: 'Policy updated',
      message: 'Device trust policy has been saved.',
    })
  }

  const trustedCount = devices.filter(d => d.isTrusted).length
  const avgTrustScore = Math.round(devices.reduce((acc, d) => acc + d.trustScore, 0) / devices.length)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Device Management</h1>
        <p className="text-muted-foreground">
          Manage trusted devices and configure device trust policies
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="p-4">
          <p className="text-sm text-muted-foreground">Registered Devices</p>
          <p className="text-2xl font-bold">{devices.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-muted-foreground">Trusted Devices</p>
          <p className="text-2xl font-bold text-green-600">{trustedCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-muted-foreground">Average Trust Score</p>
          <p className={cn(
            "text-2xl font-bold",
            avgTrustScore >= 80 ? "text-green-600" : 
            avgTrustScore >= 50 ? "text-yellow-600" : "text-red-600"
          )}>
            {avgTrustScore}
          </p>
        </Card>
      </div>

      {/* Trust Policy Settings */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold">Device Trust Policy</h2>
            <p className="text-sm text-muted-foreground">
              Configure requirements for device trust
            </p>
          </div>
          <Shield className="w-8 h-8 text-primary" />
        </div>

        <div className="space-y-4">
          <div className="flex items-center justify-between py-3 border-b">
            <div>
              <p className="font-medium">Require Trusted Device</p>
              <p className="text-sm text-muted-foreground">
                Only allow login from explicitly trusted devices
              </p>
            </div>
            <Switch
              checked={policy.requireTrustedDevice}
              onCheckedChange={(checked) => handlePolicyUpdate({ requireTrustedDevice: checked })}
            />
          </div>

          <div className="flex items-center justify-between py-3 border-b">
            <div>
              <p className="font-medium">Require Device Encryption</p>
              <p className="text-sm text-muted-foreground">
                Untrusted if device encryption is disabled
              </p>
            </div>
            <Switch
              checked={policy.requireEncryption}
              onCheckedChange={(checked) => handlePolicyUpdate({ requireEncryption: checked })}
            />
          </div>

          <div className="flex items-center justify-between py-3 border-b">
            <div>
              <p className="font-medium">Require Password/PIN</p>
              <p className="text-sm text-muted-foreground">
                Untrusted if device has no password protection
              </p>
            </div>
            <Switch
              checked={policy.requirePassword}
              onCheckedChange={(checked) => handlePolicyUpdate({ requirePassword: checked })}
            />
          </div>

          <div className="flex items-center justify-between py-3 border-b">
            <div>
              <p className="font-medium">Maximum Device Age</p>
              <p className="text-sm text-muted-foreground">
                Auto-revoke devices older than {policy.maxDeviceAge} days
              </p>
            </div>
            <input
              type="number"
              value={policy.maxDeviceAge}
              onChange={(e) => handlePolicyUpdate({ maxDeviceAge: parseInt(e.target.value) || 90 })}
              className="w-20 px-3 py-1 bg-muted rounded-lg border border-border text-sm"
              min={1}
              max={365}
            />
          </div>

          <div className="flex items-center justify-between py-3">
            <div>
              <p className="font-medium">Auto-Revoke Inactive Devices</p>
              <p className="text-sm text-muted-foreground">
                Revoke devices inactive for {policy.autoRevokeInactiveDays} days
              </p>
            </div>
            <input
              type="number"
              value={policy.autoRevokeInactiveDays}
              onChange={(e) => handlePolicyUpdate({ autoRevokeInactiveDays: parseInt(e.target.value) || 30 })}
              className="w-20 px-3 py-1 bg-muted rounded-lg border border-border text-sm"
              min={1}
              max={365}
            />
          </div>
        </div>
      </Card>

      {/* Devices List */}
      <Card>
        <div className="p-6 border-b">
          <h2 className="text-lg font-semibold">Registered Devices</h2>
          <p className="text-sm text-muted-foreground">
            Manage access for each device
          </p>
        </div>

        <div className="divide-y">
          {devices.map((device) => (
            <div 
              key={device.id} 
              className={cn(
                "p-4 flex items-center justify-between hover:bg-muted/50 transition-colors",
                device.isCurrentDevice && "bg-primary/5"
              )}
            >
              <div className="flex items-start gap-4">
                <div className={cn(
                  "w-10 h-10 rounded-lg flex items-center justify-center",
                  device.isTrusted ? "bg-green-100 text-green-600" : "bg-gray-100 text-gray-600"
                )}>
                  <DeviceIcon type={device.type} className="w-5 h-5" />
                </div>
                
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium">{device.name}</p>
                    {device.isCurrentDevice && (
                      <Badge variant="secondary" className="text-xs">Current</Badge>
                    )}
                  </div>
                  
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1 text-sm text-muted-foreground">
                    <span>{device.os}</span>
                    <span>{device.browser}</span>
                    <span>•</span>
                    <span>{device.location}</span>
                  </div>
                  
                  <div className="flex flex-wrap items-center gap-3 mt-2">
                    <TrustScoreBadge score={device.trustScore} />
                    <EncryptionBadge status={device.encryptionStatus} />
                    <span className="text-xs text-muted-foreground">
                      Last seen: {formatRelativeTime(device.lastSeen)}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Switch
                  checked={device.isTrusted}
                  onCheckedChange={(checked) => handleTrustToggle(device.id, checked)}
                  disabled={device.isCurrentDevice}
                  aria-label={device.isTrusted ? "Untrust device" : "Trust device"}
                />
                
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon-sm" aria-label="Device actions">
                      <MoreHorizontal className="w-4 h-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => { setSelectedDevice(device); setShowDetailsDialog(true); }}>
                      <Info className="mr-2 h-4 w-4" />
                      View Details
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      className="text-destructive focus:text-destructive"
                      onClick={() => handleRevoke(device)}
                      disabled={device.isCurrentDevice}
                    >
                      <Trash2 className="mr-2 h-4 w-4" />
                      Revoke Access
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Revoke Confirmation Dialog */}
      <Dialog open={showRevokeDialog} onOpenChange={setShowRevokeDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke Device Access</DialogTitle>
            <DialogDescription>
              Are you sure you want to revoke access for {selectedDevice?.name}?
              This device will be signed out immediately.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRevokeDialog(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmRevoke}>
              Revoke Access
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Device Details Dialog */}
      <Dialog open={showDetailsDialog} onOpenChange={setShowDetailsDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Device Details</DialogTitle>
          </DialogHeader>
          {selectedDevice && (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <DeviceIcon type={selectedDevice.type} className="w-8 h-8 text-primary" />
                <div>
                  <p className="font-medium">{selectedDevice.name}</p>
                  <p className="text-sm text-muted-foreground">ID: {selectedDevice.id}</p>
                </div>
              </div>

              <div className="space-y-2 text-sm">
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Operating System</span>
                  <span>{selectedDevice.os}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Browser</span>
                  <span>{selectedDevice.browser}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">IP Address</span>
                  <span className="font-mono">{selectedDevice.ipAddress}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Location</span>
                  <span>{selectedDevice.location}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Registered</span>
                  <span>{selectedDevice.registeredAt.toLocaleDateString()}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Last Seen</span>
                  <span>{selectedDevice.lastSeen.toLocaleString()}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Trust Score</span>
                  <span className={cn(
                    "font-medium",
                    selectedDevice.trustScore >= 80 ? "text-green-600" : 
                    selectedDevice.trustScore >= 50 ? "text-yellow-600" : "text-red-600"
                  )}>
                    {selectedDevice.trustScore}/100
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Encryption</span>
                  <EncryptionBadge status={selectedDevice.encryptionStatus} />
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Password Protected</span>
                  <span>{selectedDevice.hasPassword ? 'Yes' : 'No'}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-muted-foreground">Biometric Support</span>
                  <span>{selectedDevice.biometricSupport ? 'Yes' : 'No'}</span>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
