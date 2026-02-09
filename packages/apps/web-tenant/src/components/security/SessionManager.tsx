//! Session Manager - Zero Trust Session Visibility & Control
//!
//! Allows users to:
//! - View all active sessions across all devices
//! - See session details (IP, location, device, started time)
//! - Revoke individual sessions
//! - Revoke all other sessions ("Log out everywhere else")
//! - See session risk scores

import { useState } from 'react'
import {
  Laptop,
  Smartphone,
  Tablet,
  Globe,
  Clock,
  MapPin,
  Shield,
  ShieldAlert,
  LogOutIcon,
  AlertTriangle,
  X,
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
  DialogTitle,
} from '@/components/ui/Dialog'
import { useNotificationStore } from '@/store'

interface Session {
  id: string
  deviceType: 'desktop' | 'mobile' | 'tablet'
  deviceName: string
  browser: string
  os: string
  ipAddress: string
  location: string
  startedAt: Date
  lastActiveAt: Date
  isCurrentSession: boolean
  riskScore: number
  isSuspicious: boolean
  mfaVerified: boolean
  factors: ('password' | 'mfa_totp' | 'mfa_sms' | 'mfa_email' | 'webauthn' | 'biometric')[]
}

// Mock data
const mockSessions: Session[] = [
  {
    id: 'sess_1',
    deviceType: 'desktop',
    deviceName: 'MacBook Pro',
    browser: 'Chrome 120',
    os: 'macOS Sonoma',
    ipAddress: '192.168.1.100',
    location: 'San Francisco, CA',
    startedAt: new Date(Date.now() - 3600000 * 2), // 2 hours ago
    lastActiveAt: new Date(),
    isCurrentSession: true,
    riskScore: 10,
    isSuspicious: false,
    mfaVerified: true,
    factors: ['password', 'mfa_totp'],
  },
  {
    id: 'sess_2',
    deviceType: 'mobile',
    deviceName: 'iPhone 15 Pro',
    browser: 'Safari',
    os: 'iOS 17.2',
    ipAddress: '203.0.113.45',
    location: 'San Francisco, CA',
    startedAt: new Date(Date.now() - 86400000), // 1 day ago
    lastActiveAt: new Date(Date.now() - 3600000), // 1 hour ago
    isCurrentSession: false,
    riskScore: 15,
    isSuspicious: false,
    mfaVerified: true,
    factors: ['password', 'biometric'],
  },
  {
    id: 'sess_3',
    deviceType: 'desktop',
    deviceName: 'Unknown Windows PC',
    browser: 'Firefox',
    os: 'Windows 10',
    ipAddress: '185.220.101.42',
    location: 'Bucharest, Romania',
    startedAt: new Date(Date.now() - 3600000 * 4), // 4 hours ago
    lastActiveAt: new Date(Date.now() - 3600000 * 3), // 3 hours ago
    isCurrentSession: false,
    riskScore: 85,
    isSuspicious: true,
    mfaVerified: false,
    factors: ['password'],
  },
]

function DeviceIcon({ type, className }: { type: Session['deviceType']; className?: string }) {
  switch (type) {
    case 'mobile':
      return <Smartphone className={className} />
    case 'tablet':
      return <Tablet className={className} />
    default:
      return <Laptop className={className} />
  }
}

function RiskBadge({ score, isSuspicious }: { score: number; isSuspicious: boolean }) {
  if (isSuspicious) {
    return (
      <Badge variant="destructive" className="gap-1">
        <ShieldAlert className="w-3 h-3" />
        Suspicious
      </Badge>
    )
  }
  if (score < 20) {
    return (
      <Badge variant="success" className="gap-1">
        <Shield className="w-3 h-3" />
        Low Risk
      </Badge>
    )
  }
  if (score < 50) {
    return (
      <Badge variant="warning" className="gap-1">
        <Shield className="w-3 h-3" />
        Medium Risk
      </Badge>
    )
  }
  return (
    <Badge variant="destructive" className="gap-1">
      <ShieldAlert className="w-3 h-3" />
      High Risk
    </Badge>
  )
}

function formatDuration(startDate: Date): string {
  const diff = Date.now() - startDate.getTime()
  const hours = Math.floor(diff / 3600000)
  const days = Math.floor(hours / 24)
  
  if (days > 0) return `${days}d ${hours % 24}h`
  return `${hours}h`
}

function formatLastActive(date: Date): string {
  const diff = Date.now() - date.getTime()
  const minutes = Math.floor(diff / 60000)
  const hours = Math.floor(minutes / 60)
  
  if (minutes < 1) return 'Just now'
  if (minutes < 60) return `${minutes}m ago`
  if (hours < 24) return `${hours}h ago`
  return date.toLocaleDateString()
}

function FactorBadge({ factor }: { factor: Session['factors'][0] }) {
  const labels: Record<typeof factor, string> = {
    password: 'Password',
    mfa_totp: 'Authenticator',
    mfa_sms: 'SMS',
    mfa_email: 'Email',
    webauthn: 'Security Key',
    biometric: 'Biometric',
  }
  
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-muted">
      {labels[factor]}
    </span>
  )
}

export function SessionManager() {
  const [sessions, setSessions] = useState<Session[]>(mockSessions)
  const [selectedSession, setSelectedSession] = useState<Session | null>(null)
  const [showRevokeDialog, setShowRevokeDialog] = useState(false)
  const [showRevokeAllDialog, setShowRevokeAllDialog] = useState(false)
  const { addNotification } = useNotificationStore()

  const currentSession = sessions.find(s => s.isCurrentSession)
  const otherSessions = sessions.filter(s => !s.isCurrentSession)
  const suspiciousSessions = sessions.filter(s => s.isSuspicious && !s.isCurrentSession)

  const handleRevoke = (session: Session) => {
    if (session.isCurrentSession) {
      addNotification({
        type: 'error',
        title: 'Cannot revoke current session',
        message: 'Use the "Log Out" button in the header to end your current session.',
      })
      return
    }
    setSelectedSession(session)
    setShowRevokeDialog(true)
  }

  const confirmRevoke = () => {
    if (!selectedSession) return
    
    setSessions(sessions.filter(s => s.id !== selectedSession.id))
    addNotification({
      type: 'success',
      title: 'Session revoked',
      message: `Session on ${selectedSession.deviceName} has been terminated.`,
    })
    setShowRevokeDialog(false)
    setSelectedSession(null)
  }

  const handleRevokeAll = () => {
    setShowRevokeAllDialog(true)
  }

  const confirmRevokeAll = () => {
    setSessions(sessions.filter(s => s.isCurrentSession))
    addNotification({
      type: 'success',
      title: 'All sessions revoked',
      message: 'You have been logged out from all other devices.',
    })
    setShowRevokeAllDialog(false)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Active Sessions</h1>
          <p className="text-muted-foreground">
            Manage your active sessions across all devices
          </p>
        </div>
        {otherSessions.length > 0 && (
          <Button
            variant="outline"
            onClick={handleRevokeAll}
            leftIcon={<LogOutIcon className="w-4 h-4" />}
          >
            Log Out All Other Devices
          </Button>
        )}
      </div>

      {/* Suspicious Alert */}
      {suspiciousSessions.length > 0 && (
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-destructive">Suspicious Activity Detected</p>
            <p className="text-sm text-destructive/80">
              We detected {suspiciousSessions.length} suspicious session(s) from unusual locations. 
              Review and revoke these sessions if you don't recognize them.
            </p>
          </div>
        </div>
      )}

      {/* Current Session */}
      {currentSession && (
        <Card className="border-primary/20 bg-primary/5">
          <div className="p-6">
            <div className="flex items-center gap-2 mb-4">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-sm font-medium text-green-600">Current Session</span>
            </div>
            
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                  <DeviceIcon type={currentSession.deviceType} className="w-6 h-6 text-primary" />
                </div>
                
                <div>
                  <p className="font-medium text-lg">{currentSession.deviceName}</p>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1 text-sm text-muted-foreground">
                    <span>{currentSession.browser}</span>
                    <span>•</span>
                    <span>{currentSession.os}</span>
                  </div>
                  
                  <div className="flex flex-wrap items-center gap-3 mt-3">
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                      <MapPin className="w-3.5 h-3.5" />
                      {currentSession.location}
                    </div>
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                      <Globe className="w-3.5 h-3.5" />
                      {currentSession.ipAddress}
                    </div>
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                      <Clock className="w-3.5 h-3.5" />
                      Started {formatDuration(currentSession.startedAt)} ago
                    </div>
                  </div>
                  
                  <div className="flex flex-wrap gap-1 mt-3">
                    {currentSession.factors.map(factor => (
                      <FactorBadge key={factor} factor={factor} />
                    ))}
                  </div>
                </div>
              </div>
              
              <RiskBadge score={currentSession.riskScore} isSuspicious={currentSession.isSuspicious} />
            </div>
          </div>
        </Card>
      )}

      {/* Other Sessions */}
      <Card>
        <div className="p-6 border-b">
          <h2 className="text-lg font-semibold">Other Active Sessions</h2>
          <p className="text-sm text-muted-foreground">
            {otherSessions.length === 0 
              ? 'No other active sessions' 
              : `${otherSessions.length} active session(s) on other devices`
            }
          </p>
        </div>

        {otherSessions.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center mx-auto mb-4">
              <Shield className="w-8 h-8 text-muted-foreground" />
            </div>
            <p className="text-muted-foreground">No other active sessions</p>
            <p className="text-sm text-muted-foreground mt-1">
              You're only signed in on this device
            </p>
          </div>
        ) : (
          <div className="divide-y">
            {otherSessions.map((session) => (
              <div 
                key={session.id} 
                className={cn(
                  "p-6 flex items-start justify-between hover:bg-muted/50 transition-colors",
                  session.isSuspicious && "bg-destructive/5"
                )}
              >
                <div className="flex items-start gap-4">
                  <div className={cn(
                    "w-12 h-12 rounded-xl flex items-center justify-center",
                    session.isSuspicious ? "bg-destructive/10 text-destructive" : "bg-muted"
                  )}>
                    <DeviceIcon type={session.deviceType} className="w-6 h-6" />
                  </div>
                  
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="font-medium">{session.deviceName}</p>
                      {session.isSuspicious && (
                        <Badge variant="destructive" className="text-xs">Suspicious</Badge>
                      )}
                    </div>
                    
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1 text-sm text-muted-foreground">
                      <span>{session.browser}</span>
                      <span>•</span>
                      <span>{session.os}</span>
                    </div>
                    
                    <div className="flex flex-wrap items-center gap-3 mt-2 text-sm text-muted-foreground">
                      <div className="flex items-center gap-1">
                        <MapPin className="w-3.5 h-3.5" />
                        {session.location}
                      </div>
                      <div className="flex items-center gap-1">
                        <Globe className="w-3.5 h-3.5" />
                        {session.ipAddress}
                      </div>
                    </div>
                    
                    <div className="flex flex-wrap items-center gap-3 mt-2 text-sm">
                      <span className="text-muted-foreground">
                        Last active: {formatLastActive(session.lastActiveAt)}
                      </span>
                      <span className="text-muted-foreground">
                        Duration: {formatDuration(session.startedAt)}
                      </span>
                    </div>
                    
                    <div className="flex flex-wrap gap-1 mt-3">
                      {session.factors.map(factor => (
                        <FactorBadge key={factor} factor={factor} />
                      ))}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <RiskBadge score={session.riskScore} isSuspicious={session.isSuspicious} />
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-destructive hover:text-destructive hover:bg-destructive/10"
                    onClick={() => handleRevoke(session)}
                    leftIcon={<X className="w-4 h-4" />}
                  >
                    Revoke
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Security Tips */}
      <Card className="p-6">
        <h3 className="font-semibold mb-4">Security Tips</h3>
        <ul className="space-y-2 text-sm text-muted-foreground">
          <li className="flex items-start gap-2">
            <Shield className="w-4 h-4 mt-0.5 text-green-500" />
            <span>Review your active sessions regularly and revoke any you don't recognize</span>
          </li>
          <li className="flex items-start gap-2">
            <Shield className="w-4 h-4 mt-0.5 text-green-500" />
            <span>Sessions from unexpected locations or without MFA may be suspicious</span>
          </li>
          <li className="flex items-start gap-2">
            <Shield className="w-4 h-4 mt-0.5 text-green-500" />
            <span>Enable MFA for all sessions to increase security</span>
          </li>
          <li className="flex items-start gap-2">
            <Shield className="w-4 h-4 mt-0.5 text-green-500" />
            <span>Use "Log Out All Other Devices" if you suspect unauthorized access</span>
          </li>
        </ul>
      </Card>

      {/* Revoke Single Dialog */}
      <Dialog open={showRevokeDialog} onOpenChange={setShowRevokeDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke Session</DialogTitle>
            <DialogDescription>
              Are you sure you want to end the session on {selectedSession?.deviceName}?
              The user will be immediately signed out from that device.
            </DialogDescription>
          </DialogHeader>
          {selectedSession?.isSuspicious && (
            <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-destructive flex-shrink-0 mt-0.5" />
              <p className="text-sm text-destructive">
                This session was flagged as suspicious. Revoking it is recommended.
              </p>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRevokeDialog(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmRevoke}>
              Revoke Session
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Revoke All Dialog */}
      <Dialog open={showRevokeAllDialog} onOpenChange={setShowRevokeAllDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Log Out All Other Devices</DialogTitle>
            <DialogDescription>
              This will end all sessions except your current one ({currentSession?.deviceName}).
              You will need to sign in again on those devices.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRevokeAllDialog(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmRevokeAll}>
              Log Out All Others
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
