import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import {
  Monitor,
  Smartphone,
  Globe,
  Clock,
  MapPin,
  Shield,
  AlertTriangle,
  LogOut,
  CheckCircle2,
  Fingerprint,
  Loader2,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
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
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/Alert'
import { FeatureUnavailable } from '@/components/FeatureUnavailable'
import { features } from '@/lib/features'
import { toast } from 'sonner'
import { formatDate, formatRelativeTime } from '@/lib/utils'
import {
  useSessions,
  useSessionStats,
  useTerminateSession,
  useTerminateAllOtherSessions,
} from '@/lib/api'

export const Route = createFileRoute('/sessions')({
  component: SessionsPage,
})

function SessionsPage() {
  if (!features.sessions) {
    return (
      <FeatureUnavailable
        title="Session Management Disabled"
        description="Session management is disabled until production session APIs are fully validated."
      />
    )
  }

  const [sessionToRevoke, setSessionToRevoke] = useState<string | null>(null)
  const [showLogoutAllDialog, setShowLogoutAllDialog] = useState(false)

  const { data: sessionsData, isLoading: isLoadingSessions, error: sessionsError } = useSessions()
  const { data: stats } = useSessionStats()
  
  const terminateMutation = useTerminateSession()
  const terminateAllMutation = useTerminateAllOtherSessions()

  const handleRevokeSession = async () => {
    if (!sessionToRevoke) return
    
    try {
      await terminateMutation.mutateAsync(sessionToRevoke)
      setSessionToRevoke(null)
      toast.success('Session revoked')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to revoke session')
    }
  }

  const handleLogoutAllOthers = async () => {
    try {
      await terminateAllMutation.mutateAsync()
      setShowLogoutAllDialog(false)
      toast.success('All other sessions have been logged out')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to log out other sessions')
    }
  }

  const getDeviceIcon = (device?: string) => {
    if (device?.toLowerCase().includes('mobile') || device?.toLowerCase().includes('phone')) {
      return <Smartphone className="h-5 w-5" aria-hidden="true" />
    }
    return <Monitor className="h-5 w-5" aria-hidden="true" />
  }

  const getFactorIcon = (factor: string) => {
    switch (factor.toLowerCase()) {
      case 'password':
        return <Shield className="h-3 w-3" aria-hidden="true" />
      case 'totp':
      case 'otp':
        return <Smartphone className="h-3 w-3" aria-hidden="true" />
      case 'biometric':
      case 'webauthn':
        return <Fingerprint className="h-3 w-3" aria-hidden="true" />
      default:
        return <Shield className="h-3 w-3" aria-hidden="true" />
    }
  }

  const getFactorLabel = (factor: string) => {
    switch (factor.toLowerCase()) {
      case 'password':
        return 'Password'
      case 'totp':
      case 'otp':
        return 'Authenticator'
      case 'biometric':
      case 'webauthn':
        return 'Biometric'
      default:
        return factor
    }
  }

  const getRiskBadge = (score: number) => {
    if (score < 30) return <Badge variant="default" className="bg-green-500">Low Risk</Badge>
    if (score < 60) return <Badge variant="secondary">Medium Risk</Badge>
    return <Badge variant="destructive">High Risk</Badge>
  }

  const sessions = sessionsData?.sessions || []
  const currentSession = sessions.find((s) => s.isCurrentSession)
  const otherSessions = sessions.filter((s) => !s.isCurrentSession)
  const suspiciousSessions = otherSessions.filter((s) => s.riskScore >= 60)

  if (sessionsError) {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Error loading sessions</AlertTitle>
        <AlertDescription>
          {sessionsError instanceof Error ? sessionsError.message : 'Please try again later'}
        </AlertDescription>
      </Alert>
    )
  }

  if (isLoadingSessions) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" aria-hidden="true" />
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Active Sessions</h1>
          <p className="text-muted-foreground mt-2">
            Manage your active sessions and sign out from devices you don't recognize
          </p>
        </div>
        {otherSessions.length > 0 && (
          <Button 
            variant="outline" 
            onClick={() => setShowLogoutAllDialog(true)}
            disabled={terminateAllMutation.isPending}
          >
            {terminateAllMutation.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <LogOut className="mr-2 h-4 w-4" />
            )}
            Log Out All Others
          </Button>
        )}
      </div>

      {/* Stats Overview */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Sessions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats?.totalSessions || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Active</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-green-600">{stats?.activeSessions || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Expired</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-muted-foreground">{stats?.expiredSessions || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Revoked</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-orange-600">{stats?.revokedSessions || 0}</div>
          </CardContent>
        </Card>
      </div>

      {/* Suspicious Activity Alert */}
      {suspiciousSessions.length > 0 && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" aria-hidden="true" />
          <AlertTitle>Suspicious Activity Detected</AlertTitle>
          <AlertDescription>
            We detected {suspiciousSessions.length} session(s) with unusual activity from unfamiliar locations or devices.
            Review and revoke these sessions if you don't recognize them.
          </AlertDescription>
        </Alert>
      )}

      {/* Current Session Card */}
      {currentSession && (
        <Card className="border-primary">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-primary" />
              Current Session
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-start gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
                {getDeviceIcon(currentSession.device)}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <p className="font-medium">{currentSession.device || 'Unknown Device'}</p>
                  <Badge>Current</Badge>
                  {getRiskBadge(currentSession.riskScore)}
                </div>
                <div className="flex items-center gap-4 mt-2 text-sm text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Globe className="h-3.5 w-3.5" aria-hidden="true" />
                    {currentSession.ipAddress}
                  </span>
                  {currentSession.location && (
                    <span className="flex items-center gap-1">
                      <MapPin className="h-3.5 w-3.5" aria-hidden="true" />
                      {currentSession.location}
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap gap-2 mt-3">
                  {currentSession.mfaFactors?.map((factor) => (
                    <Badge key={factor} variant="secondary" className="flex items-center gap-1">
                      {getFactorIcon(factor)}
                      {getFactorLabel(factor)}
                    </Badge>
                  )) || <Badge variant="secondary">Password</Badge>}
                </div>
                <p className="text-xs text-muted-foreground mt-3">
                  Started {formatDate(currentSession.createdAt)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Other Sessions */}
      <Card>
        <CardHeader>
          <CardTitle>Other Active Sessions</CardTitle>
          <CardDescription>
            Sessions on other devices that are currently signed in to your account
          </CardDescription>
        </CardHeader>
        <CardContent>
          {otherSessions.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <CheckCircle2 className="h-12 w-12 mx-auto mb-3 text-green-500" aria-hidden="true" />
              <p>No other active sessions</p>
              <p className="text-sm">You're only signed in on this device</p>
            </div>
          ) : (
            <div className="space-y-4">
              {otherSessions.map((session) => (
                <div
                  key={session.id}
                  className={`p-4 rounded-lg border ${session.riskScore >= 60 ? 'border-destructive/50 bg-destructive/5' : ''}`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4">
                      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted">
                        {getDeviceIcon(session.device)}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <p className="font-medium">{session.device || 'Unknown Device'}</p>
                          {getRiskBadge(session.riskScore)}
                          {session.riskScore >= 60 && (
                            <AlertTriangle className="h-4 w-4 text-destructive" />
                          )}
                        </div>
                        <div className="flex items-center gap-4 mt-2 text-sm text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Globe className="h-3.5 w-3.5" aria-hidden="true" />
                            {session.ipAddress}
                          </span>
                          {session.location && (
                            <span className="flex items-center gap-1">
                              <MapPin className="h-3.5 w-3.5" aria-hidden="true" />
                              {session.location}
                            </span>
                          )}
                        </div>
                        <div className="flex flex-wrap gap-2 mt-3">
                          {session.mfaFactors?.map((factor) => (
                            <Badge key={factor} variant="secondary" className="flex items-center gap-1">
                              {getFactorIcon(factor)}
                              {getFactorLabel(factor)}
                            </Badge>
                          )) || <Badge variant="secondary">Password</Badge>}
                        </div>
                        <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" aria-hidden="true" />
                            Last active {formatRelativeTime(session.lastActivityAt)}
                          </span>
                        </div>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-destructive"
                      onClick={() => setSessionToRevoke(session.id)}
                      disabled={terminateMutation.isPending}
                    >
                      <LogOut className="mr-1 h-4 w-4" aria-hidden="true" />
                      Revoke
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Session Info */}
      <Alert>
        <Clock className="h-4 w-4" aria-hidden="true" />
        <AlertTitle>Session Information</AlertTitle>
        <AlertDescription>
          Sessions automatically expire after 7 days of inactivity. You can revoke access at any time to immediately sign out a device.
        </AlertDescription>
      </Alert>

      {/* Revoke Dialog */}
      <Dialog open={!!sessionToRevoke} onOpenChange={() => setSessionToRevoke(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke Session</DialogTitle>
            <DialogDescription>
              This will immediately sign out the selected device. You'll need to sign in again on that device.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSessionToRevoke(null)}>
              Cancel
            </Button>
            <Button 
              variant="destructive" 
              onClick={handleRevokeSession}
              disabled={terminateMutation.isPending}
            >
              {terminateMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                  Revoking...
                </>
              ) : (
                'Revoke Session'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Logout All Dialog */}
      <Dialog open={showLogoutAllDialog} onOpenChange={setShowLogoutAllDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Log Out All Other Sessions</DialogTitle>
            <DialogDescription>
              This will sign out all other devices except your current one. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowLogoutAllDialog(false)}>
              Cancel
            </Button>
            <Button 
              variant="destructive" 
              onClick={handleLogoutAllOthers}
              disabled={terminateAllMutation.isPending}
            >
              {terminateAllMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                  Logging out...
                </>
              ) : (
                'Log Out All Others'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
