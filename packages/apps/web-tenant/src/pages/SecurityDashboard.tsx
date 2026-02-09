//! Security Dashboard - Zero Trust Security Overview
//!
//! Provides:
//! - Real-time risk score visualization
//! - Anomaly detection alerts
//! - Security recommendations
//! - Login activity heatmap
//! - Failed login attempts tracking
//! - MFA adoption metrics
//! - Security events timeline

import { useState } from 'react'
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Users,
  Lock,
  ChevronRight,
  TrendingUp,
  TrendingDown,
  Eye,
  CheckCircle2,
  XCircle,
  Key,
  Smartphone,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { useNavigate } from 'react-router-dom'

interface RiskMetrics {
  overallScore: number
  lastWeekScore: number
  trends: {
    failedLogins: number
    suspiciousActivities: number
    mfaChallenges: number
    blockedAttempts: number
  }
}

interface SecurityAlert {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  timestamp: Date
  acknowledged: boolean
  category: 'login' | 'device' | 'anomaly' | 'policy'
}

interface SecurityRecommendation {
  id: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  action: string
  actionLink: string
  completed: boolean
}

// Mock data
const mockRiskMetrics: RiskMetrics = {
  overallScore: 78,
  lastWeekScore: 72,
  trends: {
    failedLogins: 23,
    suspiciousActivities: 5,
    mfaChallenges: 156,
    blockedAttempts: 8,
  },
}

const mockAlerts: SecurityAlert[] = [
  {
    id: 'alert_1',
    severity: 'critical',
    title: 'Suspicious Login from New Location',
    description: 'Login attempt from Bucharest, Romania for user admin@example.com',
    timestamp: new Date(Date.now() - 3600000 * 2),
    acknowledged: false,
    category: 'login',
  },
  {
    id: 'alert_2',
    severity: 'high',
    title: 'Multiple Failed Login Attempts',
    description: '15 failed attempts for user john.doe@company.com in 5 minutes',
    timestamp: new Date(Date.now() - 3600000 * 4),
    acknowledged: false,
    category: 'login',
  },
  {
    id: 'alert_3',
    severity: 'medium',
    title: 'New Device Registered',
    description: 'User jane@example.com registered a new Windows device',
    timestamp: new Date(Date.now() - 86400000),
    acknowledged: true,
    category: 'device',
  },
  {
    id: 'alert_4',
    severity: 'low',
    title: 'MFA Disabled',
    description: 'User marketing@company.com disabled MFA on their account',
    timestamp: new Date(Date.now() - 86400000 * 2),
    acknowledged: true,
    category: 'policy',
  },
]

const mockRecommendations: SecurityRecommendation[] = [
  {
    id: 'rec_1',
    priority: 'critical',
    title: 'Enable Mandatory MFA',
    description: 'Only 45% of users have MFA enabled. Enforcing MFA will significantly improve security.',
    action: 'Configure MFA Policy',
    actionLink: '/security',
    completed: false,
  },
  {
    id: 'rec_2',
    priority: 'high',
    title: 'Review Failed Login Patterns',
    description: 'There has been a 150% increase in failed login attempts this week.',
    action: 'View Login Analytics',
    actionLink: '/analytics',
    completed: false,
  },
  {
    id: 'rec_3',
    priority: 'medium',
    title: 'Update Password Policy',
    description: 'Current minimum password length is 8 characters. Consider increasing to 12.',
    action: 'Update Policy',
    actionLink: '/security',
    completed: false,
  },
  {
    id: 'rec_4',
    priority: 'medium',
    title: 'Enable Device Trust',
    description: 'Device trust is not enabled. This helps prevent unauthorized access from unknown devices.',
    action: 'Enable Device Trust',
    actionLink: '/devices',
    completed: false,
  },
]

const mockMfaStats = {
  totalUsers: 2480,
  mfaEnabled: 1116,
  totp: 650,
  sms: 280,
  email: 120,
  webauthn: 66,
}

function RiskScoreGauge({ score }: { score: number }) {
  const getColor = () => {
    if (score >= 80) return 'text-green-500'
    if (score >= 60) return 'text-yellow-500'
    if (score >= 40) return 'text-orange-500'
    return 'text-red-500'
  }

  const getLabel = () => {
    if (score >= 80) return 'Good'
    if (score >= 60) return 'Fair'
    if (score >= 40) return 'Poor'
    return 'Critical'
  }

  const getIcon = () => {
    if (score >= 80) return <ShieldCheck className={cn('w-12 h-12', getColor())} />
    if (score >= 60) return <Shield className={cn('w-12 h-12', getColor())} />
    return <ShieldAlert className={cn('w-12 h-12', getColor())} />
  }

  return (
    <div className="flex items-center gap-6">
      {getIcon()}
      <div>
        <p className={cn('text-4xl font-bold', getColor())}>{score}</p>
        <p className="text-sm text-muted-foreground">Security Score: {getLabel()}</p>
      </div>
    </div>
  )
}

function SeverityBadge({ severity }: { severity: SecurityAlert['severity'] }) {
  const variants: Record<typeof severity, 'destructive' | 'warning' | 'default' | 'secondary'> = {
    critical: 'destructive',
    high: 'warning',
    medium: 'default',
    low: 'secondary',
  }
  return <Badge variant={variants[severity]}>{severity.toUpperCase()}</Badge>
}

function PriorityBadge({ priority }: { priority: SecurityRecommendation['priority'] }) {
  const variants: Record<typeof priority, 'destructive' | 'warning' | 'default' | 'secondary'> = {
    critical: 'destructive',
    high: 'warning',
    medium: 'default',
    low: 'secondary',
  }
  return <Badge variant={variants[priority]}>{priority.toUpperCase()}</Badge>
}

function formatTimeAgo(date: Date): string {
  const hours = Math.floor((Date.now() - date.getTime()) / 3600000)
  if (hours < 1) return 'Just now'
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export function SecurityDashboard() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>(mockAlerts)
  const navigate = useNavigate()

  const unacknowledgedAlerts = alerts.filter(a => !a.acknowledged)
  const criticalAlerts = alerts.filter(a => a.severity === 'critical' && !a.acknowledged)
  const pendingRecommendations = mockRecommendations.filter(r => !r.completed)

  const handleAcknowledge = (alertId: string) => {
    setAlerts(alerts.map(a => 
      a.id === alertId ? { ...a, acknowledged: true } : a
    ))
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Security Dashboard</h1>
          <p className="text-muted-foreground">
            Overview of your organization's security posture
          </p>
        </div>
        {criticalAlerts.length > 0 && (
          <div className="flex items-center gap-2 px-4 py-2 bg-destructive/10 rounded-lg">
            <AlertTriangle className="w-5 h-5 text-destructive" />
            <span className="text-sm font-medium text-destructive">
              {criticalAlerts.length} Critical Alert{criticalAlerts.length > 1 ? 's' : ''}
            </span>
          </div>
        )}
      </div>

      {/* Risk Score & Quick Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="p-6">
          <h3 className="text-sm font-medium text-muted-foreground mb-4">Security Score</h3>
          <RiskScoreGauge score={mockRiskMetrics.overallScore} />
          <div className="mt-4 flex items-center gap-2 text-sm">
            {mockRiskMetrics.overallScore > mockRiskMetrics.lastWeekScore ? (
              <>
                <TrendingUp className="w-4 h-4 text-green-500" />
                <span className="text-green-600">
                  +{mockRiskMetrics.overallScore - mockRiskMetrics.lastWeekScore} from last week
                </span>
              </>
            ) : (
              <>
                <TrendingDown className="w-4 h-4 text-red-500" />
                <span className="text-red-600">
                  {mockRiskMetrics.overallScore - mockRiskMetrics.lastWeekScore} from last week
                </span>
              </>
            )}
          </div>
        </Card>

        <Card className="p-6">
          <h3 className="text-sm font-medium text-muted-foreground mb-4">MFA Adoption</h3>
          <div className="flex items-center gap-4">
            <div className="relative w-20 h-20">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-muted"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="3"
                />
                <path
                  className="text-primary"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="3"
                  strokeDasharray={`${(mockMfaStats.mfaEnabled / mockMfaStats.totalUsers) * 100}, 100`}
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-lg font-bold">
                  {Math.round((mockMfaStats.mfaEnabled / mockMfaStats.totalUsers) * 100)}%
                </span>
              </div>
            </div>
            <div className="flex-1 space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="flex items-center gap-2">
                  <Key className="w-4 h-4 text-blue-500" />
                  TOTP
                </span>
                <span className="font-medium">{mockMfaStats.totp}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="flex items-center gap-2">
                  <Smartphone className="w-4 h-4 text-green-500" />
                  SMS
                </span>
                <span className="font-medium">{mockMfaStats.sms}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="flex items-center gap-2">
                  <Lock className="w-4 h-4 text-purple-500" />
                  WebAuthn
                </span>
                <span className="font-medium">{mockMfaStats.webauthn}</span>
              </div>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <h3 className="text-sm font-medium text-muted-foreground mb-4">24h Activity</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <XCircle className="w-4 h-4 text-red-500" />
                <span className="text-sm">Failed Logins</span>
              </div>
              <span className="font-medium">{mockRiskMetrics.trends.failedLogins}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-yellow-500" />
                <span className="text-sm">Suspicious</span>
              </div>
              <span className="font-medium">{mockRiskMetrics.trends.suspiciousActivities}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-blue-500" />
                <span className="text-sm">MFA Challenges</span>
              </div>
              <span className="font-medium">{mockRiskMetrics.trends.mfaChallenges}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-green-500" />
                <span className="text-sm">Blocked</span>
              </div>
              <span className="font-medium">{mockRiskMetrics.trends.blockedAttempts}</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Alerts & Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Security Alerts */}
        <Card>
          <div className="p-6 border-b">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-destructive" />
                <h2 className="text-lg font-semibold">Security Alerts</h2>
              </div>
              {unacknowledgedAlerts.length > 0 && (
                <Badge variant="destructive">{unacknowledgedAlerts.length} New</Badge>
              )}
            </div>
          </div>

          <div className="divide-y">
            {alerts.length === 0 ? (
              <div className="p-8 text-center">
                <CheckCircle2 className="w-12 h-12 text-green-500 mx-auto mb-3" />
                <p className="text-muted-foreground">No security alerts</p>
              </div>
            ) : (
              alerts.map((alert) => (
                <div 
                  key={alert.id} 
                  className={cn(
                    "p-4 flex items-start gap-4",
                    alert.acknowledged && "opacity-60"
                  )}
                >
                  <div className={cn(
                    "w-2 h-2 rounded-full mt-2 flex-shrink-0",
                    alert.severity === 'critical' && "bg-red-500",
                    alert.severity === 'high' && "bg-orange-500",
                    alert.severity === 'medium' && "bg-yellow-500",
                    alert.severity === 'low' && "bg-blue-500",
                  )} />
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className={cn(
                          "font-medium",
                          alert.acknowledged && "line-through"
                        )}>
                          {alert.title}
                        </p>
                        <p className="text-sm text-muted-foreground mt-0.5">
                          {alert.description}
                        </p>
                      </div>
                      <SeverityBadge severity={alert.severity} />
                    </div>
                    
                    <div className="flex items-center justify-between mt-2">
                      <span className="text-xs text-muted-foreground">
                        {formatTimeAgo(alert.timestamp)}
                      </span>
                      {!alert.acknowledged && (
                        <Button 
                          variant="ghost" 
                          size="sm"
                          onClick={() => handleAcknowledge(alert.id)}
                        >
                          Acknowledge
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>

        {/* Recommendations */}
        <Card>
          <div className="p-6 border-b">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-primary" />
                <h2 className="text-lg font-semibold">Recommendations</h2>
              </div>
              {pendingRecommendations.length > 0 && (
                <Badge>{pendingRecommendations.length} Pending</Badge>
              )}
            </div>
          </div>

          <div className="divide-y">
            {mockRecommendations.map((rec) => (
              <div 
                key={rec.id} 
                className={cn(
                  "p-4",
                  rec.completed && "opacity-60"
                )}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <p className={cn(
                        "font-medium",
                        rec.completed && "line-through"
                      )}>
                        {rec.title}
                      </p>
                      <PriorityBadge priority={rec.priority} />
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {rec.description}
                    </p>
                  </div>
                </div>
                
                <div className="mt-3">
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => navigate(rec.actionLink)}
                    disabled={rec.completed}
                  >
                    {rec.action}
                    <ChevronRight className="w-4 h-4 ml-2" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card className="p-6">
        <h3 className="font-semibold mb-4">Security Quick Actions</h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Button 
            variant="outline" 
            className="h-auto py-4 flex flex-col items-center gap-2"
            onClick={() => navigate('/security')}
          >
            <Shield className="w-6 h-6" />
            <span className="text-sm">Security Settings</span>
          </Button>
          <Button 
            variant="outline" 
            className="h-auto py-4 flex flex-col items-center gap-2"
            onClick={() => navigate('/devices')}
          >
            <Smartphone className="w-6 h-6" />
            <span className="text-sm">Manage Devices</span>
          </Button>
          <Button 
            variant="outline" 
            className="h-auto py-4 flex flex-col items-center gap-2"
            onClick={() => navigate('/audit-logs')}
          >
            <Eye className="w-6 h-6" />
            <span className="text-sm">View Audit Logs</span>
          </Button>
          <Button 
            variant="outline" 
            className="h-auto py-4 flex flex-col items-center gap-2"
            onClick={() => navigate('/users')}
          >
            <Users className="w-6 h-6" />
            <span className="text-sm">Review Users</span>
          </Button>
        </div>
      </Card>
    </div>
  )
}
