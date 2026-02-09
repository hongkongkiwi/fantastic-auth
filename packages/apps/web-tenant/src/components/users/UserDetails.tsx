import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Mail, Shield, Smartphone, Key,
  Building2, Globe, Copy, Check
} from 'lucide-react'
import { cn, formatDate, initials, copyToClipboard } from '@/lib/utils'
import { useUser, useUserSessions, useSuspendUser, useActivateUser, useDeleteUser, useImpersonateUser } from '@/hooks/useApi'
import type { Session } from '@/types'

interface UserDetailsProps {
  userId: string
}

export function UserDetails({ userId }: UserDetailsProps) {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<'overview' | 'sessions' | 'activity' | 'organizations'>('overview')
  const [copied, setCopied] = useState<string | null>(null)

  const { data: user, isLoading } = useUser(userId)
  const { data: sessions } = useUserSessions(userId)
  const suspendMutation = useSuspendUser()
  const activateMutation = useActivateUser()
  const deleteMutation = useDeleteUser()
  const impersonateMutation = useImpersonateUser()

  const handleCopy = async (text: string, label: string) => {
    await copyToClipboard(text)
    setCopied(label)
    setTimeout(() => setCopied(null), 2000)
  }

  const handleSuspend = () => {
    if (confirm('Are you sure you want to suspend this user?')) {
      suspendMutation.mutate({ id: userId, reason: 'Suspended by admin' })
    }
  }

  const handleActivate = () => {
    activateMutation.mutate(userId)
  }

  const handleDelete = () => {
    if (confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
      deleteMutation.mutate(userId)
      navigate('/users')
    }
  }

  const handleImpersonate = () => {
    if (confirm('Impersonate this user? You will be logged out of your current session.')) {
      impersonateMutation.mutate(userId, {
        onSuccess: (data) => {
          const payload = data as { url?: string }
          if (payload.url) {
            window.open(payload.url, '_blank')
          }
        },
      })
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-32 bg-muted rounded animate-pulse" />
        <div className="h-48 bg-muted rounded-lg animate-pulse" />
      </div>
    )
  }

  if (!user) {
    return (
      <div className="text-center py-12">
        <p className="text-muted-foreground">User not found</p>
        <button type="button"
          onClick={() => navigate('/users')}
          className="mt-4 text-primary hover:underline"
        >
          Back to users
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <button type="button"
            onClick={() => navigate('/users')}
            className="p-2 rounded-lg hover:bg-muted"
            aria-label="Back to users"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
              {user.avatarUrl ? (
                <img
                  src={user.avatarUrl}
                  alt={user.email}
                  className="w-16 h-16 rounded-full object-cover"
                />
              ) : (
                <span className="text-2xl font-medium text-primary">
                  {initials(user.displayName || user.email)}
                </span>
              )}
            </div>
            <div>
              <h1 className="text-2xl font-bold">
                {user.displayName || (user.firstName && user.lastName 
                  ? `${user.firstName} ${user.lastName}` 
                  : user.email)}
              </h1>
              <div className="flex items-center gap-3 text-sm text-muted-foreground">
                <span>{user.email}</span>
                <span>•</span>
                <span
                  className={cn(
                    "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium",
                    user.status === 'active' && "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
                    user.status === 'suspended' && "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
                    user.status === 'pending' && "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
                  )}
                >
                  {user.status}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2">
          <button type="button"
            onClick={handleImpersonate}
            className="px-4 py-2 rounded-lg border border-border hover:bg-muted text-sm font-medium"
          >
            Impersonate
          </button>
          {user.status === 'active' ? (
            <button type="button"
              onClick={handleSuspend}
              className="px-4 py-2 rounded-lg bg-yellow-500 text-white hover:bg-yellow-600 text-sm font-medium"
            >
              Suspend
            </button>
          ) : (
            <button type="button"
              onClick={handleActivate}
              className="px-4 py-2 rounded-lg bg-green-500 text-white hover:bg-green-600 text-sm font-medium"
            >
              Activate
            </button>
          )}
          <button type="button"
            onClick={handleDelete}
            className="px-4 py-2 rounded-lg bg-red-500 text-white hover:bg-red-600 text-sm font-medium"
          >
            Delete
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-border">
        <nav className="flex gap-6">
          {(['overview', 'sessions', 'activity', 'organizations'] as const).map((tab) => (
            <button type="button"
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={cn(
                "pb-3 text-sm font-medium border-b-2 transition-colors",
                activeTab === tab
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-6">
          {activeTab === 'overview' && (
            <>
              {/* Profile Info */}
              <div className="bg-card rounded-lg border border-border p-6">
                <h2 className="text-lg font-semibold mb-4">Profile Information</h2>
                <div className="grid grid-cols-2 gap-6">
                  <div>
                    <label className="text-sm text-muted-foreground">User ID</label>
                    <div className="flex items-center gap-2 mt-1">
                      <code className="text-sm bg-muted px-2 py-1 rounded">{user.id}</code>
                      <button type="button"
                        onClick={() => handleCopy(user.id, 'id')}
                        className="text-muted-foreground hover:text-foreground"
                        aria-label="Copy user ID"
                      >
                        {copied === 'id' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm text-muted-foreground">Email</label>
                    <div className="flex items-center gap-2 mt-1">
                      <Mail className="w-4 h-4 text-muted-foreground" />
                      <span>{user.email}</span>
                      {user.emailVerified ? (
                        <span className="text-xs text-green-600">Verified</span>
                      ) : (
                        <span className="text-xs text-yellow-600">Unverified</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <label className="text-sm text-muted-foreground">First Name</label>
                    <p className="mt-1">{user.firstName || '-'}</p>
                  </div>
                  <div>
                    <label className="text-sm text-muted-foreground">Last Name</label>
                    <p className="mt-1">{user.lastName || '-'}</p>
                  </div>
                  <div>
                    <label className="text-sm text-muted-foreground">Display Name</label>
                    <p className="mt-1">{user.displayName || '-'}</p>
                  </div>
                  <div>
                    <label className="text-sm text-muted-foreground">Phone Number</label>
                    <div className="flex items-center gap-2 mt-1">
                      <Smartphone className="w-4 h-4 text-muted-foreground" />
                      <span>{user.phoneNumber || '-'}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Security */}
              <div className="bg-card rounded-lg border border-border p-6">
                <h2 className="text-lg font-semibold mb-4">Security</h2>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Shield className="w-5 h-5 text-muted-foreground" />
                      <div>
                        <p className="font-medium">Multi-Factor Authentication</p>
                        <p className="text-sm text-muted-foreground">
                          {user.mfaEnabled 
                            ? `Enabled (${(user.mfaMethods ?? []).join(', ')})` 
                            : 'Not enabled'}
                        </p>
                      </div>
                    </div>
                    <span
                      className={cn(
                        "px-2 py-1 rounded text-xs font-medium",
                        user.mfaEnabled
                          ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                          : "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200"
                      )}
                    >
                      {user.mfaEnabled ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Key className="w-5 h-5 text-muted-foreground" />
                      <div>
                        <p className="font-medium">Role</p>
                        <p className="text-sm text-muted-foreground">User access level</p>
                      </div>
                    </div>
                    <span className="px-2 py-1 bg-primary/10 text-primary rounded text-xs font-medium capitalize">
                      {user.role}
                    </span>
                  </div>
                </div>
              </div>
            </>
          )}

          {activeTab === 'sessions' && (
            <div className="bg-card rounded-lg border border-border">
              <div className="p-4 border-b border-border">
                <h2 className="text-lg font-semibold">Active Sessions</h2>
              </div>
              <div className="divide-y divide-border">
                {(sessions as Session[] | undefined)?.map((session) => (
                  <div key={session.id} className="p-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-muted flex items-center justify-center">
                        <Globe className="w-5 h-5 text-muted-foreground" />
                      </div>
                      <div>
                        <p className="font-medium">
                          {session.browser} on {session.os}
                        </p>
                        <p className="text-sm text-muted-foreground">
                          {session.ipAddress} • {session.location}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Last active {formatDate(session.lastActiveAt, 'relative')}
                        </p>
                      </div>
                    </div>
                    {session.isCurrent ? (
                      <span className="text-xs text-green-600 font-medium">Current</span>
                    ) : (
                      <button type="button" className="text-sm text-red-600 hover:text-red-700">
                        Revoke
                      </button>
                    )}
                  </div>
                )) || (
                  <div className="p-8 text-center text-muted-foreground">
                    No active sessions
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'activity' && (
            <div className="bg-card rounded-lg border border-border p-6">
              <h2 className="text-lg font-semibold mb-4">Recent Activity</h2>
              <p className="text-muted-foreground">Activity feed would be shown here...</p>
            </div>
          )}

          {activeTab === 'organizations' && (
            <div className="bg-card rounded-lg border border-border">
              <div className="p-4 border-b border-border flex items-center justify-between">
                <h2 className="text-lg font-semibold">Organization Memberships</h2>
              </div>
              <div className="divide-y divide-border">
                {user.organizations?.map((membership) => (
                  <div key={membership.organizationId} className="p-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                        <Building2 className="w-5 h-5 text-primary" />
                      </div>
                      <div>
                        <p className="font-medium">{membership.organizationName || membership.name || membership.organizationId}</p>
                        <p className="text-sm text-muted-foreground">
                          Joined {formatDate(membership.joinedAt || user.createdAt, 'short')}
                        </p>
                      </div>
                    </div>
                    <span className="px-2 py-1 bg-muted rounded text-xs font-medium capitalize">
                      {membership.role || 'member'}
                    </span>
                  </div>
                )) || (
                  <div className="p-8 text-center text-muted-foreground">
                    Not a member of any organizations
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Timeline */}
          <div className="bg-card rounded-lg border border-border p-6">
            <h3 className="font-semibold mb-4">Timeline</h3>
            <div className="space-y-4">
              <div className="flex gap-3">
                <div className="w-2 h-2 rounded-full bg-green-500 mt-2" />
                <div>
                  <p className="text-sm font-medium">Account Created</p>
                  <p className="text-xs text-muted-foreground">
                    {formatDate(user.createdAt, 'long')}
                  </p>
                </div>
              </div>
              {user.emailVerified && (
                <div className="flex gap-3">
                  <div className="w-2 h-2 rounded-full bg-blue-500 mt-2" />
                  <div>
                    <p className="text-sm font-medium">Email Verified</p>
                    <p className="text-xs text-muted-foreground">
                      Email address has been verified
                    </p>
                  </div>
                </div>
              )}
              {user.lastLoginAt && (
                <div className="flex gap-3">
                  <div className="w-2 h-2 rounded-full bg-purple-500 mt-2" />
                  <div>
                    <p className="text-sm font-medium">Last Login</p>
                    <p className="text-xs text-muted-foreground">
                      {formatDate(user.lastLoginAt, 'relative')}
                      {user.lastLoginIp && ` from ${user.lastLoginIp}`}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Metadata */}
          {user.metadata && Object.keys(user.metadata).length > 0 && (
            <div className="bg-card rounded-lg border border-border p-6">
              <h3 className="font-semibold mb-4">Metadata</h3>
              <pre className="text-xs overflow-auto">
                {JSON.stringify(user.metadata, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
