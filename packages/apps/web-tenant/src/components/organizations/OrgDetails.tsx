import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Building2, Globe, Users, Shield,
  Edit2, Trash2, CheckCircle, XCircle, Plus
} from 'lucide-react'
import { cn, formatDate, initials } from '@/lib/utils'
import { 
  useOrganization, 
  useOrganizationMembers, 
  useDeleteOrganization,
  useRemoveOrganizationMember,
  useUpdateOrganizationMember
} from '@/hooks/useApi'
import type { OrganizationMember } from '@/types'

interface OrgDetailsProps {
  orgId: string
}

export function OrgDetails({ orgId }: OrgDetailsProps) {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<'overview' | 'members' | 'settings' | 'sso'>('overview')

  const { data: org, isLoading } = useOrganization(orgId)
  const { data: members } = useOrganizationMembers(orgId)
  const organizationMembers = (members || []) as OrganizationMember[]
  const deleteMutation = useDeleteOrganization()
  const removeMemberMutation = useRemoveOrganizationMember()
  const updateMemberMutation = useUpdateOrganizationMember()

  const handleDelete = () => {
    if (confirm(`Are you sure you want to delete "${org?.name}"? This action cannot be undone.`)) {
      deleteMutation.mutate(orgId)
      navigate('/organizations')
    }
  }

  const handleRemoveMember = (userId: string, email: string) => {
    if (confirm(`Remove ${email} from this organization?`)) {
      removeMemberMutation.mutate({ orgId, userId })
    }
  }

  const handleChangeRole = (userId: string, newRole: string) => {
    updateMemberMutation.mutate({ orgId, userId, role: newRole })
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-32 bg-muted rounded animate-pulse" />
        <div className="h-48 bg-muted rounded-lg animate-pulse" />
      </div>
    )
  }

  if (!org) {
    return (
      <div className="text-center py-12">
        <p className="text-muted-foreground">Organization not found</p>
        <button type="button"
          onClick={() => navigate('/organizations')}
          className="mt-4 text-primary hover:underline"
        >
          Back to organizations
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
            onClick={() => navigate('/organizations')}
            className="p-2 rounded-lg hover:bg-muted"
            aria-label="Back to organizations"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-lg bg-primary/10 flex items-center justify-center">
              {org.logoUrl ? (
                <img
                  src={org.logoUrl}
                  alt={org.name}
                  className="w-16 h-16 rounded-lg object-cover"
                />
              ) : (
                <Building2 className="w-8 h-8 text-primary" />
              )}
            </div>
            <div>
              <h1 className="text-2xl font-bold">{org.name}</h1>
              <div className="flex items-center gap-3 text-sm text-muted-foreground">
                <span>{org.slug}</span>
                <span>•</span>
                <span
                  className={cn(
                    "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium",
                    org.status === 'active' && "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
                    org.status === 'inactive' && "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
                    org.status === 'suspended' && "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                  )}
                >
                  {org.status}
                </span>
                <span className={cn(
                  "px-2 py-0.5 rounded text-xs font-medium capitalize",
                  org.plan === 'free' && "bg-gray-100 text-gray-800",
                  org.plan === 'starter' && "bg-blue-100 text-blue-800",
                  org.plan === 'pro' && "bg-purple-100 text-purple-800",
                  org.plan === 'enterprise' && "bg-amber-100 text-amber-800"
                )}>
                  {org.plan}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2">
          <button type="button"
            onClick={() => navigate(`/organizations/${orgId}/edit`)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border hover:bg-muted text-sm font-medium"
          >
            <Edit2 className="w-4 h-4" />
            Edit
          </button>
          <button type="button"
            onClick={handleDelete}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500 text-white hover:bg-red-600 text-sm font-medium"
          >
            <Trash2 className="w-4 h-4" />
            Delete
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-border">
        <nav className="flex gap-6">
          {(['overview', 'members', 'settings', 'sso'] as const).map((tab) => (
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
              {/* Organization Info */}
              <div className="bg-card rounded-lg border border-border p-6">
                <h2 className="text-lg font-semibold mb-4">Organization Details</h2>
                <div className="grid grid-cols-2 gap-6">
                  <div>
                    <label className="text-sm text-muted-foreground">Organization ID</label>
                    <code className="block mt-1 text-sm bg-muted px-2 py-1 rounded">{org.id}</code>
                  </div>
                  <div>
                    <label className="text-sm text-muted-foreground">Slug</label>
                    <p className="mt-1">{org.slug}</p>
                  </div>
                  {org.website && (
                    <div>
                      <label className="text-sm text-muted-foreground">Website</label>
                      <div className="flex items-center gap-2 mt-1">
                        <Globe className="w-4 h-4 text-muted-foreground" />
                        <a 
                          href={org.website} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-primary hover:underline"
                        >
                          {org.website}
                        </a>
                      </div>
                    </div>
                  )}
                  {org.description && (
                    <div className="col-span-2">
                      <label className="text-sm text-muted-foreground">Description</label>
                      <p className="mt-1">{org.description}</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Domain */}
              {org.domain && (
                <div className="bg-card rounded-lg border border-border p-6">
                  <h2 className="text-lg font-semibold mb-4">Domain</h2>
                  <div className="flex items-center justify-between p-4 bg-muted rounded-lg">
                    <div className="flex items-center gap-3">
                      <Globe className="w-5 h-5 text-muted-foreground" />
                      <span className="font-medium">{org.domain}</span>
                    </div>
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium",
                        org.domainVerified
                          ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                          : "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
                      )}
                    >
                      {org.domainVerified ? (
                        <><CheckCircle className="w-3 h-3" /> Verified</>
                      ) : (
                        <><XCircle className="w-3 h-3" /> Unverified</>
                      )}
                    </span>
                  </div>
                </div>
              )}

              {/* Quick Stats */}
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-card rounded-lg border border-border p-4">
                  <div className="flex items-center gap-2 text-muted-foreground mb-2">
                    <Users className="w-4 h-4" />
                    <span className="text-sm">Members</span>
                  </div>
                  <p className="text-2xl font-bold">{org.memberCount}</p>
                </div>
                <div className="bg-card rounded-lg border border-border p-4">
                  <div className="flex items-center gap-2 text-muted-foreground mb-2">
                    <Shield className="w-4 h-4" />
                    <span className="text-sm">SSO</span>
                  </div>
                  <p className="text-2xl font-bold">
                    {org.ssoEnabled ? 'On' : 'Off'}
                  </p>
                </div>
                <div className="bg-card rounded-lg border border-border p-4">
                  <div className="flex items-center gap-2 text-muted-foreground mb-2">
                    <CheckCircle className="w-4 h-4" />
                    <span className="text-sm">Plan</span>
                  </div>
                  <p className="text-2xl font-bold capitalize">{org.plan}</p>
                </div>
              </div>
            </>
          )}

          {activeTab === 'members' && (
            <div className="bg-card rounded-lg border border-border">
              <div className="p-4 border-b border-border flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-semibold">Members</h2>
                  <p className="text-sm text-muted-foreground">{members?.length || 0} members</p>
                </div>
                <button type="button"
                  onClick={() => navigate('/users')}
                  className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
                >
                  <Plus className="w-4 h-4" />
                  Add Member
                </button>
              </div>
              <div className="divide-y divide-border">
                {organizationMembers.map((member) => (
                  <div key={member.userId} className="p-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                        {member.avatarUrl ? (
                          <img
                            src={member.avatarUrl}
                            alt={member.email}
                            className="w-10 h-10 rounded-full object-cover"
                          />
                        ) : (
                          <span className="text-sm font-medium text-primary">
                            {initials(member.firstName && member.lastName 
                              ? `${member.firstName} ${member.lastName}` 
                              : member.email)}
                          </span>
                        )}
                      </div>
                      <div>
                        <p className="font-medium">
                          {member.firstName && member.lastName 
                            ? `${member.firstName} ${member.lastName}` 
                            : member.email}
                        </p>
                        <p className="text-sm text-muted-foreground">{member.email}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <select
                        value={member.role}
                        onChange={(e) => handleChangeRole(member.userId, e.target.value)}
                        className="px-2 py-1 bg-muted rounded text-sm"
                      >
                        <option value="member">Member</option>
                        <option value="admin">Admin</option>
                        <option value="owner">Owner</option>
                      </select>
                      <button type="button"
                        onClick={() => handleRemoveMember(member.userId, member.email)}
                        className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-red-600"
                        aria-label={`Remove ${member.email} from organization`}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                )) || (
                  <div className="p-8 text-center text-muted-foreground">
                    No members found
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="bg-card rounded-lg border border-border p-6">
              <h2 className="text-lg font-semibold mb-4">Organization Settings</h2>
              <div className="space-y-4">
                <div className="flex items-center justify-between py-3 border-b border-border">
                  <div>
                    <p className="font-medium">Allow Public Signup</p>
                    <p className="text-sm text-muted-foreground">Allow anyone to join this organization</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input 
                      type="checkbox" 
                      className="sr-only peer"
                      checked={org.settings.allowPublicSignup}
                      onChange={() => {}}
                    />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/20 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-transform peer-checked:bg-primary"></div>
                  </label>
                </div>
                <div className="flex items-center justify-between py-3 border-b border-border">
                  <div>
                    <p className="font-medium">Require Email Verification</p>
                    <p className="text-sm text-muted-foreground">Members must verify their email</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input 
                      type="checkbox" 
                      className="sr-only peer"
                      checked={org.settings.requireEmailVerification}
                      onChange={() => {}}
                    />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/20 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-transform peer-checked:bg-primary"></div>
                  </label>
                </div>
                <div className="flex items-center justify-between py-3 border-b border-border">
                  <div>
                    <p className="font-medium">Allow Members to Invite</p>
                    <p className="text-sm text-muted-foreground">Members can invite new users</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input 
                      type="checkbox" 
                      className="sr-only peer"
                      checked={org.settings.allowMembersToInvite}
                      onChange={() => {}}
                    />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/20 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-transform peer-checked:bg-primary"></div>
                  </label>
                </div>
                <div className="flex items-center justify-between py-3">
                  <div>
                    <p className="font-medium">Session Timeout</p>
                    <p className="text-sm text-muted-foreground">Minutes of inactivity before logout</p>
                  </div>
                  <input
                    type="number"
                    value={org.settings.sessionTimeoutMinutes}
                    className="w-20 px-3 py-1 bg-muted rounded text-sm text-right"
                    readOnly
                  />
                </div>
              </div>
            </div>
          )}

          {activeTab === 'sso' && (
            <div className="bg-card rounded-lg border border-border p-6">
              <h2 className="text-lg font-semibold mb-4">Single Sign-On</h2>
              {org.ssoEnabled ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-2 text-green-600">
                    <CheckCircle className="w-5 h-5" />
                    <span className="font-medium">SSO is enabled</span>
                  </div>
                  <div className="p-4 bg-muted rounded-lg">
                    <p className="text-sm text-muted-foreground mb-2">Provider</p>
                    <p className="font-medium">{org.ssoProvider?.toUpperCase()}</p>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8">
                  <Shield className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <h3 className="font-medium mb-2">SSO is not enabled</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Enable SSO to allow members to sign in with your identity provider
                  </p>
                  <button type="button" className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium">
                    Configure SSO
                  </button>
                </div>
              )}
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
                  <p className="text-sm font-medium">Organization Created</p>
                  <p className="text-xs text-muted-foreground">
                    {formatDate(org.createdAt, 'long')}
                  </p>
                </div>
              </div>
              <div className="flex gap-3">
                <div className="w-2 h-2 rounded-full bg-blue-500 mt-2" />
                <div>
                  <p className="text-sm font-medium">Last Updated</p>
                  <p className="text-xs text-muted-foreground">
                    {formatDate(org.updatedAt, 'relative')}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
