import { useEffect, useState } from 'react'
import { Shield, Lock, Clock, Globe, Save, RefreshCw, Bell } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useSecuritySettings, useUpdateSecuritySettings } from '@/hooks/useApi'
import { useNotificationStore } from '@/store'
import type { NotificationChannel, SecurityNotificationEvent, SecuritySettings } from '@/types'

const tabs = [
  { id: 'password', name: 'Password Policy', icon: Lock },
  { id: 'mfa', name: 'MFA', icon: Shield },
  { id: 'session', name: 'Session', icon: Clock },
  { id: 'rate', name: 'Rate Limiting', icon: RefreshCw },
  { id: 'geo', name: 'Geographic', icon: Globe },
  { id: 'notifications', name: 'Notifications', icon: Bell },
]

export function Security() {
  const [activeTab, setActiveTab] = useState('password')
  const { addNotification } = useNotificationStore()
  
  const { data: settings, isLoading } = useSecuritySettings()
  const updateSettings = useUpdateSecuritySettings()
  const [securitySettings, setSecuritySettings] = useState<SecuritySettings | null>(null)

  useEffect(() => {
    if (settings) {
      setSecuritySettings(settings)
    }
  }, [settings])

  const handleSave = () => {
    if (!securitySettings) return
    updateSettings.mutate(securitySettings, {
      onSuccess: () => {
        addNotification({
          type: 'success',
          title: 'Settings saved',
          message: 'Security settings have been updated.',
        })
      },
    })
  }

  const toggleEvent = (audience: 'user' | 'admin', event: SecurityNotificationEvent) => {
    if (!securitySettings) return
    const current = securitySettings.notifications[audience]
    const exists = current.events.includes(event)
    const events = exists
      ? current.events.filter((item) => item !== event)
      : [...current.events, event]
    setSecuritySettings({
      ...securitySettings,
      notifications: {
        ...securitySettings.notifications,
        [audience]: {
          ...current,
          events,
        },
      },
    })
  }

  const toggleChannel = (audience: 'user' | 'admin', channel: NotificationChannel) => {
    if (!securitySettings) return
    const current = securitySettings.notifications[audience]
    const exists = current.channels.includes(channel)
    const channels = exists
      ? current.channels.filter((item) => item !== channel)
      : [...current.channels, channel]
    setSecuritySettings({
      ...securitySettings,
      notifications: {
        ...securitySettings.notifications,
        [audience]: {
          ...current,
          channels,
        },
      },
    })
  }

  const setAdminRoles = (value: string) => {
    if (!securitySettings) return
    const roles = value
      .split(',')
      .map((role) => role.trim())
      .filter((role) => role.length > 0)
    setSecuritySettings({
      ...securitySettings,
      notifications: {
        ...securitySettings.notifications,
        admin_roles: roles,
      },
    })
  }

  const setWhatsappTemplate = (value: string) => {
    if (!securitySettings) return
    setSecuritySettings({
      ...securitySettings,
      notifications: {
        ...securitySettings.notifications,
        whatsapp_template_name: value.trim() ? value.trim() : null,
      },
    })
  }

  const updateAudienceEnabled = (audience: 'user' | 'admin', enabled: boolean) => {
    if (!securitySettings) return
    setSecuritySettings({
      ...securitySettings,
      notifications: {
        ...securitySettings.notifications,
        [audience]: {
          ...securitySettings.notifications[audience],
          enabled,
        },
      },
    })
  }

  const eventOptions: { id: SecurityNotificationEvent; label: string; description: string }[] = [
    { id: 'login_failed', label: 'Failed login', description: 'Notify on failed login attempts' },
    { id: 'login_blocked_risk', label: 'Login blocked (risk)', description: 'Notify when risk engine blocks a login' },
    { id: 'password_changed', label: 'Password changed', description: 'Notify on password changes' },
    { id: 'password_reset', label: 'Password reset', description: 'Notify on password resets' },
    { id: 'mfa_enabled', label: 'MFA enabled', description: 'Notify when MFA is enabled' },
    { id: 'mfa_disabled', label: 'MFA disabled', description: 'Notify when MFA is disabled' },
    { id: 'suspicious_login', label: 'Suspicious login', description: 'Notify on suspicious activity' },
    { id: 'account_locked', label: 'Account locked', description: 'Notify when an account is locked' },
    { id: 'impersonation_started', label: 'Impersonation started', description: 'Notify when impersonation begins' },
    { id: 'security_policy_updated', label: 'Security policy updated', description: 'Notify on security policy changes' },
  ]

  const channelOptions: { id: NotificationChannel; label: string }[] = [
    { id: 'email', label: 'Email' },
    { id: 'sms', label: 'SMS' },
    { id: 'whatsapp', label: 'WhatsApp' },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Security Settings</h1>
        <p className="text-muted-foreground">Configure security policies and protection</p>
      </div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Sidebar */}
        <div className="lg:w-64">
          <nav className="space-y-1">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button type="button"
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    "w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors",
                    activeTab === tab.id
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground"
                  )}
                >
                  <Icon className="w-4 h-4" />
                  {tab.name}
                </button>
              )
            })}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1">
          <div className="bg-card rounded-lg border border-border p-6">
            {activeTab === 'password' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Password Policy</h2>
                  <p className="text-sm text-muted-foreground">Configure password requirements</p>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Minimum Length</label>
                    <div className="flex items-center gap-4">
                      <input
                        type="range"
                        min="6"
                        max="32"
                        defaultValue="8"
                        className="flex-1"
                      />
                      <span className="w-12 text-center font-medium">8</span>
                    </div>
                  </div>

                  <div className="space-y-3">
                    {[
                      { id: 'uppercase', label: 'Require uppercase letters' },
                      { id: 'lowercase', label: 'Require lowercase letters' },
                      { id: 'numbers', label: 'Require numbers' },
                      { id: 'special', label: 'Require special characters' },
                    ].map((item) => (
                      <label key={item.id} className="flex items-center gap-3 cursor-pointer">
                        <input type="checkbox" defaultChecked className="rounded border-border" />
                        <span className="text-sm">{item.label}</span>
                      </label>
                    ))}
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Password Expiry (days)</label>
                    <input
                      type="number"
                      defaultValue="90"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                    <p className="text-xs text-muted-foreground mt-1">Set to 0 for no expiry</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Prevent Reuse (previous passwords)</label>
                    <input
                      type="number"
                      defaultValue="5"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'mfa' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Multi-Factor Authentication</h2>
                  <p className="text-sm text-muted-foreground">Configure MFA requirements</p>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between py-2">
                    <div>
                      <p className="font-medium">Require MFA</p>
                      <p className="text-sm text-muted-foreground">All users must enable MFA</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" className="sr-only peer" />
                      <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/20 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-transform peer-checked:bg-primary"></div>
                    </label>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Allowed Methods</label>
                    <div className="space-y-2">
                      {[
                        { id: 'totp', label: 'Authenticator App (TOTP)' },
                        { id: 'sms', label: 'SMS' },
                        { id: 'email', label: 'Email' },
                        { id: 'webauthn', label: 'Security Key (WebAuthn)' },
                      ].map((method) => (
                        <label key={method.id} className="flex items-center gap-3 cursor-pointer">
                          <input type="checkbox" defaultChecked className="rounded border-border" />
                          <span className="text-sm">{method.label}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Grace Period (days)</label>
                    <input
                      type="number"
                      defaultValue="7"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                    <p className="text-xs text-muted-foreground mt-1">Days users have to set up MFA before enforcement</p>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'session' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Session Management</h2>
                  <p className="text-sm text-muted-foreground">Configure session timeouts</p>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Session Duration (hours)</label>
                    <input
                      type="number"
                      defaultValue="24"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Idle Timeout (minutes)</label>
                    <input
                      type="number"
                      defaultValue="30"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Absolute Timeout (hours)</label>
                    <input
                      type="number"
                      defaultValue="168"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                    <p className="text-xs text-muted-foreground mt-1">Maximum session lifetime regardless of activity</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Concurrent Sessions</label>
                    <input
                      type="number"
                      defaultValue="5"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                    <p className="text-xs text-muted-foreground mt-1">Maximum active sessions per user (0 = unlimited)</p>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'rate' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Rate Limiting</h2>
                  <p className="text-sm text-muted-foreground">Protect against brute force attacks</p>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Login Attempts</label>
                    <input
                      type="number"
                      defaultValue="5"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                    <p className="text-xs text-muted-foreground mt-1">Failed attempts before temporary block</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Time Window (seconds)</label>
                    <input
                      type="number"
                      defaultValue="300"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Block Duration (seconds)</label>
                    <input
                      type="number"
                      defaultValue="900"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'geo' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Geographic Restrictions</h2>
                  <p className="text-sm text-muted-foreground">Control access by location</p>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between py-2">
                    <div>
                      <p className="font-medium">Enable Geographic Restrictions</p>
                      <p className="text-sm text-muted-foreground">Restrict access based on user location</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" className="sr-only peer" />
                      <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/20 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-transform peer-checked:bg-primary"></div>
                    </label>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Allowed Countries</label>
                    <select multiple className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring h-32">
                      <option value="US">United States</option>
                      <option value="CA">Canada</option>
                      <option value="GB">United Kingdom</option>
                      <option value="DE">Germany</option>
                      <option value="FR">France</option>
                      <option value="JP">Japan</option>
                      <option value="AU">Australia</option>
                    </select>
                    <p className="text-xs text-muted-foreground mt-1">Hold Ctrl/Cmd to select multiple</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Blocked Countries</label>
                    <select multiple className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring h-32">
                      <option value="KP">North Korea</option>
                      <option value="IR">Iran</option>
                      <option value="SY">Syria</option>
                    </select>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'notifications' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Security Notifications</h2>
                  <p className="text-sm text-muted-foreground">
                    Configure alerting for users and tenant admins
                  </p>
                </div>

                {!securitySettings && isLoading && (
                  <p className="text-sm text-muted-foreground">Loading settings…</p>
                )}

                {securitySettings && (
                  <div className="space-y-8">
                    {(['user', 'admin'] as const).map((audience) => {
                      const audienceSettings = securitySettings.notifications[audience]
                      const title = audience === 'user' ? 'User Alerts' : 'Admin/Owner Alerts'
                      const subtitle =
                        audience === 'user'
                          ? 'Notifications sent to the affected user'
                          : 'Notifications sent to tenant owners/admins'

                      return (
                        <div key={audience} className="space-y-4 border border-border rounded-lg p-4">
                          <div className="flex items-center justify-between gap-4">
                            <div>
                              <p className="font-medium">{title}</p>
                              <p className="text-sm text-muted-foreground">{subtitle}</p>
                            </div>
                            <label className="relative inline-flex items-center cursor-pointer">
                              <input
                                type="checkbox"
                                className="sr-only peer"
                                checked={audienceSettings.enabled}
                                onChange={(e) => updateAudienceEnabled(audience, e.target.checked)}
                              />
                              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/20 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-transform peer-checked:bg-primary"></div>
                            </label>
                          </div>

                          <div className="space-y-3">
                            <p className="text-sm font-medium">Channels</p>
                            <div className="flex flex-wrap gap-4">
                              {channelOptions.map((channel) => (
                                <label key={channel.id} className="flex items-center gap-2 text-sm">
                                  <input
                                    type="checkbox"
                                    className="rounded border-border"
                                    checked={audienceSettings.channels.includes(channel.id)}
                                    onChange={() => toggleChannel(audience, channel.id)}
                                  />
                                  {channel.label}
                                </label>
                              ))}
                            </div>
                          </div>

                          <div className="space-y-3">
                            <p className="text-sm font-medium">Events</p>
                            <div className="space-y-2">
                              {eventOptions.map((event) => (
                                <label key={event.id} className="flex items-start gap-3 text-sm">
                                  <input
                                    type="checkbox"
                                    className="mt-1 rounded border-border"
                                    checked={audienceSettings.events.includes(event.id)}
                                    onChange={() => toggleEvent(audience, event.id)}
                                  />
                                  <span>
                                    <span className="font-medium">{event.label}</span>
                                    <span className="block text-xs text-muted-foreground">{event.description}</span>
                                  </span>
                                </label>
                              ))}
                            </div>
                          </div>
                        </div>
                      )
                    })}

                    <div className="space-y-3">
                      <label className="block text-sm font-medium">Admin Roles to Notify</label>
                      <input
                        type="text"
                        className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                        value={securitySettings.notifications.admin_roles.join(', ')}
                        onChange={(e) => setAdminRoles(e.target.value)}
                        placeholder="owner, admin"
                      />
                      <p className="text-xs text-muted-foreground">
                        Comma-separated role names. Default: owner, admin.
                      </p>
                    </div>

                    <div className="space-y-3">
                      <label className="block text-sm font-medium">WhatsApp Template Name</label>
                      <input
                        type="text"
                        className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                        value={securitySettings.notifications.whatsapp_template_name ?? ''}
                        onChange={(e) => setWhatsappTemplate(e.target.value)}
                        placeholder="security_alert_v1"
                      />
                      <p className="text-xs text-muted-foreground">
                        Required if WhatsApp is enabled. Must be pre-approved with Meta.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Save Button */}
            <div className="pt-6 mt-6 border-t border-border flex justify-end">
              <button type="button"
                onClick={handleSave}
                disabled={updateSettings.isPending || !securitySettings}
                className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
              >
                <Save className="w-4 h-4" />
                {updateSettings.isPending ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
