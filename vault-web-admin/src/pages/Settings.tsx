import { useEffect, useState } from 'react'
import { Building2, Palette, Globe, Mail, Bell, Save, Shield } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useBrandingSettings, useUpdateBrandingSettings, usePrivacySettings, useUpdatePrivacySettings } from '@/hooks/useApi'
import { useNotificationStore } from '@/store'
import type { PrivacySettings } from '@/types'

const tabs = [
  { id: 'general', name: 'General', icon: Building2 },
  { id: 'branding', name: 'Branding', icon: Palette },
  { id: 'email', name: 'Email', icon: Mail },
  { id: 'notifications', name: 'Notifications', icon: Bell },
  { id: 'privacy', name: 'Privacy', icon: Shield },
  { id: 'localization', name: 'Localization', icon: Globe },
]

export function Settings() {
  const [activeTab, setActiveTab] = useState('general')
  const { addNotification } = useNotificationStore()
  
  const { data: branding } = useBrandingSettings()
  const updateBranding = useUpdateBrandingSettings()
  const { data: privacy } = usePrivacySettings()
  const updatePrivacy = useUpdatePrivacySettings()

  const [formData, setFormData] = useState({
    companyName: branding?.companyName || '',
    supportEmail: branding?.supportEmail || '',
    supportUrl: branding?.supportUrl || '',
    termsUrl: branding?.termsUrl || '',
    privacyUrl: branding?.privacyUrl || '',
    primaryColor: branding?.primaryColor || '#000000',
    accentColor: branding?.accentColor || '#000000',
  })

  const [privacySettings, setPrivacySettings] = useState<PrivacySettings | null>(privacy ?? null)
  const [retentionDays, setRetentionDays] = useState<number>(privacy?.data_retention_days ?? 365)

  useEffect(() => {
    if (privacy) {
      setPrivacySettings(privacy)
      setRetentionDays(privacy.data_retention_days ?? 365)
    }
  }, [privacy])

  const handleSave = () => {
    if (activeTab === 'branding' || activeTab === 'general') {
      updateBranding.mutate(formData, {
        onSuccess: () => {
          addNotification({
            type: 'success',
            title: 'Settings saved',
            message: 'Your changes have been saved successfully.',
          })
        },
      })
      return
    }

    if (activeTab === 'privacy') {
      if (!privacySettings) return
      updatePrivacy.mutate(
        {
          ...privacySettings,
          data_retention_days: retentionDays,
        },
        {
          onSuccess: () => {
            addNotification({
              type: 'success',
              title: 'Settings saved',
              message: 'Privacy settings have been updated.',
            })
          },
        },
      )
      return
    }

    addNotification({
      type: 'info',
      title: 'No changes',
      message: 'This section does not have editable settings yet.',
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-muted-foreground">Manage your Vault configuration</p>
      </div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Sidebar */}
        <div className="lg:w-64">
          <nav className="space-y-1">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button
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
            {activeTab === 'general' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">General Settings</h2>
                  <p className="text-sm text-muted-foreground">Basic configuration for your Vault instance</p>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Company Name</label>
                    <input
                      type="text"
                      value={formData.companyName}
                      onChange={(e) => setFormData({ ...formData, companyName: e.target.value })}
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="Acme Inc."
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Support Email</label>
                    <input
                      type="email"
                      value={formData.supportEmail}
                      onChange={(e) => setFormData({ ...formData, supportEmail: e.target.value })}
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="support@example.com"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Support URL</label>
                    <input
                      type="url"
                      value={formData.supportUrl}
                      onChange={(e) => setFormData({ ...formData, supportUrl: e.target.value })}
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="https://support.example.com"
                    />
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'branding' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Branding</h2>
                  <p className="text-sm text-muted-foreground">Customize the look and feel</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Primary Color</label>
                    <div className="flex items-center gap-2">
                      <input
                        type="color"
                        value={formData.primaryColor}
                        onChange={(e) => setFormData({ ...formData, primaryColor: e.target.value })}
                        className="w-10 h-10 rounded-lg border border-border"
                      />
                      <input
                        type="text"
                        value={formData.primaryColor}
                        onChange={(e) => setFormData({ ...formData, primaryColor: e.target.value })}
                        className="flex-1 px-3 py-2 bg-muted rounded-lg border border-border text-sm"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Accent Color</label>
                    <div className="flex items-center gap-2">
                      <input
                        type="color"
                        value={formData.accentColor}
                        onChange={(e) => setFormData({ ...formData, accentColor: e.target.value })}
                        className="w-10 h-10 rounded-lg border border-border"
                      />
                      <input
                        type="text"
                        value={formData.accentColor}
                        onChange={(e) => setFormData({ ...formData, accentColor: e.target.value })}
                        className="flex-1 px-3 py-2 bg-muted rounded-lg border border-border text-sm"
                      />
                    </div>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-1">Logo URL</label>
                  <input
                    type="url"
                    className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    placeholder="https://example.com/logo.png"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-1">Favicon URL</label>
                  <input
                    type="url"
                    className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    placeholder="https://example.com/favicon.ico"
                  />
                </div>
              </div>
            )}

            {activeTab === 'email' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Email Settings</h2>
                  <p className="text-sm text-muted-foreground">Configure email templates and delivery</p>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">From Name</label>
                    <input
                      type="text"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="Vault"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">From Email</label>
                    <input
                      type="email"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="noreply@example.com"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Reply-To Email</label>
                    <input
                      type="email"
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="support@example.com"
                    />
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'notifications' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Notifications</h2>
                  <p className="text-sm text-muted-foreground">Configure notification preferences</p>
                </div>

                <div className="space-y-4">
                  {[
                    { id: 'new-user', label: 'New user signup', description: 'Get notified when a new user registers' },
                    { id: 'security-alert', label: 'Security alerts', description: 'Get notified of suspicious activity' },
                    { id: 'org-creation', label: 'Organization created', description: 'Get notified when a new organization is created' },
                    { id: 'failed-login', label: 'Failed login attempts', description: 'Get notified of multiple failed logins' },
                  ].map((item) => (
                    <div key={item.id} className="flex items-start justify-between py-2">
                      <div>
                        <p className="font-medium">{item.label}</p>
                        <p className="text-sm text-muted-foreground">{item.description}</p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input type="checkbox" className="sr-only peer" defaultChecked />
                        <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/20 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
                      </label>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'privacy' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Privacy & Retention</h2>
                  <p className="text-sm text-muted-foreground">
                    Configure audit log retention for this tenant
                  </p>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Audit Log Retention (days)</label>
                    <input
                      type="number"
                      min={1}
                      max={2555}
                      value={retentionDays}
                      onChange={(e) => setRetentionDays(Number(e.target.value))}
                      className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      Default is 365 days. Max 2555 days (~7 years).
                    </p>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'localization' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-semibold">Localization</h2>
                  <p className="text-sm text-muted-foreground">Language and regional settings</p>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Default Language</label>
                    <select className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring">
                      <option value="en">English</option>
                      <option value="es">Spanish</option>
                      <option value="fr">French</option>
                      <option value="de">German</option>
                      <option value="ja">Japanese</option>
                      <option value="zh">Chinese</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Timezone</label>
                    <select className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring">
                      <option value="UTC">UTC</option>
                      <option value="America/New_York">Eastern Time (ET)</option>
                      <option value="America/Chicago">Central Time (CT)</option>
                      <option value="America/Denver">Mountain Time (MT)</option>
                      <option value="America/Los_Angeles">Pacific Time (PT)</option>
                      <option value="Europe/London">London</option>
                      <option value="Europe/Paris">Paris</option>
                      <option value="Asia/Tokyo">Tokyo</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">Date Format</label>
                    <select className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-ring">
                      <option value="MM/DD/YYYY">MM/DD/YYYY</option>
                      <option value="DD/MM/YYYY">DD/MM/YYYY</option>
                      <option value="YYYY-MM-DD">YYYY-MM-DD</option>
                    </select>
                  </div>
                </div>
              </div>
            )}

            {/* Save Button */}
            <div className="pt-6 mt-6 border-t border-border flex justify-end">
              <button
                onClick={handleSave}
                disabled={
                  updateBranding.isPending ||
                  updatePrivacy.isPending ||
                  (activeTab === 'privacy' && !privacySettings)
                }
                className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
              >
                <Save className="w-4 h-4" />
                {updateBranding.isPending || updatePrivacy.isPending ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
