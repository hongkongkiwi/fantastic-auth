import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import {
  FileText,
  Download,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  Database,
  Eye,
  Shield,
  MapPin,
  Loader2,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Switch } from '@/components/ui/Switch'
import { Label } from '@/components/ui/Label'
import { Input } from '@/components/ui/Input'
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
import { formatDate } from '@/lib/utils'
import {
  useDataExports,
  useRequestExport,
  useConsents,
  useUpdateConsent,
  useDeleteAccount,
} from '@/lib/api'

export const Route = createFileRoute('/privacy')({
  component: PrivacyPage,
})

// Data categories info (static)
const dataCategories = [
  {
    id: 'profile',
    name: 'Profile Information',
    description: 'Your name, email, phone number, and avatar',
    icon: FileText,
    retention: 'Until account deletion',
    legalBasis: 'Contract',
    isRequired: true,
  },
  {
    id: 'authentication',
    name: 'Authentication Data',
    description: 'Password hashes, MFA settings, and security keys',
    icon: Shield,
    retention: 'Until account deletion',
    legalBasis: 'Contract',
    isRequired: true,
  },
  {
    id: 'activity',
    name: 'Activity Logs',
    description: 'Login history, IP addresses, and device information',
    icon: Eye,
    retention: '90 days',
    legalBasis: 'Legitimate Interest',
    isRequired: false,
  },
  {
    id: 'location',
    name: 'Location Data',
    description: 'Approximate location based on IP address',
    icon: MapPin,
    retention: '90 days',
    legalBasis: 'Legitimate Interest',
    isRequired: false,
  },
  {
    id: 'preferences',
    name: 'Preferences',
    description: 'Theme settings, language, and notification preferences',
    icon: Database,
    retention: 'Until account deletion',
    legalBasis: 'Consent',
    isRequired: false,
  },
]

function PrivacyPage() {
  if (!features.privacy) {
    return (
      <FeatureUnavailable
        title="Privacy Center Disabled"
        description="Privacy controls are disabled until production privacy APIs are fully validated."
      />
    )
  }

  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [deleteConfirmation, setDeleteConfirmation] = useState('')
  const [deleteReason, setDeleteReason] = useState('')

  const { data: exports, isLoading: isLoadingExports } = useDataExports()
  const { data: consentsData, isLoading: isLoadingConsents } = useConsents()
  
  const requestExportMutation = useRequestExport()
  const updateConsentMutation = useUpdateConsent()
  const deleteAccountMutation = useDeleteAccount()

  const handleExportData = async (format: 'json' | 'csv') => {
    try {
      await requestExportMutation.mutateAsync({
        format,
        dataCategories: ['profile', 'sessions', 'devices', 'consents'],
      })
      toast.success('Data export requested. You will receive an email when it\'s ready.')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to request export')
    }
  }

  const handleToggleConsent = async (consentType: string, granted: boolean) => {
    try {
      await updateConsentMutation.mutateAsync({ consentType, granted })
      toast.success(granted ? 'Consent granted' : 'Consent withdrawn')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to update consent')
    }
  }

  const handleDeleteAccount = async () => {
    if (deleteConfirmation !== 'DELETE MY ACCOUNT') return
    
    try {
      await deleteAccountMutation.mutateAsync({
        confirmationText: deleteConfirmation,
        reason: deleteReason,
      })
      setShowDeleteDialog(false)
      toast.success('Account deletion scheduled. You have 30 days to cancel.')
      // Redirect to logout or deletion pending page
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to request deletion')
    }
  }

  const getConsentLabel = (type: string) => {
    const labels: Record<string, string> = {
      marketing: 'Marketing Communications',
      analytics: 'Analytics & Improvements',
      third_party: 'Third-Party Integrations',
      activity_tracking: 'Activity Tracking',
    }
    return labels[type] || type
  }

  const getConsentDescription = (type: string) => {
    const descriptions: Record<string, string> = {
      marketing: 'Receive product updates, newsletters, and promotional offers',
      analytics: 'Help us improve by sharing usage analytics',
      third_party: 'Share data with authorized third-party services',
      activity_tracking: 'Track your activity for security purposes',
    }
    return descriptions[type] || 'Manage consent for this feature'
  }

  const consents = consentsData?.consents || []

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Privacy Center</h1>
        <p className="text-muted-foreground mt-2">
          Manage your data, privacy settings, and GDPR rights
        </p>
      </div>

      {/* GDPR Rights Overview */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <Download className="h-8 w-8 text-blue-500 mb-3" aria-hidden="true" />
            <h3 className="font-semibold">Right to Access</h3>
            <p className="text-sm text-muted-foreground mt-1">
              Download all your personal data
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <Database className="h-8 w-8 text-green-500 mb-3" aria-hidden="true" />
            <h3 className="font-semibold">Right to Portability</h3>
            <p className="text-sm text-muted-foreground mt-1">
              Export in machine-readable format
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <Trash2 className="h-8 w-8 text-red-500 mb-3" aria-hidden="true" />
            <h3 className="font-semibold">Right to Erasure</h3>
            <p className="text-sm text-muted-foreground mt-1">
              Request account deletion
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <Shield className="h-8 w-8 text-purple-500 mb-3" aria-hidden="true" />
            <h3 className="font-semibold">Right to Object</h3>
            <p className="text-sm text-muted-foreground mt-1">
              Manage consent preferences
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Data Export Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" aria-hidden="true" />
            Export Your Data
          </CardTitle>
          <CardDescription>
            Download a copy of your personal data (Article 20 - Right to Data Portability)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-4">
            <Button
              onClick={() => handleExportData('json')}
              disabled={requestExportMutation.isPending}
              className="flex-1"
            >
              {requestExportMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                  Requesting...
                </>
              ) : (
                <>
                  <Download className="mr-2 h-4 w-4" aria-hidden="true" />
                  Export as JSON
                </>
              )}
            </Button>
            <Button
              onClick={() => handleExportData('csv')}
              disabled={requestExportMutation.isPending}
              variant="outline"
              className="flex-1"
            >
              <Download className="mr-2 h-4 w-4" />
              Export as CSV
            </Button>
          </div>

          {isLoadingExports ? (
            <div className="flex items-center gap-2 py-4">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              <span className="text-sm text-muted-foreground">Loading exports...</span>
            </div>
          ) : exports && exports.length > 0 ? (
            <div className="mt-4">
              <h4 className="text-sm font-medium mb-3">Export History</h4>
              <div className="space-y-2">
                {exports.map((exp) => (
                  <div
                    key={exp.id}
                    className="flex items-center justify-between p-3 rounded-lg border"
                  >
                    <div className="flex items-center gap-3">
                      <FileText className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                      <div>
                        <p className="text-sm font-medium">
                          Data Export
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Requested {formatDate(exp.requestedAt)}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {exp.status === 'completed' ? (
                        <>
                          <Badge variant="default" className="bg-green-500">Ready</Badge>
                          {exp.downloadUrl && (
                            <Button size="sm" variant="ghost" asChild aria-label="Download export">
                              <a href={exp.downloadUrl} download>
                                <Download className="h-4 w-4" aria-hidden="true" />
                              </a>
                            </Button>
                          )}
                        </>
                      ) : exp.status === 'pending' ? (
                        <Badge variant="secondary">
                          <Loader2 className="h-3 w-3 mr-1 animate-spin" aria-hidden="true" />
                          Processing
                        </Badge>
                      ) : (
                        <Badge variant="destructive">Failed</Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Data Categories */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" aria-hidden="true" />
            Data We Collect
          </CardTitle>
          <CardDescription>
            Information we store about you and why we need it (Article 15 - Right to Access)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {dataCategories.map((category) => (
              <div
                key={category.id}
                className="flex items-start justify-between p-4 rounded-lg border"
              >
                <div className="flex items-start gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                    <category.icon className="h-5 w-5" aria-hidden="true" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="font-medium">{category.name}</p>
                      {category.isRequired && (
                        <Badge variant="secondary">Required</Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {category.description}
                    </p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      <span>Retention: {category.retention}</span>
                      <span>Legal basis: {category.legalBasis}</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Consent Management */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" aria-hidden="true" />
            Consent Preferences
          </CardTitle>
          <CardDescription>
            Manage how we use your data for optional purposes (Article 21 - Right to Object)
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoadingConsents ? (
            <div className="flex items-center gap-2 py-4">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              <span className="text-sm text-muted-foreground">Loading consents...</span>
            </div>
          ) : consents.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <CheckCircle2 className="h-12 w-12 mx-auto mb-3 text-green-500" aria-hidden="true" />
              <p>No optional consents configured</p>
            </div>
          ) : (
            <div className="space-y-4">
              {consents.map((consent) => (
                <div
                  key={consent.id}
                  className="flex items-center justify-between p-4 rounded-lg border"
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <p className="font-medium">{getConsentLabel(consent.consentType)}</p>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {getConsentDescription(consent.consentType)}
                    </p>
                    {consent.grantedAt && (
                      <p className="text-xs text-muted-foreground mt-1">
                        Granted on {formatDate(consent.grantedAt)}
                      </p>
                    )}
                    {consent.withdrawnAt && (
                      <p className="text-xs text-muted-foreground mt-1">
                        Withdrawn on {formatDate(consent.withdrawnAt)}
                      </p>
                    )}
                  </div>
                  <Switch
                    checked={consent.granted}
                    onCheckedChange={(checked) => handleToggleConsent(consent.consentType, checked)}
                    disabled={updateConsentMutation.isPending}
                  />
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Account Deletion */}
      <Card className="border-destructive">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <Trash2 className="h-5 w-5" aria-hidden="true" />
            Delete Account
          </CardTitle>
          <CardDescription>
            Permanently delete your account and all associated data (Article 17 - Right to Erasure)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive" className="mb-4">
            <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            <AlertTitle>Warning: This action cannot be undone</AlertTitle>
            <AlertDescription>
              Deleting your account will permanently remove all your data, including:
              <ul className="list-disc list-inside mt-2">
                <li>Your profile and personal information</li>
                <li>All activity history and logs</li>
                <li>Connected devices and sessions</li>
                <li>Organization memberships</li>
              </ul>
            </AlertDescription>
          </Alert>
          <Button variant="destructive" onClick={() => setShowDeleteDialog(true)}>
            Request Account Deletion
          </Button>
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="text-destructive">Delete Your Account</DialogTitle>
            <DialogDescription>
              This action is permanent and cannot be undone. All your data will be permanently deleted within 30 days.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="reason">Reason for leaving (optional)</Label>
              <Input
                id="reason"
                value={deleteReason}
                onChange={(e) => setDeleteReason(e.target.value)}
                placeholder="Tell us why you're leaving"
              />
            </div>
            <p className="text-sm">
              To confirm, type <strong>DELETE MY ACCOUNT</strong> in the box below:
            </p>
            <Input
              value={deleteConfirmation}
              onChange={(e) => setDeleteConfirmation(e.target.value)}
              placeholder="Type DELETE MY ACCOUNT to confirm"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteDialog(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDeleteAccount}
              disabled={deleteConfirmation !== 'DELETE MY ACCOUNT' || deleteAccountMutation.isPending}
            >
              {deleteAccountMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                  Processing...
                </>
              ) : (
                'Permanently Delete Account'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
