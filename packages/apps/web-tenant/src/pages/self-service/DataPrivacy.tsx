//! Data Privacy - GDPR & Privacy Compliance Center
//!
//! Allows users to:
//! - View what data is collected about them
//! - Download their personal data (GDPR Article 20)
//! - Request account deletion (GDPR Article 17)
//! - Manage consent preferences
//! - View data processing records
//! - Configure privacy settings

import { useState } from 'react'
import {
  Shield,
  Download,
  Trash2,
  FileText,
  Check,
  Clock,
  AlertCircle,
  ExternalLink,
  Database,
  Eye,
  Lock,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Switch } from '@/components/ui/Switch'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/Dialog'
import { useNotificationStore } from '@/store'

interface DataCategory {
  id: string
  name: string
  description: string
  dataTypes: string[]
  retentionDays: number
  legalBasis: 'consent' | 'contract' | 'legal_obligation' | 'legitimate_interest'
  isOptional: boolean
}

interface ConsentRecord {
  id: string
  purpose: string
  granted: boolean
  grantedAt: Date | null
  lastUpdated: Date
  required: boolean
}

interface DataExportRequest {
  id: string
  status: 'pending' | 'processing' | 'ready' | 'expired'
  requestedAt: Date
  completedAt: Date | null
  expiresAt: Date | null
  format: 'json' | 'csv'
  size: string | null
}

// Mock data
const dataCategories: DataCategory[] = [
  {
    id: 'profile',
    name: 'Profile Information',
    description: 'Basic account information used to identify you',
    dataTypes: ['Email address', 'Name', 'Profile picture', 'Phone number', 'Timezone', 'Language'],
    retentionDays: 2555, // 7 years after account deletion
    legalBasis: 'contract',
    isOptional: false,
  },
  {
    id: 'activity',
    name: 'Activity Logs',
    description: 'Records of your actions within the system',
    dataTypes: ['Login history', 'Page views', 'Actions performed', 'IP addresses', 'User agent'],
    retentionDays: 365,
    legalBasis: 'legitimate_interest',
    isOptional: false,
  },
  {
    id: 'analytics',
    name: 'Analytics Data',
    description: 'Data used to improve our services',
    dataTypes: ['Feature usage', 'Performance metrics', 'Error logs', 'Device information'],
    retentionDays: 90,
    legalBasis: 'consent',
    isOptional: true,
  },
  {
    id: 'marketing',
    name: 'Marketing Preferences',
    description: 'Your preferences for marketing communications',
    dataTypes: ['Email preferences', 'Communication history', 'Campaign interactions'],
    retentionDays: 365,
    legalBasis: 'consent',
    isOptional: true,
  },
]

const initialConsents: ConsentRecord[] = [
  {
    id: 'analytics',
    purpose: 'Analytics & Product Improvement',
    granted: true,
    grantedAt: new Date('2024-01-15'),
    lastUpdated: new Date('2024-01-15'),
    required: false,
  },
  {
    id: 'marketing',
    purpose: 'Marketing Communications',
    granted: false,
    grantedAt: null,
    lastUpdated: new Date('2024-01-15'),
    required: false,
  },
  {
    id: 'third_party',
    purpose: 'Third-Party Integrations',
    granted: true,
    grantedAt: new Date('2024-01-15'),
    lastUpdated: new Date('2024-01-15'),
    required: false,
  },
]

const mockExportHistory: DataExportRequest[] = [
  {
    id: 'exp_1',
    status: 'ready',
    requestedAt: new Date(Date.now() - 86400000 * 2),
    completedAt: new Date(Date.now() - 86400000),
    expiresAt: new Date(Date.now() + 86400000 * 5),
    format: 'json',
    size: '2.4 MB',
  },
]

function LegalBasisBadge({ basis }: { basis: DataCategory['legalBasis'] }) {
  const labels: Record<typeof basis, string> = {
    consent: 'Consent',
    contract: 'Contract',
    legal_obligation: 'Legal Obligation',
    legitimate_interest: 'Legitimate Interest',
  }
  
  const variants: Record<typeof basis, 'default' | 'secondary' | 'success' | 'warning'> = {
    consent: 'success',
    contract: 'secondary',
    legal_obligation: 'warning',
    legitimate_interest: 'default',
  }
  
  return <Badge variant={variants[basis]}>{labels[basis]}</Badge>
}

export function DataPrivacy() {
  const [consents, setConsents] = useState<ConsentRecord[]>(initialConsents)
  const [exportHistory, setExportHistory] = useState<DataExportRequest[]>(mockExportHistory)
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [showExportDialog, setShowExportDialog] = useState(false)
  const [deleteConfirmation, setDeleteConfirmation] = useState('')
  const [isExporting, setIsExporting] = useState(false)
  const { addNotification } = useNotificationStore()

  const handleConsentToggle = (consentId: string, granted: boolean) => {
    setConsents(consents.map(c => 
      c.id === consentId 
        ? { ...c, granted, grantedAt: granted ? new Date() : null, lastUpdated: new Date() }
        : c
    ))
    
    addNotification({
      type: 'success',
      title: 'Preference saved',
      message: `Your preference has been updated.`,
    })
  }

  const handleExportRequest = async () => {
    setIsExporting(true)
    
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 2000))
    
    const newExport: DataExportRequest = {
      id: `exp_${Date.now()}`,
      status: 'processing',
      requestedAt: new Date(),
      completedAt: null,
      expiresAt: null,
      format: 'json',
      size: null,
    }
    
    setExportHistory([newExport, ...exportHistory])
    setIsExporting(false)
    setShowExportDialog(false)
    
    addNotification({
      type: 'success',
      title: 'Export requested',
      message: 'Your data export is being prepared. You will be notified when it is ready.',
    })
  }

  const handleDeleteRequest = () => {
    if (deleteConfirmation !== 'DELETE') {
      addNotification({
        type: 'error',
        title: 'Confirmation required',
        message: 'Please type DELETE to confirm account deletion.',
      })
      return
    }
    
    addNotification({
      type: 'success',
      title: 'Deletion requested',
      message: 'Your account deletion request has been submitted. You will receive an email with further instructions.',
    })
    setShowDeleteDialog(false)
  }

  const formatRetention = (days: number): string => {
    if (days >= 365) return `${Math.floor(days / 365)} years`
    if (days >= 30) return `${Math.floor(days / 30)} months`
    return `${days} days`
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Data & Privacy</h1>
        <p className="text-muted-foreground">
          Manage your personal data and privacy preferences
        </p>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <Card className="p-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-blue-100 dark:bg-blue-900 flex items-center justify-center">
              <Download className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="font-medium">Download Your Data</p>
              <p className="text-sm text-muted-foreground">Get a copy of your personal data</p>
            </div>
          </div>
          <Button onClick={() => setShowExportDialog(true)}>
            Request Export
          </Button>
        </Card>

        <Card className="p-6 flex items-center justify-between border-destructive/20">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-red-100 dark:bg-red-900 flex items-center justify-center">
              <Trash2 className="w-6 h-6 text-red-600 dark:text-red-400" />
            </div>
            <div>
              <p className="font-medium text-destructive">Delete Account</p>
              <p className="text-sm text-muted-foreground">Permanently delete your account and data</p>
            </div>
          </div>
          <Button variant="destructive" onClick={() => setShowDeleteDialog(true)}>
            Request Deletion
          </Button>
        </Card>
      </div>

      {/* Data Categories */}
      <Card>
        <div className="p-6 border-b">
          <div className="flex items-center gap-3">
            <Database className="w-5 h-5 text-primary" />
            <h2 className="text-lg font-semibold">Data We Collect</h2>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Overview of the data categories we process and why
          </p>
        </div>

        <div className="divide-y">
          {dataCategories.map((category) => (
            <div key={category.id} className="p-6">
              <button type="button"
                onClick={() => setExpandedCategory(expandedCategory === category.id ? null : category.id)}
                className="w-full flex items-start justify-between text-left"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium">{category.name}</p>
                    {category.isOptional && (
                      <Badge variant="secondary" className="text-xs">Optional</Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">{category.description}</p>
                  <div className="flex items-center gap-3 mt-2">
                    <LegalBasisBadge basis={category.legalBasis} />
                    <span className="text-xs text-muted-foreground">
                      Retention: {formatRetention(category.retentionDays)}
                    </span>
                  </div>
                </div>
                {expandedCategory === category.id ? (
                  <ChevronUp className="w-5 h-5 text-muted-foreground" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-muted-foreground" />
                )}
              </button>

              {expandedCategory === category.id && (
                <div className="mt-4 pt-4 border-t">
                  <p className="text-sm font-medium mb-2">Data types in this category:</p>
                  <div className="flex flex-wrap gap-2">
                    {category.dataTypes.map((type) => (
                      <span 
                        key={type} 
                        className="inline-flex items-center px-2 py-1 rounded-md bg-muted text-xs"
                      >
                        {type}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>

      {/* Consent Management */}
      <Card>
        <div className="p-6 border-b">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-primary" />
            <h2 className="text-lg font-semibold">Consent Preferences</h2>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Manage your consent for optional data processing
          </p>
        </div>

        <div className="divide-y">
          {consents.map((consent) => (
            <div key={consent.id} className="p-6 flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <p className="font-medium">{consent.purpose}</p>
                  {consent.required && (
                    <Badge variant="secondary" className="text-xs">Required</Badge>
                  )}
                </div>
                <p className="text-sm text-muted-foreground mt-1">
                  {consent.granted 
                    ? `Granted on ${consent.grantedAt?.toLocaleDateString()}`
                    : 'Not granted'
                  }
                  {' • '}
                  Last updated: {consent.lastUpdated.toLocaleDateString()}
                </p>
              </div>
              <Switch
                checked={consent.granted}
                onCheckedChange={(checked) => handleConsentToggle(consent.id, checked)}
                disabled={consent.required}
              />
            </div>
          ))}
        </div>
      </Card>

      {/* Export History */}
      {exportHistory.length > 0 && (
        <Card>
          <div className="p-6 border-b">
            <div className="flex items-center gap-3">
              <FileText className="w-5 h-5 text-primary" />
              <h2 className="text-lg font-semibold">Data Export History</h2>
            </div>
          </div>

          <div className="divide-y">
            {exportHistory.map((export_) => (
              <div key={export_.id} className="p-6 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-medium">Data Export</p>
                    {export_.status === 'ready' && (
                      <Badge variant="success" className="text-xs">Ready</Badge>
                    )}
                    {export_.status === 'processing' && (
                      <Badge variant="warning" className="text-xs">Processing</Badge>
                    )}
                    {export_.status === 'pending' && (
                      <Badge variant="secondary" className="text-xs">Pending</Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">
                    Requested: {export_.requestedAt.toLocaleDateString()}
                    {export_.size && ` • Size: ${export_.size}`}
                    {export_.expiresAt && (
                      <span className="text-amber-600">
                        {' • '}Expires: {export_.expiresAt.toLocaleDateString()}
                      </span>
                    )}
                  </p>
                </div>
                {export_.status === 'ready' && (
                  <Button variant="outline" size="sm">
                    <Download className="w-4 h-4 mr-2" />
                    Download
                  </Button>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Privacy Rights Info */}
      <Card className="p-6">
        <h3 className="font-semibold mb-4">Your Privacy Rights</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-start gap-3">
            <Eye className="w-5 h-5 text-primary mt-0.5" />
            <div>
              <p className="font-medium text-sm">Right to Access</p>
              <p className="text-xs text-muted-foreground">
                You can request a copy of all data we hold about you
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <Check className="w-5 h-5 text-primary mt-0.5" />
            <div>
              <p className="font-medium text-sm">Right to Rectification</p>
              <p className="text-xs text-muted-foreground">
                You can update your personal information at any time
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <Trash2 className="w-5 h-5 text-primary mt-0.5" />
            <div>
              <p className="font-medium text-sm">Right to Erasure</p>
              <p className="text-xs text-muted-foreground">
                You can request deletion of your personal data
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <Lock className="w-5 h-5 text-primary mt-0.5" />
            <div>
              <p className="font-medium text-sm">Right to Restrict Processing</p>
              <p className="text-xs text-muted-foreground">
                You can limit how we use your data
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <Download className="w-5 h-5 text-primary mt-0.5" />
            <div>
              <p className="font-medium text-sm">Right to Portability</p>
              <p className="text-xs text-muted-foreground">
                You can export your data in a portable format
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-primary mt-0.5" />
            <div>
              <p className="font-medium text-sm">Right to Object</p>
              <p className="text-xs text-muted-foreground">
                You can object to certain types of processing
              </p>
            </div>
          </div>
        </div>
        <div className="mt-6 pt-6 border-t">
          <a 
            href="/privacy-policy" 
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center text-sm text-primary hover:underline"
          >
            View full Privacy Policy
            <ExternalLink className="w-3 h-3 ml-1" />
          </a>
        </div>
      </Card>

      {/* Export Dialog */}
      <Dialog open={showExportDialog} onOpenChange={setShowExportDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Download Your Data</DialogTitle>
            <DialogDescription>
              We will prepare a copy of your personal data. This may take a few minutes.
              You will be notified when the export is ready for download.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="flex items-start gap-3 p-3 bg-muted rounded-lg">
              <Clock className="w-5 h-5 text-muted-foreground flex-shrink-0 mt-0.5" />
              <p className="text-sm text-muted-foreground">
                The export will include all data categories listed above. 
                The file will be available for download for 7 days.
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowExportDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleExportRequest} isLoading={isExporting}>
              Request Export
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Account Dialog */}
      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="text-destructive">Delete Your Account</DialogTitle>
            <DialogDescription>
              This action cannot be undone. All your data will be permanently deleted.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4">
              <p className="text-sm font-medium text-destructive mb-2">You will lose:</p>
              <ul className="text-sm text-destructive/80 space-y-1">
                <li>• All your account data and settings</li>
                <li>• Access to all organizations you own</li>
                <li>• All API keys and integrations</li>
                <li>• Audit logs associated with your account</li>
              </ul>
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">
                Type DELETE to confirm:
              </label>
              <input
                type="text"
                value={deleteConfirmation}
                onChange={(e) => setDeleteConfirmation(e.target.value)}
                className="w-full px-3 py-2 bg-muted rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-destructive"
                placeholder="DELETE"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteDialog(false)}>
              Cancel
            </Button>
            <Button 
              variant="destructive" 
              onClick={handleDeleteRequest}
              disabled={deleteConfirmation !== 'DELETE'}
            >
              Delete Account
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
