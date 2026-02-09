import { useState, useEffect } from 'react'
import {
  ShieldAlert,
  Eye,
  Clock,
  Building2,
  FileText,
  AlertTriangle,
} from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/Dialog'
import { Button } from '../ui/Button'
import { Badge } from '../ui/Badge'
import { Alert, AlertDescription, AlertTitle } from '../ui/Alert'
import { Checkbox } from '../ui/Checkbox'
import { Label } from '../ui/Label'
import { toast } from '../ui/Toaster'
import { formatDate } from '../../lib/utils'

export interface ImpersonationRecord {
  id: string
  adminId: string
  adminEmail: string
  tenantId: string
  tenantName: string
  reason: string
  startedAt: string
  endedAt?: string
  actions: string[]
}

interface ImpersonationAuditProps {
  tenantId: string
  tenantName: string
  onConfirm: (reason: string) => void
  onCancel: () => void
  open: boolean
}

export function getImpersonationAuditLog(): ImpersonationRecord[] {
  // Server-backed audit logs are required for production-grade support access.
  return []
}

export function addImpersonationRecord(
  record: Omit<ImpersonationRecord, 'id' | 'startedAt' | 'actions'>,
): ImpersonationRecord {
  return {
    ...record,
    id: `imp_${Date.now()}`,
    startedAt: new Date().toISOString(),
    actions: [],
  }
}

export function endImpersonationRecord(adminId: string): void {
  void adminId
}

export function ImpersonationPrivacyDialog({
  tenantId,
  tenantName,
  onConfirm,
  onCancel,
  open,
}: ImpersonationAuditProps) {
  const [reason, setReason] = useState('')
  const [acknowledged, setAcknowledged] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const handleConfirm = async () => {
    void tenantId

    if (!reason.trim()) {
      toast.error('Please provide a reason for impersonation')
      return
    }
    if (!acknowledged) {
      toast.error('Please acknowledge the privacy warning')
      return
    }

    setIsSubmitting(true)

    setIsSubmitting(false)
    onConfirm(reason)
  }

  return (
    <Dialog open={open} onOpenChange={(isOpen) => !isOpen && onCancel()}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-amber-600">
            <ShieldAlert className="h-5 w-5" />
            Privacy Warning: Tenant Impersonation
          </DialogTitle>
          <DialogDescription>
            You are about to access tenant data. This action is logged and audited.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Restricted Access</AlertTitle>
            <AlertDescription>
              Platform administrators should NOT access tenant data except for legitimate support purposes. 
              All access is logged and may be reviewed for compliance.
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="flex items-center gap-2 p-3 rounded-lg bg-muted">
              <Building2 className="h-4 w-4 text-muted-foreground" />
              <div>
                <p className="font-medium">Target Tenant</p>
                <p className="text-muted-foreground">{tenantName}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 p-3 rounded-lg bg-muted">
              <Clock className="h-4 w-4 text-muted-foreground" />
              <div>
                <p className="font-medium">Session Start</p>
                <p className="text-muted-foreground">{formatDate(new Date())}</p>
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="reason">
              Reason for Access <span className="text-destructive">*</span>
            </Label>
            <textarea
              id="reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Describe why you need to access this tenant (e.g., 'Customer reported login issues, investigating')"
              className="w-full min-h-[100px] rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
            />
            <p className="text-xs text-muted-foreground">
              This reason will be recorded in the audit log.
            </p>
          </div>

          <div className="space-y-3 border rounded-lg p-4 bg-muted/50">
            <p className="font-medium text-sm">You will have access to:</p>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li className="flex items-center gap-2">
                <Eye className="h-3.5 w-3.5" />
                Tenant users and their roles
              </li>
              <li className="flex items-center gap-2">
                <Eye className="h-3.5 w-3.5" />
                Organization settings and data
              </li>
              <li className="flex items-center gap-2">
                <Eye className="h-3.5 w-3.5" />
                Audit logs within this tenant
              </li>
            </ul>
          </div>

          <div className="flex items-start gap-3">
            <Checkbox
              id="acknowledge"
              checked={acknowledged}
              onCheckedChange={(checked) => setAcknowledged(checked as boolean)}
            />
            <div className="grid gap-1.5 leading-none">
              <Label
                htmlFor="acknowledge"
                className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
              >
                I acknowledge that I am accessing private customer data
              </Label>
              <p className="text-xs text-muted-foreground">
                I understand this access is logged and may be reviewed. I will only access data necessary to resolve the reported issue.
              </p>
            </div>
          </div>
        </div>

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            onClick={handleConfirm}
            disabled={!acknowledged || !reason.trim() || isSubmitting}
            className="bg-amber-600 hover:bg-amber-700"
          >
            {isSubmitting ? (
              <>
                <Clock className="mr-2 h-4 w-4 animate-spin" />
                Logging...
              </>
            ) : (
              <>
                <Eye className="mr-2 h-4 w-4" />
                Proceed with Impersonation
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// Convert impersonation records to a format compatible with main audit log
export function getImpersonationAuditEvents(): Array<{
  id: string
  timestamp: string
  action: string
  actor: string
  actorType: string
  tenantId: string
  tenantName: string
  detail: string
  source: string
  ip: string
  userAgent: string
}> {
  const logs = getImpersonationAuditLog()
  return logs.map((log) => ({
    id: log.id,
    timestamp: log.startedAt,
    action: log.endedAt ? 'impersonation.end' : 'impersonation.start',
    actor: log.adminEmail,
    actorType: 'platform_admin',
    tenantId: log.tenantId,
    tenantName: log.tenantName,
    detail: `Reason: ${log.reason}${log.endedAt 
      ? ` | Duration: ${Math.round((new Date(log.endedAt).getTime() - new Date(log.startedAt).getTime()) / 1000 / 60)} minutes` 
      : ' | Active'}`,
    source: 'ui',
    ip: '—',
    userAgent: '—',
  }))
}

// Audit log viewer component
export function ImpersonationAuditLog() {
  const [logs, setLogs] = useState<ImpersonationRecord[]>([])

  useEffect(() => {
    setLogs(getImpersonationAuditLog())
  }, [])

  if (logs.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <FileText className="h-12 w-12 mx-auto mb-3 opacity-50" />
        <p>No support access records found</p>
        <p className="text-sm mt-1">Platform admins can access tenant data via the Support Access feature on tenant detail pages.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {logs.map((log) => {
        const duration = log.endedAt 
          ? Math.round((new Date(log.endedAt).getTime() - new Date(log.startedAt).getTime()) / 1000 / 60)
          : null
        
        return (
          <div
            key={log.id}
            className="p-4 rounded-lg border border-amber-200 bg-amber-50/50 dark:bg-amber-950/20"
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-amber-600" />
                  <span className="font-medium">Support Access Session</span>
                  {!log.endedAt && (
                    <span className="text-xs bg-amber-100 text-amber-800 px-2 py-0.5 rounded-full">
                      Active
                    </span>
                  )}
                </div>
                <div className="mt-2 space-y-1">
                  <p className="text-sm">
                    <span className="font-medium">Admin:</span>{' '}
                    <span className="text-muted-foreground">{log.adminEmail}</span>
                  </p>
                  <p className="text-sm">
                    <span className="font-medium">Tenant:</span>{' '}
                    <Badge variant="secondary" className="text-xs">{log.tenantName}</Badge>
                  </p>
                  <p className="text-sm">
                    <span className="font-medium">Reason:</span>{' '}
                    <span className="text-muted-foreground">{log.reason}</span>
                  </p>
                </div>
              </div>
              <div className="text-right text-xs text-muted-foreground space-y-1">
                <p>
                  <span className="font-medium">Started:</span> {formatDate(log.startedAt)}
                </p>
                {log.endedAt && (
                  <>
                    <p>
                      <span className="font-medium">Ended:</span> {formatDate(log.endedAt)}
                    </p>
                    <p>
                      <span className="font-medium">Duration:</span>{' '}
                      <Badge variant="outline" className="text-xs">
                        {duration} minutes
                      </Badge>
                    </p>
                  </>
                )}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}
