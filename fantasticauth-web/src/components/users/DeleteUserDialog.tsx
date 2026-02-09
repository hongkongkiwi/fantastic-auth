import { useState } from 'react'
import { AlertTriangle, Building2, ArrowRightLeft } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/Dialog'
import { Button } from '../ui/Button'
import { Alert, AlertDescription } from '../ui/Alert'
import { useOwnershipGuards, useDeleteUser } from '../../hooks/useOwnership'
import type { User as AuthUser } from '../../hooks/useAuth'

// Re-export type for component props
type User = AuthUser

interface DeleteUserDialogProps {
  user: User | null
  isOpen: boolean
  onClose: () => void
  onSuccess?: () => void
  onTransferOwnership?: (userId: string) => void
}

export function DeleteUserDialog({
  user,
  isOpen,
  onClose,
  onSuccess,
  onTransferOwnership,
}: DeleteUserDialogProps) {
  const [confirmText, setConfirmText] = useState('')
  const userId = user?.id ?? ''
  const { isLoading, canDelete, deleteBlockReason, deleteBlockMessage, ownedTenants } =
    useOwnershipGuards(userId)
  const deleteUser = useDeleteUser()

  const isBlocked = deleteBlockReason === 'PRIMARY_OWNER'
  const canProceed = !isLoading && canDelete && confirmText === 'DELETE'

  const handleDelete = async () => {
    if (!canProceed || !user) return

    try {
      await deleteUser.mutateAsync({ userId: user.id })
      setConfirmText('')
      onSuccess?.()
      onClose()
    } catch (error) {
      // Error is handled by mutation
    }
  }

  const handleTransferClick = () => {
    if (user && onTransferOwnership) {
      onTransferOwnership(user.id)
      onClose()
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-destructive">
            <AlertTriangle className="h-5 w-5" />
            Delete User
          </DialogTitle>
          <DialogDescription>
            This action cannot be undone. This will permanently delete{' '}
            <strong>{user?.email}</strong> and remove their data from our servers.
          </DialogDescription>
        </DialogHeader>

        {isBlocked && (
          <Alert variant="destructive" className="mt-4">
            <Building2 className="h-4 w-4" />
            <AlertDescription className="mt-2">
              <p className="font-medium">Cannot Delete Account</p>
              <p className="mt-1 text-sm">{deleteBlockMessage}</p>
              {ownedTenants.length > 0 && (
                <div className="mt-2">
                  <p className="text-sm font-medium">Owned Tenants:</p>
                  <ul className="mt-1 list-inside list-disc text-sm">
                    {ownedTenants.map((tenantId) => (
                      <li key={tenantId}>{tenantId}</li>
                    ))}
                  </ul>
                </div>
              )}
            </AlertDescription>
          </Alert>
        )}

        {!isBlocked && (
          <div className="space-y-4 py-4">
            <p className="text-sm text-muted-foreground">
              To confirm deletion, type <strong>DELETE</strong> below:
            </p>
            <input
              type="text"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder="Type DELETE to confirm"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
          </div>
        )}

        <DialogFooter className="gap-2 sm:gap-0">
          {isBlocked ? (
            <>
              <Button variant="outline" onClick={onClose}>
                Cancel
              </Button>
              <Button
                variant="outline"
                onClick={handleTransferClick}
                className="gap-2"
              >
                <ArrowRightLeft className="h-4 w-4" />
                Transfer Ownership
              </Button>
            </>
          ) : (
            <>
              <Button variant="outline" onClick={onClose}>
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={handleDelete}
                disabled={!canProceed || deleteUser.isPending}
              >
                {deleteUser.isPending ? 'Deleting…' : 'Delete User'}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
