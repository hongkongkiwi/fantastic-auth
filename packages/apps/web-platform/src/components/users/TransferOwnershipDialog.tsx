import { useState, useMemo } from 'react'
import { ArrowRightLeft, User as UserIcon, Check, AlertCircle } from 'lucide-react'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../ui/SelectRadix'
import { useRequestOwnershipTransfer } from '../../hooks/useOwnership'
import { useUsers } from '../../hooks/useUsers'
import type { User as AuthUser } from '../../hooks/useAuth'

type User = AuthUser

interface TransferOwnershipDialogProps {
  user: User | null
  tenantId: string
  isOpen: boolean
  onClose: () => void
  onSuccess?: () => void
}

export function TransferOwnershipDialog({
  user,
  tenantId,
  isOpen,
  onClose,
  onSuccess,
}: TransferOwnershipDialogProps) {
  const [selectedUserId, setSelectedUserId] = useState('')
  const [step, setStep] = useState<'select' | 'confirm'>('select')
  
  const { data: usersData, isLoading: usersLoading } = useUsers({ tenantId })
  const requestTransfer = useRequestOwnershipTransfer()

  // Filter out current owner and get eligible users
  const eligibleUsers = useMemo(() => {
    const users = usersData?.data as { id: string; name?: string; email: string }[] | undefined
    if (!users) return []
    return users.filter((u: { id: string }) => u.id !== user?.id)
  }, [usersData, user])

  const selectedUser = useMemo(() => {
    return eligibleUsers.find((u: { id: string }) => u.id === selectedUserId)
  }, [eligibleUsers, selectedUserId])

  const handleNext = () => {
    if (selectedUserId) {
      setStep('confirm')
    }
  }

  const handleBack = () => {
    setStep('select')
  }

  const handleTransfer = async () => {
    if (!user || !selectedUserId) return

    try {
      await requestTransfer.mutateAsync({
        tenantId,
        fromUserId: user.id,
        toUserId: selectedUserId,
      })
      
      setSelectedUserId('')
      setStep('select')
      onSuccess?.()
      onClose()
    } catch (error) {
      // Error is handled by mutation
    }
  }

  const handleClose = () => {
    setSelectedUserId('')
    setStep('select')
    onClose()
  }

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ArrowRightLeft className="h-5 w-5" />
            Transfer Ownership
          </DialogTitle>
          <DialogDescription>
            {step === 'select'
              ? 'Select a new primary owner for this tenant.'
              : 'Review and confirm the ownership transfer.'}
          </DialogDescription>
        </DialogHeader>

        {step === 'select' ? (
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Current Owner</label>
              <div className="flex items-center gap-3 rounded-md border bg-muted/50 px-3 py-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10">
                  <UserIcon className="h-4 w-4 text-primary" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{user?.name}</p>
                  <p className="text-xs text-muted-foreground truncate">
                    {user?.email}
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">New Owner</label>
              <Select
                value={selectedUserId}
                onValueChange={setSelectedUserId}
                disabled={usersLoading}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a user…" />
                </SelectTrigger>
                <SelectContent>
                  {eligibleUsers.map((u: { id: string; name?: string; email: string }) => (
                    <SelectItem key={u.id} value={u.id}>
                      <div className="flex flex-col items-start">
                        <span className="font-medium">{u.name}</span>
                        <span className="text-xs text-muted-foreground">
                          {u.email}
                        </span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {eligibleUsers.length === 0 && !usersLoading && (
                <p className="text-xs text-muted-foreground">
                  No eligible users found. Add more users to this tenant first.
                </p>
              )}
            </div>

            <Alert variant="info" className="bg-blue-500/10 border-blue-500/20">
              <AlertCircle className="h-4 w-4 text-blue-500" />
              <AlertDescription className="text-sm text-blue-700 dark:text-blue-300">
                The selected user will receive an invitation to accept ownership.
                They must accept within 7 days.
              </AlertDescription>
            </Alert>
          </div>
        ) : (
          <div className="space-y-4 py-4">
            <div className="rounded-lg border p-4 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">From</p>
                  <p className="font-medium">{user?.name}</p>
                  <p className="text-xs text-muted-foreground">{user?.email}</p>
                </div>
                <ArrowRightLeft className="h-5 w-5 text-muted-foreground" />
                <div className="text-right">
                  <p className="text-xs text-muted-foreground">To</p>
                  <p className="font-medium">{selectedUser?.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {selectedUser?.email}
                  </p>
                </div>
              </div>
            </div>

            <Alert variant="warning">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                After transfer, you will lose primary owner privileges for this
                tenant. This action requires the recipient&apos;s acceptance.
              </AlertDescription>
            </Alert>
          </div>
        )}

        <DialogFooter className="gap-2 sm:gap-0">
          {step === 'select' ? (
            <>
              <Button variant="outline" onClick={handleClose}>
                Cancel
              </Button>
              <Button onClick={handleNext} disabled={!selectedUserId}>
                Next
              </Button>
            </>
          ) : (
            <>
              <Button variant="outline" onClick={handleBack}>
                Back
              </Button>
              <Button
                onClick={handleTransfer}
                disabled={requestTransfer.isPending}
                className="gap-2"
              >
                {requestTransfer.isPending ? (
                  'Sending…'
                ) : (
                  <>
                    <Check className="h-4 w-4" />
                    Send Invitation
                  </>
                )}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
