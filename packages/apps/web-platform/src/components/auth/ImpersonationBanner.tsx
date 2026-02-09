import { ShieldAlert, LogOut } from 'lucide-react'
import { Button } from '../ui/Button'
import { toast } from '../ui/Toaster'
import { endImpersonationRecord } from './ImpersonationAudit'

interface ImpersonationBannerProps {
  impersonatedUser?: {
    id: string
    email: string
    name?: string
  }
  onStopImpersonating?: () => void
}

export function ImpersonationBanner({ 
  impersonatedUser,
  onStopImpersonating 
}: ImpersonationBannerProps) {
  if (!impersonatedUser) {
    return null
  }

  const user = impersonatedUser

  const handleStopImpersonating = () => {
    // End audit record
    endImpersonationRecord(user?.id || 'unknown')

    // Call callback if provided
    onStopImpersonating?.()

    toast.success('Support access ended')
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-amber-500 text-white px-4 py-2">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5" />
          <span className="font-medium">
            Impersonating: {user.name || user.email}
          </span>
          <span className="text-amber-100 text-sm">
            ({user.id})
          </span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleStopImpersonating}
          className="text-white hover:bg-amber-600 gap-2"
        >
          <LogOut className="h-4 w-4" />
          Stop Impersonating
        </Button>
      </div>
    </div>
  )
}
