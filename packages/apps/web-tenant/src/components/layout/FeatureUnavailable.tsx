import { Lock } from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'

interface FeatureUnavailableProps {
  title: string
  description: string
}

export function FeatureUnavailable({ title, description }: FeatureUnavailableProps) {
  return (
    <Card className="max-w-3xl p-8">
      <div className="flex items-start gap-4">
        <div className="rounded-lg bg-muted p-3">
          <Lock className="h-5 w-5 text-muted-foreground" />
        </div>
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold">{title}</h1>
          <p className="text-muted-foreground">{description}</p>
          <p className="text-sm text-muted-foreground">
            Enable this feature by setting the corresponding `VITE_FEATURE_*` flag to
            `true` once backend support is live.
          </p>
          <Button
            variant="outline"
            onClick={() => {
              window.location.href = '/security'
            }}
          >
            Back to Security Settings
          </Button>
        </div>
      </div>
    </Card>
  )
}
