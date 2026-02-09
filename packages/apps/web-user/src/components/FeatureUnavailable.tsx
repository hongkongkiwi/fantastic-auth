import { Lock } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'

interface FeatureUnavailableProps {
  title: string
  description: string
}

export function FeatureUnavailable({ title, description }: FeatureUnavailableProps) {
  return (
    <Card className="max-w-3xl">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Lock className="h-5 w-5 text-muted-foreground" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-muted-foreground">
        <p>{description}</p>
        <p className="text-sm">
          This section is disabled by default because backend endpoints are not fully integrated
          yet. Enable the matching `VITE_FEATURE_USER_*` flag only after API readiness.
        </p>
      </CardContent>
    </Card>
  )
}
