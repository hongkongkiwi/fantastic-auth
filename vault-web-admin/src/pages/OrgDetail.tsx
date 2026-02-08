import { useParams } from 'react-router-dom'
import { OrgDetails } from '@/components/organizations/OrgDetails'

export function OrgDetail() {
  const { id } = useParams<{ id: string }>()

  if (!id) {
    return (
      <div className="text-center py-12">
        <p className="text-muted-foreground">Organization ID is required</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <OrgDetails orgId={id} />
    </div>
  )
}
