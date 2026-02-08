import { useParams } from 'react-router-dom'
import { UserDetails } from '@/components/users/UserDetails'

export function UserDetail() {
  const { id } = useParams<{ id: string }>()

  if (!id) {
    return (
      <div className="text-center py-12">
        <p className="text-muted-foreground">User ID is required</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <UserDetails userId={id} />
    </div>
  )
}
