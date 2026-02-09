import { useQuery } from '@tanstack/react-query'
import { searchUsers, getUser, type PlatformUserResponse, type PlatformUserDetailResponse } from '../server/internal-api'
import { env } from '../env/client'

const UI_TOKEN = env.VITE_INTERNAL_UI_TOKEN || ''

export type User = PlatformUserResponse

export function useUsers({
  tenantId,
  email,
  page,
}: {
  tenantId?: string
  email?: string
  page?: number
} = {}) {
  return useQuery<{ data: User[]; pagination?: { page?: number; perPage?: number; total?: number; totalPages?: number } }>({
    queryKey: ['users', { tenantId, email, page }],
    queryFn: async () => {
      const result = await searchUsers({
        data: { tenantId, email, page, uiToken: UI_TOKEN },
      })
      return {
        data: result.data ?? [],
        pagination: result.pagination,
      }
    },
  })
}

export function useUser(userId: string) {
  return useQuery<PlatformUserDetailResponse>({
    queryKey: ['users', userId],
    queryFn: async () => {
      return getUser({ data: { userId, uiToken: UI_TOKEN } })
    },
    enabled: Boolean(userId),
  })
}

export function useTenantUsers(tenantId: string) {
  return useUsers({ tenantId })
}
