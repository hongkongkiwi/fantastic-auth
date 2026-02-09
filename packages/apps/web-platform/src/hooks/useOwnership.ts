import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getOwnershipStatus,
  canDeleteUser,
  deleteUser,
  requestOwnershipTransfer,
  acceptOwnershipTransfer,
  getOwnershipTransfers,
  getTenantOwners,
  type OwnershipStatus,
  type OwnershipTransferRequest,
} from '../server/internal-api'

export function useOwnershipStatus(userId: string) {
  return useQuery<OwnershipStatus>({
    queryKey: ['ownership', 'status', userId],
    queryFn: async () => {
      return getOwnershipStatus({ data: { userId } })
    },
    enabled: Boolean(userId),
  })
}

export function useCanDeleteUser(userId: string) {
  return useQuery<{
    canDelete: boolean
    reason: string | null
    message: string | null
    ownedTenants: string[]
  }>({
    queryKey: ['ownership', 'canDelete', userId],
    queryFn: async () => {
      return canDeleteUser({ data: { userId } })
    },
    enabled: Boolean(userId),
  })
}

export function useDeleteUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ userId, tenantId }: { userId: string; tenantId?: string }) => {
      return deleteUser({ data: { userId, tenantId } })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({ queryKey: ['ownership'] })
    },
  })
}

export function useRequestOwnershipTransfer() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({
      tenantId,
      fromUserId,
      toUserId,
    }: {
      tenantId: string
      fromUserId: string
      toUserId: string
    }) => {
      return requestOwnershipTransfer({
        data: { tenantId, fromUserId, toUserId },
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ownership', 'transfers'] })
    },
  })
}

export function useAcceptOwnershipTransfer() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ transferId, accept }: { transferId: string; accept: boolean }) => {
      return acceptOwnershipTransfer({ data: { transferId, accept } })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ownership', 'transfers'] })
      queryClient.invalidateQueries({ queryKey: ['ownership', 'status'] })
      queryClient.invalidateQueries({ queryKey: ['tenants'] })
    },
  })
}

export function useOwnershipTransfers({
  userId,
  tenantId,
  status,
}: {
  userId?: string
  tenantId?: string
  status?: 'pending' | 'accepted' | 'rejected' | 'expired'
} = {}) {
  return useQuery<{ data: OwnershipTransferRequest[] }>({
    queryKey: ['ownership', 'transfers', { userId, tenantId, status }],
    queryFn: async () => {
      return getOwnershipTransfers({ data: { userId, tenantId, status } })
    },
  })
}

export function useTenantOwners(tenantId: string) {
  return useQuery<{
    primaryOwner: { userId: string; name: string; email: string } | null
  }>({
    queryKey: ['ownership', 'owners', tenantId],
    queryFn: async () => {
      return getTenantOwners({ data: { tenantId } })
    },
    enabled: Boolean(tenantId),
  })
}

// Helper hook for ownership guards
export function useOwnershipGuards(userId: string) {
  const { data: status, isLoading: statusLoading } = useOwnershipStatus(userId)
  const { data: canDelete, isLoading: canDeleteLoading } = useCanDeleteUser(userId)

  return {
    isLoading: statusLoading || canDeleteLoading,
    status,
    canDelete: canDelete?.canDelete ?? false,
    deleteBlockReason: canDelete?.reason ?? null,
    deleteBlockMessage: canDelete?.message ?? null,
    ownedTenants: canDelete?.ownedTenants ?? [],
  }
}
