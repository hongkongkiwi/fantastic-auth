import { useQuery, useMutation, useQueryClient, UseQueryOptions } from '@tanstack/react-query'
import { api } from '@/services/api'
import type { 
  User, Organization, Session, AuditLog, Webhook, OAuthClient, SAMLConnection,
  SecuritySettings, PrivacySettings, EmailTemplate, BrandingSettings, DashboardStats, ActivityData, SystemHealth,
  UserListParams, PaginatedResponse, OrganizationMember 
} from '@/types'

// Dashboard Hooks
export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => api.getDashboardStats(),
    refetchInterval: 30000, // Refetch every 30 seconds
  })
}

export function useActivityData(days = 30) {
  return useQuery({
    queryKey: ['dashboard', 'activity', days],
    queryFn: () => api.getActivityData(days),
  })
}

export function useSystemHealth() {
  return useQuery({
    queryKey: ['dashboard', 'health'],
    queryFn: () => api.getSystemHealth(),
    refetchInterval: 10000, // Refetch every 10 seconds
  })
}

// User Hooks
export function useUsers(params: UserListParams = {}) {
  return useQuery({
    queryKey: ['users', params],
    queryFn: () => api.getUsers(params),
    keepPreviousData: true,
  })
}

export function useUser(id: string) {
  return useQuery({
    queryKey: ['user', id],
    queryFn: () => api.getUser(id),
    enabled: !!id,
  })
}

export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<User>) => api.createUser(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })
}

export function useUpdateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<User> }) => api.updateUser(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({ queryKey: ['user', variables.id] })
    },
  })
}

export function useDeleteUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deleteUser(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })
}

export function useSuspendUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason?: string }) => api.suspendUser(id, reason),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({ queryKey: ['user', variables.id] })
    },
  })
}

export function useActivateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.activateUser(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({ queryKey: ['user', id] })
    },
  })
}

export function useImpersonateUser() {
  return useMutation({
    mutationFn: (id: string) => api.impersonateUser(id),
  })
}

export function useExportUsers() {
  return useMutation({
    mutationFn: ({ format, filters }: { format: 'csv' | 'json'; filters?: UserListParams }) =>
      api.exportUsers(format, filters),
  })
}

// User Session Hooks
export function useUserSessions(userId: string) {
  return useQuery({
    queryKey: ['user-sessions', userId],
    queryFn: () => api.getUserSessions(userId),
    enabled: !!userId,
  })
}

export function useRevokeSession() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ userId, sessionId }: { userId: string; sessionId: string }) =>
      api.revokeUserSession(userId, sessionId),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['user-sessions', variables.userId] })
    },
  })
}

// Organization Hooks
export function useOrganizations(params?: { page?: number; limit?: number; search?: string }) {
  return useQuery({
    queryKey: ['organizations', params],
    queryFn: () => api.getOrganizations(params),
    keepPreviousData: true,
  })
}

export function useOrganization(id: string) {
  return useQuery({
    queryKey: ['organization', id],
    queryFn: () => api.getOrganization(id),
    enabled: !!id,
  })
}

export function useCreateOrganization() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Organization>) => api.createOrganization(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
    },
  })
}

export function useUpdateOrganization() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Organization> }) =>
      api.updateOrganization(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
      queryClient.invalidateQueries({ queryKey: ['organization', variables.id] })
    },
  })
}

export function useDeleteOrganization() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deleteOrganization(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] })
    },
  })
}

// Organization Member Hooks
export function useOrganizationMembers(orgId: string) {
  return useQuery({
    queryKey: ['organization-members', orgId],
    queryFn: () => api.getOrganizationMembers(orgId),
    enabled: !!orgId,
  })
}

export function useAddOrganizationMember() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ orgId, userId, role }: { orgId: string; userId: string; role: string }) =>
      api.addOrganizationMember(orgId, userId, role),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['organization-members', variables.orgId] })
    },
  })
}

export function useUpdateOrganizationMember() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ orgId, userId, role }: { orgId: string; userId: string; role: string }) =>
      api.updateOrganizationMember(orgId, userId, role),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['organization-members', variables.orgId] })
    },
  })
}

export function useRemoveOrganizationMember() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ orgId, userId }: { orgId: string; userId: string }) =>
      api.removeOrganizationMember(orgId, userId),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['organization-members', variables.orgId] })
    },
  })
}

// Audit Log Hooks
export function useAuditLogs(params?: {
  page?: number
  limit?: number
  eventType?: string
  actorId?: string
  resourceType?: string
  resourceId?: string
  status?: string
  dateFrom?: string
  dateTo?: string
}) {
  return useQuery({
    queryKey: ['audit-logs', params],
    queryFn: () => api.getAuditLogs(params),
    keepPreviousData: true,
  })
}

export function useExportAuditLogs() {
  return useMutation({
    mutationFn: ({ format, filters }: { format: 'csv' | 'json'; filters?: object }) =>
      api.exportAuditLogs(format, filters),
  })
}

// Webhook Hooks
export function useWebhooks() {
  return useQuery({
    queryKey: ['webhooks'],
    queryFn: () => api.getWebhooks(),
  })
}

export function useWebhook(id: string) {
  return useQuery({
    queryKey: ['webhook', id],
    queryFn: () => api.getWebhook(id),
    enabled: !!id,
  })
}

export function useCreateWebhook() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Webhook>) => api.createWebhook(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
    },
  })
}

export function useUpdateWebhook() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Webhook> }) => api.updateWebhook(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
    },
  })
}

export function useDeleteWebhook() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deleteWebhook(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
    },
  })
}

export function useTestWebhook() {
  return useMutation({
    mutationFn: (id: string) => api.testWebhook(id),
  })
}

// OAuth Client Hooks
export function useOAuthClients() {
  return useQuery({
    queryKey: ['oauth-clients'],
    queryFn: () => api.getOAuthClients(),
  })
}

export function useCreateOAuthClient() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<OAuthClient>) => api.createOAuthClient(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oauth-clients'] })
    },
  })
}

export function useUpdateOAuthClient() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<OAuthClient> }) =>
      api.updateOAuthClient(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oauth-clients'] })
    },
  })
}

export function useDeleteOAuthClient() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deleteOAuthClient(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oauth-clients'] })
    },
  })
}

export function useRegenerateOAuthSecret() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.regenerateOAuthClientSecret(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oauth-clients'] })
    },
  })
}

// SAML Connection Hooks
export function useSAMLConnections() {
  return useQuery({
    queryKey: ['saml-connections'],
    queryFn: () => api.getSAMLConnections(),
  })
}

export function useCreateSAMLConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<SAMLConnection>) => api.createSAMLConnection(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-connections'] })
    },
  })
}

export function useUpdateSAMLConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<SAMLConnection> }) =>
      api.updateSAMLConnection(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-connections'] })
    },
  })
}

export function useDeleteSAMLConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deleteSAMLConnection(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saml-connections'] })
    },
  })
}

// Security Settings Hooks
export function useSecuritySettings() {
  return useQuery({
    queryKey: ['settings', 'security'],
    queryFn: () => api.getSecuritySettings(),
  })
}

export function useUpdateSecuritySettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: SecuritySettings) => api.updateSecuritySettings(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'security'] })
    },
  })
}

// Privacy Settings Hooks
export function usePrivacySettings() {
  return useQuery({
    queryKey: ['settings', 'privacy'],
    queryFn: () => api.getPrivacySettings(),
  })
}

export function useUpdatePrivacySettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: PrivacySettings) => api.updatePrivacySettings(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'privacy'] })
    },
  })
}

// Email Template Hooks
export function useEmailTemplates() {
  return useQuery({
    queryKey: ['settings', 'email-templates'],
    queryFn: () => api.getEmailTemplates(),
  })
}

export function useUpdateEmailTemplate() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<EmailTemplate> }) =>
      api.updateEmailTemplate(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'email-templates'] })
    },
  })
}

// Branding Settings Hooks
export function useBrandingSettings() {
  return useQuery({
    queryKey: ['settings', 'branding'],
    queryFn: () => api.getBrandingSettings(),
  })
}

export function useUpdateBrandingSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<BrandingSettings>) => api.updateBrandingSettings(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'branding'] })
    },
  })
}
