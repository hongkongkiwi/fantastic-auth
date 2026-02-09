import { QueryClient, useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getCsrfToken, setCsrfToken } from '@/auth/storage'
import { env } from '@/env/client'

const API_BASE_URL = env.VITE_API_URL || '/api/v1'

// Generic fetch wrapper with auth and CSRF
async function fetchWithAuth<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options.headers as Record<string, string>) || {}),
  }

  // Add CSRF token for mutating requests
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method?.toUpperCase() || '')) {
    let token = getCsrfToken()
    
    // If no token, try to fetch one
    if (!token) {
      try {
        const csrfResponse = await fetch(`${API_BASE_URL}/auth/csrf`, {
          credentials: 'include',
        })
        if (csrfResponse.ok) {
          const csrfData = await csrfResponse.json()
          token = csrfData.csrfToken
          if (token) setCsrfToken(token)
        }
      } catch {
        // Continue without CSRF token - server will reject if required
      }
    }
    
    if (token) {
      headers['X-CSRF-Token'] = token
    }
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
    credentials: 'include', // Always include cookies
  })

  if (!response.ok) {
    // Handle CSRF expiration
    if (response.status === 403) {
      const errorData = await response.json().catch(() => ({ message: 'Forbidden' }))
      if (errorData.code === 'CSRF_INVALID') {
        // Clear cached CSRF token
        setCsrfToken('')
        throw new Error('Session expired. Please refresh the page.')
      }
    }
    
    // Handle session expiration
    if (response.status === 401) {
      window.location.href = '/login?error=session_expired'
      throw new Error('Session expired')
    }
    
    const error = await response.json().catch(() => ({ message: 'Unknown error' }))
    throw new Error(error.message || `HTTP error! status: ${response.status}`)
  }

  // Update CSRF token if provided in response
  const newCsrfToken = response.headers.get('X-CSRF-Token')
  if (newCsrfToken) {
    setCsrfToken(newCsrfToken)
  }

  return response.json()
}

// ============= Device Types =============

export interface DeviceInfo {
  id: string
  userId: string
  deviceName: string
  deviceType: string
  trustScore: number
  isTrusted: boolean
  lastSeenAt: string
  firstSeenAt: string
  location?: string
  ipAddress: string
  browserFingerprint?: string
  encryptionStatus: string
  mfaStatus: string
}

export interface DeviceStats {
  totalDevices: number
  trustedDevices: number
  untrustedDevices: number
  avgTrustScore: number
}

export interface DeviceTrustPolicy {
  autoRevokeUntrusted: boolean
  requireApprovalForNewDevices: boolean
  maxTrustScore: number
  locationMismatchAction: string
}

export interface UpdateTrustRequest {
  trustScore: number
  isTrusted: boolean
}

// ============= Session Types =============

export interface SessionInfo {
  id: string
  userId: string
  createdAt: string
  expiresAt: string
  lastActivityAt: string
  status: string
  ipAddress: string
  location?: string
  device?: string
  riskScore: number
  mfaFactors: string[]
  isCurrentSession: boolean
}

export interface SessionStats {
  totalSessions: number
  activeSessions: number
  expiredSessions: number
  revokedSessions: number
}

// ============= Privacy Types =============

export interface DataExportRequest {
  id: string
  userId: string
  requestedAt: string
  expiresAt: string
  status: string
  downloadUrl?: string
  dataCategories: string[]
}

export interface ConsentRecord {
  id: string
  userId: string
  consentType: string
  granted: boolean
  grantedAt?: string
  withdrawnAt?: string
  version: string
}

export interface PrivacySettings {
  profileVisibility: string
  activityTracking: boolean
  analyticsConsent: boolean
  marketingConsent: boolean
  thirdPartySharing: boolean
}

// ============= Device API =============

const deviceKeys = {
  all: ['devices'] as const,
  lists: () => [...deviceKeys.all, 'list'] as const,
  list: () => [...deviceKeys.lists()] as const,
  stats: () => [...deviceKeys.all, 'stats'] as const,
  policy: () => [...deviceKeys.all, 'policy'] as const,
}

export const useDevices = () => {
  return useQuery({
    queryKey: deviceKeys.list(),
    queryFn: () => fetchWithAuth<{ devices: DeviceInfo[]; total: number }>('/me/devices'),
  })
}

export const useDeviceStats = () => {
  return useQuery({
    queryKey: deviceKeys.stats(),
    queryFn: () => fetchWithAuth<DeviceStats>('/me/devices/stats'),
  })
}

export const useDevicePolicy = () => {
  return useQuery({
    queryKey: deviceKeys.policy(),
    queryFn: () => fetchWithAuth<DeviceTrustPolicy>('/me/devices/policy'),
  })
}

export const useUpdateDeviceTrust = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: ({ deviceId, data }: { deviceId: string; data: UpdateTrustRequest }) =>
      fetchWithAuth<{ success: boolean; message: string }>(`/me/devices/${deviceId}/trust`, {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: deviceKeys.all })
    },
  })
}

export const useRevokeDevice = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (deviceId: string) =>
      fetchWithAuth<{ success: boolean; message: string }>(`/me/devices/${deviceId}`, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: deviceKeys.all })
    },
  })
}

export const useUpdateDevicePolicy = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (data: DeviceTrustPolicy) =>
      fetchWithAuth<DeviceTrustPolicy>('/me/devices/policy', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: deviceKeys.policy() })
    },
  })
}

// ============= Session API =============

const sessionKeys = {
  all: ['sessions'] as const,
  lists: () => [...sessionKeys.all, 'list'] as const,
  list: () => [...sessionKeys.lists()] as const,
  stats: () => [...sessionKeys.all, 'stats'] as const,
}

export const useSessions = () => {
  return useQuery({
    queryKey: sessionKeys.list(),
    queryFn: () => fetchWithAuth<{ sessions: SessionInfo[]; total: number }>('/me/sessions'),
  })
}

export const useSessionStats = () => {
  return useQuery({
    queryKey: sessionKeys.stats(),
    queryFn: () => fetchWithAuth<SessionStats>('/me/sessions/stats'),
  })
}

export const useTerminateSession = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (sessionId: string) =>
      fetchWithAuth<{ success: boolean; message: string }>(`/me/sessions/${sessionId}`, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: sessionKeys.all })
    },
  })
}

export const useTerminateAllOtherSessions = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: () =>
      fetchWithAuth<{ success: boolean; message: string; terminatedCount?: number }>(
        '/me/sessions/all-others',
        { method: 'DELETE' }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: sessionKeys.all })
    },
  })
}

// ============= Privacy API =============

const privacyKeys = {
  all: ['privacy'] as const,
  exports: () => [...privacyKeys.all, 'exports'] as const,
  consents: () => [...privacyKeys.all, 'consents'] as const,
  settings: () => [...privacyKeys.all, 'settings'] as const,
}

export const useDataExports = () => {
  return useQuery({
    queryKey: privacyKeys.exports(),
    queryFn: () => fetchWithAuth<DataExportRequest[]>('/me/privacy/exports'),
  })
}

export const useRequestExport = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (data?: { dataCategories?: string[]; format?: string }) =>
      fetchWithAuth<{ success: boolean; message: string; export?: DataExportRequest }>(
        '/me/privacy/exports',
        {
          method: 'POST',
          body: JSON.stringify(data || {}),
        }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: privacyKeys.exports() })
    },
  })
}

export const useConsents = () => {
  return useQuery({
    queryKey: privacyKeys.consents(),
    queryFn: () => fetchWithAuth<{ success: boolean; consents: ConsentRecord[] }>('/me/privacy/consents'),
  })
}

export const useUpdateConsent = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: ({ consentType, granted }: { consentType: string; granted: boolean }) =>
      fetchWithAuth<ConsentRecord>(`/me/privacy/consents/${consentType}`, {
        method: 'POST',
        body: JSON.stringify({ granted }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: privacyKeys.consents() })
    },
  })
}

export const usePrivacySettings = () => {
  return useQuery({
    queryKey: privacyKeys.settings(),
    queryFn: () => fetchWithAuth<PrivacySettings>('/me/privacy/settings'),
  })
}

export const useUpdatePrivacySettings = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (data: PrivacySettings) =>
      fetchWithAuth<PrivacySettings>('/me/privacy/settings', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: privacyKeys.settings() })
    },
  })
}

export const useDeleteAccount = () => {
  return useMutation({
    mutationFn: (data: { confirmationText: string; reason?: string; feedback?: string }) =>
      fetchWithAuth<{ success: boolean; message: string; scheduledAt: string; gracePeriodDays: number }>(
        '/me/privacy/account',
        {
          method: 'DELETE',
          body: JSON.stringify(data),
        }
      ),
  })
}

// ============= MFA Types =============

export interface MfaFactor {
  id: string
  type: 'totp' | 'sms' | 'email' | 'webauthn' | 'recovery'
  name: string
  createdAt: string
  lastUsedAt?: string
  verified: boolean
  enabled: boolean
}

export interface MfaSetupResponse {
  secret?: string
  qrCode?: string
  backupCodes?: string[]
  message: string
}

export interface MfaVerifyRequest {
  code: string
  type: string
}

export interface MfaChallenge {
  challengeId: string
  type: string
  expiresAt: string
}

// ============= MFA API =============

const mfaKeys = {
  all: ['mfa'] as const,
  factors: () => [...mfaKeys.all, 'factors'] as const,
  setup: (type: string) => [...mfaKeys.all, 'setup', type] as const,
}

export const useMfaFactors = () => {
  return useQuery({
    queryKey: mfaKeys.factors(),
    queryFn: () => fetchWithAuth<{ factors: MfaFactor[] }>('/users/me/mfa'),
  })
}

export const useSetupMfa = () => {
  return useMutation({
    mutationFn: ({ type, name }: { type: string; name: string }) =>
      fetchWithAuth<MfaSetupResponse>('/users/me/mfa', {
        method: 'POST',
        body: JSON.stringify({ type, name }),
      }),
  })
}

export const useVerifyMfaSetup = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: ({ type, code }: { type: string; code: string }) =>
      fetchWithAuth<{ success: boolean; backupCodes?: string[] }>('/users/me/mfa/verify', {
        method: 'POST',
        body: JSON.stringify({ type, code }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: mfaKeys.all })
    },
  })
}

export const useDisableMfa = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: ({ factorId, code }: { factorId: string; code: string }) =>
      fetchWithAuth<{ success: boolean }>(`/users/me/mfa/${factorId}`, {
        method: 'DELETE',
        body: JSON.stringify({ code }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: mfaKeys.all })
    },
  })
}

export const useRegenerateBackupCodes = () => {
  return useMutation({
    mutationFn: (code: string) =>
      fetchWithAuth<{ backupCodes: string[] }>('/users/me/mfa/backup-codes', {
        method: 'POST',
        body: JSON.stringify({ code }),
      }),
  })
}

// ============= Security Keys Types =============

export interface SecurityKey {
  id: string
  name: string
  type: 'hardware' | 'platform'
  createdAt: string
  lastUsed?: string
}

export interface SecurityKeysResponse {
  keys: SecurityKey[]
}

// ============= Security Keys API =============

const securityKeyKeys = {
  all: ['security-keys'] as const,
  list: () => [...securityKeyKeys.all, 'list'] as const,
}

export const useSecurityKeys = () => {
  return useQuery({
    queryKey: securityKeyKeys.list(),
    queryFn: () => fetchWithAuth<SecurityKeysResponse>('/users/me/mfa/webauthn'),
  })
}

export const useRegisterSecurityKey = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (name: string) =>
      fetchWithAuth<{ success: boolean; key: SecurityKey }>('/users/me/mfa/webauthn/register/begin', {
        method: 'POST',
        body: JSON.stringify({ name }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: securityKeyKeys.all })
    },
  })
}

export const useRemoveSecurityKey = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (keyId: string) =>
      fetchWithAuth<{ success: boolean }>(`/users/me/mfa/webauthn/${keyId}`, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: securityKeyKeys.all })
    },
  })
}

// ============= Password Change API =============

export interface ChangePasswordRequest {
  currentPassword: string
  newPassword: string
}

export const useChangePassword = () => {
  return useMutation({
    mutationFn: (data: ChangePasswordRequest) =>
      fetchWithAuth<{ message: string }>('/me/password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: data.currentPassword,
          new_password: data.newPassword,
        }),
      }),
  })
}

// ============= Security Dashboard Types =============

export interface SecurityScore {
  overallScore: number
  mfaScore: number
  passwordScore: number
  sessionScore: number
  deviceScore: number
  lastUpdated: string
}

export interface SecurityAlert {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string
  title: string
  description: string
  createdAt: string
  status: 'open' | 'acknowledged' | 'resolved'
  relatedSessionId?: string
  relatedDeviceId?: string
}

export interface SecurityRecommendation {
  id: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  category: string
  title: string
  description: string
  actionText: string
  actionRoute?: string
  isCompleted: boolean
  createdAt: string
}

export interface MfaStats {
  enabled: boolean
  totalFactors: number
  factorsByType: Array<{
    factorType: string
    count: number
    percentage: number
  }>
  backupCodesAvailable: boolean
}

export interface RiskFactors {
  weakPasswords: number
  noMfaUsers: number
  suspiciousDevices: number
  failedLoginAttempts: number
  untrustedDevices: number
}

// ============= Security Dashboard API =============

const securityKeys = {
  all: ['security'] as const,
  score: () => [...securityKeys.all, 'score'] as const,
  alerts: () => [...securityKeys.all, 'alerts'] as const,
  recommendations: () => [...securityKeys.all, 'recommendations'] as const,
  mfaStats: () => [...securityKeys.all, 'mfaStats'] as const,
  riskFactors: () => [...securityKeys.all, 'riskFactors'] as const,
}

export const useSecurityScore = () => {
  return useQuery({
    queryKey: securityKeys.score(),
    queryFn: () => fetchWithAuth<SecurityScore>('/me/security/score'),
  })
}

export const useSecurityAlerts = () => {
  return useQuery({
    queryKey: securityKeys.alerts(),
    queryFn: () => fetchWithAuth<{ alerts: SecurityAlert[]; total: number; unacknowledgedCount: number }>(
      '/me/security/alerts'
    ),
  })
}

export const useAcknowledgeAlert = () => {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (alertId: string) =>
      fetchWithAuth<{ success: boolean; message: string }>(`/me/security/alerts/${alertId}/ack`, {
        method: 'PUT',
        body: JSON.stringify({}),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: securityKeys.alerts() })
    },
  })
}

export const useSecurityRecommendations = () => {
  return useQuery({
    queryKey: securityKeys.recommendations(),
    queryFn: () => fetchWithAuth<SecurityRecommendation[]>('/me/security/recommendations'),
  })
}

export const useMfaStats = () => {
  return useQuery({
    queryKey: securityKeys.mfaStats(),
    queryFn: () => fetchWithAuth<MfaStats>('/me/security/mfa-stats'),
  })
}

export const useRiskFactors = () => {
  return useQuery({
    queryKey: securityKeys.riskFactors(),
    queryFn: () => fetchWithAuth<RiskFactors>('/me/security/risk-factors'),
  })
}

// ============= Activity API =============

export interface ActivityEntry {
  id: string
  type: string
  action?: string
  description?: string
  ip?: string
  location?: string
  device?: string
  timestamp: string
  status: 'success' | 'failure' | 'blocked' | string
}

export interface ActivityLogResponse {
  activities: ActivityEntry[]
  total: number
}

export const useActivityLog = (params: {
  page?: number
  limit?: number
  filter?: string
  search?: string
}) => {
  return useQuery({
    queryKey: ['activity', params],
    queryFn: () =>
      fetchWithAuth<ActivityLogResponse>(
        `/me/activity?page=${params.page ?? 1}&limit=${params.limit ?? 10}` +
          `&filter=${encodeURIComponent(params.filter ?? 'all')}` +
          `&search=${encodeURIComponent(params.search ?? '')}`,
      ),
  })
}

// ============= Query Client =============

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})
