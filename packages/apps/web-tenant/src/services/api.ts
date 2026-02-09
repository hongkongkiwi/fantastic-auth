import axios, { type AxiosError, type InternalAxiosRequestConfig } from 'axios'
import { QueryClient } from '@tanstack/react-query'
import { env } from '@/env/client'
import { appLogger } from '@/lib/logger'

const API_BASE_URL = env.VITE_API_URL || 'https://api.vault.example.com'
export const queryClient = new QueryClient()

// Create axios instance with credentials support
export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Enable cookie sending
  timeout: 30000, // 30 second timeout
})

// CSRF token management
let csrfToken: string | null = null

const getCsrfToken = async (): Promise<string | null> => {
  if (csrfToken) return csrfToken
  
  try {
    // Try to get from meta tag
    const meta = document.querySelector('meta[name="csrf-token"]')
    if (meta) {
      csrfToken = meta.getAttribute('content')
      return csrfToken
    }
    
    // Fetch new CSRF token from server
    const response = await axios.get(`${API_BASE_URL}/auth/csrf`, {
      withCredentials: true,
    })
    csrfToken = response.data.csrfToken
    return csrfToken
  } catch (error) {
    appLogger.warn('Failed to get CSRF token')
    return null
  }
}

// Request interceptor to add CSRF token
apiClient.interceptors.request.use(
  async (config: InternalAxiosRequestConfig) => {
    // Add CSRF token to mutating requests
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(config.method?.toUpperCase() || '')) {
      const token = await getCsrfToken()
      if (token) {
        config.headers['X-CSRF-Token'] = token
      }
    }
    
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }
    
    if (!originalRequest) {
      return Promise.reject(error)
    }

    // Handle CSRF token expiration
    if (error.response?.status === 403 && !originalRequest._retry) {
      originalRequest._retry = true
      
      // Clear cached CSRF token and fetch new one
      csrfToken = null
      const newToken = await getCsrfToken()
      
      if (newToken) {
        originalRequest.headers['X-CSRF-Token'] = newToken
        return apiClient(originalRequest)
      }
    }
    
    // Handle 401 - redirect to login
    if (error.response?.status === 401) {
      appLogger.warn('Tenant app received unauthorized response')
      window.location.href = '/login?error=session_expired'
    }
    
    return Promise.reject(error)
  }
)

// API Types
export interface User {
  id: string
  email: string
  avatarUrl?: string
  firstName?: string
  lastName?: string
  displayName?: string
  role: 'admin' | 'member' | 'user' | 'super_admin'
  status: 'active' | 'inactive' | 'suspended' | 'pending' | 'deleted'
  emailVerified?: boolean
  mfaEnabled?: boolean
  mfaMethods?: string[]
  phoneNumber?: string
  lastLoginIp?: string
  organizations?: {
    organizationId: string
    organizationName?: string
    name?: string
    role?: string
    joinedAt?: string
  }[]
  metadata?: Record<string, unknown>
  createdAt: string
  updatedAt?: string
  lastLoginAt?: string
}

export interface Tenant {
  id: string
  name: string
  slug: string
  plan: 'free' | 'starter' | 'pro' | 'enterprise'
  status: 'active' | 'suspended' | 'deleted'
  createdAt: string
}

export class AuthMfaRequiredError extends Error {
  code = 'MFA_REQUIRED'
  mfaToken?: string
  constructor(message: string, mfaToken?: string) {
    super(message)
    this.name = 'AuthMfaRequiredError'
    this.mfaToken = mfaToken
  }
}

// Auth API
export const authApi = {
  login: async (email: string, password: string, mfaCode?: string, mfaToken?: string) => {
    const response = await apiClient.post('/auth/login', {
      email,
      password,
      mfaCode,
      mfaToken,
    })
    const payload = response.data as {
      mfaRequired?: boolean
      requires_mfa?: boolean
      mfaToken?: string
      mfa_token?: string
    }
    if (payload.mfaRequired || payload.requires_mfa) {
      throw new AuthMfaRequiredError(
        'Multi-factor authentication code required.',
        payload.mfaToken || payload.mfa_token,
      )
    }
    return response.data
  },
  
  logout: async () => {
    await apiClient.post('/auth/logout')
    csrfToken = null
  },
  
  getCurrentUser: async (): Promise<User> => {
    const response = await apiClient.get('/auth/me')
    return response.data
  },
  
  refreshSession: async () => {
    const response = await apiClient.post('/auth/refresh')
    return response.data
  },
  
  verifySession: async (): Promise<boolean> => {
    try {
      await apiClient.get('/auth/verify')
      return true
    } catch {
      return false
    }
  },

  getOAuthRedirect: async (
    provider: 'google' | 'github' | 'microsoft' | 'apple',
    redirectUri: string,
  ) => {
    const response = await apiClient.post(`/auth/oauth/${provider}`, { redirectUri })
    return response.data as { authUrl?: string; authorizationUrl?: string }
  },
}

// Users API
export const usersApi = {
  getUsers: async (params?: { page?: number; limit?: number; search?: string }) => {
    const response = await apiClient.get('/users', { params })
    return response.data
  },
  
  getUser: async (id: string): Promise<User> => {
    const response = await apiClient.get(`/users/${id}`)
    return response.data
  },
  
  createUser: async (data: Partial<User>) => {
    const response = await apiClient.post('/users', data)
    return response.data
  },
  
  updateUser: async (id: string, data: Partial<User>) => {
    const response = await apiClient.put(`/users/${id}`, data)
    return response.data
  },
  
  deleteUser: async (id: string) => {
    await apiClient.delete(`/users/${id}`)
  },
  
  exportUsers: async (format: 'csv' | 'json' = 'csv') => {
    const response = await apiClient.get('/users/export', {
      params: { format },
      responseType: 'blob',
    })
    return response.data
  },
}

// Organizations API
export const orgsApi = {
  getOrganizations: async () => {
    const response = await apiClient.get('/organizations')
    return response.data
  },
  
  getOrganization: async (id: string) => {
    const response = await apiClient.get(`/organizations/${id}`)
    return response.data
  },
  
  createOrganization: async (data: Partial<{ name: string; slug: string }>) => {
    const response = await apiClient.post('/organizations', data)
    return response.data
  },
  
  updateOrganization: async (id: string, data: Partial<{ name: string; settings: unknown }>) => {
    const response = await apiClient.put(`/organizations/${id}`, data)
    return response.data
  },
  
  deleteOrganization: async (id: string) => {
    await apiClient.delete(`/organizations/${id}`)
  },
}

// Security API
export const securityApi = {
  getSecuritySettings: async () => {
    const response = await apiClient.get('/security/settings')
    return response.data
  },
  
  updateSecuritySettings: async (data: unknown) => {
    const response = await apiClient.put('/security/settings', data)
    return response.data
  },
  
  getSessions: async () => {
    const response = await apiClient.get('/security/sessions')
    return response.data
  },
  
  revokeSession: async (sessionId: string) => {
    await apiClient.delete(`/security/sessions/${sessionId}`)
  },
}

// Audit Logs API
export const auditApi = {
  getAuditLogs: async (params?: { page?: number; limit?: number; startDate?: string; endDate?: string }) => {
    const response = await apiClient.get('/audit-logs', { params })
    return response.data
  },
}

// Webhooks API
export const webhooksApi = {
  getWebhooks: async () => {
    const response = await apiClient.get('/webhooks')
    return response.data
  },
  
  createWebhook: async (data: Partial<{ url: string; events: string[]; secret?: string }>) => {
    const response = await apiClient.post('/webhooks', data)
    return response.data
  },
  
  updateWebhook: async (id: string, data: Partial<{ url: string; events: string[]; active: boolean }>) => {
    const response = await apiClient.put(`/webhooks/${id}`, data)
    return response.data
  },
  
  deleteWebhook: async (id: string) => {
    await apiClient.delete(`/webhooks/${id}`)
  },
  
  testWebhook: async (id: string) => {
    const response = await apiClient.post(`/webhooks/${id}/test`)
    return response.data
  },
}

// Settings API
export const settingsApi = {
  getSettings: async () => {
    const response = await apiClient.get('/settings')
    return response.data
  },
  
  updateSettings: async (data: unknown) => {
    const response = await apiClient.put('/settings', data)
    return response.data
  },
}

// SAML Connections API
export const samlApi = {
  getConnections: async () => {
    const response = await apiClient.get('/saml-connections')
    return response.data
  },
  
  createConnection: async (data: unknown) => {
    const response = await apiClient.post('/saml-connections', data)
    return response.data
  },
  
  updateConnection: async (id: string, data: unknown) => {
    const response = await apiClient.put(`/saml-connections/${id}`, data)
    return response.data
  },
  
  deleteConnection: async (id: string) => {
    await apiClient.delete(`/saml-connections/${id}`)
  },
}

// Legacy compatibility surface used by hooks/pages.
export const api = {
  getCurrentUser: () => authApi.getCurrentUser(),
  getDashboardStats: async () => (await apiClient.get('/dashboard')).data,
  getActivityData: async (days = 30) =>
    (
      await apiClient.get('/analytics/dashboard', {
        params: { days },
      })
    ).data,
  getSystemHealth: async () => (await apiClient.get('/system/health')).data,
  getUsers: usersApi.getUsers,
  getUser: usersApi.getUser,
  createUser: usersApi.createUser,
  updateUser: usersApi.updateUser,
  deleteUser: usersApi.deleteUser,
  suspendUser: async (id: string, reason?: string) =>
    (await apiClient.post(`/users/${id}/suspend`, { reason })).data,
  activateUser: async (id: string) =>
    (await apiClient.post(`/users/${id}/activate`)).data,
  impersonateUser: async (id: string) =>
    (await apiClient.post(`/users/${id}/impersonate`)).data,
  exportUsers: async (format: 'csv' | 'json', filters?: unknown) =>
    (
      await apiClient.get('/users/export', {
        params: { format, ...(filters as Record<string, unknown> | undefined) },
        responseType: 'blob',
      })
    ).data,
  getUserSessions: async (userId: string) =>
    (await apiClient.get(`/users/${userId}/sessions`)).data,
  revokeUserSession: async (userId: string, sessionId: string) =>
    (await apiClient.delete(`/users/${userId}/sessions/${sessionId}`)).data,
  getOrganizations: async (params?: unknown) =>
    (await apiClient.get('/organizations', { params })).data,
  getOrganization: orgsApi.getOrganization,
  createOrganization: orgsApi.createOrganization,
  updateOrganization: orgsApi.updateOrganization,
  deleteOrganization: orgsApi.deleteOrganization,
  getOrganizationMembers: async (orgId: string) =>
    (await apiClient.get(`/organizations/${orgId}/members`)).data,
  addOrganizationMember: async (orgId: string, userId: string, role: string) =>
    (await apiClient.post(`/organizations/${orgId}/members`, { userId, role })).data,
  updateOrganizationMember: async (
    orgId: string,
    userId: string,
    role: string,
  ) =>
    (
      await apiClient.put(`/organizations/${orgId}/members/${userId}`, {
        role,
      })
    ).data,
  removeOrganizationMember: async (orgId: string, userId: string) =>
    (await apiClient.delete(`/organizations/${orgId}/members/${userId}`)).data,
  getAuditLogs: auditApi.getAuditLogs,
  exportAuditLogs: async (format: 'csv' | 'json', filters?: unknown) =>
    (
      await apiClient.get('/audit-logs/exports', {
        params: { format, ...(filters as Record<string, unknown> | undefined) },
        responseType: 'blob',
      })
    ).data,
  getWebhooks: webhooksApi.getWebhooks,
  getWebhook: async (id: string) => (await apiClient.get(`/webhooks/${id}`)).data,
  createWebhook: webhooksApi.createWebhook,
  updateWebhook: webhooksApi.updateWebhook,
  deleteWebhook: webhooksApi.deleteWebhook,
  testWebhook: webhooksApi.testWebhook,
  getOAuthClients: async () => (await apiClient.get('/oauth/clients')).data,
  createOAuthClient: async (data: unknown) =>
    (await apiClient.post('/oauth/clients', data)).data,
  updateOAuthClient: async (id: string, data: unknown) =>
    (await apiClient.put(`/oauth/clients/${id}`, data)).data,
  deleteOAuthClient: async (id: string) =>
    (await apiClient.delete(`/oauth/clients/${id}`)).data,
  regenerateOAuthClientSecret: async (id: string) =>
    (await apiClient.post(`/oauth/clients/${id}/rotate-secret`)).data,
  getSAMLConnections: samlApi.getConnections,
  createSAMLConnection: samlApi.createConnection,
  updateSAMLConnection: samlApi.updateConnection,
  deleteSAMLConnection: samlApi.deleteConnection,
  getSecuritySettings: securityApi.getSecuritySettings,
  updateSecuritySettings: securityApi.updateSecuritySettings,
  getPrivacySettings: async () => (await apiClient.get('/settings/v2/privacy')).data,
  updatePrivacySettings: async (data: unknown) =>
    (await apiClient.put('/settings/v2/privacy', data)).data,
  getEmailTemplates: async () => (await apiClient.get('/settings/v2/email')).data,
  updateEmailTemplate: async (id: string, data: unknown) =>
    (await apiClient.put(`/settings/v2/email/${id}`, data)).data,
  getBrandingSettings: async () => (await apiClient.get('/settings/v2/branding')).data,
  updateBrandingSettings: async (data: unknown) =>
    (await apiClient.put('/settings/v2/branding', data)).data,
}

// Export API client for direct use
export default apiClient
