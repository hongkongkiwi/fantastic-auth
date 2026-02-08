import axios, { AxiosError, AxiosInstance, AxiosRequestConfig } from 'axios'
import { 
  User, Organization, Session, AuditLog, Webhook, OAuthClient, SAMLConnection,
  SecuritySettings, PrivacySettings, EmailTemplate, BrandingSettings, DashboardStats, ActivityData, SystemHealth,
  UserListParams, PaginatedResponse 
} from '@/types'

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1/admin'

class ApiClient {
  private client: AxiosInstance

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    })

    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('vault_admin_token')
        if (token) {
          config.headers.Authorization = `Bearer ${token}`
        }
        return config
      },
      (error) => Promise.reject(error)
    )

    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('vault_admin_token')
          window.location.href = '/login'
        }
        return Promise.reject(error)
      }
    )
  }

  // Auth
  async login(email: string, password: string, mfaCode?: string) {
    const response = await this.client.post('/auth/login', { email, password, mfaCode })
    const { token, user } = response.data
    localStorage.setItem('vault_admin_token', token)
    return { token, user }
  }

  async logout() {
    await this.client.post('/auth/logout')
    localStorage.removeItem('vault_admin_token')
  }

  async getCurrentUser() {
    const response = await this.client.get('/auth/me')
    return response.data
  }

  // Dashboard
  async getDashboardStats(): Promise<DashboardStats> {
    const response = await this.client.get('/dashboard/stats')
    return response.data
  }

  async getActivityData(days = 30): Promise<ActivityData[]> {
    const response = await this.client.get('/dashboard/activity', { params: { days } })
    return response.data
  }

  async getSystemHealth(): Promise<SystemHealth> {
    const response = await this.client.get('/dashboard/health')
    return response.data
  }

  // Users
  async getUsers(params: UserListParams = {}): Promise<PaginatedResponse<User>> {
    const response = await this.client.get('/users', { params })
    return response.data
  }

  async getUser(id: string): Promise<User> {
    const response = await this.client.get(`/users/${id}`)
    return response.data
  }

  async createUser(data: Partial<User>): Promise<User> {
    const response = await this.client.post('/users', data)
    return response.data
  }

  async updateUser(id: string, data: Partial<User>): Promise<User> {
    const response = await this.client.patch(`/users/${id}`, data)
    return response.data
  }

  async deleteUser(id: string): Promise<void> {
    await this.client.delete(`/users/${id}`)
  }

  async suspendUser(id: string, reason?: string): Promise<User> {
    const response = await this.client.post(`/users/${id}/suspend`, { reason })
    return response.data
  }

  async activateUser(id: string): Promise<User> {
    const response = await this.client.post(`/users/${id}/activate`)
    return response.data
  }

  async impersonateUser(id: string): Promise<{ token: string; url: string }> {
    const response = await this.client.post(`/users/${id}/impersonate`)
    return response.data
  }

  async exportUsers(format: 'csv' | 'json', filters?: UserListParams): Promise<Blob> {
    const response = await this.client.post('/users/export', { format, filters }, {
      responseType: 'blob',
    })
    return response.data
  }

  // User Sessions
  async getUserSessions(userId: string): Promise<Session[]> {
    const response = await this.client.get(`/users/${userId}/sessions`)
    return response.data
  }

  async revokeUserSession(userId: string, sessionId: string): Promise<void> {
    await this.client.delete(`/users/${userId}/sessions/${sessionId}`)
  }

  // Organizations
  async getOrganizations(params?: { page?: number; limit?: number; search?: string }): Promise<PaginatedResponse<Organization>> {
    const response = await this.client.get('/organizations', { params })
    return response.data
  }

  async getOrganization(id: string): Promise<Organization> {
    const response = await this.client.get(`/organizations/${id}`)
    return response.data
  }

  async createOrganization(data: Partial<Organization>): Promise<Organization> {
    const response = await this.client.post('/organizations', data)
    return response.data
  }

  async updateOrganization(id: string, data: Partial<Organization>): Promise<Organization> {
    const response = await this.client.patch(`/organizations/${id}`, data)
    return response.data
  }

  async deleteOrganization(id: string): Promise<void> {
    await this.client.delete(`/organizations/${id}`)
  }

  // Organization Members
  async getOrganizationMembers(orgId: string): Promise<Organization['members']> {
    const response = await this.client.get(`/organizations/${orgId}/members`)
    return response.data
  }

  async addOrganizationMember(orgId: string, userId: string, role: string): Promise<void> {
    await this.client.post(`/organizations/${orgId}/members`, { userId, role })
  }

  async updateOrganizationMember(orgId: string, userId: string, role: string): Promise<void> {
    await this.client.patch(`/organizations/${orgId}/members/${userId}`, { role })
  }

  async removeOrganizationMember(orgId: string, userId: string): Promise<void> {
    await this.client.delete(`/organizations/${orgId}/members/${userId}`)
  }

  // Audit Logs
  async getAuditLogs(params?: {
    page?: number
    limit?: number
    eventType?: string
    actorId?: string
    resourceType?: string
    resourceId?: string
    status?: string
    dateFrom?: string
    dateTo?: string
  }): Promise<PaginatedResponse<AuditLog>> {
    const response = await this.client.get('/audit-logs', { params })
    return response.data
  }

  async exportAuditLogs(format: 'csv' | 'json', filters?: object): Promise<Blob> {
    const response = await this.client.post('/audit-logs/export', { format, filters }, {
      responseType: 'blob',
    })
    return response.data
  }

  // Webhooks
  async getWebhooks(): Promise<Webhook[]> {
    const response = await this.client.get('/webhooks')
    return response.data
  }

  async getWebhook(id: string): Promise<Webhook> {
    const response = await this.client.get(`/webhooks/${id}`)
    return response.data
  }

  async createWebhook(data: Partial<Webhook>): Promise<Webhook> {
    const response = await this.client.post('/webhooks', data)
    return response.data
  }

  async updateWebhook(id: string, data: Partial<Webhook>): Promise<Webhook> {
    const response = await this.client.patch(`/webhooks/${id}`, data)
    return response.data
  }

  async deleteWebhook(id: string): Promise<void> {
    await this.client.delete(`/webhooks/${id}`)
  }

  async testWebhook(id: string): Promise<{ success: boolean; message: string }> {
    const response = await this.client.post(`/webhooks/${id}/test`)
    return response.data
  }

  // OAuth Clients
  async getOAuthClients(): Promise<OAuthClient[]> {
    const response = await this.client.get('/oauth-clients')
    return response.data
  }

  async getOAuthClient(id: string): Promise<OAuthClient> {
    const response = await this.client.get(`/oauth-clients/${id}`)
    return response.data
  }

  async createOAuthClient(data: Partial<OAuthClient>): Promise<OAuthClient> {
    const response = await this.client.post('/oauth-clients', data)
    return response.data
  }

  async updateOAuthClient(id: string, data: Partial<OAuthClient>): Promise<OAuthClient> {
    const response = await this.client.patch(`/oauth-clients/${id}`, data)
    return response.data
  }

  async deleteOAuthClient(id: string): Promise<void> {
    await this.client.delete(`/oauth-clients/${id}`)
  }

  async regenerateOAuthClientSecret(id: string): Promise<{ clientSecret: string }> {
    const response = await this.client.post(`/oauth-clients/${id}/regenerate-secret`)
    return response.data
  }

  // SAML Connections
  async getSAMLConnections(): Promise<SAMLConnection[]> {
    const response = await this.client.get('/saml-connections')
    return response.data
  }

  async getSAMLConnection(id: string): Promise<SAMLConnection> {
    const response = await this.client.get(`/saml-connections/${id}`)
    return response.data
  }

  async createSAMLConnection(data: Partial<SAMLConnection>): Promise<SAMLConnection> {
    const response = await this.client.post('/saml-connections', data)
    return response.data
  }

  async updateSAMLConnection(id: string, data: Partial<SAMLConnection>): Promise<SAMLConnection> {
    const response = await this.client.patch(`/saml-connections/${id}`, data)
    return response.data
  }

  async deleteSAMLConnection(id: string): Promise<void> {
    await this.client.delete(`/saml-connections/${id}`)
  }

  // Security Settings
  async getSecuritySettings(): Promise<SecuritySettings> {
    const response = await this.client.get('/settings/security')
    return response.data.settings ?? response.data
  }

  async updateSecuritySettings(data: SecuritySettings): Promise<SecuritySettings> {
    const response = await this.client.patch('/settings/security', data)
    return response.data
  }

  async getPrivacySettings(): Promise<PrivacySettings> {
    const response = await this.client.get('/settings/privacy')
    return response.data.settings ?? response.data
  }

  async updatePrivacySettings(data: PrivacySettings): Promise<PrivacySettings> {
    const response = await this.client.patch('/settings/privacy', data)
    return response.data
  }

  // Email Templates
  async getEmailTemplates(): Promise<EmailTemplate[]> {
    const response = await this.client.get('/settings/email-templates')
    return response.data
  }

  async getEmailTemplate(id: string): Promise<EmailTemplate> {
    const response = await this.client.get(`/settings/email-templates/${id}`)
    return response.data
  }

  async updateEmailTemplate(id: string, data: Partial<EmailTemplate>): Promise<EmailTemplate> {
    const response = await this.client.patch(`/settings/email-templates/${id}`, data)
    return response.data
  }

  // Branding Settings
  async getBrandingSettings(): Promise<BrandingSettings> {
    const response = await this.client.get('/settings/branding')
    return response.data
  }

  async updateBrandingSettings(data: Partial<BrandingSettings>): Promise<BrandingSettings> {
    const response = await this.client.patch('/settings/branding', data)
    return response.data
  }

  // Generic request method
  async request<T>(config: AxiosRequestConfig): Promise<T> {
    const response = await this.client.request<T>(config)
    return response.data
  }
}

export const api = new ApiClient()
export default api
