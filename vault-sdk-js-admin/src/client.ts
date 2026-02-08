/**
 * Vault Admin API Client
 * 
 * A TypeScript client for the Vault Admin API, designed for
 * building admin dashboards and tenant management tools.
 */

import type {
  DashboardResponse,
  MetricsResponse,
  AdminUserResponse,
  CreateUserRequest,
  UpdateUserRequest,
  SuspendUserRequest,
  PaginatedUsersResponse,
  AdminSessionResponse,
  AdminOrganizationResponse,
  UpdateOrgRequest,
  PaginatedOrganizationsResponse,
  AdminOrganizationMemberResponse,
  InvitationResponse,
  UpdateMemberRequest,
  AuditLogEntry,
  PaginatedAuditLogResponse,
  TenantSettings,
  UpdateTenantSettingsRequest,
  SystemHealthResponse,
  ListUsersQuery,
  ListOrganizationsQuery,
  QueryAuditLogsQuery,
  DateRangeQuery,
  MessageResponse,
} from './generated/client';

export interface VaultAdminClientOptions {
  /** Base URL of the Vault API */
  baseUrl: string;
  /** JWT access token */
  token: string;
  /** Tenant ID for all requests */
  tenantId: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom fetch implementation */
  fetch?: typeof fetch;
}

export interface RequestOptions {
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Additional headers */
  headers?: Record<string, string>;
}

export interface SsoConnection {
  id: string;
  type: 'saml' | 'oidc';
  name: string;
  status: 'active' | 'disabled';
  domains: string[];
  config: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface OrganizationSsoSettings {
  orgId: string;
  connectionId: string | null;
  required: boolean;
  jitEnabled: boolean;
  defaultRole: string;
}

export interface OrganizationDomain {
  id: string;
  domain: string;
  verificationToken: string;
  verifiedAt: string | null;
  createdAt: string;
}

export interface OrganizationRole {
  id: string;
  name: string;
  permissions: string[];
  createdAt: string;
  updatedAt: string;
}

export interface BrandingSettings {
  logoUrl?: string | null;
  faviconUrl?: string | null;
  productName?: string | null;
  supportEmail?: string | null;
  primaryColor?: string | null;
  secondaryColor?: string | null;
  customCss?: string | null;
}

export interface ThemeSettings {
  theme: Record<string, unknown>;
}

export interface ScimListResponse {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: unknown[];
}

export interface ScimUser {
  id?: string;
  userName: string;
  active?: boolean;
  emails?: unknown[];
  externalId?: string;
}

export interface ScimGroup {
  id?: string;
  displayName: string;
  members?: unknown[];
}

export interface AuditExport {
  id: string;
  status: 'queued' | 'running' | 'complete' | 'failed';
  format: 'json' | 'csv';
  from: string;
  to: string;
  createdAt: string;
}

export interface AuditWebhook {
  id: string;
  url: string;
  status: 'active' | 'disabled';
  secretLastFour: string;
  createdAt: string;
}

export interface DirectoryConnection {
  id: string;
  type: 'ldap';
  name: string;
  status: 'active' | 'disabled';
  config: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  enabled: boolean;
  conditions: Record<string, unknown>;
  actions: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface MfaSettings {
  required: boolean;
  allowedMethods: string[];
}

export class VaultAdminError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'VaultAdminError';
  }
}

export class VaultAdminClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly tenantId: string;
  private readonly timeout: number;
  private readonly fetch: typeof fetch;

  constructor(options: VaultAdminClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.token = options.token;
    this.tenantId = options.tenantId;
    this.timeout = options.timeout ?? 30000;
    this.fetch = options.fetch ?? globalThis.fetch;

    if (!this.token) {
      throw new Error('JWT token is required');
    }
    if (!this.tenantId) {
      throw new Error('Tenant ID is required');
    }
  }

  // ========================================================================
  // HTTP Client
  // ========================================================================

  private async request<T>(
    method: string,
    path: string,
    options: {
      body?: unknown;
      query?: Record<string, string | number | boolean | undefined>;
      requestOptions?: RequestOptions;
    } = {}
  ): Promise<T> {
    const { body, query, requestOptions } = options;

    // Build URL with query parameters
    let url = `${this.baseUrl}${path}`;
    if (query) {
      const params = new URLSearchParams();
      Object.entries(query).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          params.append(key, String(value));
        }
      });
      const queryString = params.toString();
      if (queryString) {
        url += `?${queryString}`;
      }
    }

    // Build headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.token}`,
      'X-Tenant-ID': this.tenantId,
      ...requestOptions?.headers,
    };

    // Build request init
    const init: RequestInit = {
      method,
      headers,
    };

    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }

    // Execute request with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), requestOptions?.timeout ?? this.timeout);

    try {
      const response = await this.fetch(url, {
        ...init,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Handle errors
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new VaultAdminError(
          errorData.error?.message || `HTTP ${response.status}: ${response.statusText}`,
          errorData.error?.code || 'UNKNOWN_ERROR',
          response.status,
          errorData.error?.details
        );
      }

      // Handle empty responses
      if (response.status === 204) {
        return undefined as T;
      }

      return await response.json() as T;
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof VaultAdminError) {
        throw error;
      }
      
      if (error instanceof Error && error.name === 'AbortError') {
        throw new VaultAdminError(
          'Request timeout',
          'TIMEOUT',
          408
        );
      }
      
      throw new VaultAdminError(
        error instanceof Error ? error.message : 'Unknown error',
        'NETWORK_ERROR',
        0
      );
    }
  }

  // ========================================================================
  // Dashboard
  // ========================================================================

  /**
   * Get admin dashboard statistics
   */
  async getDashboard(): Promise<DashboardResponse> {
    return this.request('GET', '/admin/');
  }

  /**
   * Get detailed metrics
   */
  async getMetrics(query?: DateRangeQuery): Promise<MetricsResponse> {
    return this.request('GET', '/admin/metrics', { query });
  }

  // ========================================================================
  // User Management
  // ========================================================================

  /**
   * List all users in the tenant
   */
  async listUsers(query?: ListUsersQuery): Promise<PaginatedUsersResponse> {
    return this.request('GET', '/admin/users', { query });
  }

  /**
   * Create a new user
   */
  async createUser(data: CreateUserRequest): Promise<AdminUserResponse> {
    return this.request('POST', '/admin/users', { body: data });
  }

  /**
   * Get user details
   */
  async getUser(userId: string): Promise<AdminUserResponse> {
    return this.request('GET', `/admin/users/${userId}`);
  }

  /**
   * Update user
   */
  async updateUser(userId: string, data: UpdateUserRequest): Promise<AdminUserResponse> {
    return this.request('PATCH', `/admin/users/${userId}`, { body: data });
  }

  /**
   * Delete user permanently
   */
  async deleteUser(userId: string): Promise<MessageResponse> {
    return this.request('DELETE', `/admin/users/${userId}`);
  }

  /**
   * Suspend user account
   */
  async suspendUser(userId: string, data?: SuspendUserRequest): Promise<AdminUserResponse> {
    return this.request('POST', `/admin/users/${userId}/suspend`, { body: data });
  }

  /**
   * Activate/reactivate user account
   */
  async activateUser(userId: string): Promise<AdminUserResponse> {
    return this.request('POST', `/admin/users/${userId}/activate`);
  }

  /**
   * List user's active sessions
   */
  async listUserSessions(userId: string): Promise<AdminSessionResponse[]> {
    return this.request('GET', `/admin/users/${userId}/sessions`);
  }

  /**
   * Revoke all user sessions (force logout)
   */
  async revokeAllUserSessions(userId: string): Promise<MessageResponse> {
    return this.request('DELETE', `/admin/users/${userId}/sessions`);
  }

  // ========================================================================
  // Organization Management
  // ========================================================================

  /**
   * List all organizations
   */
  async listOrganizations(query?: ListOrganizationsQuery): Promise<PaginatedOrganizationsResponse> {
    return this.request('GET', '/admin/organizations', { query });
  }

  /**
   * Get organization details
   */
  async getOrganization(orgId: string): Promise<AdminOrganizationResponse> {
    return this.request('GET', `/admin/organizations/${orgId}`);
  }

  /**
   * Update organization
   */
  async updateOrganization(orgId: string, data: UpdateOrgRequest): Promise<AdminOrganizationResponse> {
    return this.request('PATCH', `/admin/organizations/${orgId}`, { body: data });
  }

  /**
   * Delete organization
   */
  async deleteOrganization(orgId: string): Promise<MessageResponse> {
    return this.request('DELETE', `/admin/organizations/${orgId}`);
  }

  /**
   * List organization members
   */
  async listOrganizationMembers(orgId: string): Promise<AdminOrganizationMemberResponse[]> {
    return this.request('GET', `/admin/organizations/${orgId}/members`);
  }

  /**
   * Update member role
   */
  async updateOrganizationMember(
    orgId: string,
    userId: string,
    data: UpdateMemberRequest
  ): Promise<AdminOrganizationMemberResponse> {
    return this.request('PATCH', `/admin/organizations/${orgId}/members/${userId}`, { body: data });
  }

  /**
   * Remove member from organization
   */
  async removeOrganizationMember(orgId: string, userId: string): Promise<MessageResponse> {
    return this.request('DELETE', `/admin/organizations/${orgId}/members/${userId}`);
  }

  /**
   * List pending invitations
   */
  async listOrganizationInvitations(orgId: string): Promise<InvitationResponse[]> {
    return this.request('GET', `/admin/organizations/${orgId}/invitations`);
  }

  /**
   * Cancel invitation
   */
  async cancelInvitation(orgId: string, invitationId: string): Promise<MessageResponse> {
    return this.request('DELETE', `/admin/organizations/${orgId}/invitations/${invitationId}`);
  }

  // ========================================================================
  // Audit Logs
  // ========================================================================

  /**
   * Query audit logs with filters
   */
  async queryAuditLogs(query?: QueryAuditLogsQuery): Promise<PaginatedAuditLogResponse> {
    return this.request('GET', '/admin/audit-logs', { query });
  }

  /**
   * Get recent audit log entries
   */
  async getRecentAuditLogs(limit: number = 50): Promise<AuditLogEntry[]> {
    const result = await this.queryAuditLogs({ perPage: limit });
    return result.data;
  }

  /**
   * Get audit logs for a specific user
   */
  async getUserAuditLogs(userId: string, query?: Omit<QueryAuditLogsQuery, 'userId'>): Promise<PaginatedAuditLogResponse> {
    return this.queryAuditLogs({ ...query, userId });
  }

  // ========================================================================
  // Tenant Settings
  // ========================================================================

  /**
   * Get tenant settings
   */
  async getSettings(): Promise<TenantSettings> {
    return this.request('GET', '/admin/settings');
  }

  /**
   * Update tenant settings
   */
  async updateSettings(data: UpdateTenantSettingsRequest): Promise<TenantSettings> {
    return this.request('PATCH', '/admin/settings', { body: data });
  }

  /**
   * Update MFA enforcement settings
   */
  async updateMfaSettings(data: Partial<MfaSettings>): Promise<MfaSettings> {
    return this.request('PATCH', '/admin/settings/mfa', { body: data });
  }

  // ========================================================================
  // SSO
  // ========================================================================

  async listSamlConnections(): Promise<{ data: SsoConnection[] }> {
    return this.request('GET', '/admin/sso/saml/connections');
  }

  async createSamlConnection(data: Partial<SsoConnection>): Promise<SsoConnection> {
    return this.request('POST', '/admin/sso/saml/connections', { body: data });
  }

  async getSamlConnection(connectionId: string): Promise<SsoConnection> {
    return this.request('GET', `/admin/sso/saml/connections/${connectionId}`);
  }

  async updateSamlConnection(connectionId: string, data: Partial<SsoConnection>): Promise<SsoConnection> {
    return this.request('PATCH', `/admin/sso/saml/connections/${connectionId}`, { body: data });
  }

  async deleteSamlConnection(connectionId: string): Promise<void> {
    await this.request('DELETE', `/admin/sso/saml/connections/${connectionId}`);
  }

  async listOidcConnections(): Promise<{ data: SsoConnection[] }> {
    return this.request('GET', '/admin/sso/oidc/connections');
  }

  async createOidcConnection(data: Partial<SsoConnection>): Promise<SsoConnection> {
    return this.request('POST', '/admin/sso/oidc/connections', { body: data });
  }

  async getOidcConnection(connectionId: string): Promise<SsoConnection> {
    return this.request('GET', `/admin/sso/oidc/connections/${connectionId}`);
  }

  async updateOidcConnection(connectionId: string, data: Partial<SsoConnection>): Promise<SsoConnection> {
    return this.request('PATCH', `/admin/sso/oidc/connections/${connectionId}`, { body: data });
  }

  async deleteOidcConnection(connectionId: string): Promise<void> {
    await this.request('DELETE', `/admin/sso/oidc/connections/${connectionId}`);
  }

  async updateOrganizationSso(orgId: string, data: Partial<OrganizationSsoSettings>): Promise<OrganizationSsoSettings> {
    return this.request('PATCH', `/admin/organizations/${orgId}/sso`, { body: data });
  }

  // ========================================================================
  // Domains
  // ========================================================================

  async listOrganizationDomains(orgId: string): Promise<{ data: OrganizationDomain[] }> {
    return this.request('GET', `/admin/organizations/${orgId}/domains`);
  }

  async createOrganizationDomain(orgId: string, domain: string): Promise<OrganizationDomain> {
    return this.request('POST', `/admin/organizations/${orgId}/domains`, { body: { domain } });
  }

  async verifyOrganizationDomain(orgId: string, domainId: string): Promise<OrganizationDomain> {
    return this.request('POST', `/admin/organizations/${orgId}/domains/${domainId}/verify`);
  }

  async deleteOrganizationDomain(orgId: string, domainId: string): Promise<void> {
    await this.request('DELETE', `/admin/organizations/${orgId}/domains/${domainId}`);
  }

  // ========================================================================
  // Roles & Permissions
  // ========================================================================

  async listOrganizationRoles(orgId: string): Promise<{ data: OrganizationRole[] }> {
    return this.request('GET', `/admin/organizations/${orgId}/roles`);
  }

  async createOrganizationRole(orgId: string, data: Partial<OrganizationRole>): Promise<OrganizationRole> {
    return this.request('POST', `/admin/organizations/${orgId}/roles`, { body: data });
  }

  async updateOrganizationRole(orgId: string, roleId: string, data: Partial<OrganizationRole>): Promise<OrganizationRole> {
    return this.request('PATCH', `/admin/organizations/${orgId}/roles/${roleId}`, { body: data });
  }

  async deleteOrganizationRole(orgId: string, roleId: string): Promise<void> {
    await this.request('DELETE', `/admin/organizations/${orgId}/roles/${roleId}`);
  }

  // ========================================================================
  // Branding
  // ========================================================================

  async getBranding(): Promise<BrandingSettings> {
    return this.request('GET', '/admin/branding');
  }

  async updateBranding(data: BrandingSettings): Promise<BrandingSettings> {
    return this.request('PATCH', '/admin/branding', { body: data });
  }

  async getTheme(): Promise<ThemeSettings> {
    return this.request('GET', '/admin/themes');
  }

  async updateTheme(data: ThemeSettings): Promise<ThemeSettings> {
    return this.request('PATCH', '/admin/themes', { body: data });
  }

  // ========================================================================
  // SCIM
  // ========================================================================

  async scimListUsers(): Promise<ScimListResponse> {
    return this.request('GET', '/admin/scim/v2/Users');
  }

  async scimCreateUser(data: ScimUser): Promise<ScimUser> {
    return this.request('POST', '/admin/scim/v2/Users', { body: data });
  }

  async scimGetUser(userId: string): Promise<ScimUser> {
    return this.request('GET', `/admin/scim/v2/Users/${userId}`);
  }

  async scimPatchUser(userId: string, data: Record<string, unknown>): Promise<ScimUser> {
    return this.request('PATCH', `/admin/scim/v2/Users/${userId}`, { body: data });
  }

  async scimDeleteUser(userId: string): Promise<void> {
    await this.request('DELETE', `/admin/scim/v2/Users/${userId}`);
  }

  async scimListGroups(): Promise<ScimListResponse> {
    return this.request('GET', '/admin/scim/v2/Groups');
  }

  async scimCreateGroup(data: ScimGroup): Promise<ScimGroup> {
    return this.request('POST', '/admin/scim/v2/Groups', { body: data });
  }

  async scimGetGroup(groupId: string): Promise<ScimGroup> {
    return this.request('GET', `/admin/scim/v2/Groups/${groupId}`);
  }

  async scimPatchGroup(groupId: string, data: Record<string, unknown>): Promise<ScimGroup> {
    return this.request('PATCH', `/admin/scim/v2/Groups/${groupId}`, { body: data });
  }

  async scimDeleteGroup(groupId: string): Promise<void> {
    await this.request('DELETE', `/admin/scim/v2/Groups/${groupId}`);
  }

  // ========================================================================
  // Audit Exports
  // ========================================================================

  async listAuditExports(): Promise<{ data: AuditExport[] }> {
    return this.request('GET', '/admin/audit-logs/exports');
  }

  async createAuditExport(data: { format: 'json' | 'csv'; from: string; to: string }): Promise<AuditExport> {
    return this.request('POST', '/admin/audit-logs/exports', { body: data });
  }

  async listAuditWebhooks(): Promise<{ data: AuditWebhook[] }> {
    return this.request('GET', '/admin/audit-logs/webhooks');
  }

  async createAuditWebhook(data: { url: string; secret: string }): Promise<AuditWebhook> {
    return this.request('POST', '/admin/audit-logs/webhooks', { body: data });
  }

  async deleteAuditWebhook(webhookId: string): Promise<void> {
    await this.request('DELETE', `/admin/audit-logs/webhooks/${webhookId}`);
  }

  // ========================================================================
  // Directory
  // ========================================================================

  async listDirectoryConnections(): Promise<{ data: DirectoryConnection[] }> {
    return this.request('GET', '/admin/directory/ldap/connections');
  }

  async createDirectoryConnection(data: Partial<DirectoryConnection>): Promise<DirectoryConnection> {
    return this.request('POST', '/admin/directory/ldap/connections', { body: data });
  }

  async updateDirectoryConnection(connectionId: string, data: Partial<DirectoryConnection>): Promise<DirectoryConnection> {
    return this.request('PATCH', `/admin/directory/ldap/connections/${connectionId}`, { body: data });
  }

  async deleteDirectoryConnection(connectionId: string): Promise<void> {
    await this.request('DELETE', `/admin/directory/ldap/connections/${connectionId}`);
  }

  // ========================================================================
  // Security Policies
  // ========================================================================

  async createSecurityPolicy(data: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
    return this.request('POST', '/admin/security/policies', { body: data });
  }

  async updateSecurityPolicy(policyId: string, data: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
    return this.request('PATCH', `/admin/security/policies/${policyId}`, { body: data });
  }

  // ========================================================================
  // System
  // ========================================================================

  /**
   * Get system health status
   */
  async getSystemHealth(): Promise<SystemHealthResponse> {
    return this.request('GET', '/admin/system/health');
  }
}
