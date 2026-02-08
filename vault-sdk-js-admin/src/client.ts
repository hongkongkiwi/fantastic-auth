/**
 * Vault Admin API Client
 */

import type {
  AdminOrganizationMemberResponse,
  AdminOrganizationResponse,
  AdminSessionListResponse,
  AdminUserResponse,
  AnalyticsResponse,
  ApiKey,
  AuditExport,
  AuditLogEntry,
  AuditWebhook,
  BrandingSettings,
  BulkJob,
  ConsentPolicy,
  CreateUserRequest,
  DateRangeQuery,
  DirectoryConnection,
  DashboardResponse,
  JsonObject,
  InvitationResponse,
  ListOrganizationsQuery,
  ListUsersQuery,
  ListUsersResponse,
  MessageResponse,
  MetricsResponse,
  MigrationJob,
  OidcClient,
  OrganizationDomain,
  OrganizationRole,
  OrganizationSsoSettings,
  PaginatedAuditLogResponse,
  PaginatedOrganizationsResponse,
  QueryAuditLogsQuery,
  ScimGroup,
  ScimListResponse,
  ScimUser,
  SecurityPolicy,
  SecurityResponse,
  SsoConnection,
  SystemHealthResponse,
  TenantSettings,
  ThemeSettings,
  UpdateMemberRequest,
  UpdateOrgRequest,
  UpdateTenantSettingsRequest,
  UpdateUserRequest,
} from './generated/client';

export type ResponseType = 'json' | 'text' | 'blob' | 'arrayBuffer' | 'stream' | 'void';
export type QueryStyle = 'snake' | 'preserve';

export interface VaultAdminClientOptions {
  baseUrl: string;
  token: string;
  tenantId: string;
  timeout?: number;
  fetch?: typeof fetch;
}

export interface RequestOptions {
  timeout?: number;
  headers?: Record<string, string>;
  responseType?: ResponseType;
  queryStyle?: QueryStyle;
  signal?: AbortSignal;
}

interface RequestConfig {
  body?: unknown;
  query?: unknown;
  requestOptions?: RequestOptions;
}

const SNAKE_CASE_REGEX = /[A-Z]/g;

function toSnakeCase(value: string): string {
  return value.replace(SNAKE_CASE_REGEX, (match) => `_${match.toLowerCase()}`);
}

function isFormData(value: unknown): value is FormData {
  return typeof FormData !== 'undefined' && value instanceof FormData;
}

function isBodyInit(value: unknown): value is BodyInit {
  if (!value) {
    return false;
  }

  return (
    typeof value === 'string' ||
    value instanceof ArrayBuffer ||
    ArrayBuffer.isView(value) ||
    value instanceof URLSearchParams ||
    value instanceof Blob ||
    value instanceof ReadableStream ||
    isFormData(value)
  );
}

function buildQueryString(query: Record<string, unknown>, queryStyle: QueryStyle): string {
  const params = new URLSearchParams();

  for (const [rawKey, rawValue] of Object.entries(query)) {
    if (rawValue === undefined || rawValue === null) {
      continue;
    }

    const key = queryStyle === 'snake' ? toSnakeCase(rawKey) : rawKey;

    if (Array.isArray(rawValue)) {
      for (const item of rawValue) {
        if (item !== undefined && item !== null) {
          params.append(key, String(item));
        }
      }
      continue;
    }

    params.append(key, String(rawValue));
  }

    const queryString = params.toString();
  return queryString.length > 0 ? `?${queryString}` : '';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
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
  private readonly fetchImpl: typeof fetch;

  constructor(options: VaultAdminClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.token = options.token;
    this.tenantId = options.tenantId;
    this.timeout = options.timeout ?? 30000;
    this.fetchImpl = options.fetch ?? globalThis.fetch;

    if (!this.token) {
      throw new Error('JWT token is required');
    }
    if (!this.tenantId) {
      throw new Error('Tenant ID is required');
    }
  }

  async rawRequest<T>(method: string, path: string, config: RequestConfig = {}): Promise<T> {
    return this.request<T>(method, path, config);
  }

  private async request<T>(method: string, path: string, config: RequestConfig = {}): Promise<T> {
    const { body, query, requestOptions } = config;
    const responseType = requestOptions?.responseType ?? 'json';
    const queryStyle = requestOptions?.queryStyle ?? 'snake';
    const queryString = isRecord(query) ? buildQueryString(query, queryStyle) : '';
    const url = `${this.baseUrl}${path}${queryString}`;

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.token}`,
      'X-Tenant-ID': this.tenantId,
      ...requestOptions?.headers,
    };

    const init: RequestInit = {
      method,
      headers,
    };

    if (body !== undefined) {
      if (isBodyInit(body)) {
        init.body = body;
      } else {
        headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(body);
      }

      if (isFormData(body) && headers['Content-Type']) {
        delete headers['Content-Type'];
      }
    }

    const controller = new AbortController();
    const timeoutMs = requestOptions?.timeout ?? this.timeout;
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    if (requestOptions?.signal) {
      if (requestOptions.signal.aborted) {
        controller.abort(requestOptions.signal.reason);
      } else {
        requestOptions.signal.addEventListener('abort', () => controller.abort(requestOptions.signal?.reason), {
          once: true,
        });
      }
    }

    try {
      const response = await this.fetchImpl(url, {
        ...init,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let message = `HTTP ${response.status}: ${response.statusText}`;
        let code = 'UNKNOWN_ERROR';
        let details: Record<string, unknown> | undefined;

        const contentType = response.headers.get('content-type') ?? '';
        if (contentType.includes('application/json')) {
          const errorData = (await response.json().catch(() => ({}))) as {
            error?: { message?: string; code?: string; details?: Record<string, unknown> };
          };
          message = errorData.error?.message ?? message;
          code = errorData.error?.code ?? code;
          details = errorData.error?.details;
        } else {
          const text = await response.text().catch(() => '');
          if (text) {
            message = text;
          }
        }

        throw new VaultAdminError(message, code, response.status, details);
      }

      if (responseType === 'void' || response.status === 204) {
        return undefined as T;
      }

      switch (responseType) {
        case 'text':
          return (await response.text()) as T;
        case 'blob':
          return (await response.blob()) as T;
        case 'arrayBuffer':
          return (await response.arrayBuffer()) as T;
        case 'stream':
          return response.body as T;
        case 'json':
        default:
          return (await response.json()) as T;
      }
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof VaultAdminError) {
        throw error;
      }

      if (error instanceof Error && error.name === 'AbortError') {
        throw new VaultAdminError('Request timeout', 'TIMEOUT', 408);
      }

      throw new VaultAdminError(error instanceof Error ? error.message : 'Unknown error', 'NETWORK_ERROR', 0);
    }
  }

  async *iteratePages<T>(
    fetchPage: (page: number, perPage: number) => Promise<{ items: T[]; hasMore: boolean }>,
    perPage = 100
  ): AsyncGenerator<T, void, unknown> {
    let page = 1;
    let hasMore = true;

    while (hasMore) {
      const result = await fetchPage(page, perPage);
      for (const item of result.items) {
        yield item;
      }
      hasMore = result.hasMore;
      page += 1;
    }
  }

  async getDashboard(): Promise<DashboardResponse> {
    return this.request('GET', '/admin/');
  }

  async getMetrics(query?: DateRangeQuery): Promise<MetricsResponse> {
    return this.request('GET', '/admin/analytics/dashboard', { query });
  }

  async listUsers(query?: ListUsersQuery): Promise<ListUsersResponse> {
    return this.request('GET', '/admin/users', { query });
  }

  async *iterateUsers(query: Omit<ListUsersQuery, 'page' | 'perPage'> = {}): AsyncGenerator<AdminUserResponse, void, unknown> {
    yield* this.iteratePages(async (page, perPage) => {
      const response = await this.listUsers({ ...query, page, perPage });
      const effectivePerPage = response.per_page > 0 ? response.per_page : perPage;
      const totalPages = Math.max(1, Math.ceil(response.total / effectivePerPage));
      return {
        items: response.users,
        hasMore: response.users.length > 0 && page < totalPages,
      };
    });
  }

  async createUser(data: CreateUserRequest): Promise<AdminUserResponse> {
    return this.request('POST', '/admin/users', { body: data });
  }

  async getUser(userId: string): Promise<AdminUserResponse> {
    return this.request('GET', `/admin/users/${userId}`);
  }

  async updateUser(userId: string, data: UpdateUserRequest): Promise<AdminUserResponse> {
    return this.request('PATCH', `/admin/users/${userId}`, { body: data });
  }

  async deleteUser(userId: string): Promise<MessageResponse> {
    return this.request('DELETE', `/admin/users/${userId}`);
  }

  async suspendUser(userId: string, data?: { reason?: string }): Promise<AdminUserResponse> {
    return this.request('POST', `/admin/users/${userId}/suspend`, { body: data ?? {} });
  }

  async activateUser(userId: string): Promise<AdminUserResponse> {
    return this.request('POST', `/admin/users/${userId}/activate`);
  }

  async listUserSessions(userId: string): Promise<AdminSessionListResponse> {
    return this.request('GET', `/admin/users/${userId}/sessions`);
  }

  async revokeAllUserSessions(userId: string): Promise<MessageResponse> {
    return this.request('DELETE', `/admin/users/${userId}/sessions`);
  }

  async listOrganizations(query?: ListOrganizationsQuery): Promise<PaginatedOrganizationsResponse> {
    return this.request('GET', '/admin/organizations', { query });
  }

  async *iterateOrganizations(
    query: Omit<ListOrganizationsQuery, 'page' | 'perPage'> = {}
  ): AsyncGenerator<AdminOrganizationResponse, void, unknown> {
    yield* this.iteratePages(async (page, perPage) => {
      const response = await this.listOrganizations({ ...query, page, perPage });
      return {
        items: response.data,
        hasMore: page < response.pagination.totalPages,
      };
    });
  }

  async getOrganization(orgId: string): Promise<AdminOrganizationResponse> {
    return this.request('GET', `/admin/organizations/${orgId}`);
  }

  async updateOrganization(orgId: string, data: UpdateOrgRequest): Promise<AdminOrganizationResponse> {
    return this.request('PATCH', `/admin/organizations/${orgId}`, { body: data });
  }

  async deleteOrganization(orgId: string): Promise<MessageResponse> {
    return this.request('DELETE', `/admin/organizations/${orgId}`);
  }

  async listOrganizationMembers(orgId: string): Promise<AdminOrganizationMemberResponse[]> {
    return this.request('GET', `/admin/organizations/${orgId}/members`);
  }

  async updateOrganizationMember(
    orgId: string,
    userId: string,
    data: UpdateMemberRequest
  ): Promise<AdminOrganizationMemberResponse> {
    return this.request('PATCH', `/admin/organizations/${orgId}/members/${userId}`, { body: data });
  }

  async removeOrganizationMember(orgId: string, userId: string): Promise<MessageResponse> {
    return this.request('DELETE', `/admin/organizations/${orgId}/members/${userId}`);
  }

  async listOrganizationInvitations(orgId: string): Promise<InvitationResponse[]> {
    return this.request('GET', `/admin/organizations/${orgId}/invitations`);
  }

  async cancelInvitation(orgId: string, invitationId: string): Promise<MessageResponse> {
    return this.request('DELETE', `/admin/organizations/${orgId}/invitations/${invitationId}`);
  }

  async queryAuditLogs(query?: QueryAuditLogsQuery): Promise<PaginatedAuditLogResponse> {
    return this.request('GET', '/admin/audit-logs', { query });
  }

  async *iterateAuditLogs(
    query: Omit<QueryAuditLogsQuery, 'page' | 'perPage'> = {}
  ): AsyncGenerator<AuditLogEntry, void, unknown> {
    yield* this.iteratePages(async (page, perPage) => {
      const response = await this.queryAuditLogs({ ...query, page, perPage });
      return {
        items: response.data,
        hasMore: page < response.pagination.totalPages,
      };
    });
  }

  async getRecentAuditLogs(limit = 50): Promise<AuditLogEntry[]> {
    const result = await this.queryAuditLogs({ perPage: limit });
    return result.data;
  }

  async getUserAuditLogs(userId: string, query?: Omit<QueryAuditLogsQuery, 'userId'>): Promise<PaginatedAuditLogResponse> {
    return this.queryAuditLogs({ ...query, userId });
  }

  async getSettings(): Promise<TenantSettings> {
    return this.request('GET', '/admin/settings');
  }

  async updateSettings(data: UpdateTenantSettingsRequest): Promise<TenantSettings> {
    return this.request('PATCH', '/admin/settings', { body: data });
  }

  async updateMfaSettings(data: JsonObject): Promise<JsonObject> {
    return this.request('PATCH', '/admin/settings/mfa', { body: data });
  }

  async getSecuritySettings(): Promise<JsonObject> {
    return this.request('GET', '/admin/settings/security');
  }

  async updateSecuritySettings(data: JsonObject): Promise<JsonObject> {
    return this.request('PATCH', '/admin/settings/security', { body: data });
  }

  async getPrivacySettings(): Promise<JsonObject> {
    return this.request('GET', '/admin/settings/privacy');
  }

  async updatePrivacySettings(data: JsonObject): Promise<JsonObject> {
    return this.request('PATCH', '/admin/settings/privacy', { body: data });
  }

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
    await this.request('DELETE', `/admin/sso/saml/connections/${connectionId}`, { requestOptions: { responseType: 'void' } });
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
    await this.request('DELETE', `/admin/sso/oidc/connections/${connectionId}`, { requestOptions: { responseType: 'void' } });
  }

  async updateOrganizationSso(orgId: string, data: Partial<OrganizationSsoSettings>): Promise<OrganizationSsoSettings> {
    return this.request('PATCH', `/admin/organizations/${orgId}/sso`, { body: data });
  }

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
    await this.request('DELETE', `/admin/organizations/${orgId}/domains/${domainId}`, { requestOptions: { responseType: 'void' } });
  }

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
    await this.request('DELETE', `/admin/organizations/${orgId}/roles/${roleId}`, { requestOptions: { responseType: 'void' } });
  }

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

  async scimListUsers(): Promise<ScimListResponse> {
    return this.request('GET', '/admin/scim/v2/Users');
  }

  async scimCreateUser(data: ScimUser): Promise<ScimUser> {
    return this.request('POST', '/admin/scim/v2/Users', { body: data });
  }

  async scimGetUser(userId: string): Promise<ScimUser> {
    return this.request('GET', `/admin/scim/v2/Users/${userId}`);
  }

  async scimPatchUser(userId: string, data: JsonObject): Promise<ScimUser> {
    return this.request('PATCH', `/admin/scim/v2/Users/${userId}`, { body: data });
  }

  async scimDeleteUser(userId: string): Promise<void> {
    await this.request('DELETE', `/admin/scim/v2/Users/${userId}`, { requestOptions: { responseType: 'void' } });
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

  async scimPatchGroup(groupId: string, data: JsonObject): Promise<ScimGroup> {
    return this.request('PATCH', `/admin/scim/v2/Groups/${groupId}`, { body: data });
  }

  async scimDeleteGroup(groupId: string): Promise<void> {
    await this.request('DELETE', `/admin/scim/v2/Groups/${groupId}`, { requestOptions: { responseType: 'void' } });
  }

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
    await this.request('DELETE', `/admin/directory/ldap/connections/${connectionId}`, { requestOptions: { responseType: 'void' } });
  }

  async createSecurityPolicy(data: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
    return this.request('POST', '/admin/security/policies', { body: data });
  }

  async updateSecurityPolicy(policyId: string, data: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
    return this.request('PATCH', `/admin/security/policies/${policyId}`, { body: data });
  }

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
    await this.request('DELETE', `/admin/audit-logs/webhooks/${webhookId}`, { requestOptions: { responseType: 'void' } });
  }

  async getSystemHealth(): Promise<SystemHealthResponse> {
    return this.request('GET', '/admin/system/health');
  }

  async getAnalyticsDashboard(query?: DateRangeQuery): Promise<AnalyticsResponse> {
    return this.request('GET', '/admin/analytics/dashboard', { query });
  }

  async getAnalyticsLogins(query?: DateRangeQuery): Promise<AnalyticsResponse> {
    return this.request('GET', '/admin/analytics/logins', { query });
  }

  async getAnalyticsUsers(query?: DateRangeQuery): Promise<AnalyticsResponse> {
    return this.request('GET', '/admin/analytics/users', { query });
  }

  async getAnalyticsSecurity(query?: DateRangeQuery): Promise<AnalyticsResponse> {
    return this.request('GET', '/admin/analytics/security', { query });
  }

  async exportAnalytics(query?: Record<string, unknown>): Promise<Blob> {
    return this.request('GET', '/admin/analytics/export', {
      query,
      requestOptions: { responseType: 'blob' },
    });
  }

  async getSecurityGeoPolicy(): Promise<SecurityResponse> {
    return this.request('GET', '/admin/security/geo');
  }

  async updateSecurityGeoPolicy(data: JsonObject): Promise<SecurityResponse> {
    return this.request('PUT', '/admin/security/geo', { body: data });
  }

  async getSecurityVpnDetection(): Promise<SecurityResponse> {
    return this.request('GET', '/admin/security/vpn-detection');
  }

  async updateSecurityVpnDetection(data: JsonObject): Promise<SecurityResponse> {
    return this.request('PUT', '/admin/security/vpn-detection', { body: data });
  }

  async listScimTokens(): Promise<JsonObject> {
    return this.request('GET', '/admin/scim/tokens');
  }

  async createScimToken(data: JsonObject): Promise<JsonObject> {
    return this.request('POST', '/admin/scim/tokens', { body: data });
  }

  async revokeScimToken(tokenId: string): Promise<JsonObject> {
    return this.request('POST', `/admin/scim/tokens/${tokenId}`);
  }

  async deleteScimToken(tokenId: string): Promise<void> {
    await this.request('DELETE', `/admin/scim/tokens/${tokenId}`, { requestOptions: { responseType: 'void' } });
  }

  async getScimConfig(): Promise<JsonObject> {
    return this.request('GET', '/admin/scim/config');
  }

  async updateScimConfig(data: JsonObject): Promise<JsonObject> {
    return this.request('PUT', '/admin/scim/config', { body: data });
  }

  async getScimStats(): Promise<JsonObject> {
    return this.request('GET', '/admin/scim/stats');
  }

  async listApiKeys(): Promise<ApiKey[]> {
    return this.request('GET', '/admin/api-keys');
  }

  async createApiKey(data: JsonObject): Promise<ApiKey> {
    return this.request('POST', '/admin/api-keys', { body: data });
  }

  async getApiKey(id: string): Promise<ApiKey> {
    return this.request('GET', `/admin/api-keys/${id}`);
  }

  async updateApiKey(id: string, data: JsonObject): Promise<ApiKey> {
    return this.request('PUT', `/admin/api-keys/${id}`, { body: data });
  }

  async revokeApiKey(id: string): Promise<ApiKey> {
    return this.request('PUT', `/admin/api-keys/${id}/revoke`);
  }

  async rotateApiKey(id: string): Promise<ApiKey> {
    return this.request('POST', `/admin/api-keys/${id}/rotate`);
  }

  async listOidcClients(): Promise<OidcClient[]> {
    return this.request('GET', '/admin/oidc/clients');
  }

  async createOidcClient(data: JsonObject): Promise<OidcClient> {
    return this.request('POST', '/admin/oidc/clients', { body: data });
  }

  async getOidcClient(clientId: string): Promise<OidcClient> {
    return this.request('GET', `/admin/oidc/clients/${clientId}`);
  }

  async updateOidcClient(clientId: string, data: JsonObject): Promise<OidcClient> {
    return this.request('PATCH', `/admin/oidc/clients/${clientId}`, { body: data });
  }

  async deleteOidcClient(clientId: string): Promise<void> {
    await this.request('DELETE', `/admin/oidc/clients/${clientId}`, { requestOptions: { responseType: 'void' } });
  }

  async rotateOidcClientSecret(clientId: string): Promise<JsonObject> {
    return this.request('POST', `/admin/oidc/clients/${clientId}/rotate-secret`);
  }

  async listBulkJobs(query?: Record<string, unknown>): Promise<BulkJob[]> {
    return this.request('GET', '/admin/bulk/jobs', { query });
  }

  async startBulkImport(body: FormData): Promise<BulkJob> {
    return this.request('POST', '/admin/bulk/import', { body });
  }

  async getBulkImportStatus(jobId: string): Promise<BulkJob> {
    return this.request('GET', `/admin/bulk/import/${jobId}`);
  }

  async downloadBulkImportErrorReport(jobId: string): Promise<Blob> {
    return this.request('GET', `/admin/bulk/import/${jobId}/download`, {
      requestOptions: { responseType: 'blob' },
    });
  }

  async startBulkExport(data: JsonObject): Promise<BulkJob> {
    return this.request('POST', '/admin/bulk/export', { body: data });
  }

  async getBulkExportStatus(jobId: string): Promise<BulkJob> {
    return this.request('GET', `/admin/bulk/export/${jobId}`);
  }

  async downloadBulkExportFile(jobId: string): Promise<Blob> {
    return this.request('GET', `/admin/bulk/export/${jobId}/download`, {
      requestOptions: { responseType: 'blob' },
    });
  }

  async deleteBulkJob(jobId: string): Promise<void> {
    await this.request('DELETE', `/admin/bulk/jobs/${jobId}`, { requestOptions: { responseType: 'void' } });
  }

  async listMigrations(): Promise<MigrationJob[]> {
    return this.request('GET', '/admin/migrations');
  }

  async getMigration(id: string): Promise<MigrationJob> {
    return this.request('GET', `/admin/migrations/${id}`);
  }

  async getMigrationProgress(id: string): Promise<JsonObject> {
    return this.request('GET', `/admin/migrations/${id}/progress`);
  }

  async getMigrationErrors(id: string): Promise<JsonObject> {
    return this.request('GET', `/admin/migrations/${id}/errors`);
  }

  async startAuth0Migration(data: JsonObject): Promise<MigrationJob> {
    return this.request('POST', '/admin/migrations/auth0', { body: data });
  }

  async startFirebaseMigration(data: JsonObject): Promise<MigrationJob> {
    return this.request('POST', '/admin/migrations/firebase', { body: data });
  }

  async startCognitoMigration(data: JsonObject): Promise<MigrationJob> {
    return this.request('POST', '/admin/migrations/cognito', { body: data });
  }

  async startCsvMigration(body: FormData): Promise<MigrationJob> {
    return this.request('POST', '/admin/migrations/csv', { body });
  }

  async validateCsvMigration(body: FormData): Promise<JsonObject> {
    return this.request('POST', '/admin/migrations/validate/csv', { body });
  }

  async previewCsvMigration(body: FormData): Promise<JsonObject> {
    return this.request('POST', '/admin/migrations/preview/csv', { body });
  }

  async cancelMigration(id: string): Promise<JsonObject> {
    return this.request('POST', `/admin/migrations/${id}/cancel`);
  }

  async pauseMigration(id: string): Promise<JsonObject> {
    return this.request('POST', `/admin/migrations/${id}/pause`);
  }

  async resumeMigration(id: string): Promise<JsonObject> {
    return this.request('POST', `/admin/migrations/${id}/resume`);
  }

  async listConsentPolicies(query?: Record<string, unknown>): Promise<ConsentPolicy[]> {
    return this.request('GET', '/admin/consents', { query });
  }

  async createConsentPolicy(data: JsonObject): Promise<ConsentPolicy> {
    return this.request('POST', '/admin/consents', { body: data });
  }

  async updateConsentPolicy(id: string, data: JsonObject): Promise<ConsentPolicy> {
    return this.request('PUT', `/admin/consents/${id}`, { body: data });
  }

  async getConsentPolicyStats(id: string): Promise<JsonObject> {
    return this.request('GET', `/admin/consents/${id}/stats`);
  }

  async listPendingConsentExports(): Promise<JsonObject> {
    return this.request('GET', '/admin/consents/export/pending');
  }

  async listPendingConsentDeletions(): Promise<JsonObject> {
    return this.request('GET', '/admin/consents/deletion/pending');
  }
}
