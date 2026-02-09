"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  AnalyticsManager: () => AnalyticsManager,
  ApiKeysManager: () => ApiKeysManager,
  AuditManager: () => AuditManager,
  BulkManager: () => BulkManager,
  ConsentManager: () => ConsentManager,
  MigrationManager: () => MigrationManager,
  OidcManager: () => OidcManager,
  OrganizationManager: () => OrganizationManager,
  ScimAdminManager: () => ScimAdminManager,
  SecurityManager: () => SecurityManager,
  SettingsManager: () => SettingsManager,
  UserManager: () => UserManager,
  VaultAdminClient: () => VaultAdminClient,
  VaultAdminError: () => VaultAdminError
});
module.exports = __toCommonJS(index_exports);

// src/client.ts
var SNAKE_CASE_REGEX = /[A-Z]/g;
function toSnakeCase(value) {
  return value.replace(SNAKE_CASE_REGEX, (match) => `_${match.toLowerCase()}`);
}
function isFormData(value) {
  return typeof FormData !== "undefined" && value instanceof FormData;
}
function isBodyInit(value) {
  if (!value) {
    return false;
  }
  return typeof value === "string" || value instanceof ArrayBuffer || ArrayBuffer.isView(value) || value instanceof URLSearchParams || value instanceof Blob || value instanceof ReadableStream || isFormData(value);
}
function buildQueryString(query, queryStyle) {
  const params = new URLSearchParams();
  for (const [rawKey, rawValue] of Object.entries(query)) {
    if (rawValue === void 0 || rawValue === null) {
      continue;
    }
    const key = queryStyle === "snake" ? toSnakeCase(rawKey) : rawKey;
    if (Array.isArray(rawValue)) {
      for (const item of rawValue) {
        if (item !== void 0 && item !== null) {
          params.append(key, String(item));
        }
      }
      continue;
    }
    params.append(key, String(rawValue));
  }
  const queryString = params.toString();
  return queryString.length > 0 ? `?${queryString}` : "";
}
function isRecord(value) {
  return typeof value === "object" && value !== null;
}
var VaultAdminError = class extends Error {
  constructor(message, code, statusCode, details) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.name = "VaultAdminError";
  }
};
var VaultAdminClient = class {
  baseUrl;
  token;
  tenantId;
  timeout;
  fetchImpl;
  constructor(options) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.token = options.token;
    this.tenantId = options.tenantId;
    this.timeout = options.timeout ?? 3e4;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    if (!this.token) {
      throw new Error("JWT token is required");
    }
    if (!this.tenantId) {
      throw new Error("Tenant ID is required");
    }
  }
  async rawRequest(method, path, config = {}) {
    return this.request(method, path, config);
  }
  async request(method, path, config = {}) {
    const { body, query, requestOptions } = config;
    const responseType = requestOptions?.responseType ?? "json";
    const queryStyle = requestOptions?.queryStyle ?? "snake";
    const queryString = isRecord(query) ? buildQueryString(query, queryStyle) : "";
    const url = `${this.baseUrl}${path}${queryString}`;
    const headers = {
      Authorization: `Bearer ${this.token}`,
      "X-Tenant-ID": this.tenantId,
      ...requestOptions?.headers
    };
    const init = {
      method,
      headers
    };
    if (body !== void 0) {
      if (isBodyInit(body)) {
        init.body = body;
      } else {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
      }
      if (isFormData(body) && headers["Content-Type"]) {
        delete headers["Content-Type"];
      }
    }
    const controller = new AbortController();
    const timeoutMs = requestOptions?.timeout ?? this.timeout;
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    if (requestOptions?.signal) {
      if (requestOptions.signal.aborted) {
        controller.abort(requestOptions.signal.reason);
      } else {
        requestOptions.signal.addEventListener("abort", () => controller.abort(requestOptions.signal?.reason), {
          once: true
        });
      }
    }
    try {
      const response = await this.fetchImpl(url, {
        ...init,
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      if (!response.ok) {
        let message = `HTTP ${response.status}: ${response.statusText}`;
        let code = "UNKNOWN_ERROR";
        let details;
        const contentType = response.headers.get("content-type") ?? "";
        if (contentType.includes("application/json")) {
          const errorData = await response.json().catch(() => ({}));
          message = errorData.error?.message ?? message;
          code = errorData.error?.code ?? code;
          details = errorData.error?.details;
        } else {
          const text = await response.text().catch(() => "");
          if (text) {
            message = text;
          }
        }
        throw new VaultAdminError(message, code, response.status, details);
      }
      if (responseType === "void" || response.status === 204) {
        return void 0;
      }
      switch (responseType) {
        case "text":
          return await response.text();
        case "blob":
          return await response.blob();
        case "arrayBuffer":
          return await response.arrayBuffer();
        case "stream":
          return response.body;
        case "json":
        default:
          return await response.json();
      }
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof VaultAdminError) {
        throw error;
      }
      if (error instanceof Error && error.name === "AbortError") {
        throw new VaultAdminError("Request timeout", "TIMEOUT", 408);
      }
      throw new VaultAdminError(error instanceof Error ? error.message : "Unknown error", "NETWORK_ERROR", 0);
    }
  }
  async *iteratePages(fetchPage, perPage = 100) {
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
  async getDashboard() {
    return this.request("GET", "/admin/");
  }
  async getMetrics(query) {
    return this.request("GET", "/admin/analytics/dashboard", { query });
  }
  async listUsers(query) {
    return this.request("GET", "/admin/users", { query });
  }
  async *iterateUsers(query = {}) {
    yield* this.iteratePages(async (page, perPage) => {
      const response = await this.listUsers({ ...query, page, perPage });
      const effectivePerPage = response.per_page > 0 ? response.per_page : perPage;
      const totalPages = Math.max(1, Math.ceil(response.total / effectivePerPage));
      return {
        items: response.users,
        hasMore: response.users.length > 0 && page < totalPages
      };
    });
  }
  async createUser(data) {
    return this.request("POST", "/admin/users", { body: data });
  }
  async getUser(userId) {
    return this.request("GET", `/admin/users/${userId}`);
  }
  async updateUser(userId, data) {
    return this.request("PATCH", `/admin/users/${userId}`, { body: data });
  }
  async deleteUser(userId) {
    return this.request("DELETE", `/admin/users/${userId}`);
  }
  async suspendUser(userId, data) {
    return this.request("POST", `/admin/users/${userId}/suspend`, { body: data ?? {} });
  }
  async activateUser(userId) {
    return this.request("POST", `/admin/users/${userId}/activate`);
  }
  async listUserSessions(userId) {
    return this.request("GET", `/admin/users/${userId}/sessions`);
  }
  async revokeAllUserSessions(userId) {
    return this.request("DELETE", `/admin/users/${userId}/sessions`);
  }
  async listOrganizations(query) {
    return this.request("GET", "/admin/organizations", { query });
  }
  async *iterateOrganizations(query = {}) {
    yield* this.iteratePages(async (page, perPage) => {
      const response = await this.listOrganizations({ ...query, page, perPage });
      return {
        items: response.data,
        hasMore: page < response.pagination.totalPages
      };
    });
  }
  async getOrganization(orgId) {
    return this.request("GET", `/admin/organizations/${orgId}`);
  }
  async updateOrganization(orgId, data) {
    return this.request("PATCH", `/admin/organizations/${orgId}`, { body: data });
  }
  async deleteOrganization(orgId) {
    return this.request("DELETE", `/admin/organizations/${orgId}`);
  }
  async listOrganizationMembers(orgId) {
    return this.request("GET", `/admin/organizations/${orgId}/members`);
  }
  async updateOrganizationMember(orgId, userId, data) {
    return this.request("PATCH", `/admin/organizations/${orgId}/members/${userId}`, { body: data });
  }
  async removeOrganizationMember(orgId, userId) {
    return this.request("DELETE", `/admin/organizations/${orgId}/members/${userId}`);
  }
  async listOrganizationInvitations(orgId) {
    return this.request("GET", `/admin/organizations/${orgId}/invitations`);
  }
  async cancelInvitation(orgId, invitationId) {
    return this.request("DELETE", `/admin/organizations/${orgId}/invitations/${invitationId}`);
  }
  async queryAuditLogs(query) {
    return this.request("GET", "/admin/audit-logs", { query });
  }
  async *iterateAuditLogs(query = {}) {
    yield* this.iteratePages(async (page, perPage) => {
      const response = await this.queryAuditLogs({ ...query, page, perPage });
      return {
        items: response.data,
        hasMore: page < response.pagination.totalPages
      };
    });
  }
  async getRecentAuditLogs(limit = 50) {
    const result = await this.queryAuditLogs({ perPage: limit });
    return result.data;
  }
  async getUserAuditLogs(userId, query) {
    return this.queryAuditLogs({ ...query, userId });
  }
  async getSettings() {
    return this.request("GET", "/admin/settings");
  }
  async updateSettings(data) {
    return this.request("PATCH", "/admin/settings", { body: data });
  }
  async updateMfaSettings(data) {
    return this.request("PATCH", "/admin/settings/mfa", { body: data });
  }
  async getSecuritySettings() {
    return this.request("GET", "/admin/settings/security");
  }
  async updateSecuritySettings(data) {
    return this.request("PATCH", "/admin/settings/security", { body: data });
  }
  async getPrivacySettings() {
    return this.request("GET", "/admin/settings/privacy");
  }
  async updatePrivacySettings(data) {
    return this.request("PATCH", "/admin/settings/privacy", { body: data });
  }
  async listSamlConnections() {
    return this.request("GET", "/admin/sso/saml/connections");
  }
  async createSamlConnection(data) {
    return this.request("POST", "/admin/sso/saml/connections", { body: data });
  }
  async getSamlConnection(connectionId) {
    return this.request("GET", `/admin/sso/saml/connections/${connectionId}`);
  }
  async updateSamlConnection(connectionId, data) {
    return this.request("PATCH", `/admin/sso/saml/connections/${connectionId}`, { body: data });
  }
  async deleteSamlConnection(connectionId) {
    await this.request("DELETE", `/admin/sso/saml/connections/${connectionId}`, { requestOptions: { responseType: "void" } });
  }
  async listOidcConnections() {
    return this.request("GET", "/admin/sso/oidc/connections");
  }
  async createOidcConnection(data) {
    return this.request("POST", "/admin/sso/oidc/connections", { body: data });
  }
  async getOidcConnection(connectionId) {
    return this.request("GET", `/admin/sso/oidc/connections/${connectionId}`);
  }
  async updateOidcConnection(connectionId, data) {
    return this.request("PATCH", `/admin/sso/oidc/connections/${connectionId}`, { body: data });
  }
  async deleteOidcConnection(connectionId) {
    await this.request("DELETE", `/admin/sso/oidc/connections/${connectionId}`, { requestOptions: { responseType: "void" } });
  }
  async updateOrganizationSso(orgId, data) {
    return this.request("PATCH", `/admin/organizations/${orgId}/sso`, { body: data });
  }
  async listOrganizationDomains(orgId) {
    return this.request("GET", `/admin/organizations/${orgId}/domains`);
  }
  async createOrganizationDomain(orgId, domain) {
    return this.request("POST", `/admin/organizations/${orgId}/domains`, { body: { domain } });
  }
  async verifyOrganizationDomain(orgId, domainId) {
    return this.request("POST", `/admin/organizations/${orgId}/domains/${domainId}/verify`);
  }
  async deleteOrganizationDomain(orgId, domainId) {
    await this.request("DELETE", `/admin/organizations/${orgId}/domains/${domainId}`, { requestOptions: { responseType: "void" } });
  }
  async listOrganizationRoles(orgId) {
    return this.request("GET", `/admin/organizations/${orgId}/roles`);
  }
  async createOrganizationRole(orgId, data) {
    return this.request("POST", `/admin/organizations/${orgId}/roles`, { body: data });
  }
  async updateOrganizationRole(orgId, roleId, data) {
    return this.request("PATCH", `/admin/organizations/${orgId}/roles/${roleId}`, { body: data });
  }
  async deleteOrganizationRole(orgId, roleId) {
    await this.request("DELETE", `/admin/organizations/${orgId}/roles/${roleId}`, { requestOptions: { responseType: "void" } });
  }
  async getBranding() {
    return this.request("GET", "/admin/branding");
  }
  async updateBranding(data) {
    return this.request("PATCH", "/admin/branding", { body: data });
  }
  async getTheme() {
    return this.request("GET", "/admin/themes");
  }
  async updateTheme(data) {
    return this.request("PATCH", "/admin/themes", { body: data });
  }
  async scimListUsers() {
    return this.request("GET", "/admin/scim/v2/Users");
  }
  async scimCreateUser(data) {
    return this.request("POST", "/admin/scim/v2/Users", { body: data });
  }
  async scimGetUser(userId) {
    return this.request("GET", `/admin/scim/v2/Users/${userId}`);
  }
  async scimPatchUser(userId, data) {
    return this.request("PATCH", `/admin/scim/v2/Users/${userId}`, { body: data });
  }
  async scimDeleteUser(userId) {
    await this.request("DELETE", `/admin/scim/v2/Users/${userId}`, { requestOptions: { responseType: "void" } });
  }
  async scimListGroups() {
    return this.request("GET", "/admin/scim/v2/Groups");
  }
  async scimCreateGroup(data) {
    return this.request("POST", "/admin/scim/v2/Groups", { body: data });
  }
  async scimGetGroup(groupId) {
    return this.request("GET", `/admin/scim/v2/Groups/${groupId}`);
  }
  async scimPatchGroup(groupId, data) {
    return this.request("PATCH", `/admin/scim/v2/Groups/${groupId}`, { body: data });
  }
  async scimDeleteGroup(groupId) {
    await this.request("DELETE", `/admin/scim/v2/Groups/${groupId}`, { requestOptions: { responseType: "void" } });
  }
  async listDirectoryConnections() {
    return this.request("GET", "/admin/directory/ldap/connections");
  }
  async createDirectoryConnection(data) {
    return this.request("POST", "/admin/directory/ldap/connections", { body: data });
  }
  async updateDirectoryConnection(connectionId, data) {
    return this.request("PATCH", `/admin/directory/ldap/connections/${connectionId}`, { body: data });
  }
  async deleteDirectoryConnection(connectionId) {
    await this.request("DELETE", `/admin/directory/ldap/connections/${connectionId}`, { requestOptions: { responseType: "void" } });
  }
  async createSecurityPolicy(data) {
    return this.request("POST", "/admin/security/policies", { body: data });
  }
  async updateSecurityPolicy(policyId, data) {
    return this.request("PATCH", `/admin/security/policies/${policyId}`, { body: data });
  }
  async listAuditExports() {
    return this.request("GET", "/admin/audit-logs/exports");
  }
  async createAuditExport(data) {
    return this.request("POST", "/admin/audit-logs/exports", { body: data });
  }
  async listAuditWebhooks() {
    return this.request("GET", "/admin/audit-logs/webhooks");
  }
  async createAuditWebhook(data) {
    return this.request("POST", "/admin/audit-logs/webhooks", { body: data });
  }
  async deleteAuditWebhook(webhookId) {
    await this.request("DELETE", `/admin/audit-logs/webhooks/${webhookId}`, { requestOptions: { responseType: "void" } });
  }
  async getSystemHealth() {
    return this.request("GET", "/admin/system/health");
  }
  async getAnalyticsDashboard(query) {
    return this.request("GET", "/admin/analytics/dashboard", { query });
  }
  async getAnalyticsLogins(query) {
    return this.request("GET", "/admin/analytics/logins", { query });
  }
  async getAnalyticsUsers(query) {
    return this.request("GET", "/admin/analytics/users", { query });
  }
  async getAnalyticsSecurity(query) {
    return this.request("GET", "/admin/analytics/security", { query });
  }
  async exportAnalytics(query) {
    return this.request("GET", "/admin/analytics/export", {
      query,
      requestOptions: { responseType: "blob" }
    });
  }
  async getSecurityGeoPolicy() {
    return this.request("GET", "/admin/security/geo");
  }
  async updateSecurityGeoPolicy(data) {
    return this.request("PUT", "/admin/security/geo", { body: data });
  }
  async getSecurityVpnDetection() {
    return this.request("GET", "/admin/security/vpn-detection");
  }
  async updateSecurityVpnDetection(data) {
    return this.request("PUT", "/admin/security/vpn-detection", { body: data });
  }
  async listScimTokens() {
    return this.request("GET", "/admin/scim/tokens");
  }
  async createScimToken(data) {
    return this.request("POST", "/admin/scim/tokens", { body: data });
  }
  async revokeScimToken(tokenId) {
    return this.request("POST", `/admin/scim/tokens/${tokenId}`);
  }
  async deleteScimToken(tokenId) {
    await this.request("DELETE", `/admin/scim/tokens/${tokenId}`, { requestOptions: { responseType: "void" } });
  }
  async getScimConfig() {
    return this.request("GET", "/admin/scim/config");
  }
  async updateScimConfig(data) {
    return this.request("PUT", "/admin/scim/config", { body: data });
  }
  async getScimStats() {
    return this.request("GET", "/admin/scim/stats");
  }
  async listApiKeys() {
    return this.request("GET", "/admin/api-keys");
  }
  async createApiKey(data) {
    return this.request("POST", "/admin/api-keys", { body: data });
  }
  async getApiKey(id) {
    return this.request("GET", `/admin/api-keys/${id}`);
  }
  async updateApiKey(id, data) {
    return this.request("PUT", `/admin/api-keys/${id}`, { body: data });
  }
  async revokeApiKey(id) {
    return this.request("PUT", `/admin/api-keys/${id}/revoke`);
  }
  async rotateApiKey(id) {
    return this.request("POST", `/admin/api-keys/${id}/rotate`);
  }
  async listOidcClients() {
    return this.request("GET", "/admin/oidc/clients");
  }
  async createOidcClient(data) {
    return this.request("POST", "/admin/oidc/clients", { body: data });
  }
  async getOidcClient(clientId) {
    return this.request("GET", `/admin/oidc/clients/${clientId}`);
  }
  async updateOidcClient(clientId, data) {
    return this.request("PATCH", `/admin/oidc/clients/${clientId}`, { body: data });
  }
  async deleteOidcClient(clientId) {
    await this.request("DELETE", `/admin/oidc/clients/${clientId}`, { requestOptions: { responseType: "void" } });
  }
  async rotateOidcClientSecret(clientId) {
    return this.request("POST", `/admin/oidc/clients/${clientId}/rotate-secret`);
  }
  async listBulkJobs(query) {
    return this.request("GET", "/admin/bulk/jobs", { query });
  }
  async startBulkImport(body) {
    return this.request("POST", "/admin/bulk/import", { body });
  }
  async getBulkImportStatus(jobId) {
    return this.request("GET", `/admin/bulk/import/${jobId}`);
  }
  async downloadBulkImportErrorReport(jobId) {
    return this.request("GET", `/admin/bulk/import/${jobId}/download`, {
      requestOptions: { responseType: "blob" }
    });
  }
  async startBulkExport(data) {
    return this.request("POST", "/admin/bulk/export", { body: data });
  }
  async getBulkExportStatus(jobId) {
    return this.request("GET", `/admin/bulk/export/${jobId}`);
  }
  async downloadBulkExportFile(jobId) {
    return this.request("GET", `/admin/bulk/export/${jobId}/download`, {
      requestOptions: { responseType: "blob" }
    });
  }
  async deleteBulkJob(jobId) {
    await this.request("DELETE", `/admin/bulk/jobs/${jobId}`, { requestOptions: { responseType: "void" } });
  }
  async listMigrations() {
    return this.request("GET", "/admin/migrations");
  }
  async getMigration(id) {
    return this.request("GET", `/admin/migrations/${id}`);
  }
  async getMigrationProgress(id) {
    return this.request("GET", `/admin/migrations/${id}/progress`);
  }
  async getMigrationErrors(id) {
    return this.request("GET", `/admin/migrations/${id}/errors`);
  }
  async startAuth0Migration(data) {
    return this.request("POST", "/admin/migrations/auth0", { body: data });
  }
  async startFirebaseMigration(data) {
    return this.request("POST", "/admin/migrations/firebase", { body: data });
  }
  async startCognitoMigration(data) {
    return this.request("POST", "/admin/migrations/cognito", { body: data });
  }
  async startCsvMigration(body) {
    return this.request("POST", "/admin/migrations/csv", { body });
  }
  async validateCsvMigration(body) {
    return this.request("POST", "/admin/migrations/validate/csv", { body });
  }
  async previewCsvMigration(body) {
    return this.request("POST", "/admin/migrations/preview/csv", { body });
  }
  async cancelMigration(id) {
    return this.request("POST", `/admin/migrations/${id}/cancel`);
  }
  async pauseMigration(id) {
    return this.request("POST", `/admin/migrations/${id}/pause`);
  }
  async resumeMigration(id) {
    return this.request("POST", `/admin/migrations/${id}/resume`);
  }
  async listConsentPolicies(query) {
    return this.request("GET", "/admin/consents", { query });
  }
  async createConsentPolicy(data) {
    return this.request("POST", "/admin/consents", { body: data });
  }
  async updateConsentPolicy(id, data) {
    return this.request("PUT", `/admin/consents/${id}`, { body: data });
  }
  async getConsentPolicyStats(id) {
    return this.request("GET", `/admin/consents/${id}/stats`);
  }
  async listPendingConsentExports() {
    return this.request("GET", "/admin/consents/export/pending");
  }
  async listPendingConsentDeletions() {
    return this.request("GET", "/admin/consents/deletion/pending");
  }
};

// src/users.ts
var UserManager = class {
  constructor(client) {
    this.client = client;
  }
  /**
   * Get all users with optional filtering
   */
  async getAll(filter) {
    const results = [];
    for await (const user of this.client.iterateUsers({
      status: filter?.status,
      email: filter?.email,
      orgId: filter?.organizationId
    })) {
      results.push(user);
    }
    return results;
  }
  /**
   * Find user by email
   */
  async findByEmail(email) {
    const result = await this.client.listUsers({ email, perPage: 1 });
    return result.users[0] ?? null;
  }
  /**
   * Create user with optional password
   */
  async create(data) {
    return this.client.createUser(data);
  }
  /**
   * Update user profile
   */
  async update(userId, data) {
    return this.client.updateUser(userId, data);
  }
  /**
   * Suspend user account
   */
  async suspend(userId, reason) {
    return this.client.suspendUser(userId, { reason });
  }
  /**
   * Activate suspended user
   */
  async activate(userId) {
    return this.client.activateUser(userId);
  }
  /**
   * Delete user permanently
   */
  async delete(userId) {
    await this.client.deleteUser(userId);
  }
  /**
   * Force logout from all devices
   */
  async forceLogout(userId) {
    await this.client.revokeAllUserSessions(userId);
  }
  /**
   * Get user statistics
   */
  async getStats() {
    const all = await this.getAll();
    const mfaEnabledCount = all.filter((u) => u.mfaEnabled === true).length;
    return {
      total: all.length,
      active: all.filter((u) => u.status === "active").length,
      suspended: all.filter((u) => u.status === "suspended").length,
      pending: all.filter((u) => u.status === "pending").length,
      mfaEnabled: mfaEnabledCount > 0 ? mfaEnabledCount : void 0
    };
  }
  /**
   * Get users by status
   */
  async getByStatus(status) {
    return this.getAll({ status });
  }
  /**
   * Get users who haven't logged in recently
   */
  async getInactive(days = 30) {
    const all = await this.getAll();
    const cutoff = /* @__PURE__ */ new Date();
    cutoff.setDate(cutoff.getDate() - days);
    return all.filter((user) => {
      const lastLoginAt = user.lastLoginAt ?? user.last_login_at;
      if (!lastLoginAt) return true;
      return new Date(lastLoginAt) < cutoff;
    });
  }
  /**
   * Bulk suspend users
   */
  async bulkSuspend(userIds, reason) {
    const results = await Promise.all(
      userIds.map((id) => this.client.suspendUser(id, { reason }))
    );
    return results;
  }
  /**
   * Bulk activate users
   */
  async bulkActivate(userIds) {
    const results = await Promise.all(
      userIds.map((id) => this.client.activateUser(id))
    );
    return results;
  }
};

// src/organizations.ts
var OrganizationManager = class {
  constructor(client) {
    this.client = client;
  }
  /**
   * Get all organizations
   */
  async getAll(filter) {
    const results = [];
    for await (const org of this.client.iterateOrganizations({
      status: filter?.status
    })) {
      results.push(org);
    }
    return results;
  }
  /**
   * Find organization by slug
   */
  async findBySlug(slug) {
    const all = await this.getAll();
    return all.find((o) => o.slug === slug) ?? null;
  }
  /**
   * Get organization details with members
   */
  async getDetails(orgId) {
    const [organization, members] = await Promise.all([
      this.client.getOrganization(orgId),
      this.client.listOrganizationMembers(orgId)
    ]);
    return { organization, members };
  }
  /**
   * Update organization settings
   */
  async update(orgId, data) {
    return this.client.updateOrganization(orgId, data);
  }
  /**
   * Delete organization
   */
  async delete(orgId) {
    await this.client.deleteOrganization(orgId);
  }
  /**
   * Update member role
   */
  async updateMemberRole(orgId, userId, role) {
    return this.client.updateOrganizationMember(orgId, userId, { role });
  }
  /**
   * Remove member from organization
   */
  async removeMember(orgId, userId) {
    await this.client.removeOrganizationMember(orgId, userId);
  }
  /**
   * Get organization statistics
   */
  async getStats() {
    const all = await this.getAll();
    const active = all.filter((o) => o.status === "active");
    const totalMembers = active.reduce((sum, o) => sum + o.memberCount, 0);
    return {
      total: all.length,
      active: active.length,
      totalMembers,
      averageMembersPerOrg: active.length > 0 ? Math.round(totalMembers / active.length) : 0
    };
  }
  /**
   * Get organizations with no members (orphaned)
   */
  async getOrphaned() {
    const all = await this.getAll();
    return all.filter((o) => o.memberCount === 0);
  }
  /**
   * Get organizations approaching member limit
   */
  async getNearLimit(thresholdPercent = 90) {
    const all = await this.getAll();
    return all.filter((o) => {
      if (!o.maxMembers) return false;
      return o.memberCount / o.maxMembers * 100 >= thresholdPercent;
    });
  }
  /**
   * Bulk delete organizations
   */
  async bulkDelete(orgIds) {
    await Promise.all(orgIds.map((id) => this.client.deleteOrganization(id)));
  }
};

// src/audit.ts
var AuditManager = class {
  constructor(client) {
    this.client = client;
  }
  /**
   * Query audit logs with filters
   */
  async query(filter, page = 1, perPage = 50) {
    const result = await this.client.queryAuditLogs({
      page,
      perPage,
      userId: filter?.userId,
      action: filter?.action,
      resourceType: filter?.resourceType,
      from: filter?.from?.toISOString(),
      to: filter?.to?.toISOString(),
      success: filter?.success
    });
    return {
      entries: result.data,
      total: result.pagination.total
    };
  }
  /**
   * Get all audit log entries (paginated iteration)
   */
  async getAll(filter, dateRange) {
    const results = [];
    let page = 1;
    let hasMore = true;
    while (hasMore) {
      const { entries } = await this.query(
        { ...filter, ...dateRange },
        page,
        500
        // Max page size for bulk export
      );
      results.push(...entries);
      hasMore = entries.length === 500;
      page++;
      if (page > 100) break;
    }
    return results;
  }
  /**
   * Get recent activity
   */
  async getRecent(limit = 50) {
    const { entries } = await this.query(void 0, 1, limit);
    return entries;
  }
  /**
   * Get user activity timeline
   */
  async getUserActivity(userId, days = 30) {
    const from = /* @__PURE__ */ new Date();
    from.setDate(from.getDate() - days);
    return this.getAll({ userId }, { from, to: /* @__PURE__ */ new Date() });
  }
  /**
   * Summarize actions in a time period
   */
  async summarizeActions(days = 7) {
    const from = /* @__PURE__ */ new Date();
    from.setDate(from.getDate() - days);
    const entries = await this.getAll({}, { from, to: /* @__PURE__ */ new Date() });
    const summary = /* @__PURE__ */ new Map();
    for (const entry of entries) {
      const existing = summary.get(entry.action);
      if (existing) {
        existing.count++;
        if (entry.success) {
          existing.successCount++;
        } else {
          existing.failureCount++;
        }
      } else {
        summary.set(entry.action, {
          action: entry.action,
          count: 1,
          successCount: entry.success ? 1 : 0,
          failureCount: entry.success ? 0 : 1
        });
      }
    }
    return Array.from(summary.values()).sort((a, b) => b.count - a.count);
  }
  /**
   * Get failed login attempts
   */
  async getFailedLogins(days = 7) {
    const from = /* @__PURE__ */ new Date();
    from.setDate(from.getDate() - days);
    const entries = await this.getAll(
      { action: "user.login", success: false },
      { from, to: /* @__PURE__ */ new Date() }
    );
    return entries;
  }
  /**
   * Detect suspicious activity (multiple failed logins)
   */
  async detectSuspiciousActivity(failedThreshold = 5, hours = 1) {
    const from = /* @__PURE__ */ new Date();
    from.setHours(from.getHours() - hours);
    const entries = await this.getAll(
      { success: false },
      { from, to: /* @__PURE__ */ new Date() }
    );
    const userMap = /* @__PURE__ */ new Map();
    for (const entry of entries) {
      if (!entry.userId) continue;
      const existing = userMap.get(entry.userId);
      if (existing) {
        existing.actionCount++;
        if (entry.ipAddress && !existing.ipAddresses.includes(entry.ipAddress)) {
          existing.ipAddresses.push(entry.ipAddress);
        }
        if (entry.timestamp > existing.lastActivity) {
          existing.lastActivity = entry.timestamp;
        }
      } else {
        userMap.set(entry.userId, {
          userId: entry.userId,
          email: entry.userEmail,
          actionCount: 1,
          lastActivity: entry.timestamp,
          ipAddresses: entry.ipAddress ? [entry.ipAddress] : []
        });
      }
    }
    return Array.from(userMap.values()).filter((u) => u.actionCount >= failedThreshold).sort((a, b) => b.actionCount - a.actionCount);
  }
  /**
   * Export audit logs for compliance
   */
  async exportForCompliance(startDate, endDate) {
    const entries = await this.getAll({}, { from: startDate, to: endDate });
    return {
      entries,
      generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
      dateRange: {
        from: startDate.toISOString(),
        to: endDate.toISOString()
      }
    };
  }
};

// src/settings.ts
var SettingsManager = class {
  constructor(client) {
    this.client = client;
  }
  /**
   * Get current tenant settings
   */
  async get() {
    return this.client.getSettings();
  }
  /**
   * Update tenant name
   */
  async updateName(name) {
    return this.client.updateSettings({ name });
  }
  /**
   * Update password policy
   */
  async updatePasswordPolicy(policy) {
    return this.client.updateSettings({
      passwordPolicy: {
        minLength: policy.minLength ?? 12,
        requireUppercase: policy.requireUppercase ?? true,
        requireLowercase: policy.requireLowercase ?? true,
        requireNumbers: policy.requireNumbers ?? true,
        requireSpecial: policy.requireSpecial ?? true
      }
    });
  }
  /**
   * Update MFA policy
   */
  async updateMfaPolicy(policy) {
    return this.client.updateSettings({
      mfaPolicy: {
        enabled: policy.enabled ?? true,
        required: policy.required ?? false
      }
    });
  }
  /**
   * Require MFA for all users
   */
  async requireMfa() {
    return this.updateMfaPolicy({ enabled: true, required: true });
  }
  /**
   * Make MFA optional
   */
  async makeMfaOptional() {
    return this.updateMfaPolicy({ enabled: true, required: false });
  }
  /**
   * Disable MFA entirely
   */
  async disableMfa() {
    return this.updateMfaPolicy({ enabled: false, required: false });
  }
  /**
   * Add allowed email domain
   */
  async addAllowedDomain(domain) {
    const current = await this.get();
    const domains = new Set(current.allowedDomains ?? []);
    domains.add(domain.toLowerCase());
    return this.client.updateSettings({
      allowedDomains: Array.from(domains)
    });
  }
  /**
   * Remove allowed email domain
   */
  async removeAllowedDomain(domain) {
    const current = await this.get();
    const domains = (current.allowedDomains ?? []).filter((d) => d !== domain.toLowerCase());
    return this.client.updateSettings({
      allowedDomains: domains
    });
  }
  /**
   * Set allowed domains (replaces all)
   */
  async setAllowedDomains(domains) {
    return this.client.updateSettings({
      allowedDomains: domains.map((d) => d.toLowerCase())
    });
  }
  /**
   * Check if email domain is allowed
   */
  async isDomainAllowed(email) {
    const settings = await this.get();
    const allowedDomains = settings.allowedDomains ?? [];
    if (allowedDomains.length === 0) return true;
    const domain = email.split("@")[1]?.toLowerCase();
    if (!domain) return false;
    return allowedDomains.includes(domain);
  }
  /**
   * Get security settings summary
   */
  async getSecuritySummary() {
    const settings = await this.get();
    let passwordStrength = "weak";
    const policy = settings.passwordPolicy ?? {};
    if (policy.minLength !== void 0 && policy.minLength >= 12 && policy.requireUppercase && policy.requireLowercase && policy.requireNumbers && policy.requireSpecial) {
      passwordStrength = "strong";
    } else if ((policy.minLength ?? 0) >= 8) {
      passwordStrength = "medium";
    }
    let mfaStatus = "disabled";
    if (settings.mfaPolicy?.enabled) {
      mfaStatus = settings.mfaPolicy.required ? "required" : "optional";
    }
    return {
      passwordStrength,
      mfaStatus,
      domainRestrictions: (settings.allowedDomains?.length ?? 0) > 0 ? "restricted" : "none"
    };
  }
};

// src/analytics.ts
var AnalyticsManager = class {
  constructor(client) {
    this.client = client;
  }
  getDashboard(query) {
    return this.client.getAnalyticsDashboard(query);
  }
  getLogins(query) {
    return this.client.getAnalyticsLogins(query);
  }
  getUsers(query) {
    return this.client.getAnalyticsUsers(query);
  }
  getSecurity(query) {
    return this.client.getAnalyticsSecurity(query);
  }
  export(query) {
    return this.client.exportAnalytics(query);
  }
};

// src/security.ts
var SecurityManager = class {
  constructor(client) {
    this.client = client;
  }
  getGeoPolicy() {
    return this.client.getSecurityGeoPolicy();
  }
  updateGeoPolicy(data) {
    return this.client.updateSecurityGeoPolicy(data);
  }
  getVpnDetection() {
    return this.client.getSecurityVpnDetection();
  }
  updateVpnDetection(data) {
    return this.client.updateSecurityVpnDetection(data);
  }
};

// src/scim-admin.ts
var ScimAdminManager = class {
  constructor(client) {
    this.client = client;
  }
  listTokens() {
    return this.client.listScimTokens();
  }
  createToken(data) {
    return this.client.createScimToken(data);
  }
  revokeToken(tokenId) {
    return this.client.revokeScimToken(tokenId);
  }
  deleteToken(tokenId) {
    return this.client.deleteScimToken(tokenId);
  }
  getConfig() {
    return this.client.getScimConfig();
  }
  updateConfig(data) {
    return this.client.updateScimConfig(data);
  }
  getStats() {
    return this.client.getScimStats();
  }
};

// src/api-keys.ts
var ApiKeysManager = class {
  constructor(client) {
    this.client = client;
  }
  list() {
    return this.client.listApiKeys();
  }
  create(data) {
    return this.client.createApiKey(data);
  }
  get(id) {
    return this.client.getApiKey(id);
  }
  update(id, data) {
    return this.client.updateApiKey(id, data);
  }
  rotate(id) {
    return this.client.rotateApiKey(id);
  }
  revoke(id) {
    return this.client.revokeApiKey(id);
  }
};

// src/oidc.ts
var OidcManager = class {
  constructor(client) {
    this.client = client;
  }
  listClients() {
    return this.client.listOidcClients();
  }
  createClient(data) {
    return this.client.createOidcClient(data);
  }
  getClient(clientId) {
    return this.client.getOidcClient(clientId);
  }
  updateClient(clientId, data) {
    return this.client.updateOidcClient(clientId, data);
  }
  deleteClient(clientId) {
    return this.client.deleteOidcClient(clientId);
  }
  rotateSecret(clientId) {
    return this.client.rotateOidcClientSecret(clientId);
  }
};

// src/bulk.ts
var BulkManager = class {
  constructor(client) {
    this.client = client;
  }
  listJobs(query) {
    return this.client.listBulkJobs(query);
  }
  startImport(file, fields = {}) {
    const formData = new FormData();
    formData.append("file", file);
    for (const [key, value] of Object.entries(fields)) {
      formData.append(key, value);
    }
    return this.client.startBulkImport(formData);
  }
  getImportStatus(jobId) {
    return this.client.getBulkImportStatus(jobId);
  }
  downloadImportErrors(jobId) {
    return this.client.downloadBulkImportErrorReport(jobId);
  }
  startExport(data) {
    return this.client.startBulkExport(data);
  }
  getExportStatus(jobId) {
    return this.client.getBulkExportStatus(jobId);
  }
  downloadExport(jobId) {
    return this.client.downloadBulkExportFile(jobId);
  }
  deleteJob(jobId) {
    return this.client.deleteBulkJob(jobId);
  }
};

// src/migrations.ts
var MigrationManager = class {
  constructor(client) {
    this.client = client;
  }
  list() {
    return this.client.listMigrations();
  }
  get(id) {
    return this.client.getMigration(id);
  }
  getProgress(id) {
    return this.client.getMigrationProgress(id);
  }
  getErrors(id) {
    return this.client.getMigrationErrors(id);
  }
  fromAuth0(data) {
    return this.client.startAuth0Migration(data);
  }
  fromFirebase(data) {
    return this.client.startFirebaseMigration(data);
  }
  fromCognito(data) {
    return this.client.startCognitoMigration(data);
  }
  fromCsv(file, fields = {}) {
    const formData = new FormData();
    formData.append("file", file);
    for (const [key, value] of Object.entries(fields)) {
      formData.append(key, value);
    }
    return this.client.startCsvMigration(formData);
  }
  validateCsv(file) {
    const formData = new FormData();
    formData.append("file", file);
    return this.client.validateCsvMigration(formData);
  }
  previewCsv(file) {
    const formData = new FormData();
    formData.append("file", file);
    return this.client.previewCsvMigration(formData);
  }
  cancel(id) {
    return this.client.cancelMigration(id);
  }
  pause(id) {
    return this.client.pauseMigration(id);
  }
  resume(id) {
    return this.client.resumeMigration(id);
  }
};

// src/consent.ts
var ConsentManager = class {
  constructor(client) {
    this.client = client;
  }
  list(query) {
    return this.client.listConsentPolicies(query);
  }
  create(data) {
    return this.client.createConsentPolicy(data);
  }
  update(id, data) {
    return this.client.updateConsentPolicy(id, data);
  }
  stats(id) {
    return this.client.getConsentPolicyStats(id);
  }
  pendingExports() {
    return this.client.listPendingConsentExports();
  }
  pendingDeletions() {
    return this.client.listPendingConsentDeletions();
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AnalyticsManager,
  ApiKeysManager,
  AuditManager,
  BulkManager,
  ConsentManager,
  MigrationManager,
  OidcManager,
  OrganizationManager,
  ScimAdminManager,
  SecurityManager,
  SettingsManager,
  UserManager,
  VaultAdminClient,
  VaultAdminError
});
