/**
 * Vault Admin API types
 * Regenerated from OpenAPI contract and server route validation.
 */
type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
type JsonObject = {
    [key: string]: JsonValue;
};
interface ErrorResponse {
    error: {
        code: string;
        message: string;
        details?: Record<string, unknown>;
    };
}
interface MessageResponse {
    message: string;
}
interface PaginationResponse {
    page: number;
    perPage: number;
    total: number;
    totalPages: number;
}
interface DateRangeQuery {
    from?: string;
    to?: string;
}
interface DashboardStats {
    total_users: number;
    active_users: number;
    pending_users: number;
    total_organizations: number;
}
interface DashboardResponse {
    stats: DashboardStats;
}
interface MetricsResponse {
}
type UserStatus = 'active' | 'pending' | 'suspended' | 'deactivated';
interface CreateUserRequest {
    email: string;
    name: string;
    emailVerified?: boolean;
}
interface UpdateUserRequest {
    name?: string;
    status?: UserStatus;
}
interface SuspendUserRequest {
    reason?: string;
}
interface AdminUserResponse {
    id: string;
    email: string;
    name?: string;
    status: UserStatus;
    email_verified?: boolean;
    emailVerified?: boolean;
    created_at?: string;
    createdAt?: string;
    last_login_at?: string;
    lastLoginAt?: string;
    organization_count?: number;
    organizationCount?: number;
    mfaEnabled?: boolean;
}
interface ListUsersResponse {
    users: AdminUserResponse[];
    total: number;
    page: number;
    per_page: number;
}
interface AdminSessionResponse {
    id: string;
    userId: string;
    createdAt: string;
    lastActivityAt: string;
    expiresAt: string;
    ipAddress?: string;
    userAgent?: string;
    deviceInfo?: JsonObject;
    mfaVerified: boolean;
    status: string;
}
interface AdminSessionListResponse {
    sessions: AdminSessionResponse[];
    currentSessions: number;
    maxSessions: number;
}
interface ListUsersQuery {
    page?: number;
    perPage?: number;
    status?: UserStatus;
    email?: string;
    orgId?: string;
}
interface UpdateOrgRequest {
    name?: string;
    description?: string;
    logoUrl?: string;
    website?: string;
    maxMembers?: number;
    ssoRequired?: boolean;
    status?: string;
}
interface AdminOrganizationResponse {
    id: string;
    name: string;
    slug: string;
    description?: string;
    logoUrl?: string;
    website?: string;
    memberCount: number;
    maxMembers?: number;
    ssoRequired: boolean;
    status: string;
    createdAt: string;
    updatedAt: string;
    deletedAt?: string;
}
interface PaginatedOrganizationsResponse {
    data: AdminOrganizationResponse[];
    pagination: PaginationResponse;
}
interface AdminOrganizationMemberResponse {
    id: string;
    userId: string;
    email: string;
    name?: string;
    role: string;
    status: string;
    joinedAt?: string;
}
interface InvitationResponse {
    id: string;
    email: string;
    role: string;
    expiresAt: string;
    createdAt: string;
}
interface UpdateMemberRequest {
    role: string;
}
interface ListOrganizationsQuery {
    page?: number;
    perPage?: number;
    status?: string;
}
interface AuditLogEntry {
    id: string;
    timestamp: string;
    action: string;
    resourceType: string;
    resourceId: string;
    userId?: string;
    userEmail?: string;
    ipAddress?: string;
    userAgent?: string;
    success: boolean;
    metadata?: JsonObject;
}
interface PaginatedAuditLogResponse {
    data: AuditLogEntry[];
    pagination: PaginationResponse;
}
interface QueryAuditLogsQuery {
    page?: number;
    perPage?: number;
    userId?: string;
    action?: string;
    resourceType?: string;
    from?: string;
    to?: string;
    success?: boolean;
}
interface PasswordPolicy {
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSpecial?: boolean;
}
interface MfaPolicy {
    enabled?: boolean;
    required?: boolean;
    allowedMethods?: string[];
}
interface TenantSettings {
    id?: string;
    slug?: string;
    name?: string;
    allowedDomains?: string[];
    passwordPolicy?: PasswordPolicy;
    mfaPolicy?: MfaPolicy;
}
interface UpdateTenantSettingsRequest {
    name?: string;
    allowedDomains?: string[];
    passwordPolicy?: JsonObject;
    mfaPolicy?: JsonObject;
}
interface MfaSettings {
    required?: boolean;
    allowedMethods?: string[];
}
interface SystemHealthResponse {
    status: string;
    version: string;
    database: string;
}
interface SsoConnection {
    id: string;
    type: 'saml' | 'oidc';
    name: string;
    status: 'active' | 'disabled';
    domains: string[];
    config: JsonObject;
    createdAt: string;
    updatedAt: string;
}
interface OrganizationSsoSettings {
    orgId: string;
    connectionId: string | null;
    required: boolean;
    jitEnabled: boolean;
    defaultRole: string;
}
interface OrganizationDomain {
    id: string;
    domain: string;
    verificationToken: string;
    verifiedAt: string | null;
    createdAt: string;
}
interface OrganizationRole {
    id: string;
    name: string;
    permissions: string[];
    createdAt: string;
    updatedAt: string;
}
interface BrandingSettings {
    logoUrl?: string | null;
    faviconUrl?: string | null;
    productName?: string | null;
    supportEmail?: string | null;
    primaryColor?: string | null;
    secondaryColor?: string | null;
    customCss?: string | null;
}
interface ThemeSettings {
    theme: JsonObject;
}
interface ScimListResponse {
    schemas: string[];
    totalResults: number;
    startIndex: number;
    itemsPerPage: number;
    Resources: JsonObject[];
}
interface ScimUser {
    id?: string;
    userName: string;
    active?: boolean;
    emails?: JsonObject[];
    externalId?: string;
}
interface ScimGroup {
    id?: string;
    displayName: string;
    members?: JsonObject[];
}
interface DirectoryConnection {
    id: string;
    type: 'ldap';
    name: string;
    status: 'active' | 'disabled';
    config: JsonObject;
    createdAt: string;
    updatedAt: string;
}
interface SecurityPolicy {
    id: string;
    name: string;
    enabled: boolean;
    conditions: JsonObject;
    actions: JsonObject;
    createdAt: string;
    updatedAt: string;
}
interface AuditExport {
    id: string;
    status: 'queued' | 'running' | 'complete' | 'failed';
    format: 'json' | 'csv';
    from: string;
    to: string;
    createdAt: string;
}
interface AuditWebhook {
    id: string;
    url: string;
    status: 'active' | 'disabled';
    secretLastFour: string;
    createdAt: string;
}
interface ApiKey {
    id: string;
    name: string;
    status?: string;
    createdAt?: string;
}
interface OidcClient {
    id: string;
    clientId?: string;
    name?: string;
    status?: string;
}
interface MigrationJob {
    id: string;
    type?: string;
    status?: string;
    createdAt?: string;
}
interface BulkJob {
    id: string;
    type?: string;
    status?: string;
    createdAt?: string;
}
interface ConsentPolicy {
    id: string;
    consentType?: string;
    version?: string;
    status?: string;
}
interface AnalyticsResponse {
}
interface SecurityResponse {
}

/**
 * Vault Admin API Client
 */

type ResponseType = 'json' | 'text' | 'blob' | 'arrayBuffer' | 'stream' | 'void';
type QueryStyle = 'snake' | 'preserve';
interface VaultAdminClientOptions {
    baseUrl: string;
    token: string;
    tenantId: string;
    timeout?: number;
    fetch?: typeof fetch;
}
interface RequestOptions {
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
declare class VaultAdminError extends Error {
    readonly code: string;
    readonly statusCode: number;
    readonly details?: Record<string, unknown> | undefined;
    constructor(message: string, code: string, statusCode: number, details?: Record<string, unknown> | undefined);
}
declare class VaultAdminClient {
    private readonly baseUrl;
    private readonly token;
    private readonly tenantId;
    private readonly timeout;
    private readonly fetchImpl;
    constructor(options: VaultAdminClientOptions);
    rawRequest<T>(method: string, path: string, config?: RequestConfig): Promise<T>;
    private request;
    iteratePages<T>(fetchPage: (page: number, perPage: number) => Promise<{
        items: T[];
        hasMore: boolean;
    }>, perPage?: number): AsyncGenerator<T, void, unknown>;
    getDashboard(): Promise<DashboardResponse>;
    getMetrics(query?: DateRangeQuery): Promise<MetricsResponse>;
    listUsers(query?: ListUsersQuery): Promise<ListUsersResponse>;
    iterateUsers(query?: Omit<ListUsersQuery, 'page' | 'perPage'>): AsyncGenerator<AdminUserResponse, void, unknown>;
    createUser(data: CreateUserRequest): Promise<AdminUserResponse>;
    getUser(userId: string): Promise<AdminUserResponse>;
    updateUser(userId: string, data: UpdateUserRequest): Promise<AdminUserResponse>;
    deleteUser(userId: string): Promise<MessageResponse>;
    suspendUser(userId: string, data?: {
        reason?: string;
    }): Promise<AdminUserResponse>;
    activateUser(userId: string): Promise<AdminUserResponse>;
    listUserSessions(userId: string): Promise<AdminSessionListResponse>;
    revokeAllUserSessions(userId: string): Promise<MessageResponse>;
    listOrganizations(query?: ListOrganizationsQuery): Promise<PaginatedOrganizationsResponse>;
    iterateOrganizations(query?: Omit<ListOrganizationsQuery, 'page' | 'perPage'>): AsyncGenerator<AdminOrganizationResponse, void, unknown>;
    getOrganization(orgId: string): Promise<AdminOrganizationResponse>;
    updateOrganization(orgId: string, data: UpdateOrgRequest): Promise<AdminOrganizationResponse>;
    deleteOrganization(orgId: string): Promise<MessageResponse>;
    listOrganizationMembers(orgId: string): Promise<AdminOrganizationMemberResponse[]>;
    updateOrganizationMember(orgId: string, userId: string, data: UpdateMemberRequest): Promise<AdminOrganizationMemberResponse>;
    removeOrganizationMember(orgId: string, userId: string): Promise<MessageResponse>;
    listOrganizationInvitations(orgId: string): Promise<InvitationResponse[]>;
    cancelInvitation(orgId: string, invitationId: string): Promise<MessageResponse>;
    queryAuditLogs(query?: QueryAuditLogsQuery): Promise<PaginatedAuditLogResponse>;
    iterateAuditLogs(query?: Omit<QueryAuditLogsQuery, 'page' | 'perPage'>): AsyncGenerator<AuditLogEntry, void, unknown>;
    getRecentAuditLogs(limit?: number): Promise<AuditLogEntry[]>;
    getUserAuditLogs(userId: string, query?: Omit<QueryAuditLogsQuery, 'userId'>): Promise<PaginatedAuditLogResponse>;
    getSettings(): Promise<TenantSettings>;
    updateSettings(data: UpdateTenantSettingsRequest): Promise<TenantSettings>;
    updateMfaSettings(data: JsonObject): Promise<JsonObject>;
    getSecuritySettings(): Promise<JsonObject>;
    updateSecuritySettings(data: JsonObject): Promise<JsonObject>;
    getPrivacySettings(): Promise<JsonObject>;
    updatePrivacySettings(data: JsonObject): Promise<JsonObject>;
    listSamlConnections(): Promise<{
        data: SsoConnection[];
    }>;
    createSamlConnection(data: Partial<SsoConnection>): Promise<SsoConnection>;
    getSamlConnection(connectionId: string): Promise<SsoConnection>;
    updateSamlConnection(connectionId: string, data: Partial<SsoConnection>): Promise<SsoConnection>;
    deleteSamlConnection(connectionId: string): Promise<void>;
    listOidcConnections(): Promise<{
        data: SsoConnection[];
    }>;
    createOidcConnection(data: Partial<SsoConnection>): Promise<SsoConnection>;
    getOidcConnection(connectionId: string): Promise<SsoConnection>;
    updateOidcConnection(connectionId: string, data: Partial<SsoConnection>): Promise<SsoConnection>;
    deleteOidcConnection(connectionId: string): Promise<void>;
    updateOrganizationSso(orgId: string, data: Partial<OrganizationSsoSettings>): Promise<OrganizationSsoSettings>;
    listOrganizationDomains(orgId: string): Promise<{
        data: OrganizationDomain[];
    }>;
    createOrganizationDomain(orgId: string, domain: string): Promise<OrganizationDomain>;
    verifyOrganizationDomain(orgId: string, domainId: string): Promise<OrganizationDomain>;
    deleteOrganizationDomain(orgId: string, domainId: string): Promise<void>;
    listOrganizationRoles(orgId: string): Promise<{
        data: OrganizationRole[];
    }>;
    createOrganizationRole(orgId: string, data: Partial<OrganizationRole>): Promise<OrganizationRole>;
    updateOrganizationRole(orgId: string, roleId: string, data: Partial<OrganizationRole>): Promise<OrganizationRole>;
    deleteOrganizationRole(orgId: string, roleId: string): Promise<void>;
    getBranding(): Promise<BrandingSettings>;
    updateBranding(data: BrandingSettings): Promise<BrandingSettings>;
    getTheme(): Promise<ThemeSettings>;
    updateTheme(data: ThemeSettings): Promise<ThemeSettings>;
    scimListUsers(): Promise<ScimListResponse>;
    scimCreateUser(data: ScimUser): Promise<ScimUser>;
    scimGetUser(userId: string): Promise<ScimUser>;
    scimPatchUser(userId: string, data: JsonObject): Promise<ScimUser>;
    scimDeleteUser(userId: string): Promise<void>;
    scimListGroups(): Promise<ScimListResponse>;
    scimCreateGroup(data: ScimGroup): Promise<ScimGroup>;
    scimGetGroup(groupId: string): Promise<ScimGroup>;
    scimPatchGroup(groupId: string, data: JsonObject): Promise<ScimGroup>;
    scimDeleteGroup(groupId: string): Promise<void>;
    listDirectoryConnections(): Promise<{
        data: DirectoryConnection[];
    }>;
    createDirectoryConnection(data: Partial<DirectoryConnection>): Promise<DirectoryConnection>;
    updateDirectoryConnection(connectionId: string, data: Partial<DirectoryConnection>): Promise<DirectoryConnection>;
    deleteDirectoryConnection(connectionId: string): Promise<void>;
    createSecurityPolicy(data: Partial<SecurityPolicy>): Promise<SecurityPolicy>;
    updateSecurityPolicy(policyId: string, data: Partial<SecurityPolicy>): Promise<SecurityPolicy>;
    listAuditExports(): Promise<{
        data: AuditExport[];
    }>;
    createAuditExport(data: {
        format: 'json' | 'csv';
        from: string;
        to: string;
    }): Promise<AuditExport>;
    listAuditWebhooks(): Promise<{
        data: AuditWebhook[];
    }>;
    createAuditWebhook(data: {
        url: string;
        secret: string;
    }): Promise<AuditWebhook>;
    deleteAuditWebhook(webhookId: string): Promise<void>;
    getSystemHealth(): Promise<SystemHealthResponse>;
    getAnalyticsDashboard(query?: DateRangeQuery): Promise<AnalyticsResponse>;
    getAnalyticsLogins(query?: DateRangeQuery): Promise<AnalyticsResponse>;
    getAnalyticsUsers(query?: DateRangeQuery): Promise<AnalyticsResponse>;
    getAnalyticsSecurity(query?: DateRangeQuery): Promise<AnalyticsResponse>;
    exportAnalytics(query?: Record<string, unknown>): Promise<Blob>;
    getSecurityGeoPolicy(): Promise<SecurityResponse>;
    updateSecurityGeoPolicy(data: JsonObject): Promise<SecurityResponse>;
    getSecurityVpnDetection(): Promise<SecurityResponse>;
    updateSecurityVpnDetection(data: JsonObject): Promise<SecurityResponse>;
    listScimTokens(): Promise<JsonObject>;
    createScimToken(data: JsonObject): Promise<JsonObject>;
    revokeScimToken(tokenId: string): Promise<JsonObject>;
    deleteScimToken(tokenId: string): Promise<void>;
    getScimConfig(): Promise<JsonObject>;
    updateScimConfig(data: JsonObject): Promise<JsonObject>;
    getScimStats(): Promise<JsonObject>;
    listApiKeys(): Promise<ApiKey[]>;
    createApiKey(data: JsonObject): Promise<ApiKey>;
    getApiKey(id: string): Promise<ApiKey>;
    updateApiKey(id: string, data: JsonObject): Promise<ApiKey>;
    revokeApiKey(id: string): Promise<ApiKey>;
    rotateApiKey(id: string): Promise<ApiKey>;
    listOidcClients(): Promise<OidcClient[]>;
    createOidcClient(data: JsonObject): Promise<OidcClient>;
    getOidcClient(clientId: string): Promise<OidcClient>;
    updateOidcClient(clientId: string, data: JsonObject): Promise<OidcClient>;
    deleteOidcClient(clientId: string): Promise<void>;
    rotateOidcClientSecret(clientId: string): Promise<JsonObject>;
    listBulkJobs(query?: Record<string, unknown>): Promise<BulkJob[]>;
    startBulkImport(body: FormData): Promise<BulkJob>;
    getBulkImportStatus(jobId: string): Promise<BulkJob>;
    downloadBulkImportErrorReport(jobId: string): Promise<Blob>;
    startBulkExport(data: JsonObject): Promise<BulkJob>;
    getBulkExportStatus(jobId: string): Promise<BulkJob>;
    downloadBulkExportFile(jobId: string): Promise<Blob>;
    deleteBulkJob(jobId: string): Promise<void>;
    listMigrations(): Promise<MigrationJob[]>;
    getMigration(id: string): Promise<MigrationJob>;
    getMigrationProgress(id: string): Promise<JsonObject>;
    getMigrationErrors(id: string): Promise<JsonObject>;
    startAuth0Migration(data: JsonObject): Promise<MigrationJob>;
    startFirebaseMigration(data: JsonObject): Promise<MigrationJob>;
    startCognitoMigration(data: JsonObject): Promise<MigrationJob>;
    startCsvMigration(body: FormData): Promise<MigrationJob>;
    validateCsvMigration(body: FormData): Promise<JsonObject>;
    previewCsvMigration(body: FormData): Promise<JsonObject>;
    cancelMigration(id: string): Promise<JsonObject>;
    pauseMigration(id: string): Promise<JsonObject>;
    resumeMigration(id: string): Promise<JsonObject>;
    listConsentPolicies(query?: Record<string, unknown>): Promise<ConsentPolicy[]>;
    createConsentPolicy(data: JsonObject): Promise<ConsentPolicy>;
    updateConsentPolicy(id: string, data: JsonObject): Promise<ConsentPolicy>;
    getConsentPolicyStats(id: string): Promise<JsonObject>;
    listPendingConsentExports(): Promise<JsonObject>;
    listPendingConsentDeletions(): Promise<JsonObject>;
}

/**
 * User Management Helpers
 *
 * High-level utilities for user administration
 */

interface UserFilter {
    status?: 'active' | 'pending' | 'suspended' | 'deactivated';
    email?: string;
    organizationId?: string;
}
interface UserStats {
    total: number;
    active: number;
    suspended: number;
    pending: number;
    mfaEnabled?: number;
}
/**
 * Helper class for user management operations
 */
declare class UserManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    /**
     * Get all users with optional filtering
     */
    getAll(filter?: UserFilter): Promise<AdminUserResponse[]>;
    /**
     * Find user by email
     */
    findByEmail(email: string): Promise<AdminUserResponse | null>;
    /**
     * Create user with optional password
     */
    create(data: CreateUserRequest): Promise<AdminUserResponse>;
    /**
     * Update user profile
     */
    update(userId: string, data: UpdateUserRequest): Promise<AdminUserResponse>;
    /**
     * Suspend user account
     */
    suspend(userId: string, reason?: string): Promise<AdminUserResponse>;
    /**
     * Activate suspended user
     */
    activate(userId: string): Promise<AdminUserResponse>;
    /**
     * Delete user permanently
     */
    delete(userId: string): Promise<void>;
    /**
     * Force logout from all devices
     */
    forceLogout(userId: string): Promise<void>;
    /**
     * Get user statistics
     */
    getStats(): Promise<UserStats>;
    /**
     * Get users by status
     */
    getByStatus(status: 'active' | 'pending' | 'suspended' | 'deactivated'): Promise<AdminUserResponse[]>;
    /**
     * Get users who haven't logged in recently
     */
    getInactive(days?: number): Promise<AdminUserResponse[]>;
    /**
     * Bulk suspend users
     */
    bulkSuspend(userIds: string[], reason?: string): Promise<AdminUserResponse[]>;
    /**
     * Bulk activate users
     */
    bulkActivate(userIds: string[]): Promise<AdminUserResponse[]>;
}

/**
 * Organization Management Helpers
 *
 * High-level utilities for organization administration
 */

interface OrganizationFilter {
    status?: string;
}
interface OrganizationStats {
    total: number;
    active: number;
    totalMembers: number;
    averageMembersPerOrg: number;
}
type MemberRole = 'owner' | 'admin' | 'member' | 'guest';
/**
 * Helper class for organization management operations
 */
declare class OrganizationManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    /**
     * Get all organizations
     */
    getAll(filter?: OrganizationFilter): Promise<AdminOrganizationResponse[]>;
    /**
     * Find organization by slug
     */
    findBySlug(slug: string): Promise<AdminOrganizationResponse | null>;
    /**
     * Get organization details with members
     */
    getDetails(orgId: string): Promise<{
        organization: AdminOrganizationResponse;
        members: AdminOrganizationMemberResponse[];
    }>;
    /**
     * Update organization settings
     */
    update(orgId: string, data: UpdateOrgRequest): Promise<AdminOrganizationResponse>;
    /**
     * Delete organization
     */
    delete(orgId: string): Promise<void>;
    /**
     * Update member role
     */
    updateMemberRole(orgId: string, userId: string, role: MemberRole): Promise<AdminOrganizationMemberResponse>;
    /**
     * Remove member from organization
     */
    removeMember(orgId: string, userId: string): Promise<void>;
    /**
     * Get organization statistics
     */
    getStats(): Promise<OrganizationStats>;
    /**
     * Get organizations with no members (orphaned)
     */
    getOrphaned(): Promise<AdminOrganizationResponse[]>;
    /**
     * Get organizations approaching member limit
     */
    getNearLimit(thresholdPercent?: number): Promise<AdminOrganizationResponse[]>;
    /**
     * Bulk delete organizations
     */
    bulkDelete(orgIds: string[]): Promise<void>;
}

/**
 * Audit Log Helpers
 *
 * Utilities for querying and analyzing audit logs
 */

interface AuditFilter {
    userId?: string;
    action?: string;
    resourceType?: string;
    from?: Date;
    to?: Date;
    success?: boolean;
}
interface ActionSummary {
    action: string;
    count: number;
    successCount: number;
    failureCount: number;
}
interface UserActivitySummary {
    userId: string;
    email?: string;
    actionCount: number;
    lastActivity: string;
    ipAddresses: string[];
}
/**
 * Helper class for audit log operations
 */
declare class AuditManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    /**
     * Query audit logs with filters
     */
    query(filter?: AuditFilter, page?: number, perPage?: number): Promise<{
        entries: AuditLogEntry[];
        total: number;
    }>;
    /**
     * Get all audit log entries (paginated iteration)
     */
    getAll(filter?: Omit<AuditFilter, 'from' | 'to'>, dateRange?: {
        from: Date;
        to: Date;
    }): Promise<AuditLogEntry[]>;
    /**
     * Get recent activity
     */
    getRecent(limit?: number): Promise<AuditLogEntry[]>;
    /**
     * Get user activity timeline
     */
    getUserActivity(userId: string, days?: number): Promise<AuditLogEntry[]>;
    /**
     * Summarize actions in a time period
     */
    summarizeActions(days?: number): Promise<ActionSummary[]>;
    /**
     * Get failed login attempts
     */
    getFailedLogins(days?: number): Promise<AuditLogEntry[]>;
    /**
     * Detect suspicious activity (multiple failed logins)
     */
    detectSuspiciousActivity(failedThreshold?: number, hours?: number): Promise<UserActivitySummary[]>;
    /**
     * Export audit logs for compliance
     */
    exportForCompliance(startDate: Date, endDate: Date): Promise<{
        entries: AuditLogEntry[];
        generatedAt: string;
        dateRange: {
            from: string;
            to: string;
        };
    }>;
}

/**
 * Tenant Settings Helpers
 *
 * Utilities for managing tenant configuration
 */

interface SecuritySettings {
    passwordPolicy: PasswordPolicy;
    mfaPolicy: MfaPolicy;
    allowedDomains: string[];
}
/**
 * Helper class for tenant settings management
 */
declare class SettingsManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    /**
     * Get current tenant settings
     */
    get(): Promise<TenantSettings>;
    /**
     * Update tenant name
     */
    updateName(name: string): Promise<TenantSettings>;
    /**
     * Update password policy
     */
    updatePasswordPolicy(policy: Partial<PasswordPolicy>): Promise<TenantSettings>;
    /**
     * Update MFA policy
     */
    updateMfaPolicy(policy: Partial<MfaPolicy>): Promise<TenantSettings>;
    /**
     * Require MFA for all users
     */
    requireMfa(): Promise<TenantSettings>;
    /**
     * Make MFA optional
     */
    makeMfaOptional(): Promise<TenantSettings>;
    /**
     * Disable MFA entirely
     */
    disableMfa(): Promise<TenantSettings>;
    /**
     * Add allowed email domain
     */
    addAllowedDomain(domain: string): Promise<TenantSettings>;
    /**
     * Remove allowed email domain
     */
    removeAllowedDomain(domain: string): Promise<TenantSettings>;
    /**
     * Set allowed domains (replaces all)
     */
    setAllowedDomains(domains: string[]): Promise<TenantSettings>;
    /**
     * Check if email domain is allowed
     */
    isDomainAllowed(email: string): Promise<boolean>;
    /**
     * Get security settings summary
     */
    getSecuritySummary(): Promise<{
        passwordStrength: 'weak' | 'medium' | 'strong';
        mfaStatus: 'disabled' | 'optional' | 'required';
        domainRestrictions: 'none' | 'restricted';
    }>;
}

declare class AnalyticsManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    getDashboard(query?: DateRangeQuery): Promise<AnalyticsResponse>;
    getLogins(query?: DateRangeQuery): Promise<AnalyticsResponse>;
    getUsers(query?: DateRangeQuery): Promise<AnalyticsResponse>;
    getSecurity(query?: DateRangeQuery): Promise<AnalyticsResponse>;
    export(query?: Record<string, unknown>): Promise<Blob>;
}

declare class SecurityManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    getGeoPolicy(): Promise<SecurityResponse>;
    updateGeoPolicy(data: JsonObject): Promise<SecurityResponse>;
    getVpnDetection(): Promise<SecurityResponse>;
    updateVpnDetection(data: JsonObject): Promise<SecurityResponse>;
}

declare class ScimAdminManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    listTokens(): Promise<JsonObject>;
    createToken(data: JsonObject): Promise<JsonObject>;
    revokeToken(tokenId: string): Promise<JsonObject>;
    deleteToken(tokenId: string): Promise<void>;
    getConfig(): Promise<JsonObject>;
    updateConfig(data: JsonObject): Promise<JsonObject>;
    getStats(): Promise<JsonObject>;
}

declare class ApiKeysManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    list(): Promise<ApiKey[]>;
    create(data: JsonObject): Promise<ApiKey>;
    get(id: string): Promise<ApiKey>;
    update(id: string, data: JsonObject): Promise<ApiKey>;
    rotate(id: string): Promise<ApiKey>;
    revoke(id: string): Promise<ApiKey>;
}

declare class OidcManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    listClients(): Promise<OidcClient[]>;
    createClient(data: JsonObject): Promise<OidcClient>;
    getClient(clientId: string): Promise<OidcClient>;
    updateClient(clientId: string, data: JsonObject): Promise<OidcClient>;
    deleteClient(clientId: string): Promise<void>;
    rotateSecret(clientId: string): Promise<JsonObject>;
}

declare class BulkManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    listJobs(query?: Record<string, unknown>): Promise<BulkJob[]>;
    startImport(file: File | Blob, fields?: Record<string, string>): Promise<BulkJob>;
    getImportStatus(jobId: string): Promise<BulkJob>;
    downloadImportErrors(jobId: string): Promise<Blob>;
    startExport(data: JsonObject): Promise<BulkJob>;
    getExportStatus(jobId: string): Promise<BulkJob>;
    downloadExport(jobId: string): Promise<Blob>;
    deleteJob(jobId: string): Promise<void>;
}

declare class MigrationManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    list(): Promise<MigrationJob[]>;
    get(id: string): Promise<MigrationJob>;
    getProgress(id: string): Promise<JsonObject>;
    getErrors(id: string): Promise<JsonObject>;
    fromAuth0(data: JsonObject): Promise<MigrationJob>;
    fromFirebase(data: JsonObject): Promise<MigrationJob>;
    fromCognito(data: JsonObject): Promise<MigrationJob>;
    fromCsv(file: File | Blob, fields?: Record<string, string>): Promise<MigrationJob>;
    validateCsv(file: File | Blob): Promise<JsonObject>;
    previewCsv(file: File | Blob): Promise<JsonObject>;
    cancel(id: string): Promise<JsonObject>;
    pause(id: string): Promise<JsonObject>;
    resume(id: string): Promise<JsonObject>;
}

declare class ConsentManager {
    private readonly client;
    constructor(client: VaultAdminClient);
    list(query?: Record<string, unknown>): Promise<ConsentPolicy[]>;
    create(data: JsonObject): Promise<ConsentPolicy>;
    update(id: string, data: JsonObject): Promise<ConsentPolicy>;
    stats(id: string): Promise<JsonObject>;
    pendingExports(): Promise<JsonObject>;
    pendingDeletions(): Promise<JsonObject>;
}

export { type ActionSummary, type AdminOrganizationMemberResponse, type AdminOrganizationResponse, type AdminSessionListResponse, type AdminSessionResponse, type AdminUserResponse, AnalyticsManager, type AnalyticsResponse, type ApiKey, ApiKeysManager, type AuditExport, type AuditFilter, type AuditLogEntry, AuditManager, type AuditWebhook, type BrandingSettings, type BulkJob, BulkManager, ConsentManager, type ConsentPolicy, type CreateUserRequest, type DashboardResponse, type DashboardStats, type DateRangeQuery, type DirectoryConnection, type ErrorResponse, type InvitationResponse, type JsonObject, type JsonPrimitive, type JsonValue, type ListOrganizationsQuery, type ListUsersQuery, type ListUsersResponse, type MemberRole, type MessageResponse, type MetricsResponse, type MfaPolicy, type MfaSettings, type MigrationJob, MigrationManager, type OidcClient, OidcManager, type OrganizationDomain, type OrganizationFilter, OrganizationManager, type OrganizationRole, type OrganizationSsoSettings, type OrganizationStats, type PaginatedAuditLogResponse, type PaginatedOrganizationsResponse, type PaginationResponse, type PasswordPolicy, type QueryAuditLogsQuery, type RequestOptions, ScimAdminManager, type ScimGroup, type ScimListResponse, type ScimUser, SecurityManager, type SecurityPolicy, type SecurityResponse, type SecuritySettings, SettingsManager, type SsoConnection, type SuspendUserRequest, type SystemHealthResponse, type TenantSettings, type ThemeSettings, type UpdateMemberRequest, type UpdateOrgRequest, type UpdateTenantSettingsRequest, type UpdateUserRequest, type UserActivitySummary, type UserFilter, UserManager, type UserStats, type UserStatus, VaultAdminClient, type VaultAdminClientOptions, VaultAdminError };
