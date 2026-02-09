/**
 * Vault Admin API types
 * Regenerated from OpenAPI contract and server route validation.
 */

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

export interface MessageResponse {
  message: string;
}

export interface PaginationResponse {
  page: number;
  perPage: number;
  total: number;
  totalPages: number;
}

export interface DateRangeQuery {
  from?: string;
  to?: string;
}

export interface DashboardStats {
  total_users: number;
  active_users: number;
  pending_users: number;
  total_organizations: number;
}

export interface DashboardResponse {
  stats: DashboardStats;
}

export interface MetricsResponse {}

export type UserStatus = 'active' | 'pending' | 'suspended' | 'deactivated';

export interface CreateUserRequest {
  email: string;
  name: string;
  emailVerified?: boolean;
}

export interface UpdateUserRequest {
  name?: string;
  status?: UserStatus;
}

export interface SuspendUserRequest {
  reason?: string;
}

export interface AdminUserResponse {
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

export interface ListUsersResponse {
  users: AdminUserResponse[];
  total: number;
  page: number;
  per_page: number;
}

export interface AdminSessionResponse {
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

export interface AdminSessionListResponse {
  sessions: AdminSessionResponse[];
  currentSessions: number;
  maxSessions: number;
}

export interface ListUsersQuery {
  page?: number;
  perPage?: number;
  status?: UserStatus;
  email?: string;
  orgId?: string;
}

export interface UpdateOrgRequest {
  name?: string;
  description?: string;
  logoUrl?: string;
  website?: string;
  maxMembers?: number;
  ssoRequired?: boolean;
  status?: string;
}

export interface AdminOrganizationResponse {
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

export interface PaginatedOrganizationsResponse {
  data: AdminOrganizationResponse[];
  pagination: PaginationResponse;
}

export interface AdminOrganizationMemberResponse {
  id: string;
  userId: string;
  email: string;
  name?: string;
  role: string;
  status: string;
  joinedAt?: string;
}

export interface InvitationResponse {
  id: string;
  email: string;
  role: string;
  expiresAt: string;
  createdAt: string;
}

export interface UpdateMemberRequest {
  role: string;
}

export interface ListOrganizationsQuery {
  page?: number;
  perPage?: number;
  status?: string;
}

export interface AuditLogEntry {
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

export interface PaginatedAuditLogResponse {
  data: AuditLogEntry[];
  pagination: PaginationResponse;
}

export interface QueryAuditLogsQuery {
  page?: number;
  perPage?: number;
  userId?: string;
  action?: string;
  resourceType?: string;
  from?: string;
  to?: string;
  success?: boolean;
}

export interface PasswordPolicy {
  minLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecial?: boolean;
}

export interface MfaPolicy {
  enabled?: boolean;
  required?: boolean;
  allowedMethods?: string[];
}

export interface TenantSettings {
  id?: string;
  slug?: string;
  name?: string;
  allowedDomains?: string[];
  passwordPolicy?: PasswordPolicy;
  mfaPolicy?: MfaPolicy;
}

export interface UpdateTenantSettingsRequest {
  name?: string;
  allowedDomains?: string[];
  passwordPolicy?: JsonObject;
  mfaPolicy?: JsonObject;
}

export interface MfaSettings {
  required?: boolean;
  allowedMethods?: string[];
}

export interface SystemHealthResponse {
  status: string;
  version: string;
  database: string;
}

export interface SsoConnection {
  id: string;
  type: 'saml' | 'oidc';
  name: string;
  status: 'active' | 'disabled';
  domains: string[];
  config: JsonObject;
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
  theme: JsonObject;
}

export interface ScimListResponse {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: JsonObject[];
}

export interface ScimUser {
  id?: string;
  userName: string;
  active?: boolean;
  emails?: JsonObject[];
  externalId?: string;
}

export interface ScimGroup {
  id?: string;
  displayName: string;
  members?: JsonObject[];
}

export interface DirectoryConnection {
  id: string;
  type: 'ldap';
  name: string;
  status: 'active' | 'disabled';
  config: JsonObject;
  createdAt: string;
  updatedAt: string;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  enabled: boolean;
  conditions: JsonObject;
  actions: JsonObject;
  createdAt: string;
  updatedAt: string;
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

export interface ApiKey {
  id: string;
  name: string;
  status?: string;
  createdAt?: string;
}

export interface OidcClient {
  id: string;
  clientId?: string;
  name?: string;
  status?: string;
}

export interface MigrationJob {
  id: string;
  type?: string;
  status?: string;
  createdAt?: string;
}

export interface BulkJob {
  id: string;
  type?: string;
  status?: string;
  createdAt?: string;
}

export interface ConsentPolicy {
  id: string;
  consentType?: string;
  version?: string;
  status?: string;
}

export interface AnalyticsResponse {}
export interface SecurityResponse {}
