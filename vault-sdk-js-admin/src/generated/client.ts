/**
 * Vault Admin API - TypeScript Client
 * Generated from OpenAPI specification
 */

// ============================================================================
// Core Types
// ============================================================================

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

// ============================================================================
// Dashboard
// ============================================================================

export interface ActivitySummary {
  action: string;
  count: number;
  timestamp: string;
}

export interface DashboardResponse {
  totalUsers: number;
  activeUsers: number;
  newUsersToday: number;
  totalOrganizations: number;
  activeSessions: number;
  pendingInvitations: number;
  recentActivity: ActivitySummary[];
}

export interface TimeSeriesPoint {
  date: string;
  count: number;
}

export interface MetricsResponse {
  signupsOverTime: TimeSeriesPoint[];
  loginsOverTime: TimeSeriesPoint[];
  oauthUsage: Record<string, number>;
}

// ============================================================================
// User Management
// ============================================================================

export interface CreateUserRequest {
  email: string;
  password?: string;
  name?: string;
  emailVerified?: boolean;
  status?: 'active' | 'pending' | 'suspended';
}

export interface UpdateUserRequest {
  email?: string;
  name?: string;
  status?: 'active' | 'pending' | 'suspended' | 'deactivated';
}

export interface SuspendUserRequest {
  reason?: string;
}

export interface AdminUserResponse {
  id: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  status: string;
  mfaEnabled: boolean;
  lastLoginAt?: string;
  createdAt: string;
  updatedAt: string;
  failedLoginAttempts: number;
  lockedUntil?: string;
  organizationCount: number;
}

export interface PaginatedUsersResponse {
  data: AdminUserResponse[];
  pagination: PaginationResponse;
}

export interface AdminSessionResponse {
  id: string;
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  deviceFingerprint?: string;
  mfaVerified: boolean;
  createdAt: string;
  lastActivityAt: string;
  expiresAt: string;
  status: string;
}

// ============================================================================
// Organization Management
// ============================================================================

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
  ownerId: string;
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
  invitedBy?: string;
  invitedAt?: string;
  joinedAt?: string;
}

export interface InviterResponse {
  id: string;
  email: string;
}

export interface InvitationResponse {
  id: string;
  email: string;
  role: string;
  invitedBy: InviterResponse;
  expiresAt: string;
  createdAt: string;
}

export interface UpdateMemberRequest {
  role: string;
}

// ============================================================================
// Audit Logs
// ============================================================================

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  userId?: string;
  userEmail?: string;
  sessionId?: string;
  action: string;
  resourceType: string;
  resourceId: string;
  ipAddress?: string;
  userAgent?: string;
  success: boolean;
  error?: string;
  metadata?: Record<string, unknown>;
}

export interface PaginatedAuditLogResponse {
  data: AuditLogEntry[];
  pagination: PaginationResponse;
}

// ============================================================================
// Tenant Settings
// ============================================================================

export interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecial: boolean;
}

export interface MfaPolicy {
  enabled: boolean;
  required: boolean;
  allowedMethods: string[];
}

export interface TenantSettings {
  id: string;
  slug: string;
  name: string;
  allowedDomains: string[];
  passwordPolicy: PasswordPolicy;
  mfaPolicy: MfaPolicy;
  oauthProviders: string[];
  createdAt: string;
  updatedAt: string;
}

export interface UpdatePasswordPolicyRequest {
  minLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecial?: boolean;
}

export interface UpdateMfaPolicyRequest {
  enabled?: boolean;
  required?: boolean;
}

export interface UpdateTenantSettingsRequest {
  name?: string;
  allowedDomains?: string[];
  passwordPolicy?: UpdatePasswordPolicyRequest;
  mfaPolicy?: UpdateMfaPolicyRequest;
}

// ============================================================================
// System
// ============================================================================

export interface ServiceHealthResponse {
  status: string;
  latency: number;
}

export interface ServicesHealthResponse {
  database: ServiceHealthResponse;
  redis: ServiceHealthResponse;
}

export interface SystemHealthResponse {
  status: string;
  timestamp: string;
  version: string;
  services: ServicesHealthResponse;
}

// ============================================================================
// Query Parameters
// ============================================================================

export interface ListUsersQuery {
  page?: number;
  perPage?: number;
  status?: 'active' | 'pending' | 'suspended' | 'deactivated';
  email?: string;
  orgId?: string;
}

export interface ListOrganizationsQuery {
  page?: number;
  perPage?: number;
  status?: string;
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

export interface DateRangeQuery {
  from?: string;
  to?: string;
}
