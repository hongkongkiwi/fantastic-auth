/**
 * Vault Internal API - TypeScript Client
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
// Tenant Management
// ============================================================================

export interface TenantLimits {
  maxUsers: number;
  maxOrganizations: number;
  maxApiCallsPerMonth: number;
}

export interface TenantUsage {
  currentUsers: number;
  currentOrganizations: number;
  apiCallsThisMonth: number;
}

export interface TenantBilling {
  subscriptionId: string;
  status: string;
  currentPeriodStart: string;
  currentPeriodEnd: string;
}

export interface TenantOwner {
  id: string;
  email: string;
  name?: string;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  status: 'active' | 'suspended' | 'pending_deletion' | 'trial';
  plan: string;
  customDomain?: string;
  createdAt: string;
  updatedAt: string;
  deletedAt?: string;
  owner: TenantOwner;
  limits: TenantLimits;
  usage: TenantUsage;
  billing?: TenantBilling;
}

export interface CreateTenantRequest {
  name: string;
  slug: string;
  plan?: string;
  ownerEmail?: string;
  ownerName?: string;
  customDomain?: string;
}

export interface UpdateTenantRequest {
  name?: string;
  plan?: string;
  limits?: Partial<TenantLimits>;
  settings?: {
    allowCustomBranding?: boolean;
    allowSso?: boolean;
    allowApiAccess?: boolean;
  };
}

export interface ListTenantsResponse {
  data: Tenant[];
  pagination: PaginationResponse;
}

export interface SuspendTenantRequest {
  reason?: string;
  suspendUntil?: string;
}

export interface MigrationRequest {
  targetVersion?: string;
}

export interface MigrationResponse {
  success: boolean;
  version: string;
  duration: number;
}

// ============================================================================
// Platform Users
// ============================================================================

export interface PlatformUser {
  id: string;
  email: string;
  name?: string;
  status: string;
  createdAt: string;
  tenantCount: number;
}

export interface UserTenantMembership {
  tenantId: string;
  tenantName: string;
  tenantSlug: string;
  role: string;
  joinedAt: string;
}

export interface PlatformUserDetail {
  id: string;
  email: string;
  name?: string;
  emailVerified: boolean;
  status: string;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
  tenants: UserTenantMembership[];
  mfaEnabled: boolean;
  failedLoginAttempts: number;
}

export interface ListPlatformUsersResponse {
  data: PlatformUser[];
  pagination: PaginationResponse;
}

export interface ImpersonateRequest {
  tenantId: string;
  duration?: number;
  reason: string;
}

export interface ImpersonateResponse {
  token: string;
  expiresAt: string;
  tenantId: string;
}

// ============================================================================
// Billing
// ============================================================================

export interface SubscriptionAmount {
  currency: string;
  perSeat: number;
  total: number;
}

export interface Subscription {
  id: string;
  tenantId: string;
  status: 'active' | 'past_due' | 'canceled' | 'trialing' | 'incomplete';
  plan: string;
  seats: number;
  seatsUsed: number;
  billingInterval: string;
  currentPeriodStart: string;
  currentPeriodEnd: string;
  cancelAtPeriodEnd: boolean;
  amount: SubscriptionAmount;
}

export interface ListSubscriptionsResponse {
  data: Subscription[];
}

export interface UpdateSubscriptionRequest {
  plan?: string;
  seats?: number;
  billingInterval?: string;
}

export interface Invoice {
  id: string;
  tenantId: string;
  status: string;
  amount: number;
  currency: string;
  description: string;
  createdAt: string;
  pdfUrl?: string;
}

export interface GenerateInvoiceRequest {
  amount: number;
  description: string;
}

// ============================================================================
// Analytics
// ============================================================================

export interface PlatformOverview {
  tenants: {
    total: number;
    active: number;
    trial: number;
    newThisMonth: number;
  };
  users: {
    total: number;
    activeToday: number;
  };
  revenue: {
    mrr: number;
    arr: number;
    currency: string;
  };
  system: {
    totalApiCalls24h: number;
    averageLatency: number;
    errorRate: number;
  };
}

export interface TenantAnalyticsPoint {
  date: string;
  newTenants: number;
  activeTenants: number;
  churnedTenants: number;
}

export interface TenantAnalyticsResponse {
  data: TenantAnalyticsPoint[];
}

export interface TenantUsageMetric {
  tenantId: string;
  value: number;
}

export interface UsageAnalyticsResponse {
  total: number;
  byTenant: TenantUsageMetric[];
}

// ============================================================================
// Configuration
// ============================================================================

export interface FeatureFlag {
  id: string;
  key: string;
  name: string;
  description?: string;
  enabled: boolean;
  rolloutPercentage: number;
  allowedTenants: string[];
  createdAt: string;
  updatedAt: string;
}

export interface CreateFeatureFlagRequest {
  key: string;
  name: string;
  description?: string;
  enabled?: boolean;
  rolloutPercentage?: number;
}

export interface UpdateFeatureFlagRequest {
  enabled?: boolean;
  rolloutPercentage?: number;
  allowedTenants?: string[];
}

export interface OAuthProviderConfig {
  id: string;
  provider: string;
  name: string;
  enabled: boolean;
  clientId: string;
  scopes: string[];
  allowTenantOverride: boolean;
}

export interface AddOAuthProviderRequest {
  provider: string;
  name: string;
  clientId: string;
  clientSecret: string;
  scopes?: string[];
  enabled?: boolean;
  allowTenantOverride?: boolean;
}

// ============================================================================
// Maintenance
// ============================================================================

export interface MigrationResult {
  tenantId: string;
  status: string;
  version: string;
  error?: string;
}

export interface RunMigrationsRequest {
  dryRun?: boolean;
  targetVersion?: string;
}

export interface RunMigrationsResponse {
  success: boolean;
  results: MigrationResult[];
}

export interface TriggerBackupRequest {
  tenantId?: string;
  type?: 'full' | 'incremental';
}

export interface TriggerBackupResponse {
  jobId: string;
  status: string;
}

// ============================================================================
// Query Parameters
// ============================================================================

export interface ListTenantsQuery {
  page?: number;
  perPage?: number;
  status?: 'active' | 'suspended' | 'pending_deletion' | 'trial';
  plan?: string;
}

export interface SearchUsersQuery {
  email?: string;
  tenantId?: string;
  page?: number;
}

export interface ListSubscriptionsQuery {
  status?: string;
}

export interface DateRangeQuery {
  from?: string;
  to?: string;
  groupBy?: 'day' | 'week' | 'month';
}

export interface UsageQuery {
  metric: 'activeUsers' | 'logins' | 'apiCalls' | 'storage';
}
