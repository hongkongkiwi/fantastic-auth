/**
 * Fantasticauth Tenant API SDK
 * 
 * A TypeScript SDK for the Fantasticauth Tenant API.
 * Designed for building tenant dashboards and management tools.
 * 
 * @example
 * ```typescript
 * import { TenantClient, UserManager, OrganizationManager } from '@fantasticauth/tenant-sdk';
 * 
 * const client = new TenantClient({
 *   baseUrl: 'https://api.fantasticauth.com/api/v1',
 *   token: tenantJwtToken,
 *   tenantId: 'my-tenant'
 * });
 * 
 * // List and filter users
 * const users = new UserManager(client);
 * const activeUsers = await users.getByStatus('active');
 * const stats = await users.getStats();
 * 
 * console.log(`Total users: ${stats.total}, Active: ${stats.active}`);
 * ```
 */

// Core client
export { TenantClient, TenantError } from './client';
export type { TenantClientOptions, RequestOptions } from './client';
export type {
  RequestOptions as TenantRequestOptions,
} from './client';

// Helper managers
export { UserManager } from './users';
export type { UserFilter, UserStats } from './users';

export { OrganizationManager } from './organizations';
export type { OrganizationFilter, OrganizationStats, MemberRole } from './organizations';

export { AuditManager } from './audit';
export type { AuditFilter, ActionSummary, UserActivitySummary } from './audit';

export { AnalyticsManager } from './analytics';
export { SecurityManager } from './security';
export { ScimManager } from './scim';
export { ApiKeysManager } from './api-keys';
export { OidcManager } from './oidc';
export { BulkManager } from './bulk';
export { MigrationManager } from './migrations';
export { ConsentManager } from './consent';

// Generated types
export type * from './generated/client';

// Re-export specific types for convenience
export type {
  TenantUserResponse,
  TenantOrganizationResponse,
  TenantOrganizationMemberResponse,
  AuditLogEntry,
  TenantSettings,
  DashboardResponse,
  ListUsersResponse,
  CreateUserRequest,
  UpdateUserRequest,
  UpdateOrgRequest,
  UpdateMemberRequest,
} from './generated/client';
