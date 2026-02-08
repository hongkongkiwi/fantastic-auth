/**
 * Vault Admin API SDK
 * 
 * A TypeScript SDK for the Vault Admin API.
 * Designed for building admin dashboards and tenant management tools.
 * 
 * @example
 * ```typescript
 * import { VaultAdminClient, UserManager, OrganizationManager } from '@vault/admin-sdk';
 * 
 * const client = new VaultAdminClient({
 *   baseUrl: 'https://api.vault.dev/api/v1',
 *   token: adminJwtToken,
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
export { VaultAdminClient, VaultAdminError } from './client';
export type { VaultAdminClientOptions, RequestOptions } from './client';

// Helper managers
export { UserManager } from './users';
export type { UserFilter, UserStats } from './users';

export { OrganizationManager } from './organizations';
export type { OrganizationFilter, OrganizationStats, MemberRole } from './organizations';

export { AuditManager } from './audit';
export type { AuditFilter, ActionSummary, UserActivitySummary } from './audit';

export { SettingsManager } from './settings';
export type { SecuritySettings } from './settings';

// Generated types
export type * from './generated/client';

// Re-export specific types for convenience
export type {
  AdminUserResponse,
  AdminOrganizationResponse,
  AdminOrganizationMemberResponse,
  AuditLogEntry,
  TenantSettings,
  DashboardResponse,
  CreateUserRequest,
  UpdateUserRequest,
  UpdateOrgRequest,
  UpdateMemberRequest,
} from './generated/client';
