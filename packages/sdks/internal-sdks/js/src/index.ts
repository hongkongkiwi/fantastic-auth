/**
 * Vault Internal API SDK
 * 
 * A TypeScript SDK for interacting with the Vault Internal API.
 * Designed for SaaS platform services, internal tools, and automation.
 * 
 * @example
 * ```typescript
 * import { VaultInternalClient, TenantManager, BillingManager } from '@vault/internal-sdk';
 * 
 * const client = new VaultInternalClient({
 *   baseUrl: 'https://api.vault.dev/api/v1/internal',
 *   apiKey: process.env.VAULT_INTERNAL_API_KEY!
 * });
 * 
 * // Provision a new tenant
 * const tenants = new TenantManager(client);
 * const { tenant, dashboardUrl } = await tenants.provision({
 *   name: 'Acme Corp',
 *   ownerEmail: 'admin@acme.com',
 *   plan: 'pro'
 * });
 * 
 * console.log(`Created tenant: ${dashboardUrl}`);
 * ```
 */

// Core client
export { VaultInternalClient, VaultInternalError } from './client';
export type { VaultInternalClientOptions, RequestOptions } from './client';

// Helper managers
export { TenantManager } from './tenants';
export type { ProvisionTenantOptions, ProvisionTenantResult } from './tenants';

export { BillingManager } from './billing';
export type { PlanChangeOptions, ProrationEstimate } from './billing';

export { AnalyticsManager } from './analytics';
export type { GrowthMetrics, UsageReport } from './analytics';

export { FeatureFlagManager } from './features';
export type { RolloutConfig, FeatureFlagState } from './features';

// Generated types
export type * from './generated/client';

// Re-export specific types for convenience
export type {
  Tenant,
  TenantLimits,
  TenantUsage,
  TenantBilling,
  CreateTenantRequest,
  UpdateTenantRequest,
  PlatformUser,
  PlatformUserDetail,
  Subscription,
  Invoice,
  FeatureFlag,
  PlatformOverview,
} from './generated/client';
