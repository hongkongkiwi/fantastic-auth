/**
 * Tenant Management Helpers
 * 
 * High-level utilities for common tenant operations
 */

import { VaultInternalClient } from './client';
import type { Tenant, CreateTenantRequest } from './generated/client';

export interface ProvisionTenantOptions {
  /** Tenant name */
  name: string;
  /** URL-friendly slug (auto-generated from name if not provided) */
  slug?: string;
  /** Plan to subscribe to */
  plan?: string;
  /** Owner email address */
  ownerEmail: string;
  /** Owner display name */
  ownerName?: string;
  /** Custom domain (optional) */
  customDomain?: string;
}

export interface ProvisionTenantResult {
  tenant: Tenant;
  /** URL for the new tenant's dashboard */
  dashboardUrl: string;
  /** URL for the owner to set their password */
  setupUrl?: string;
}

/**
 * Helper class for tenant-related operations
 */
export class TenantManager {
  constructor(private readonly client: VaultInternalClient) {}

  /**
   * Provision a new tenant with an owner
   * 
   * This is the main method to call during SaaS signup flow.
   * 
   * @example
   * ```typescript
   * const result = await tenantManager.provision({
   *   name: 'Acme Corp',
   *   ownerEmail: 'admin@acme.com',
   *   plan: 'pro'
   * });
   * 
   * console.log(`Tenant created: ${result.dashboardUrl}`);
   * ```
   */
  async provision(options: ProvisionTenantOptions): Promise<ProvisionTenantResult> {
    // Auto-generate slug if not provided
    const slug = options.slug ?? this.generateSlug(options.name);

    const tenant = await this.client.createTenant({
      name: options.name,
      slug,
      plan: options.plan ?? 'free',
      ownerEmail: options.ownerEmail,
      ownerName: options.ownerName,
      customDomain: options.customDomain,
    });

    // Build URLs
    const dashboardUrl = tenant.customDomain
      ? `https://${tenant.customDomain}`
      : `https://${tenant.slug}.vault.dev`;

    return {
      tenant,
      dashboardUrl,
    };
  }

  /**
   * Check if a slug is available
   */
  async isSlugAvailable(slug: string): Promise<boolean> {
    try {
      // Try to list tenants with this slug
      const result = await this.client.listTenants({ slug });
      return result.data.length === 0;
    } catch {
      return true;
    }
  }

  /**
   * Find tenant by slug
   */
  async findBySlug(slug: string): Promise<Tenant | null> {
    const result = await this.client.listTenants({ slug, perPage: 1 });
    return result.data[0] ?? null;
  }

  /**
   * Find tenant by custom domain
   */
  async findByDomain(domain: string): Promise<Tenant | null> {
    // Note: This assumes the API supports filtering by domain
    // You may need to implement this differently based on your API
    const result = await this.client.listTenants({ perPage: 100 });
    return result.data.find(t => t.customDomain === domain) ?? null;
  }

  /**
   * Upgrade tenant plan
   */
  async upgradePlan(tenantId: string, newPlan: string): Promise<Tenant> {
    return this.client.updateTenant(tenantId, { plan: newPlan });
  }

  /**
   * Update tenant limits
   */
  async setLimits(
    tenantId: string,
    limits: { maxUsers?: number; maxOrganizations?: number; maxApiCallsPerMonth?: number }
  ): Promise<Tenant> {
    return this.client.updateTenant(tenantId, { limits });
  }

  /**
   * Get all tenants on a specific plan
   */
  async getByPlan(plan: string): Promise<Tenant[]> {
    const result = await this.client.listTenants({ plan, perPage: 1000 });
    return result.data;
  }

  /**
   * Get trial tenants that need follow-up
   */
  async getTrialsExpiringSoon(days = 7): Promise<Tenant[]> {
    const result = await this.client.listTenants({ status: 'trial', perPage: 1000 });
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() + days);
    
    return result.data.filter(t => {
      if (!t.billing?.currentPeriodEnd) return false;
      const endDate = new Date(t.billing.currentPeriodEnd);
      return endDate <= cutoff;
    });
  }

  private generateSlug(name: string): string {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }
}
