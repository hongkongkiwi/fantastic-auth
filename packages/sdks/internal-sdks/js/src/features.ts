/**
 * Feature Flag Helpers
 * 
 * Utilities for managing feature flags across tenants
 */

import { VaultInternalClient } from './client';
import type { FeatureFlag } from './generated/client';

export interface RolloutConfig {
  /** Percentage of tenants (0-100) */
  percentage: number;
  /** Specific tenant IDs to include */
  include?: string[];
  /** Specific tenant IDs to exclude */
  exclude?: string[];
}

export interface FeatureFlagState {
  key: string;
  enabled: boolean;
  isEnabledForTenant: (tenantId: string) => boolean;
}

/**
 * Helper class for feature flag management
 */
export class FeatureFlagManager {
  private flags: Map<string, FeatureFlag> = new Map();
  private lastRefresh: number = 0;
  private readonly refreshInterval = 60000; // 1 minute

  constructor(private readonly client: VaultInternalClient) {}

  /**
   * Get all feature flags (with caching)
   */
  async getAll(forceRefresh = false): Promise<FeatureFlag[]> {
    const now = Date.now();
    
    if (forceRefresh || now - this.lastRefresh > this.refreshInterval || this.flags.size === 0) {
      const flags = await this.client.listFeatureFlags();
      this.flags.clear();
      for (const flag of flags) {
        this.flags.set(flag.key, flag);
      }
      this.lastRefresh = now;
    }

    return Array.from(this.flags.values());
  }

  /**
   * Get a specific feature flag by key
   */
  async get(key: string): Promise<FeatureFlag | null> {
    // Check cache first
    const cached = this.flags.get(key);
    if (cached) return cached;

    // Refresh cache
    const flags = await this.getAll(true);
    return flags.find(f => f.key === key) ?? null;
  }

  /**
   * Check if a feature is enabled for a tenant
   */
  async isEnabled(key: string, tenantId: string): Promise<boolean> {
    const flag = await this.get(key);
    if (!flag) return false;

    // If globally disabled
    if (!flag.enabled) return false;

    // If explicitly allowed for this tenant
    if (flag.allowedTenants.includes(tenantId)) return true;

    // Check rollout percentage (using hash of tenantId + key for consistency)
    if (flag.rolloutPercentage >= 100) return true;
    if (flag.rolloutPercentage <= 0) return false;

    const hash = this.hashString(`${tenantId}:${key}`);
    const bucket = hash % 100;
    return bucket < flag.rolloutPercentage;
  }

  /**
   * Enable a feature flag globally
   */
  async enable(key: string): Promise<FeatureFlag> {
    const flag = await this.get(key);
    if (!flag) throw new Error(`Feature flag not found: ${key}`);

    const updated = await this.client.updateFeatureFlag(flag.id, { enabled: true });
    this.flags.set(key, updated);
    return updated;
  }

  /**
   * Disable a feature flag globally
   */
  async disable(key: string): Promise<FeatureFlag> {
    const flag = await this.get(key);
    if (!flag) throw new Error(`Feature flag not found: ${key}`);

    const updated = await this.client.updateFeatureFlag(flag.id, { enabled: false });
    this.flags.set(key, updated);
    return updated;
  }

  /**
   * Configure gradual rollout
   */
  async configureRollout(
    key: string,
    config: RolloutConfig
  ): Promise<FeatureFlag> {
    const flag = await this.get(key);
    if (!flag) throw new Error(`Feature flag not found: ${key}`);

    const updated = await this.client.updateFeatureFlag(flag.id, {
      rolloutPercentage: config.percentage,
      allowedTenants: config.include,
    });

    this.flags.set(key, updated);
    return updated;
  }

  /**
   * Enable feature for specific tenants only
   */
  async enableForTenants(key: string, tenantIds: string[]): Promise<FeatureFlag> {
    const flag = await this.get(key);
    if (!flag) throw new Error(`Feature flag not found: ${key}`);

    const currentAllowed = new Set(flag.allowedTenants);
    for (const id of tenantIds) {
      currentAllowed.add(id);
    }

    const updated = await this.client.updateFeatureFlag(flag.id, {
      enabled: true,
      allowedTenants: Array.from(currentAllowed),
    });

    this.flags.set(key, updated);
    return updated;
  }

  /**
   * Disable feature for specific tenants
   */
  async disableForTenants(key: string, tenantIds: string[]): Promise<FeatureFlag> {
    const flag = await this.get(key);
    if (!flag) throw new Error(`Feature flag not found: ${key}`);

    const toRemove = new Set(tenantIds);
    const updated = await this.client.updateFeatureFlag(flag.id, {
      allowedTenants: flag.allowedTenants.filter(id => !toRemove.has(id)),
    });

    this.flags.set(key, updated);
    return updated;
  }

  /**
   * Create a new feature flag
   */
  async create(
    key: string,
    name: string,
    options?: {
      description?: string;
      enabled?: boolean;
      rolloutPercentage?: number;
    }
  ): Promise<FeatureFlag> {
    const flag = await this.client.createFeatureFlag({
      key,
      name,
      description: options?.description,
      enabled: options?.enabled ?? false,
      rolloutPercentage: options?.rolloutPercentage ?? 0,
    });

    this.flags.set(key, flag);
    return flag;
  }

  /**
   * Get feature flag state for evaluation
   */
  async getState(key: string): Promise<FeatureFlagState | null> {
    const flag = await this.get(key);
    if (!flag) return null;

    return {
      key: flag.key,
      enabled: flag.enabled,
      isEnabledForTenant: (tenantId: string) => {
        if (!flag.enabled) return false;
        if (flag.allowedTenants.includes(tenantId)) return true;
        const hash = this.hashString(`${tenantId}:${key}`);
        const bucket = hash % 100;
        return bucket < flag.rolloutPercentage;
      },
    };
  }

  /**
   * Clear the local cache
   */
  clearCache(): void {
    this.flags.clear();
    this.lastRefresh = 0;
  }

  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash);
  }
}
