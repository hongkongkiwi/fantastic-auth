/**
 * Tenant Settings Helpers
 * 
 * Utilities for managing tenant configuration
 */

import { VaultAdminClient } from './client';
import type { TenantSettings, PasswordPolicy, MfaPolicy } from './generated/client';

export interface SecuritySettings {
  passwordPolicy: PasswordPolicy;
  mfaPolicy: MfaPolicy;
  allowedDomains: string[];
}

/**
 * Helper class for tenant settings management
 */
export class SettingsManager {
  constructor(private readonly client: VaultAdminClient) {}

  /**
   * Get current tenant settings
   */
  async get(): Promise<TenantSettings> {
    return this.client.getSettings();
  }

  /**
   * Update tenant name
   */
  async updateName(name: string): Promise<TenantSettings> {
    return this.client.updateSettings({ name });
  }

  /**
   * Update password policy
   */
  async updatePasswordPolicy(policy: Partial<PasswordPolicy>): Promise<TenantSettings> {
    return this.client.updateSettings({
      passwordPolicy: {
        minLength: policy.minLength ?? 12,
        requireUppercase: policy.requireUppercase ?? true,
        requireLowercase: policy.requireLowercase ?? true,
        requireNumbers: policy.requireNumbers ?? true,
        requireSpecial: policy.requireSpecial ?? true,
      },
    });
  }

  /**
   * Update MFA policy
   */
  async updateMfaPolicy(policy: Partial<MfaPolicy>): Promise<TenantSettings> {
    return this.client.updateSettings({
      mfaPolicy: {
        enabled: policy.enabled ?? true,
        required: policy.required ?? false,
      },
    });
  }

  /**
   * Require MFA for all users
   */
  async requireMfa(): Promise<TenantSettings> {
    return this.updateMfaPolicy({ enabled: true, required: true });
  }

  /**
   * Make MFA optional
   */
  async makeMfaOptional(): Promise<TenantSettings> {
    return this.updateMfaPolicy({ enabled: true, required: false });
  }

  /**
   * Disable MFA entirely
   */
  async disableMfa(): Promise<TenantSettings> {
    return this.updateMfaPolicy({ enabled: false, required: false });
  }

  /**
   * Add allowed email domain
   */
  async addAllowedDomain(domain: string): Promise<TenantSettings> {
    const current = await this.get();
    const domains = new Set(current.allowedDomains ?? []);
    domains.add(domain.toLowerCase());

    return this.client.updateSettings({
      allowedDomains: Array.from(domains),
    });
  }

  /**
   * Remove allowed email domain
   */
  async removeAllowedDomain(domain: string): Promise<TenantSettings> {
    const current = await this.get();
    const domains = (current.allowedDomains ?? []).filter(d => d !== domain.toLowerCase());

    return this.client.updateSettings({
      allowedDomains: domains,
    });
  }

  /**
   * Set allowed domains (replaces all)
   */
  async setAllowedDomains(domains: string[]): Promise<TenantSettings> {
    return this.client.updateSettings({
      allowedDomains: domains.map(d => d.toLowerCase()),
    });
  }

  /**
   * Check if email domain is allowed
   */
  async isDomainAllowed(email: string): Promise<boolean> {
    const settings = await this.get();
    const allowedDomains = settings.allowedDomains ?? [];
    if (allowedDomains.length === 0) return true;

    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return false;

    return allowedDomains.includes(domain);
  }

  /**
   * Get security settings summary
   */
  async getSecuritySummary(): Promise<{
    passwordStrength: 'weak' | 'medium' | 'strong';
    mfaStatus: 'disabled' | 'optional' | 'required';
    domainRestrictions: 'none' | 'restricted';
  }> {
    const settings = await this.get();

    // Determine password strength
    let passwordStrength: 'weak' | 'medium' | 'strong' = 'weak';
    const policy = settings.passwordPolicy ?? {};
    if (policy.minLength !== undefined &&
        policy.minLength >= 12 &&
        policy.requireUppercase &&
        policy.requireLowercase &&
        policy.requireNumbers &&
        policy.requireSpecial) {
      passwordStrength = 'strong';
    } else if ((policy.minLength ?? 0) >= 8) {
      passwordStrength = 'medium';
    }

    // Determine MFA status
    let mfaStatus: 'disabled' | 'optional' | 'required' = 'disabled';
    if (settings.mfaPolicy?.enabled) {
      mfaStatus = settings.mfaPolicy.required ? 'required' : 'optional';
    }

    return {
      passwordStrength,
      mfaStatus,
      domainRestrictions: (settings.allowedDomains?.length ?? 0) > 0 ? 'restricted' : 'none',
    };
  }
}
