/**
 * Organization Management Helpers
 * 
 * High-level utilities for organization management
 */

import { TenantClient } from './client';
import type { TenantOrganizationResponse, TenantOrganizationMemberResponse, UpdateOrgRequest } from './generated/client';

export interface OrganizationFilter {
  status?: string;
}

export interface OrganizationStats {
  total: number;
  active: number;
  totalMembers: number;
  averageMembersPerOrg: number;
}

export type MemberRole = 'owner' | 'admin' | 'member' | 'guest';

/**
 * Helper class for organization management operations
 */
export class OrganizationManager {
  constructor(private readonly client: TenantClient) {}

  /**
   * Get all organizations
   */
  async getAll(filter?: OrganizationFilter): Promise<TenantOrganizationResponse[]> {
    const results: TenantOrganizationResponse[] = [];

    for await (const org of this.client.iterateOrganizations({
      status: filter?.status,
    })) {
      results.push(org);
    }

    return results;
  }

  /**
   * Find organization by slug
   */
  async findBySlug(slug: string): Promise<TenantOrganizationResponse | null> {
    const all = await this.getAll();
    return all.find(o => o.slug === slug) ?? null;
  }

  /**
   * Get organization details with members
   */
  async getDetails(orgId: string): Promise<{
    organization: TenantOrganizationResponse;
    members: TenantOrganizationMemberResponse[];
  }> {
    const [organization, members] = await Promise.all([
      this.client.getOrganization(orgId),
      this.client.listOrganizationMembers(orgId),
    ]);

    return { organization, members };
  }

  /**
   * Update organization settings
   */
  async update(orgId: string, data: UpdateOrgRequest): Promise<TenantOrganizationResponse> {
    return this.client.updateOrganization(orgId, data);
  }

  /**
   * Delete organization
   */
  async delete(orgId: string): Promise<void> {
    await this.client.deleteOrganization(orgId);
  }

  /**
   * Update member role
   */
  async updateMemberRole(
    orgId: string,
    userId: string,
    role: MemberRole
  ): Promise<TenantOrganizationMemberResponse> {
    return this.client.updateOrganizationMember(orgId, userId, { role });
  }

  /**
   * Remove member from organization
   */
  async removeMember(orgId: string, userId: string): Promise<void> {
    await this.client.removeOrganizationMember(orgId, userId);
  }

  /**
   * Get organization statistics
   */
  async getStats(): Promise<OrganizationStats> {
    const all = await this.getAll();
    const active = all.filter(o => o.status === 'active');
    const totalMembers = active.reduce((sum, o) => sum + o.memberCount, 0);

    return {
      total: all.length,
      active: active.length,
      totalMembers,
      averageMembersPerOrg: active.length > 0 ? Math.round(totalMembers / active.length) : 0,
    };
  }

  /**
   * Get organizations with no members (orphaned)
   */
  async getOrphaned(): Promise<TenantOrganizationResponse[]> {
    const all = await this.getAll();
    return all.filter(o => o.memberCount === 0);
  }

  /**
   * Get organizations approaching member limit
   */
  async getNearLimit(thresholdPercent: number = 90): Promise<TenantOrganizationResponse[]> {
    const all = await this.getAll();
    return all.filter(o => {
      if (!o.maxMembers) return false;
      return (o.memberCount / o.maxMembers) * 100 >= thresholdPercent;
    });
  }

  /**
   * Bulk delete organizations
   */
  async bulkDelete(orgIds: string[]): Promise<void> {
    await Promise.all(orgIds.map(id => this.client.deleteOrganization(id)));
  }
}
