/**
 * User Management Helpers
 * 
 * High-level utilities for user administration
 */

import { VaultAdminClient } from './client';
import type { AdminUserResponse, CreateUserRequest, UpdateUserRequest } from './generated/client';

export interface UserFilter {
  status?: 'active' | 'pending' | 'suspended' | 'deactivated';
  email?: string;
  organizationId?: string;
}

export interface UserStats {
  total: number;
  active: number;
  suspended: number;
  pending: number;
  mfaEnabled: number;
}

/**
 * Helper class for user management operations
 */
export class UserManager {
  constructor(private readonly client: VaultAdminClient) {}

  /**
   * Get all users with optional filtering
   */
  async getAll(filter?: UserFilter): Promise<AdminUserResponse[]> {
    const results: AdminUserResponse[] = [];
    let page = 1;
    let hasMore = true;

    while (hasMore) {
      const response = await this.client.listUsers({
        page,
        perPage: 100,
        status: filter?.status,
        email: filter?.email,
        orgId: filter?.organizationId,
      });

      results.push(...response.data);
      
      hasMore = response.data.length === 100 && page < response.pagination.totalPages;
      page++;
    }

    return results;
  }

  /**
   * Find user by email
   */
  async findByEmail(email: string): Promise<AdminUserResponse | null> {
    const result = await this.client.listUsers({ email, perPage: 1 });
    return result.data[0] ?? null;
  }

  /**
   * Create user with optional password
   */
  async create(data: CreateUserRequest): Promise<AdminUserResponse> {
    return this.client.createUser(data);
  }

  /**
   * Update user profile
   */
  async update(userId: string, data: UpdateUserRequest): Promise<AdminUserResponse> {
    return this.client.updateUser(userId, data);
  }

  /**
   * Suspend user account
   */
  async suspend(userId: string, reason?: string): Promise<AdminUserResponse> {
    return this.client.suspendUser(userId, { reason });
  }

  /**
   * Activate suspended user
   */
  async activate(userId: string): Promise<AdminUserResponse> {
    return this.client.activateUser(userId);
  }

  /**
   * Delete user permanently
   */
  async delete(userId: string): Promise<void> {
    await this.client.deleteUser(userId);
  }

  /**
   * Force logout from all devices
   */
  async forceLogout(userId: string): Promise<void> {
    await this.client.revokeAllUserSessions(userId);
  }

  /**
   * Get user statistics
   */
  async getStats(): Promise<UserStats> {
    const all = await this.getAll();
    
    return {
      total: all.length,
      active: all.filter(u => u.status === 'active').length,
      suspended: all.filter(u => u.status === 'suspended').length,
      pending: all.filter(u => u.status === 'pending').length,
      mfaEnabled: all.filter(u => u.mfaEnabled).length,
    };
  }

  /**
   * Get users by status
   */
  async getByStatus(status: 'active' | 'pending' | 'suspended' | 'deactivated'): Promise<AdminUserResponse[]> {
    return this.getAll({ status });
  }

  /**
   * Get users who haven't logged in recently
   */
  async getInactive(days: number = 30): Promise<AdminUserResponse[]> {
    const all = await this.getAll();
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);

    return all.filter(user => {
      if (!user.lastLoginAt) return true;
      return new Date(user.lastLoginAt) < cutoff;
    });
  }

  /**
   * Bulk suspend users
   */
  async bulkSuspend(userIds: string[], reason?: string): Promise<AdminUserResponse[]> {
    const results = await Promise.all(
      userIds.map(id => this.client.suspendUser(id, { reason }))
    );
    return results;
  }

  /**
   * Bulk activate users
   */
  async bulkActivate(userIds: string[]): Promise<AdminUserResponse[]> {
    const results = await Promise.all(
      userIds.map(id => this.client.activateUser(id))
    );
    return results;
  }
}
