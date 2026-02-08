/**
 * Audit Log Helpers
 * 
 * Utilities for querying and analyzing audit logs
 */

import { VaultAdminClient } from './client';
import type { AuditLogEntry } from './generated/client';

export interface AuditFilter {
  userId?: string;
  action?: string;
  resourceType?: string;
  from?: Date;
  to?: Date;
  success?: boolean;
}

export interface ActionSummary {
  action: string;
  count: number;
  successCount: number;
  failureCount: number;
}

export interface UserActivitySummary {
  userId: string;
  email?: string;
  actionCount: number;
  lastActivity: string;
  ipAddresses: string[];
}

/**
 * Helper class for audit log operations
 */
export class AuditManager {
  constructor(private readonly client: VaultAdminClient) {}

  /**
   * Query audit logs with filters
   */
  async query(filter?: AuditFilter, page: number = 1, perPage: number = 50): Promise<{
    entries: AuditLogEntry[];
    total: number;
  }> {
    const result = await this.client.queryAuditLogs({
      page,
      perPage,
      userId: filter?.userId,
      action: filter?.action,
      resourceType: filter?.resourceType,
      from: filter?.from?.toISOString(),
      to: filter?.to?.toISOString(),
      success: filter?.success,
    });

    return {
      entries: result.data,
      total: result.pagination.total,
    };
  }

  /**
   * Get all audit log entries (paginated iteration)
   */
  async getAll(filter?: Omit<AuditFilter, 'from' | 'to'>, dateRange?: { from: Date; to: Date }): Promise<AuditLogEntry[]> {
    const results: AuditLogEntry[] = [];
    let page = 1;
    let hasMore = true;

    while (hasMore) {
      const { entries } = await this.query(
        { ...filter, ...dateRange },
        page,
        500 // Max page size for bulk export
      );

      results.push(...entries);
      hasMore = entries.length === 500;
      page++;

      // Safety limit
      if (page > 100) break;
    }

    return results;
  }

  /**
   * Get recent activity
   */
  async getRecent(limit: number = 50): Promise<AuditLogEntry[]> {
    const { entries } = await this.query(undefined, 1, limit);
    return entries;
  }

  /**
   * Get user activity timeline
   */
  async getUserActivity(userId: string, days: number = 30): Promise<AuditLogEntry[]> {
    const from = new Date();
    from.setDate(from.getDate() - days);

    return this.getAll({ userId }, { from, to: new Date() });
  }

  /**
   * Summarize actions in a time period
   */
  async summarizeActions(days: number = 7): Promise<ActionSummary[]> {
    const from = new Date();
    from.setDate(from.getDate() - days);

    const entries = await this.getAll({}, { from, to: new Date() });
    const summary = new Map<string, ActionSummary>();

    for (const entry of entries) {
      const existing = summary.get(entry.action);
      if (existing) {
        existing.count++;
        if (entry.success) {
          existing.successCount++;
        } else {
          existing.failureCount++;
        }
      } else {
        summary.set(entry.action, {
          action: entry.action,
          count: 1,
          successCount: entry.success ? 1 : 0,
          failureCount: entry.success ? 0 : 1,
        });
      }
    }

    return Array.from(summary.values()).sort((a, b) => b.count - a.count);
  }

  /**
   * Get failed login attempts
   */
  async getFailedLogins(days: number = 7): Promise<AuditLogEntry[]> {
    const from = new Date();
    from.setDate(from.getDate() - days);

    const entries = await this.getAll(
      { action: 'user.login', success: false },
      { from, to: new Date() }
    );

    return entries;
  }

  /**
   * Detect suspicious activity (multiple failed logins)
   */
  async detectSuspiciousActivity(failedThreshold: number = 5, hours: number = 1): Promise<UserActivitySummary[]> {
    const from = new Date();
    from.setHours(from.getHours() - hours);

    const entries = await this.getAll(
      { success: false },
      { from, to: new Date() }
    );

    const userMap = new Map<string, UserActivitySummary>();

    for (const entry of entries) {
      if (!entry.userId) continue;

      const existing = userMap.get(entry.userId);
      if (existing) {
        existing.actionCount++;
        if (entry.ipAddress && !existing.ipAddresses.includes(entry.ipAddress)) {
          existing.ipAddresses.push(entry.ipAddress);
        }
        if (entry.timestamp > existing.lastActivity) {
          existing.lastActivity = entry.timestamp;
        }
      } else {
        userMap.set(entry.userId, {
          userId: entry.userId,
          email: entry.userEmail,
          actionCount: 1,
          lastActivity: entry.timestamp,
          ipAddresses: entry.ipAddress ? [entry.ipAddress] : [],
        });
      }
    }

    return Array.from(userMap.values())
      .filter(u => u.actionCount >= failedThreshold)
      .sort((a, b) => b.actionCount - a.actionCount);
  }

  /**
   * Export audit logs for compliance
   */
  async exportForCompliance(startDate: Date, endDate: Date): Promise<{
    entries: AuditLogEntry[];
    generatedAt: string;
    dateRange: { from: string; to: string };
  }> {
    const entries = await this.getAll({}, { from: startDate, to: endDate });

    return {
      entries,
      generatedAt: new Date().toISOString(),
      dateRange: {
        from: startDate.toISOString(),
        to: endDate.toISOString(),
      },
    };
  }
}
