/**
 * Analytics Helpers
 * 
 * Utilities for platform analytics and reporting
 */

import { VaultInternalClient } from './client';
import type { PlatformOverview, TenantAnalyticsPoint } from './generated/client';

export interface GrowthMetrics {
  /** Period start */
  from: Date;
  /** Period end */
  to: Date;
  /** New tenants in period */
  newTenants: number;
  /** Churned tenants in period */
  churnedTenants: number;
  /** Net growth */
  netGrowth: number;
  /** Growth rate as percentage */
  growthRate: number;
}

export interface UsageReport {
  /** Metric name */
  metric: string;
  /** Total across all tenants */
  total: number;
  /** Average per tenant */
  average: number;
  /** Top 10 tenants by usage */
  topTenants: Array<{ tenantId: string; value: number; percentage: number }>;
  /** Period */
  period: { from: string; to: string };
}

/**
 * Helper class for analytics operations
 */
export class AnalyticsManager {
  constructor(private readonly client: VaultInternalClient) {}

  /**
   * Get current platform health snapshot
   */
  async getOverview(): Promise<PlatformOverview> {
    return this.client.getPlatformOverview();
  }

  /**
   * Get tenant growth metrics for a period
   */
  async getGrowthMetrics(from: Date, to: Date): Promise<GrowthMetrics> {
    const analytics = await this.client.getTenantAnalytics({
      from: from.toISOString().split('T')[0],
      to: to.toISOString().split('T')[0],
    });

    let newTenants = 0;
    let churnedTenants = 0;

    for (const point of analytics.data) {
      newTenants += point.newTenants;
      churnedTenants += point.churnedTenants;
    }

    const netGrowth = newTenants - churnedTenants;
    
    // Get starting active count
    const startActive = analytics.data[0]?.activeTenants ?? 0;
    const growthRate = startActive > 0 ? (netGrowth / startActive) * 100 : 0;

    return {
      from,
      to,
      newTenants,
      churnedTenants,
      netGrowth,
      growthRate: Math.round(growthRate * 100) / 100,
    };
  }

  /**
   * Get monthly recurring growth rate
   */
  async getMonthlyGrowthRate(): Promise<number> {
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);

    const metrics = await this.getGrowthMetrics(startOfLastMonth, startOfMonth);
    return metrics.growthRate;
  }

  /**
   * Generate usage report for a specific metric
   */
  async getUsageReport(
    metric: 'activeUsers' | 'logins' | 'apiCalls' | 'storage'
  ): Promise<UsageReport> {
    const data = await this.client.getUsageAnalytics({ metric });

    // Sort by value descending
    const sorted = [...data.byTenant].sort((a, b) => b.value - a.value);
    const topTen = sorted.slice(0, 10);

    const topTenants = topTen.map(t => ({
      tenantId: t.tenantId,
      value: t.value,
      percentage: data.total > 0 ? Math.round((t.value / data.total) * 10000) / 100 : 0,
    }));

    const average = data.byTenant.length > 0 
      ? data.total / data.byTenant.length 
      : 0;

    return {
      metric,
      total: data.total,
      average: Math.round(average * 100) / 100,
      topTenants,
      period: {
        from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        to: new Date().toISOString(),
      },
    };
  }

  /**
   * Get daily active users (DAU) trend
   */
  async getDAUTrend(days = 30): Promise<Array<{ date: string; dau: number }>> {
    const end = new Date();
    const start = new Date();
    start.setDate(start.getDate() - days);

    const analytics = await this.client.getUsageAnalytics({
      metric: 'activeUsers',
    });

    // This is simplified - in reality you'd want daily breakdown from the API
    return [];
  }

  /**
   * Get system health metrics
   */
  async getSystemHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    apiCalls24h: number;
    averageLatency: number;
    errorRate: number;
  }> {
    const overview = await this.getOverview();
    const { system } = overview;

    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    if (system.errorRate > 0.05 || system.averageLatency > 500) {
      status = 'unhealthy';
    } else if (system.errorRate > 0.01 || system.averageLatency > 200) {
      status = 'degraded';
    }

    return {
      status,
      apiCalls24h: system.totalApiCalls24h,
      averageLatency: system.averageLatency,
      errorRate: system.errorRate,
    };
  }

  /**
   * Export analytics data for external BI tools
   */
  async exportForBI(
    from: Date,
    to: Date
  ): Promise<{
    tenantGrowth: TenantAnalyticsPoint[];
    overview: PlatformOverview;
  }> {
    const [tenantGrowth, overview] = await Promise.all([
      this.client.getTenantAnalytics({
        from: from.toISOString().split('T')[0],
        to: to.toISOString().split('T')[0],
        groupBy: 'day',
      }),
      this.getOverview(),
    ]);

    return {
      tenantGrowth: tenantGrowth.data,
      overview,
    };
  }
}
