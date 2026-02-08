import type { AnalyticsResponse, DateRangeQuery } from './generated/client';
import { VaultAdminClient } from './client';

export class AnalyticsManager {
  constructor(private readonly client: VaultAdminClient) {}

  getDashboard(query?: DateRangeQuery): Promise<AnalyticsResponse> {
    return this.client.getAnalyticsDashboard(query);
  }

  getLogins(query?: DateRangeQuery): Promise<AnalyticsResponse> {
    return this.client.getAnalyticsLogins(query);
  }

  getUsers(query?: DateRangeQuery): Promise<AnalyticsResponse> {
    return this.client.getAnalyticsUsers(query);
  }

  getSecurity(query?: DateRangeQuery): Promise<AnalyticsResponse> {
    return this.client.getAnalyticsSecurity(query);
  }

  export(query?: Record<string, unknown>): Promise<Blob> {
    return this.client.exportAnalytics(query);
  }
}
