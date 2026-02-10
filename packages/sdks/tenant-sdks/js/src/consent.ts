import type { ConsentPolicy, JsonObject } from './generated/client';
import { TenantClient } from './client';

export class ConsentManager {
  constructor(private readonly client: TenantClient) {}

  list(query?: Record<string, unknown>): Promise<ConsentPolicy[]> {
    return this.client.listConsentPolicies(query);
  }

  create(data: JsonObject): Promise<ConsentPolicy> {
    return this.client.createConsentPolicy(data);
  }

  update(id: string, data: JsonObject): Promise<ConsentPolicy> {
    return this.client.updateConsentPolicy(id, data);
  }

  stats(id: string): Promise<JsonObject> {
    return this.client.getConsentPolicyStats(id);
  }

  pendingExports(): Promise<JsonObject> {
    return this.client.listPendingConsentExports();
  }

  pendingDeletions(): Promise<JsonObject> {
    return this.client.listPendingConsentDeletions();
  }
}
