import type { ApiKey, JsonObject } from './generated/client';
import { TenantClient } from './client';

export class ApiKeysManager {
  constructor(private readonly client: TenantClient) {}

  list(): Promise<ApiKey[]> {
    return this.client.listApiKeys();
  }

  create(data: JsonObject): Promise<ApiKey> {
    return this.client.createApiKey(data);
  }

  get(id: string): Promise<ApiKey> {
    return this.client.getApiKey(id);
  }

  update(id: string, data: JsonObject): Promise<ApiKey> {
    return this.client.updateApiKey(id, data);
  }

  rotate(id: string): Promise<ApiKey> {
    return this.client.rotateApiKey(id);
  }

  revoke(id: string): Promise<ApiKey> {
    return this.client.revokeApiKey(id);
  }
}
