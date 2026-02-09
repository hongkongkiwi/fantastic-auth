import type { JsonObject } from './generated/client';
import { VaultAdminClient } from './client';

export class ScimAdminManager {
  constructor(private readonly client: VaultAdminClient) {}

  listTokens(): Promise<JsonObject> {
    return this.client.listScimTokens();
  }

  createToken(data: JsonObject): Promise<JsonObject> {
    return this.client.createScimToken(data);
  }

  revokeToken(tokenId: string): Promise<JsonObject> {
    return this.client.revokeScimToken(tokenId);
  }

  deleteToken(tokenId: string): Promise<void> {
    return this.client.deleteScimToken(tokenId);
  }

  getConfig(): Promise<JsonObject> {
    return this.client.getScimConfig();
  }

  updateConfig(data: JsonObject): Promise<JsonObject> {
    return this.client.updateScimConfig(data);
  }

  getStats(): Promise<JsonObject> {
    return this.client.getScimStats();
  }
}
