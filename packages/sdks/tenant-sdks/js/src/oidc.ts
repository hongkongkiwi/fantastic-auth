import type { JsonObject, OidcClient } from './generated/client';
import { TenantClient } from './client';

export class OidcManager {
  constructor(private readonly client: TenantClient) {}

  listClients(): Promise<OidcClient[]> {
    return this.client.listOidcClients();
  }

  createClient(data: JsonObject): Promise<OidcClient> {
    return this.client.createOidcClient(data);
  }

  getClient(clientId: string): Promise<OidcClient> {
    return this.client.getOidcClient(clientId);
  }

  updateClient(clientId: string, data: JsonObject): Promise<OidcClient> {
    return this.client.updateOidcClient(clientId, data);
  }

  deleteClient(clientId: string): Promise<void> {
    return this.client.deleteOidcClient(clientId);
  }

  rotateSecret(clientId: string): Promise<JsonObject> {
    return this.client.rotateOidcClientSecret(clientId);
  }
}
