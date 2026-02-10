import type { JsonObject, SecurityResponse } from './generated/client';
import { TenantClient } from './client';

export class SecurityManager {
  constructor(private readonly client: TenantClient) {}

  getGeoPolicy(): Promise<SecurityResponse> {
    return this.client.getSecurityGeoPolicy();
  }

  updateGeoPolicy(data: JsonObject): Promise<SecurityResponse> {
    return this.client.updateSecurityGeoPolicy(data);
  }

  getVpnDetection(): Promise<SecurityResponse> {
    return this.client.getSecurityVpnDetection();
  }

  updateVpnDetection(data: JsonObject): Promise<SecurityResponse> {
    return this.client.updateSecurityVpnDetection(data);
  }
}
