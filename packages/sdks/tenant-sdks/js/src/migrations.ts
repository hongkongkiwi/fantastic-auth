import type { JsonObject, MigrationJob } from './generated/client';
import { TenantClient } from './client';

export class MigrationManager {
  constructor(private readonly client: TenantClient) {}

  list(): Promise<MigrationJob[]> {
    return this.client.listMigrations();
  }

  get(id: string): Promise<MigrationJob> {
    return this.client.getMigration(id);
  }

  getProgress(id: string): Promise<JsonObject> {
    return this.client.getMigrationProgress(id);
  }

  getErrors(id: string): Promise<JsonObject> {
    return this.client.getMigrationErrors(id);
  }

  fromAuth0(data: JsonObject): Promise<MigrationJob> {
    return this.client.startAuth0Migration(data);
  }

  fromFirebase(data: JsonObject): Promise<MigrationJob> {
    return this.client.startFirebaseMigration(data);
  }

  fromCognito(data: JsonObject): Promise<MigrationJob> {
    return this.client.startCognitoMigration(data);
  }

  fromCsv(file: File | Blob, fields: Record<string, string> = {}): Promise<MigrationJob> {
    const formData = new FormData();
    formData.append('file', file);

    for (const [key, value] of Object.entries(fields)) {
      formData.append(key, value);
    }

    return this.client.startCsvMigration(formData);
  }

  validateCsv(file: File | Blob): Promise<JsonObject> {
    const formData = new FormData();
    formData.append('file', file);
    return this.client.validateCsvMigration(formData);
  }

  previewCsv(file: File | Blob): Promise<JsonObject> {
    const formData = new FormData();
    formData.append('file', file);
    return this.client.previewCsvMigration(formData);
  }

  cancel(id: string): Promise<JsonObject> {
    return this.client.cancelMigration(id);
  }

  pause(id: string): Promise<JsonObject> {
    return this.client.pauseMigration(id);
  }

  resume(id: string): Promise<JsonObject> {
    return this.client.resumeMigration(id);
  }
}
