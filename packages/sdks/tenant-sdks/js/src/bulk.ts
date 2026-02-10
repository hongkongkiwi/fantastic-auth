import type { BulkJob, JsonObject } from './generated/client';
import { TenantClient } from './client';

export class BulkManager {
  constructor(private readonly client: TenantClient) {}

  listJobs(query?: Record<string, unknown>): Promise<BulkJob[]> {
    return this.client.listBulkJobs(query);
  }

  startImport(file: File | Blob, fields: Record<string, string> = {}): Promise<BulkJob> {
    const formData = new FormData();
    formData.append('file', file);

    for (const [key, value] of Object.entries(fields)) {
      formData.append(key, value);
    }

    return this.client.startBulkImport(formData);
  }

  getImportStatus(jobId: string): Promise<BulkJob> {
    return this.client.getBulkImportStatus(jobId);
  }

  downloadImportErrors(jobId: string): Promise<Blob> {
    return this.client.downloadBulkImportErrorReport(jobId);
  }

  startExport(data: JsonObject): Promise<BulkJob> {
    return this.client.startBulkExport(data);
  }

  getExportStatus(jobId: string): Promise<BulkJob> {
    return this.client.getBulkExportStatus(jobId);
  }

  downloadExport(jobId: string): Promise<Blob> {
    return this.client.downloadBulkExportFile(jobId);
  }

  deleteJob(jobId: string): Promise<void> {
    return this.client.deleteBulkJob(jobId);
  }
}
