const metrics = {
  auditExportRequests: 0,
  auditExportBytes: 0,
  auditExportErrors: 0,
  auditExportLastAt: undefined as string | undefined,
}

export const recordAuditExportRequest = () => {
  metrics.auditExportRequests += 1
  metrics.auditExportLastAt = new Date().toISOString()
}

export const recordAuditExportBytes = (bytes: number) => {
  metrics.auditExportBytes += bytes
}

export const recordAuditExportError = () => {
  metrics.auditExportErrors += 1
  metrics.auditExportLastAt = new Date().toISOString()
}

export const getUiMetrics = () => ({ ...metrics })
