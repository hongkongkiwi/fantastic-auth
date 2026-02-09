-- Bulk operations jobs table
-- Stores import/export job metadata and status tracking

CREATE TABLE bulk_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_type VARCHAR(50) NOT NULL, -- import, export
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, processing, completed, failed, cancelled
    format VARCHAR(20) NOT NULL, -- csv, json
    
    -- Record counts
    total_records INTEGER NOT NULL DEFAULT 0,
    processed_records INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    
    -- File paths (relative to storage root)
    file_path VARCHAR(500),
    error_report_path VARCHAR(500),
    result_file_path VARCHAR(500),
    
    -- Processing options
    options JSONB NOT NULL DEFAULT '{}',
    
    -- Error details (for failed jobs)
    error_message TEXT,
    
    -- Timestamps
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    
    -- Metadata
    metadata JSONB NOT NULL DEFAULT '{}'
);

-- Enable RLS
ALTER TABLE bulk_jobs ENABLE ROW LEVEL SECURITY;

-- RLS Policy: tenant isolation
CREATE POLICY tenant_isolation_bulk_jobs ON bulk_jobs
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Indexes for common queries
CREATE INDEX idx_bulk_jobs_tenant ON bulk_jobs(tenant_id, created_at DESC);
CREATE INDEX idx_bulk_jobs_status ON bulk_jobs(status, job_type);
CREATE INDEX idx_bulk_jobs_tenant_status ON bulk_jobs(tenant_id, status, job_type);
CREATE INDEX idx_bulk_jobs_created_by ON bulk_jobs(created_by);

-- Index for cleanup queries
CREATE INDEX idx_bulk_jobs_completed_at ON bulk_jobs(completed_at) 
    WHERE completed_at IS NOT NULL;

COMMENT ON TABLE bulk_jobs IS 'Tracks bulk import/export operations with progress and error reporting';
COMMENT ON COLUMN bulk_jobs.job_type IS 'Type of bulk operation: import or export';
COMMENT ON COLUMN bulk_jobs.status IS 'Current job status: pending, processing, completed, failed, cancelled';
COMMENT ON COLUMN bulk_jobs.format IS 'File format: csv or json';
COMMENT ON COLUMN bulk_jobs.options IS 'Processing options like continue_on_error, preview_mode, etc.';
