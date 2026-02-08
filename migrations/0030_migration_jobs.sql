-- Migration jobs table for tracking user migrations from external providers
-- Created: 2026-02-08

-- Migration source enum
CREATE TYPE migration_source AS ENUM ('auth0', 'firebase', 'cognito', 'csv', 'ldap', 'okta', 'onelogin');

-- Migration status enum
CREATE TYPE migration_status AS ENUM ('pending', 'running', 'paused', 'completed', 'failed', 'cancelled');

-- Main migration jobs table
CREATE TABLE migration_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source migration_source NOT NULL,
    status migration_status NOT NULL DEFAULT 'pending',
    total_users INTEGER NOT NULL DEFAULT 0,
    processed INTEGER NOT NULL DEFAULT 0,
    succeeded INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    config JSONB NOT NULL DEFAULT '{}',
    dry_run BOOLEAN NOT NULL DEFAULT false,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    resumed_from UUID REFERENCES migration_jobs(id),
    last_processed_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Migration errors table
CREATE TABLE migration_errors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    migration_id UUID NOT NULL REFERENCES migration_jobs(id) ON DELETE CASCADE,
    external_id VARCHAR(255),
    email VARCHAR(255),
    error_message TEXT NOT NULL,
    error_details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for migration jobs
CREATE INDEX idx_migration_jobs_tenant ON migration_jobs(tenant_id);
CREATE INDEX idx_migration_jobs_status ON migration_jobs(status);
CREATE INDEX idx_migration_jobs_source ON migration_jobs(source);
CREATE INDEX idx_migration_jobs_started_at ON migration_jobs(started_at DESC);
CREATE INDEX idx_migration_jobs_created_by ON migration_jobs(created_by);

-- Indexes for migration errors
CREATE INDEX idx_migration_errors_migration_id ON migration_errors(migration_id);
CREATE INDEX idx_migration_errors_email ON migration_errors(email);
CREATE INDEX idx_migration_errors_created_at ON migration_errors(created_at DESC);

-- RLS policies for migration_jobs
ALTER TABLE migration_jobs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_migration_jobs_isolation ON migration_jobs
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- RLS policies for migration_errors
ALTER TABLE migration_errors ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_migration_errors_isolation ON migration_errors
    USING (EXISTS (
        SELECT 1 FROM migration_jobs 
        WHERE migration_jobs.id = migration_errors.migration_id
        AND migration_jobs.tenant_id = current_setting('app.current_tenant_id')::UUID
    ));

-- Updated at trigger
CREATE OR REPLACE FUNCTION update_migration_jobs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER migration_jobs_updated_at
    BEFORE UPDATE ON migration_jobs
    FOR EACH ROW
    EXECUTE FUNCTION update_migration_jobs_updated_at();

-- View for migration statistics
CREATE VIEW migration_statistics AS
SELECT 
    tenant_id,
    source,
    COUNT(*) as total_jobs,
    COUNT(*) FILTER (WHERE status = 'completed') as completed_jobs,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_jobs,
    COUNT(*) FILTER (WHERE status = 'running') as running_jobs,
    SUM(succeeded) as total_succeeded,
    SUM(failed) as total_failed,
    AVG(
        CASE 
            WHEN total_users > 0 THEN (succeeded::float / total_users::float) * 100 
            ELSE 0 
        END
    ) as avg_success_rate
FROM migration_jobs
GROUP BY tenant_id, source;

-- Comments
COMMENT ON TABLE migration_jobs IS 'Tracks user migration jobs from external identity providers';
COMMENT ON TABLE migration_errors IS 'Stores errors encountered during user migrations';
COMMENT ON COLUMN migration_jobs.config IS 'JSON configuration for the migration source';
COMMENT ON COLUMN migration_jobs.dry_run IS 'Whether this was a dry run (no actual changes)';
COMMENT ON COLUMN migration_jobs.resumed_from IS 'Reference to original job if this is a resume';
COMMENT ON COLUMN migration_errors.external_id IS 'User ID from the external provider';
