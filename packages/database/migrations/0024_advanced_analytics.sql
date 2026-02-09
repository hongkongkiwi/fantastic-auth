-- Advanced Analytics Tables for Vault
-- Provides time-series event tracking and aggregated statistics

-- Create analytics_events table with partitioning by date range
-- This allows efficient querying of recent data and archival of old data
CREATE TABLE IF NOT EXISTS analytics_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id UUID,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Create default partition for current data
CREATE TABLE IF NOT EXISTS analytics_events_default PARTITION OF analytics_events
    DEFAULT;

-- Create indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_analytics_events_tenant_id 
    ON analytics_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_analytics_events_event_type 
    ON analytics_events(event_type);
CREATE INDEX IF NOT EXISTS idx_analytics_events_user_id 
    ON analytics_events(user_id);
CREATE INDEX IF NOT EXISTS idx_analytics_events_created_at 
    ON analytics_events(created_at);
CREATE INDEX IF NOT EXISTS idx_analytics_events_tenant_created 
    ON analytics_events(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_analytics_events_tenant_type_created 
    ON analytics_events(tenant_id, event_type, created_at);

-- GIN index for JSONB metadata queries
CREATE INDEX IF NOT EXISTS idx_analytics_events_metadata 
    ON analytics_events USING GIN(metadata);

-- Create daily aggregated statistics table
-- This pre-aggregates data for fast dashboard queries
CREATE TABLE IF NOT EXISTS analytics_daily_stats (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value BIGINT NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, date, metric_name)
);

-- Indexes for daily stats
CREATE INDEX IF NOT EXISTS idx_analytics_daily_stats_tenant_date 
    ON analytics_daily_stats(tenant_id, date);
CREATE INDEX IF NOT EXISTS idx_analytics_daily_stats_metric 
    ON analytics_daily_stats(metric_name);
CREATE INDEX IF NOT EXISTS idx_analytics_daily_stats_date 
    ON analytics_daily_stats(date);

-- Create hourly aggregated statistics table (for real-time analytics)
CREATE TABLE IF NOT EXISTS analytics_hourly_stats (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hour TIMESTAMP NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value BIGINT NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, hour, metric_name)
);

-- Indexes for hourly stats
CREATE INDEX IF NOT EXISTS idx_analytics_hourly_stats_tenant_hour 
    ON analytics_hourly_stats(tenant_id, hour);
CREATE INDEX IF NOT EXISTS idx_analytics_hourly_stats_hour 
    ON analytics_hourly_stats(hour);

-- Create weekly aggregated statistics table
CREATE TABLE IF NOT EXISTS analytics_weekly_stats (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    week_start DATE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value BIGINT NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, week_start, metric_name)
);

-- Create monthly aggregated statistics table
CREATE TABLE IF NOT EXISTS analytics_monthly_stats (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    month_start DATE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value BIGINT NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, month_start, metric_name)
);

-- Create aggregation job tracking table
CREATE TABLE IF NOT EXISTS analytics_aggregation_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type VARCHAR(50) NOT NULL, -- 'hourly', 'daily', 'weekly', 'monthly', 'cleanup'
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed'
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    records_processed BIGINT DEFAULT 0,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analytics_aggregation_jobs_type_status 
    ON analytics_aggregation_jobs(job_type, status);
CREATE INDEX IF NOT EXISTS idx_analytics_aggregation_jobs_created 
    ON analytics_aggregation_jobs(created_at);

-- Create real-time metrics snapshot table (for fast dashboard queries)
CREATE TABLE IF NOT EXISTS analytics_realtime_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    snapshot_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active_sessions BIGINT DEFAULT 0,
    logins_last_minute BIGINT DEFAULT 0,
    logins_last_5_minutes BIGINT DEFAULT 0,
    logins_last_hour BIGINT DEFAULT 0,
    current_auth_rate FLOAT DEFAULT 0,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_analytics_realtime_snapshots_tenant_time 
    ON analytics_realtime_snapshots(tenant_id, snapshot_time);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_analytics_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to stats tables
DROP TRIGGER IF EXISTS trigger_analytics_daily_stats_updated ON analytics_daily_stats;
CREATE TRIGGER trigger_analytics_daily_stats_updated
    BEFORE UPDATE ON analytics_daily_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_analytics_updated_at();

DROP TRIGGER IF EXISTS trigger_analytics_hourly_stats_updated ON analytics_hourly_stats;
CREATE TRIGGER trigger_analytics_hourly_stats_updated
    BEFORE UPDATE ON analytics_hourly_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_analytics_updated_at();

DROP TRIGGER IF EXISTS trigger_analytics_weekly_stats_updated ON analytics_weekly_stats;
CREATE TRIGGER trigger_analytics_weekly_stats_updated
    BEFORE UPDATE ON analytics_weekly_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_analytics_updated_at();

DROP TRIGGER IF EXISTS trigger_analytics_monthly_stats_updated ON analytics_monthly_stats;
CREATE TRIGGER trigger_analytics_monthly_stats_updated
    BEFORE UPDATE ON analytics_monthly_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_analytics_updated_at();

-- Create function to aggregate daily stats from events
CREATE OR REPLACE FUNCTION aggregate_daily_stats(
    p_date DATE,
    p_tenant_id UUID DEFAULT NULL
)
RETURNS TABLE (
    metric_name VARCHAR(100),
    metric_value BIGINT
) AS $$
BEGIN
    -- Login metrics
    RETURN QUERY
    SELECT 
        'login_total'::VARCHAR(100) as metric_name,
        COUNT(*)::BIGINT as metric_value
    FROM analytics_events
    WHERE event_type = 'login'
      AND DATE(created_at) = p_date
      AND (p_tenant_id IS NULL OR tenant_id = p_tenant_id)
    
    UNION ALL
    
    SELECT 
        'login_success'::VARCHAR(100) as metric_name,
        COUNT(*)::BIGINT as metric_value
    FROM analytics_events
    WHERE event_type = 'login'
      AND DATE(created_at) = p_date
      AND (metadata->>'success')::boolean = true
      AND (p_tenant_id IS NULL OR tenant_id = p_tenant_id)
    
    UNION ALL
    
    SELECT 
        'login_failed'::VARCHAR(100) as metric_name,
        COUNT(*)::BIGINT as metric_value
    FROM analytics_events
    WHERE event_type = 'login'
      AND DATE(created_at) = p_date
      AND (metadata->>'success')::boolean = false
      AND (p_tenant_id IS NULL OR tenant_id = p_tenant_id);

    -- Signup metrics
    RETURN QUERY
    SELECT 
        'signup_total'::VARCHAR(100) as metric_name,
        COUNT(*)::BIGINT as metric_value
    FROM analytics_events
    WHERE event_type = 'signup'
      AND DATE(created_at) = p_date
      AND (p_tenant_id IS NULL OR tenant_id = p_tenant_id);

    -- MFA metrics
    RETURN QUERY
    SELECT 
        'mfa_attempt'::VARCHAR(100) as metric_name,
        COUNT(*)::BIGINT as metric_value
    FROM analytics_events
    WHERE event_type = 'mfa'
      AND DATE(created_at) = p_date
      AND (p_tenant_id IS NULL OR tenant_id = p_tenant_id)
    
    UNION ALL
    
    SELECT 
        'mfa_success'::VARCHAR(100) as metric_name,
        COUNT(*)::BIGINT as metric_value
    FROM analytics_events
    WHERE event_type = 'mfa'
      AND DATE(created_at) = p_date
      AND (metadata->>'success')::boolean = true
      AND (p_tenant_id IS NULL OR tenant_id = p_tenant_id);

    -- Session metrics
    RETURN QUERY
    SELECT 
        'session_created'::VARCHAR(100) as metric_name,
        COUNT(*)::BIGINT as metric_value
    FROM analytics_events
    WHERE event_type = 'session'
      AND DATE(created_at) = p_date
      AND (metadata->>'event_type')::text = 'created'
      AND (p_tenant_id IS NULL OR tenant_id = p_tenant_id);

    -- Active users count
    RETURN QUERY
    SELECT 
        'active_users'::VARCHAR(100) as metric_name,
        COUNT(DISTINCT user_id)::BIGINT as metric_value
    FROM analytics_events
    WHERE event_type = 'login'
      AND DATE(created_at) = p_date
      AND (p_tenant_id IS NULL OR tenant_id = p_tenant_id);
END;
$$ LANGUAGE plpgsql;

-- Create function to upsert daily stats
CREATE OR REPLACE FUNCTION upsert_daily_stats(
    p_tenant_id UUID,
    p_date DATE,
    p_metric_name VARCHAR(100),
    p_metric_value BIGINT,
    p_metadata JSONB DEFAULT '{}'
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO analytics_daily_stats (
        tenant_id, date, metric_name, metric_value, metadata
    ) VALUES (
        p_tenant_id, p_date, p_metric_name, p_metric_value, p_metadata
    )
    ON CONFLICT (tenant_id, date, metric_name)
    DO UPDATE SET
        metric_value = analytics_daily_stats.metric_value + EXCLUDED.metric_value,
        metadata = analytics_daily_stats.metadata || EXCLUDED.metadata,
        updated_at = NOW();
END;
$$ LANGUAGE plpgsql;

-- Create function to cleanup old analytics data
CREATE OR REPLACE FUNCTION cleanup_old_analytics_data(
    p_raw_retention_days INTEGER DEFAULT 30,
    p_stats_retention_days INTEGER DEFAULT 365
)
RETURNS TABLE (
    deleted_raw_events BIGINT,
    deleted_hourly_stats BIGINT,
    deleted_snapshots BIGINT
) AS $$
DECLARE
    v_deleted_raw BIGINT;
    v_deleted_hourly BIGINT;
    v_deleted_snapshots BIGINT;
BEGIN
    -- Delete old raw events
    DELETE FROM analytics_events
    WHERE created_at < NOW() - INTERVAL '1 day' * p_raw_retention_days;
    GET DIAGNOSTICS v_deleted_raw = ROW_COUNT;

    -- Delete old hourly stats
    DELETE FROM analytics_hourly_stats
    WHERE hour < NOW() - INTERVAL '1 day' * p_raw_retention_days;
    GET DIAGNOSTICS v_deleted_hourly = ROW_COUNT;

    -- Delete old realtime snapshots (keep only last 24 hours)
    DELETE FROM analytics_realtime_snapshots
    WHERE snapshot_time < NOW() - INTERVAL '24 hours';
    GET DIAGNOSTICS v_deleted_snapshots = ROW_COUNT;

    RETURN QUERY SELECT v_deleted_raw, v_deleted_hourly, v_deleted_snapshots;
END;
$$ LANGUAGE plpgsql;

-- Create view for dashboard summary
CREATE OR REPLACE VIEW analytics_dashboard_summary AS
SELECT 
    tenant_id,
    date,
    SUM(CASE WHEN metric_name = 'login_total' THEN metric_value ELSE 0 END) as total_logins,
    SUM(CASE WHEN metric_name = 'login_success' THEN metric_value ELSE 0 END) as successful_logins,
    SUM(CASE WHEN metric_name = 'login_failed' THEN metric_value ELSE 0 END) as failed_logins,
    SUM(CASE WHEN metric_name = 'signup_total' THEN metric_value ELSE 0 END) as new_signups,
    SUM(CASE WHEN metric_name = 'active_users' THEN metric_value ELSE 0 END) as active_users
FROM analytics_daily_stats
GROUP BY tenant_id, date
ORDER BY tenant_id, date DESC;

-- Create view for login trends
CREATE OR REPLACE VIEW analytics_login_trends AS
SELECT 
    tenant_id,
    date_trunc('week', date) as week,
    SUM(CASE WHEN metric_name = 'login_total' THEN metric_value ELSE 0 END) as total_logins,
    SUM(CASE WHEN metric_name = 'login_success' THEN metric_value ELSE 0 END) as successful_logins,
    SUM(CASE WHEN metric_name = 'login_failed' THEN metric_value ELSE 0 END) as failed_logins,
    ROUND(
        100.0 * SUM(CASE WHEN metric_name = 'login_success' THEN metric_value ELSE 0 END) / 
        NULLIF(SUM(CASE WHEN metric_name = 'login_total' THEN metric_value ELSE 0 END), 0),
        2
    ) as success_rate_percent
FROM analytics_daily_stats
WHERE metric_name LIKE 'login_%'
GROUP BY tenant_id, date_trunc('week', date)
ORDER BY tenant_id, week DESC;

-- Create RLS policies
ALTER TABLE analytics_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics_daily_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics_hourly_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics_weekly_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics_monthly_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics_realtime_snapshots ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view analytics for their tenant
DROP POLICY IF EXISTS analytics_events_select_tenant ON analytics_events;
CREATE POLICY analytics_events_select_tenant ON analytics_events
    FOR SELECT
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));

DROP POLICY IF EXISTS analytics_daily_stats_select_tenant ON analytics_daily_stats;
CREATE POLICY analytics_daily_stats_select_tenant ON analytics_daily_stats
    FOR SELECT
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));

DROP POLICY IF EXISTS analytics_hourly_stats_select_tenant ON analytics_hourly_stats;
CREATE POLICY analytics_hourly_stats_select_tenant ON analytics_hourly_stats
    FOR SELECT
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Policy: Admins can insert analytics events
DROP POLICY IF EXISTS analytics_events_insert_service ON analytics_events;
CREATE POLICY analytics_events_insert_service ON analytics_events
    FOR INSERT
    WITH CHECK (
        current_setting('app.current_user_role', true) IN ('service', 'admin', 'owner', 'superadmin')
    );

-- Policy: Superadmins can view all analytics
DROP POLICY IF EXISTS analytics_events_superadmin ON analytics_events;
CREATE POLICY analytics_events_superadmin ON analytics_events
    FOR ALL
    TO PUBLIC
    USING (current_setting('app.current_user_role', true) = 'superadmin');

-- Grant permissions
GRANT SELECT, INSERT ON analytics_events TO vault_app;
GRANT SELECT, INSERT, UPDATE ON analytics_daily_stats TO vault_app;
GRANT SELECT, INSERT, UPDATE ON analytics_hourly_stats TO vault_app;
GRANT SELECT, INSERT, UPDATE ON analytics_weekly_stats TO vault_app;
GRANT SELECT, INSERT, UPDATE ON analytics_monthly_stats TO vault_app;
GRANT SELECT, INSERT ON analytics_realtime_snapshots TO vault_app;
GRANT SELECT, INSERT, UPDATE ON analytics_aggregation_jobs TO vault_app;
GRANT EXECUTE ON FUNCTION aggregate_daily_stats(DATE, UUID) TO vault_app;
GRANT EXECUTE ON FUNCTION upsert_daily_stats(UUID, DATE, VARCHAR, BIGINT, JSONB) TO vault_app;
GRANT EXECUTE ON FUNCTION cleanup_old_analytics_data(INTEGER, INTEGER) TO vault_app;
GRANT SELECT ON analytics_dashboard_summary TO vault_app;
GRANT SELECT ON analytics_login_trends TO vault_app;

-- Add comments
COMMENT ON TABLE analytics_events IS 'Raw analytics events partitioned by date for efficient querying and archival';
COMMENT ON TABLE analytics_daily_stats IS 'Pre-aggregated daily statistics for fast dashboard queries';
COMMENT ON TABLE analytics_hourly_stats IS 'Pre-aggregated hourly statistics for real-time analytics';
COMMENT ON TABLE analytics_weekly_stats IS 'Weekly rollup of daily statistics';
COMMENT ON TABLE analytics_monthly_stats IS 'Monthly rollup of daily statistics';
COMMENT ON TABLE analytics_aggregation_jobs IS 'Tracking table for background aggregation jobs';
COMMENT ON TABLE analytics_realtime_snapshots IS 'Cached real-time metrics for dashboard performance';
COMMENT ON FUNCTION aggregate_daily_stats IS 'Aggregates raw events into daily statistics';
COMMENT ON FUNCTION cleanup_old_analytics_data IS 'Removes old analytics data based on retention policy';
