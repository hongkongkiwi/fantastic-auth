-- Webhook system tables
-- Stores webhook endpoints and delivery attempts

-- Webhook endpoints table
CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL, -- For HMAC signature
    events JSONB NOT NULL DEFAULT '[]', -- Array of event types to subscribe to
    active BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT,
    headers JSONB DEFAULT '{}', -- Custom headers to include
    max_retries INTEGER NOT NULL DEFAULT 3,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Webhook delivery attempts table
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(255) NOT NULL,
    payload JSONB NOT NULL,
    payload_size INTEGER NOT NULL,
    attempt_number INTEGER NOT NULL DEFAULT 1,
    status VARCHAR(50) NOT NULL, -- pending, delivered, failed
    http_status_code INTEGER,
    response_body TEXT,
    response_headers JSONB,
    error_message TEXT,
    duration_ms INTEGER,
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_webhook_endpoints_tenant ON webhook_endpoints(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_webhook_endpoints_active ON webhook_endpoints(tenant_id, active) WHERE deleted_at IS NULL;
CREATE INDEX idx_webhook_deliveries_endpoint ON webhook_deliveries(endpoint_id);
CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries(status) WHERE status = 'pending';
CREATE INDEX idx_webhook_deliveries_scheduled ON webhook_deliveries(scheduled_at) WHERE status = 'pending';
CREATE INDEX idx_webhook_deliveries_tenant ON webhook_deliveries(tenant_id, created_at DESC);

-- Enable RLS
ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;

-- RLS policies for webhook_endpoints
CREATE POLICY tenant_isolation_webhook_endpoints ON webhook_endpoints
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- RLS policies for webhook_deliveries
CREATE POLICY tenant_isolation_webhook_deliveries ON webhook_deliveries
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Function to update updated_at
CREATE TRIGGER update_webhook_endpoints_updated_at BEFORE UPDATE ON webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments
COMMENT ON TABLE webhook_endpoints IS 'Webhook endpoints configured by tenants';
COMMENT ON TABLE webhook_deliveries IS 'Webhook delivery attempts and their status';
COMMENT ON COLUMN webhook_endpoints.secret IS 'HMAC secret for signing webhook payloads';
COMMENT ON COLUMN webhook_endpoints.events IS 'JSON array of event type strings (e.g., ["user.created", "user.updated"])';
