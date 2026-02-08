-- Per-tenant data encryption keys (DEKs) with provider metadata

-- Provider enum for envelope encryption
CREATE TYPE kms_provider AS ENUM ('local', 'aws_kms', 'azure_kv');

CREATE TABLE IF NOT EXISTS tenant_data_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider kms_provider NOT NULL DEFAULT 'local',
    provider_key_id TEXT,
    provider_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    encrypted_dek TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenant_data_keys_active
    ON tenant_data_keys(tenant_id, is_active);
CREATE INDEX IF NOT EXISTS idx_tenant_data_keys_version
    ON tenant_data_keys(tenant_id, version DESC);

ALTER TABLE tenant_data_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenant_data_keys ON tenant_data_keys
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

COMMENT ON TABLE tenant_data_keys IS 'Per-tenant data encryption keys (DEKs) wrapped by KMS or local master key';
COMMENT ON COLUMN tenant_data_keys.encrypted_dek IS 'Base64 of provider-wrapped DEK';
COMMENT ON COLUMN tenant_data_keys.provider_metadata IS 'Provider-specific JSON metadata (encryption context, key ARN, etc.)';
