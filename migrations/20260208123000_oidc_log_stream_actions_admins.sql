-- OIDC IdP, Log Streaming, Actions, Tenant Admins

-- =============================
-- Tenant Admins
-- =============================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tenant_admin_role') THEN
        CREATE TYPE tenant_admin_role AS ENUM ('owner', 'admin', 'support', 'viewer');
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tenant_admin_status') THEN
        CREATE TYPE tenant_admin_status AS ENUM ('active', 'suspended');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS tenant_admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role tenant_admin_role NOT NULL DEFAULT 'admin',
    status tenant_admin_status NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS tenant_admin_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role tenant_admin_role NOT NULL DEFAULT 'admin',
    token_hash TEXT NOT NULL,
    invited_by UUID REFERENCES users(id),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_tenant_admins_tenant ON tenant_admins(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_admins_user ON tenant_admins(user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_admin_invites_tenant ON tenant_admin_invitations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_admin_invites_email ON tenant_admin_invitations(email);

ALTER TABLE tenant_admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_admin_invitations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_admins_isolation ON tenant_admins;
CREATE POLICY tenant_admins_isolation ON tenant_admins
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS tenant_admin_invites_isolation ON tenant_admin_invitations;
CREATE POLICY tenant_admin_invites_isolation ON tenant_admin_invitations
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- =============================
-- OIDC IdP
-- =============================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'oauth_client_type') THEN
        CREATE TYPE oauth_client_type AS ENUM ('public', 'confidential');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    client_secret_hash TEXT,
    name VARCHAR(255) NOT NULL,
    client_type oauth_client_type NOT NULL DEFAULT 'confidential',
    redirect_uris JSONB NOT NULL DEFAULT '[]',
    allowed_scopes JSONB NOT NULL DEFAULT '["openid","profile","email"]',
    pkce_required BOOLEAN NOT NULL DEFAULT true,
    token_endpoint_auth_method VARCHAR(50) NOT NULL DEFAULT 'client_secret_basic',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, client_id)
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT,
    code_challenge_method VARCHAR(10),
    nonce TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    access_token_jti VARCHAR(255) NOT NULL,
    refresh_token_hash TEXT,
    scope TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_tenant ON oauth_clients(tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_client ON oauth_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_client ON oauth_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_access_jti ON oauth_tokens(access_token_jti);

ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS oauth_clients_isolation ON oauth_clients;
CREATE POLICY oauth_clients_isolation ON oauth_clients
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS oauth_codes_isolation ON oauth_authorization_codes;
CREATE POLICY oauth_codes_isolation ON oauth_authorization_codes
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS oauth_tokens_isolation ON oauth_tokens;
CREATE POLICY oauth_tokens_isolation ON oauth_tokens
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- =============================
-- Log Streaming
-- =============================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'log_stream_type') THEN
        CREATE TYPE log_stream_type AS ENUM ('http', 'kafka');
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'log_stream_status') THEN
        CREATE TYPE log_stream_status AS ENUM ('active', 'paused');
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'log_delivery_status') THEN
        CREATE TYPE log_delivery_status AS ENUM ('pending', 'delivered', 'failed');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS log_streams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    destination_type log_stream_type NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    filter JSONB NOT NULL DEFAULT '{}',
    status log_stream_status NOT NULL DEFAULT 'active',
    last_delivered_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS log_stream_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stream_id UUID NOT NULL REFERENCES log_streams(id) ON DELETE CASCADE,
    audit_log_id UUID NOT NULL REFERENCES audit_logs(id) ON DELETE CASCADE,
    status log_delivery_status NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_log_streams_tenant ON log_streams(tenant_id);
CREATE INDEX IF NOT EXISTS idx_log_streams_status ON log_streams(status);
CREATE INDEX IF NOT EXISTS idx_log_deliveries_stream ON log_stream_deliveries(stream_id);
CREATE INDEX IF NOT EXISTS idx_log_deliveries_status ON log_stream_deliveries(status);

ALTER TABLE log_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_stream_deliveries ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS log_streams_isolation ON log_streams;
CREATE POLICY log_streams_isolation ON log_streams
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS log_stream_deliveries_isolation ON log_stream_deliveries;
CREATE POLICY log_stream_deliveries_isolation ON log_stream_deliveries
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- =============================
-- Actions / Rules
-- =============================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_trigger') THEN
        CREATE TYPE action_trigger AS ENUM ('pre_login', 'post_login', 'pre_register', 'post_register', 'token_issue');
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_status') THEN
        CREATE TYPE action_status AS ENUM ('enabled', 'disabled');
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'action_execution_status') THEN
        CREATE TYPE action_execution_status AS ENUM ('success', 'failed', 'timeout');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    trigger action_trigger NOT NULL,
    status action_status NOT NULL DEFAULT 'enabled',
    runtime VARCHAR(20) NOT NULL DEFAULT 'wasm',
    code BYTEA NOT NULL,
    timeout_ms INTEGER NOT NULL DEFAULT 1000,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS action_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    status action_execution_status NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    error TEXT,
    output JSONB
);

CREATE INDEX IF NOT EXISTS idx_actions_tenant ON actions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_actions_trigger ON actions(trigger);
CREATE INDEX IF NOT EXISTS idx_action_execs_tenant ON action_executions(tenant_id);

ALTER TABLE actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_executions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS actions_isolation ON actions;
CREATE POLICY actions_isolation ON actions
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS action_execs_isolation ON action_executions;
CREATE POLICY action_execs_isolation ON action_executions
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());
