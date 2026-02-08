-- Account linking migration
-- Enables users to link multiple authentication methods to a single account

-- ============================================
-- Linked Accounts Table
-- ============================================

CREATE TABLE user_linked_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- google, github, microsoft, apple, email, phone, webauthn
    provider_account_id VARCHAR(255) NOT NULL, -- email address or provider user ID
    provider_data JSONB NOT NULL DEFAULT '{}', -- extra data from provider (name, picture, etc.)
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE, -- primary authentication method
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Ensure unique provider account per tenant
    UNIQUE(tenant_id, provider, provider_account_id),
    -- Ensure only one primary per user
    UNIQUE(tenant_id, user_id, provider, is_primary) WHERE is_primary = TRUE
);

-- ============================================
-- Indexes
-- ============================================

CREATE INDEX idx_linked_accounts_user ON user_linked_accounts(tenant_id, user_id);
CREATE INDEX idx_linked_accounts_provider ON user_linked_accounts(tenant_id, provider);
CREATE INDEX idx_linked_accounts_lookup ON user_linked_accounts(tenant_id, provider, provider_account_id);

-- ============================================
-- Row-Level Security (RLS)
-- ============================================

ALTER TABLE user_linked_accounts ENABLE ROW LEVEL SECURITY;

-- Tenant isolation policy
CREATE POLICY tenant_isolation_linked_accounts ON user_linked_accounts
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Users can only see their own linked accounts (unless admin)
CREATE POLICY own_linked_accounts ON user_linked_accounts
    FOR SELECT
    TO vault_app
    USING (
        tenant_id = current_tenant_id() AND 
        (user_id = current_setting('app.current_user_id', TRUE)::UUID OR is_admin())
    );

-- ============================================
-- Audit Log Actions for Account Linking
-- ============================================

COMMENT ON TABLE user_linked_accounts IS 'Linked authentication methods for users (OAuth, email, phone, etc.)';
COMMENT ON COLUMN user_linked_accounts.provider IS 'Authentication provider: google, github, microsoft, apple, email, phone, webauthn';
COMMENT ON COLUMN user_linked_accounts.provider_account_id IS 'Unique identifier from provider (email or provider user ID)';
COMMENT ON COLUMN user_linked_accounts.is_primary IS 'Whether this is the primary authentication method for the user';
