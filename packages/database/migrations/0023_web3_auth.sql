-- Web3 Authentication (Sign-In with Ethereum) Migration
-- Adds wallet address support to users table

-- ============================================
-- Update Users Table
-- ============================================

-- Add wallet address column to users table
ALTER TABLE users 
    ADD COLUMN IF NOT EXISTS wallet_address VARCHAR(42),
    ADD COLUMN IF NOT EXISTS chain_id INTEGER,
    ADD COLUMN IF NOT EXISTS wallet_verified_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS wallet_verification_method VARCHAR(50);

-- Add comments for new columns
COMMENT ON COLUMN users.wallet_address IS 'Ethereum or Solana wallet address (normalized lowercase)';
COMMENT ON COLUMN users.chain_id IS 'Chain ID for EVM chains (1=Ethereum, 137=Polygon, etc.)';
COMMENT ON COLUMN users.wallet_verified_at IS 'When the wallet was last verified';
COMMENT ON COLUMN users.wallet_verification_method IS 'Method used for wallet verification (siwe, signature, etc.)';

-- Create unique index for wallet addresses per tenant
-- This ensures a wallet can only be linked to one user per tenant
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_wallet 
    ON users(tenant_id, wallet_address) 
    WHERE wallet_address IS NOT NULL AND deleted_at IS NULL;

-- Create index for chain ID lookups
CREATE INDEX IF NOT EXISTS idx_users_chain_id 
    ON users(chain_id) 
    WHERE wallet_address IS NOT NULL;

-- ============================================
-- Wallet Nonce Storage Table (for non-Redis deployments)
-- ============================================

CREATE TABLE IF NOT EXISTS wallet_nonces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nonce VARCHAR(32) NOT NULL UNIQUE,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    chain_id INTEGER,
    client_ip INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ
);

-- Indexes for efficient cleanup and lookups
CREATE INDEX IF NOT EXISTS idx_wallet_nonces_nonce ON wallet_nonces(nonce);
CREATE INDEX IF NOT EXISTS idx_wallet_nonces_expires ON wallet_nonces(expires_at) WHERE NOT used;
CREATE INDEX IF NOT EXISTS idx_wallet_nonces_tenant ON wallet_nonces(tenant_id);

-- Add comment
COMMENT ON TABLE wallet_nonces IS 'Temporary storage for SIWE nonces when Redis is not available';

-- ============================================
-- Web3 Login Sessions (for replay protection)
-- ============================================

CREATE TABLE IF NOT EXISTS web3_login_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    wallet_address VARCHAR(42) NOT NULL,
    chain_id INTEGER NOT NULL,
    signature_hash VARCHAR(64) NOT NULL UNIQUE,
    message_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    ip_address INET,
    user_agent TEXT,
    used BOOLEAN NOT NULL DEFAULT FALSE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_web3_sessions_signature ON web3_login_sessions(signature_hash);
CREATE INDEX IF NOT EXISTS idx_web3_sessions_wallet ON web3_login_sessions(wallet_address);
CREATE INDEX IF NOT EXISTS idx_web3_sessions_expires ON web3_login_sessions(expires_at) WHERE NOT used;

-- Add comment
COMMENT ON TABLE web3_login_sessions IS 'Tracks used SIWE signatures to prevent replay attacks';

-- ============================================
-- NFT Access Control (optional feature)
-- ============================================

CREATE TABLE IF NOT EXISTS nft_access_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    chain_id INTEGER NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    min_balance INTEGER NOT NULL DEFAULT 1,
    role_assignment VARCHAR(100),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(tenant_id, contract_address)
);

-- Add comment
COMMENT ON TABLE nft_access_policies IS 'NFT-based access control policies for automatic role assignment';

-- Trigger for updated_at
DROP TRIGGER IF EXISTS update_nft_access_policies_updated_at ON nft_access_policies;
CREATE TRIGGER update_nft_access_policies_updated_at
    BEFORE UPDATE ON nft_access_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- User NFT Holdings (cached)
-- ============================================

CREATE TABLE IF NOT EXISTS user_nft_holdings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    chain_id INTEGER NOT NULL,
    contract_address VARCHAR(42) NOT NULL,
    token_count INTEGER NOT NULL DEFAULT 0,
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(user_id, contract_address)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_user_nfts_user ON user_nft_holdings(user_id);
CREATE INDEX IF NOT EXISTS idx_user_nfts_contract ON user_nft_holdings(contract_address);
CREATE INDEX IF NOT EXISTS idx_user_nfts_verified ON user_nft_holdings(last_verified_at);

-- Trigger for updated_at
DROP TRIGGER IF EXISTS update_user_nft_holdings_updated_at ON user_nft_holdings;
CREATE TRIGGER update_user_nft_holdings_updated_at
    BEFORE UPDATE ON user_nft_holdings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add comment
COMMENT ON TABLE user_nft_holdings IS 'Cached NFT holdings for users (refreshed periodically)';

-- ============================================
-- RLS Policies
-- ============================================

-- Enable RLS
ALTER TABLE wallet_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE web3_login_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE nft_access_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_nft_holdings ENABLE ROW LEVEL SECURITY;

-- Wallet nonces policies
DROP POLICY IF EXISTS wallet_nonces_tenant_isolation ON wallet_nonces;
CREATE POLICY wallet_nonces_tenant_isolation ON wallet_nonces
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- Web3 sessions policies
DROP POLICY IF EXISTS web3_sessions_tenant_isolation ON web3_login_sessions;
CREATE POLICY web3_sessions_tenant_isolation ON web3_login_sessions
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- NFT access policies (readable by all tenants, managed by admins)
DROP POLICY IF EXISTS nft_policies_tenant_isolation ON nft_access_policies;
CREATE POLICY nft_policies_tenant_isolation ON nft_access_policies
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- User NFT holdings policies
DROP POLICY IF EXISTS user_nfts_tenant_isolation ON user_nft_holdings;
CREATE POLICY user_nfts_tenant_isolation ON user_nft_holdings
    FOR ALL
    TO vault_app
    USING (tenant_id = current_tenant_id());

-- ============================================
-- Permissions
-- ============================================

GRANT SELECT, INSERT, UPDATE, DELETE ON wallet_nonces TO vault_app;
GRANT SELECT, INSERT ON web3_login_sessions TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON nft_access_policies TO vault_app;
GRANT SELECT, INSERT, UPDATE ON user_nft_holdings TO vault_app;

-- ============================================
-- Cleanup Function
-- ============================================

CREATE OR REPLACE FUNCTION cleanup_expired_web3_data()
RETURNS TABLE (
    deleted_nonces BIGINT,
    deleted_sessions BIGINT
) AS $$
DECLARE
    v_deleted_nonces BIGINT;
    v_deleted_sessions BIGINT;
BEGIN
    -- Delete expired nonces
    DELETE FROM wallet_nonces
    WHERE expires_at < NOW() - INTERVAL '1 hour';
    GET DIAGNOSTICS v_deleted_nonces = ROW_COUNT;

    -- Delete expired sessions
    DELETE FROM web3_login_sessions
    WHERE expires_at < NOW() - INTERVAL '1 day';
    GET DIAGNOSTICS v_deleted_sessions = ROW_COUNT;

    RETURN QUERY SELECT v_deleted_nonces, v_deleted_sessions;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_web3_data IS 'Removes expired nonce and session records';

GRANT EXECUTE ON FUNCTION cleanup_expired_web3_data() TO vault_app;
