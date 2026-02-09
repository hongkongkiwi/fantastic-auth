-- Zero-Knowledge Architecture Tables
-- Enables true zero-knowledge encryption where server cannot read user data

-- Zero-knowledge user keys
CREATE TABLE IF NOT EXISTS zk_user_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    salt BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    encrypted_private_key BYTEA NOT NULL,
    zk_commitment BYTEA NOT NULL,
    recovery_shares_hash BYTEA,
    protocol_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    rotated_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id)
);

-- Encrypted user profiles (server cannot read)
CREATE TABLE IF NOT EXISTS zk_encrypted_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_data BYTEA NOT NULL,
    data_nonce BYTEA NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    data_version INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id)
);

-- Recovery shares (stored by guardians)
CREATE TABLE IF NOT EXISTS zk_recovery_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    guardian_id UUID REFERENCES users(id) ON DELETE SET NULL,
    share_index INTEGER NOT NULL,
    share_hash BYTEA NOT NULL,
    encrypted_share BYTEA, -- Optional: encrypted share for server-side backup
    threshold INTEGER NOT NULL,
    total_shares INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'used', 'revoked')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, share_index)
);

-- Recovery sessions for tracking recovery attempts
CREATE TABLE IF NOT EXISTS zk_recovery_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash BYTEA NOT NULL,
    threshold INTEGER NOT NULL,
    shares_collected INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'collecting' CHECK (status IN ('collecting', 'ready', 'completed', 'expired', 'failed')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Encrypted data types (for different kinds of user data)
CREATE TABLE IF NOT EXISTS zk_encrypted_data (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data_type VARCHAR(50) NOT NULL, -- 'profile', 'preferences', 'settings', etc.
    encrypted_data BYTEA NOT NULL,
    data_nonce BYTEA NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, data_type)
);

-- ZK proof challenges (for replay protection)
CREATE TABLE IF NOT EXISTS zk_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge BYTEA NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Key rotation history
CREATE TABLE IF NOT EXISTS zk_key_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    old_public_key_hash BYTEA NOT NULL,
    new_public_key_hash BYTEA NOT NULL,
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    reason VARCHAR(100)
);

-- Indexes for performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_zk_user_keys_user_id ON zk_user_keys(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_zk_encrypted_profiles_user_id ON zk_encrypted_profiles(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_zk_recovery_shares_user_id ON zk_recovery_shares(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_zk_recovery_shares_guardian_id ON zk_recovery_shares(guardian_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_zk_recovery_sessions_user_id ON zk_recovery_sessions(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_zk_challenges_user_id ON zk_challenges(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_zk_challenges_expires ON zk_challenges(expires_at) WHERE NOT used;

-- Row Level Security Policies

-- zk_user_keys: Users can only see their own keys
ALTER TABLE zk_user_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY zk_user_keys_user_isolation ON zk_user_keys
    FOR ALL
    USING (user_id = current_setting('app.current_user_id')::UUID);

-- zk_encrypted_profiles: Users can only see their own encrypted data
ALTER TABLE zk_encrypted_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY zk_encrypted_profiles_user_isolation ON zk_encrypted_profiles
    FOR ALL
    USING (user_id = current_setting('app.current_user_id')::UUID);

-- zk_recovery_shares: Users can see shares they own or are guardian of
ALTER TABLE zk_recovery_shares ENABLE ROW LEVEL SECURITY;

CREATE POLICY zk_recovery_shares_owner ON zk_recovery_shares
    FOR ALL
    USING (
        user_id = current_setting('app.current_user_id')::UUID
        OR guardian_id = current_setting('app.current_user_id')::UUID
    );

-- zk_recovery_sessions: Users can only see their own sessions
ALTER TABLE zk_recovery_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY zk_recovery_sessions_user_isolation ON zk_recovery_sessions
    FOR ALL
    USING (user_id = current_setting('app.current_user_id')::UUID);

-- zk_encrypted_data: Users can only see their own encrypted data
ALTER TABLE zk_encrypted_data ENABLE ROW LEVEL SECURITY;

CREATE POLICY zk_encrypted_data_user_isolation ON zk_encrypted_data
    FOR ALL
    USING (user_id = current_setting('app.current_user_id')::UUID);

-- Comments explaining the zero-knowledge architecture
COMMENT ON TABLE zk_user_keys IS 'Zero-knowledge user encryption keys. Server stores encrypted private key but cannot decrypt it.';
COMMENT ON TABLE zk_encrypted_profiles IS 'User profile data encrypted with AES-256-GCM. Server cannot read plaintext.';
COMMENT ON TABLE zk_recovery_shares IS 'Shamir secret sharing recovery shares. Hash stored for verification, actual shares held by guardians.';
COMMENT ON TABLE zk_recovery_sessions IS 'Active recovery sessions for account recovery without server knowledge.';
COMMENT ON TABLE zk_encrypted_data IS 'Generic encrypted user data storage by type.';
COMMENT ON TABLE zk_challenges IS 'ZK proof challenges for replay protection.';
