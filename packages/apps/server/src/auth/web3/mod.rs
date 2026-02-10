//! Web3 Authentication module
//!
//! Implements Sign-In with Ethereum (SIWE) and multi-chain Web3 authentication.
//!
//! Features:
//! - EIP-4361 compliant SIWE message handling
//! - Multi-chain support (Ethereum, Polygon, Arbitrum, Optimism, Base, Solana)
//! - Signature verification (ECDSA for EVM, Ed25519 for Solana)
//! - Nonce management with Redis/memory storage
//! - Domain binding and replay attack prevention
//! - NFT-based access control (optional)

pub mod signature;
pub mod siwe;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use tracing::info;

pub use siwe::{ChainType, SiweError, SiweMessage};
use signature::{verify_signature, SignatureError};

/// Errors that can occur during Web3 authentication
#[derive(Debug, Error)]
pub enum Web3AuthError {
    #[error("SIWE error: {0}")]
    SiweError(#[from] SiweError),
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),
    #[error("Nonce expired or not found")]
    NonceExpired,
    #[error("Nonce already used")]
    NonceAlreadyUsed,
    #[error("Domain mismatch: expected {expected}, got {actual}")]
    DomainMismatch { expected: String, actual: String },
    #[error("Chain ID not supported: {0}")]
    UnsupportedChain(u64),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Rate limit exceeded")]
    RateLimited,
    #[error("User not found")]
    UserNotFound,
    #[error("Wallet already linked to another account")]
    WalletAlreadyLinked,
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

/// Web3 authentication service
pub struct Web3Auth {
    /// Domain for SIWE messages (e.g., "vault.example.com")
    domain: String,
    /// Base URI for the application
    uri: String,
    /// Supported chain IDs
    supported_chains: Vec<u64>,
    /// Nonce storage backend
    nonce_store: Box<dyn NonceStore>,
    /// Request storage for tracking used signatures (replay protection)
    request_store: Option<Box<dyn RequestStore>>,
    /// NFT verification service (optional)
    nft_verifier: Option<Arc<dyn NftVerifier>>,
    /// Configuration
    config: Web3AuthConfig,
}

/// Web3 authentication configuration
#[derive(Debug, Clone)]
pub struct Web3AuthConfig {
    /// How long nonces are valid (in minutes)
    pub nonce_ttl_minutes: i64,
    /// How long SIWE messages are valid (in minutes)
    pub message_ttl_minutes: i64,
    /// Maximum number of nonce requests per IP per hour
    pub rate_limit_per_hour: u32,
    /// Whether to enforce domain binding
    pub enforce_domain_binding: bool,
    /// Whether to enable NFT-based access control
    pub enable_nft_access_control: bool,
    /// Required NFT contracts for access (optional)
    pub required_nft_contracts: Vec<String>,
}

impl Default for Web3AuthConfig {
    fn default() -> Self {
        Self {
            nonce_ttl_minutes: 5,
            message_ttl_minutes: 5,
            rate_limit_per_hour: 60,
            enforce_domain_binding: true,
            enable_nft_access_control: false,
            required_nft_contracts: Vec::new(),
        }
    }
}

/// Nonce data stored for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceData {
    /// The nonce value
    pub nonce: String,
    /// When the nonce was created
    pub created_at: DateTime<Utc>,
    /// When the nonce expires
    pub expires_at: DateTime<Utc>,
    /// IP address that requested the nonce
    pub client_ip: Option<String>,
    /// Chain ID requested
    pub chain_id: Option<u64>,
    /// Whether this nonce has been used
    pub used: bool,
}

/// Storage backend for nonces
#[async_trait::async_trait]
pub trait NonceStore: Send + Sync {
    /// Store a nonce
    async fn store_nonce(&self, data: NonceData) -> Result<(), Web3AuthError>;

    /// Get and mark nonce as used (atomic operation)
    async fn consume_nonce(&self, nonce: &str) -> Result<Option<NonceData>, Web3AuthError>;

    /// Check if nonce exists without consuming it
    async fn get_nonce(&self, nonce: &str) -> Result<Option<NonceData>, Web3AuthError>;

    /// Delete a nonce
    async fn delete_nonce(&self, nonce: &str) -> Result<(), Web3AuthError>;
}

/// Storage backend for tracking used signatures (replay protection)
#[async_trait::async_trait]
pub trait RequestStore: Send + Sync {
    /// Store a used signature hash
    async fn store_signature(&self, signature_hash: &str, expires_at: DateTime<Utc>) -> Result<(), Web3AuthError>;

    /// Check if a signature has been used
    async fn is_signature_used(&self, signature_hash: &str) -> Result<bool, Web3AuthError>;
}

/// NFT verification service trait
#[async_trait::async_trait]
pub trait NftVerifier: Send + Sync {
    /// Check if a wallet owns NFTs from the specified contracts
    async fn check_nft_ownership(
        &self,
        wallet_address: &str,
        chain_id: u64,
        contracts: &[String],
    ) -> Result<NftOwnershipResult, Web3AuthError>;
}

/// NFT ownership check result
#[derive(Debug, Clone)]
pub struct NftOwnershipResult {
    /// Whether the wallet owns at least one qualifying NFT
    pub has_nft: bool,
    /// Total NFTs owned across all contracts
    pub total_nfts: u64,
    /// NFTs per contract
    pub per_contract: std::collections::HashMap<String, u64>,
    /// Suggested role based on NFT holdings
    pub suggested_role: Option<String>,
}

/// Web3 authentication result
#[derive(Debug, Clone)]
pub struct Web3AuthResult {
    /// Verified wallet address
    pub wallet_address: String,
    /// Chain ID used for authentication
    pub chain_id: u64,
    /// Chain type
    pub chain_type: ChainType,
    /// Whether this is a new user
    pub is_new_user: bool,
    /// NFT ownership result (if enabled)
    pub nft_result: Option<NftOwnershipResult>,
    /// User email (if linked)
    pub email: Option<String>,
}

/// Wallet linking request
#[derive(Debug, Clone)]
pub struct LinkWalletRequest {
    /// User ID to link wallet to
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// SIWE message
    pub message: String,
    /// Signature
    pub signature: String,
    /// Chain ID
    pub chain_id: u64,
    /// Password (for verification when linking to existing account)
    pub password: Option<String>,
    /// MFA code (if MFA is enabled)
    pub mfa_code: Option<String>,
}

impl Web3Auth {
    /// Create a new Web3 authentication service
    pub fn new(
        domain: impl Into<String>,
        uri: impl Into<String>,
        nonce_store: Box<dyn NonceStore>,
    ) -> Self {
        let config = Web3AuthConfig::default();

        Self {
            domain: domain.into(),
            uri: uri.into(),
            supported_chains: vec![
                1,      // Ethereum Mainnet
                137,    // Polygon
                42161,  // Arbitrum
                10,     // Optimism
                8453,   // Base
                43114,  // Avalanche
                56,     // BSC
            ],
            nonce_store,
            request_store: None,
            nft_verifier: None,
            config,
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        domain: impl Into<String>,
        uri: impl Into<String>,
        nonce_store: Box<dyn NonceStore>,
        config: Web3AuthConfig,
    ) -> Self {
        Self {
            domain: domain.into(),
            uri: uri.into(),
            supported_chains: vec![
                1,      // Ethereum Mainnet
                137,    // Polygon
                42161,  // Arbitrum
                10,     // Optimism
                8453,   // Base
                43114,  // Avalanche
                56,     // BSC
            ],
            nonce_store,
            request_store: None,
            nft_verifier: None,
            config,
        }
    }

    /// Set request store for replay protection
    pub fn with_request_store(mut self, store: Box<dyn RequestStore>) -> Self {
        self.request_store = Some(store);
        self
    }

    /// Set NFT verifier
    pub fn with_nft_verifier(mut self, verifier: Arc<dyn NftVerifier>) -> Self {
        self.nft_verifier = Some(verifier);
        self.config.enable_nft_access_control = true;
        self
    }

    /// Configure supported chains
    pub fn with_supported_chains(mut self, chains: Vec<u64>) -> Self {
        self.supported_chains = chains;
        self
    }

    /// Generate a new nonce for SIWE
    pub async fn generate_nonce(
        &self,
        client_ip: Option<String>,
        chain_id: Option<u64>,
    ) -> Result<NonceData, Web3AuthError> {
        // Validate chain ID if provided
        if let Some(id) = chain_id {
            if !self.supported_chains.contains(&id) {
                return Err(Web3AuthError::UnsupportedChain(id));
            }
        }

        let nonce = siwe::generate_nonce();
        let now = Utc::now();
        let expires_at = now + Duration::minutes(self.config.nonce_ttl_minutes);

        let nonce_data = NonceData {
            nonce: nonce.clone(),
            created_at: now,
            expires_at,
            client_ip,
            chain_id,
            used: false,
        };

        self.nonce_store.store_nonce(nonce_data.clone()).await?;

        info!("Generated nonce {} for chain {:?}", nonce, chain_id);

        Ok(nonce_data)
    }

    /// Create a SIWE message for signing
    pub fn create_siwe_message(
        &self,
        address: &str,
        nonce: &str,
        chain_id: u64,
    ) -> Result<SiweMessage, Web3AuthError> {
        // Validate chain ID
        if !self.supported_chains.contains(&chain_id) {
            return Err(Web3AuthError::UnsupportedChain(chain_id));
        }

        let message = SiweMessage::new(
            &self.domain,
            address,
            &self.uri,
            nonce,
            chain_id,
        )?
        .with_expiration(Utc::now() + Duration::minutes(self.config.message_ttl_minutes));

        Ok(message)
    }

    /// Verify a SIWE signature and authenticate
    pub async fn verify_signature(
        &self,
        message: &str,
        signature: &str,
    ) -> Result<Web3AuthResult, Web3AuthError> {
        // Parse the message
        let siwe_message = SiweMessage::from_message_string(message)?;

        // Check for replay attacks
        if let Some(ref store) = self.request_store {
            let sig_hash = format!("{:x}", Sha256::digest(signature.as_bytes()));
            if store.is_signature_used(&sig_hash).await? {
                return Err(Web3AuthError::VerificationFailed(
                    "Signature already used".to_string()
                ));
            }
        }

        // Get and validate nonce
        let nonce_data = self
            .nonce_store
            .consume_nonce(&siwe_message.nonce)
            .await?
            .ok_or(Web3AuthError::NonceExpired)?;

        // Check if nonce was already used
        if nonce_data.used {
            return Err(Web3AuthError::NonceAlreadyUsed);
        }

        // Validate domain
        if self.config.enforce_domain_binding && siwe_message.domain != self.domain {
            return Err(Web3AuthError::DomainMismatch {
                expected: self.domain.clone(),
                actual: siwe_message.domain.clone(),
            });
        }

        // Validate chain ID matches if specified in nonce
        if let Some(expected_chain) = nonce_data.chain_id {
            if siwe_message.chain_id != expected_chain {
                return Err(Web3AuthError::VerificationFailed(format!(
                    "Chain ID mismatch: expected {}, got {}",
                    expected_chain, siwe_message.chain_id
                )));
            }
        }

        // Check message expiration
        if siwe_message.is_expired() {
            return Err(Web3AuthError::VerificationFailed(
                "SIWE message expired".to_string()
            ));
        }

        // Determine chain type
        let chain_type = siwe_message.chain_type()
            .ok_or_else(|| Web3AuthError::UnsupportedChain(siwe_message.chain_id))?;

        // Verify signature
        let is_valid = verify_signature(
            chain_type,
            message,
            signature,
            &siwe_message.address,
        ).map_err(Web3AuthError::SignatureError)?;

        if !is_valid {
            return Err(Web3AuthError::VerificationFailed(
                "Invalid signature".to_string()
            ));
        }

        // Store signature to prevent replay
        if let Some(ref store) = self.request_store {
            let sig_hash = format!("{:x}", Sha256::digest(signature.as_bytes()));
            store.store_signature(&sig_hash, siwe_message.expiration_time.unwrap_or(
                siwe_message.issued_at + Duration::minutes(self.config.message_ttl_minutes)
            )).await?;
        }

        // Check NFT ownership if enabled
        let nft_result = if self.config.enable_nft_access_control {
            if let Some(ref verifier) = self.nft_verifier {
                Some(verifier.check_nft_ownership(
                    &siwe_message.address,
                    siwe_message.chain_id,
                    &self.config.required_nft_contracts,
                ).await?)
            } else {
                None
            }
        } else {
            None
        };

        info!(
            "Web3 authentication successful for address {} on chain {}",
            siwe_message.address, siwe_message.chain_id
        );

        Ok(Web3AuthResult {
            wallet_address: siwe_message.address.clone(),
            chain_id: siwe_message.chain_id,
            chain_type,
            is_new_user: true, // Database layer will determine this
            nft_result,
            email: None,
        })
    }

    /// Get the domain
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Get the URI
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Get supported chains
    pub fn supported_chains(&self) -> &[u64] {
        &self.supported_chains
    }
}

// ==================== Redis Implementations ====================

/// Redis-based nonce store
#[derive(Clone)]
pub struct RedisNonceStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
}

impl RedisNonceStore {
    pub fn new(redis: redis::aio::ConnectionManager) -> Self {
        Self {
            redis,
            key_prefix: "web3:nonce:".to_string(),
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    fn key(&self, nonce: &str) -> String {
        format!("{}{}", self.key_prefix, nonce)
    }
}

#[async_trait::async_trait]
impl NonceStore for RedisNonceStore {
    async fn store_nonce(&self, data: NonceData) -> Result<(), Web3AuthError> {
        let mut conn = self.redis.clone();
        let key = self.key(&data.nonce);
        let ttl = (data.expires_at - Utc::now()).num_seconds().max(0) as u64;

        let json = serde_json::to_string(&data)
            .map_err(|e| Web3AuthError::StorageError(e.to_string()))?;

        redis::cmd("SETEX")
            .arg(&key)
            .arg(ttl)
            .arg(json)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| Web3AuthError::StorageError(e.to_string()))?;

        Ok(())
    }

    async fn consume_nonce(&self, nonce: &str) -> Result<Option<NonceData>, Web3AuthError> {
        let mut conn = self.redis.clone();
        let key = self.key(nonce);

        // Get the nonce data
        let json: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| Web3AuthError::StorageError(e.to_string()))?;

        if let Some(json) = json {
            let mut data: NonceData = serde_json::from_str(&json)
                .map_err(|e| Web3AuthError::StorageError(e.to_string()))?;

            // Delete the nonce atomically
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(&key)
                .query_async(&mut conn)
                .await;

            data.used = true;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    async fn get_nonce(&self, nonce: &str) -> Result<Option<NonceData>, Web3AuthError> {
        let mut conn = self.redis.clone();
        let key = self.key(nonce);

        let json: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| Web3AuthError::StorageError(e.to_string()))?;

        if let Some(json) = json {
            let data: NonceData = serde_json::from_str(&json)
                .map_err(|e| Web3AuthError::StorageError(e.to_string()))?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    async fn delete_nonce(&self, nonce: &str) -> Result<(), Web3AuthError> {
        let mut conn = self.redis.clone();
        let key = self.key(nonce);

        let _: Result<(), _> = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut conn)
            .await;

        Ok(())
    }
}

/// Redis-based request store for replay protection
#[derive(Clone)]
pub struct RedisRequestStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
}

impl RedisRequestStore {
    pub fn new(redis: redis::aio::ConnectionManager) -> Self {
        Self {
            redis,
            key_prefix: "web3:sig:".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl RequestStore for RedisRequestStore {
    async fn store_signature(&self, signature_hash: &str, expires_at: DateTime<Utc>) -> Result<(), Web3AuthError> {
        let mut conn = self.redis.clone();
        let key = format!("{}{}", self.key_prefix, signature_hash);
        let ttl = (expires_at - Utc::now()).num_seconds().max(0) as u64;

        redis::cmd("SETEX")
            .arg(&key)
            .arg(ttl)
            .arg("1")
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| Web3AuthError::StorageError(e.to_string()))?;

        Ok(())
    }

    async fn is_signature_used(&self, signature_hash: &str) -> Result<bool, Web3AuthError> {
        let mut conn = self.redis.clone();
        let key = format!("{}{}", self.key_prefix, signature_hash);

        let exists: bool = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| Web3AuthError::StorageError(e.to_string()))?;

        Ok(exists)
    }
}

/// Memory-based nonce store (for testing or single-instance deployments)
pub struct MemoryNonceStore {
    nonces: std::sync::Mutex<std::collections::HashMap<String, NonceData>>,
}

impl MemoryNonceStore {
    pub fn new() -> Self {
        Self {
            nonces: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn cleanup_expired(&self) {
        let mut nonces = self.nonces.lock().unwrap();
        let now = Utc::now();
        nonces.retain(|_, data| data.expires_at > now);
    }
}

impl Default for MemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NonceStore for MemoryNonceStore {
    async fn store_nonce(&self, data: NonceData) -> Result<(), Web3AuthError> {
        self.cleanup_expired();
        let mut nonces = self.nonces.lock().unwrap();
        nonces.insert(data.nonce.clone(), data);
        Ok(())
    }

    async fn consume_nonce(&self, nonce: &str) -> Result<Option<NonceData>, Web3AuthError> {
        self.cleanup_expired();
        let mut nonces = self.nonces.lock().unwrap();

        if let Some(mut data) = nonces.remove(nonce) {
            data.used = true;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    async fn get_nonce(&self, nonce: &str) -> Result<Option<NonceData>, Web3AuthError> {
        self.cleanup_expired();
        let nonces = self.nonces.lock().unwrap();
        Ok(nonces.get(nonce).cloned())
    }

    async fn delete_nonce(&self, nonce: &str) -> Result<(), Web3AuthError> {
        let mut nonces = self.nonces.lock().unwrap();
        nonces.remove(nonce);
        Ok(())
    }
}

/// Create a Web3Auth service with Redis storage
pub fn create_web3_auth_with_redis(
    domain: impl Into<String>,
    uri: impl Into<String>,
    redis: redis::aio::ConnectionManager,
) -> Web3Auth {
    let nonce_store = Box::new(RedisNonceStore::new(redis.clone()));
    let request_store = Box::new(RedisRequestStore::new(redis));

    Web3Auth::new(domain, uri, nonce_store)
        .with_request_store(request_store)
}

/// Create a Web3Auth service with in-memory storage
pub fn create_web3_auth_in_memory(
    domain: impl Into<String>,
    uri: impl Into<String>,
) -> Web3Auth {
    let nonce_store = Box::new(MemoryNonceStore::new());
    Web3Auth::new(domain, uri, nonce_store)
}
