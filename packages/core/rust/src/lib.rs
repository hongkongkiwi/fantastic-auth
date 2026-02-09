//! Vault Core - User Management API
//!
//! A secure, quantum-resistant user authentication and management library.
//!
//! ## Features
//!
//! - **Quantum-Resistant Cryptography**: Hybrid Ed25519 + ML-DSA-65 signatures
//! - **Multi-Factor Authentication**: TOTP, Email OTP, WebAuthn support
//! - **Session Management**: Secure JWT with refresh token rotation
//! - **Multi-Tenancy**: Database-per-tenant isolation
//!
//! ## Example
//!
//! ```rust
//! use vault_core::crypto::{HybridSigningKey, HybridJwt, Claims, TokenType};
//!
//! // Generate hybrid key pair
//! let (signing_key, verifying_key) = HybridSigningKey::generate();
//!
//! // Create claims
//! let claims = Claims::new(
//!     "user_123",
//!     "tenant_456",
//!     TokenType::Access,
//!     "vault",
//!     "myapp",
//! );
//!
//! // Sign JWT
//! let token = HybridJwt::encode(&claims, &signing_key).unwrap();
//!
//! // Verify JWT
//! let decoded = HybridJwt::decode(&token, &verifying_key).unwrap();
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod ai;
pub mod auth;
pub mod billing;
pub mod crypto;
pub mod db;
pub mod email;
pub mod error;
pub mod hosted;
pub mod models;
pub mod plugin;
pub mod security;
pub mod sms;
pub mod webauthn;

// ZK module is behind a feature flag since it's experimental
#[cfg(feature = "zk")]
pub mod zk;

pub use crypto::{
    generate_random_bytes, generate_secure_random, Claims, HybridJwt, HybridSigningKey,
    HybridVerifyingKey, TokenType, VaultPasswordHasher,
};
pub use error::{Result, VaultError};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
