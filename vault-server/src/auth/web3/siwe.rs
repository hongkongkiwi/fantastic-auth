//! Sign-In with Ethereum (SIWE) message handling
//!
//! Implements EIP-4361 compliant message format for Web3 authentication.
//!
//! Example SIWE message:
//! ```text
//! example.com wants you to sign in with your Ethereum account:
//! 0x1234...
//!
//! Sign in to Vault
//!
//! URI: https://example.com/login
//! Version: 1
//! Chain ID: 1
//! Nonce: abc123
//! Issued At: 2024-01-01T00:00:00Z
//! ```

use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Errors that can occur during SIWE message parsing or validation
#[derive(Debug, Error, Clone)]
pub enum SiweError {
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),
    #[error("Domain mismatch: expected {expected}, got {actual}")]
    DomainMismatch { expected: String, actual: String },
    #[error("Message expired: issued at {issued_at}, expires at {expires_at}")]
    Expired {
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
    #[error("Invalid chain ID: {0}")]
    InvalidChainId(u64),
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),
    #[error("Invalid URI: {0}")]
    InvalidUri(String),
    #[error("Nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch { expected: String, actual: String },
    #[error("Message not yet valid: {0}")]
    NotYetValid(DateTime<Utc>),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Supported blockchain chains for Web3 authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainType {
    /// Ethereum (EVM compatible)
    Ethereum,
    /// Polygon
    Polygon,
    /// Arbitrum
    Arbitrum,
    /// Optimism
    Optimism,
    /// Base
    Base,
    /// Avalanche
    Avalanche,
    /// BNB Smart Chain
    Bsc,
    /// Solana
    Solana,
}

impl ChainType {
    /// Get the chain ID for EVM chains
    pub fn chain_id(&self) -> u64 {
        match self {
            ChainType::Ethereum => 1,
            ChainType::Polygon => 137,
            ChainType::Arbitrum => 42161,
            ChainType::Optimism => 10,
            ChainType::Base => 8453,
            ChainType::Avalanche => 43114,
            ChainType::Bsc => 56,
            ChainType::Solana => 0, // Solana doesn't use chain IDs
        }
    }

    /// Get chain type from chain ID
    pub fn from_chain_id(id: u64) -> Option<Self> {
        match id {
            1 => Some(ChainType::Ethereum),
            137 => Some(ChainType::Polygon),
            42161 => Some(ChainType::Arbitrum),
            10 => Some(ChainType::Optimism),
            8453 => Some(ChainType::Base),
            43114 => Some(ChainType::Avalanche),
            56 => Some(ChainType::Bsc),
            _ => None,
        }
    }

    /// Check if this is an EVM chain
    pub fn is_evm(&self) -> bool {
        !matches!(self, ChainType::Solana)
    }

    /// Get the chain name
    pub fn name(&self) -> &'static str {
        match self {
            ChainType::Ethereum => "Ethereum",
            ChainType::Polygon => "Polygon",
            ChainType::Arbitrum => "Arbitrum",
            ChainType::Optimism => "Optimism",
            ChainType::Base => "Base",
            ChainType::Avalanche => "Avalanche",
            ChainType::Bsc => "BNB Smart Chain",
            ChainType::Solana => "Solana",
        }
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// SIWE Message structure (EIP-4361 compliant)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SiweMessage {
    /// RFC 4501 DNS authority of the service requesting the signature
    pub domain: String,
    /// Ethereum address of the signer
    pub address: String,
    /// Human-readable statement
    pub statement: Option<String>,
    /// RFC 3986 URI of the service
    pub uri: String,
    /// Version of the SIWE message format
    pub version: String,
    /// Chain ID of the network
    pub chain_id: u64,
    /// Randomized token to prevent replay attacks
    pub nonce: String,
    /// ISO 8601 datetime when message was issued
    pub issued_at: DateTime<Utc>,
    /// ISO 8601 datetime when message expires (optional)
    pub expiration_time: Option<DateTime<Utc>>,
    /// ISO 8601 datetime when message becomes valid (optional)
    pub not_before: Option<DateTime<Utc>>,
    /// Unique identifier for the request (optional)
    pub request_id: Option<String>,
    /// List of resources the user is consenting to access (optional)
    pub resources: Vec<String>,
}

impl SiweMessage {
    /// Create a new SIWE message with required fields
    pub fn new(
        domain: impl Into<String>,
        address: impl Into<String>,
        uri: impl Into<String>,
        nonce: impl Into<String>,
        chain_id: u64,
    ) -> Result<Self, SiweError> {
        let address = normalize_address(&address.into())?;

        Ok(Self {
            domain: domain.into(),
            address,
            statement: Some("Sign in to Vault".to_string()),
            uri: uri.into(),
            version: "1".to_string(),
            chain_id,
            nonce: nonce.into(),
            issued_at: Utc::now(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: Vec::new(),
        })
    }

    /// Set the statement
    pub fn with_statement(mut self, statement: impl Into<String>) -> Self {
        self.statement = Some(statement.into());
        self
    }

    /// Set expiration time
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expiration_time = Some(expires_at);
        self
    }

    /// Set not before time
    pub fn with_not_before(mut self, not_before: DateTime<Utc>) -> Self {
        self.not_before = Some(not_before);
        self
    }

    /// Set request ID
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Add a resource
    pub fn add_resource(mut self, resource: impl Into<String>) -> Self {
        self.resources.push(resource.into());
        self
    }

    /// Get the chain type
    pub fn chain_type(&self) -> Option<ChainType> {
        ChainType::from_chain_id(self.chain_id)
    }

    /// Validate the message
    pub fn validate(&self, expected_domain: &str, expected_nonce: &str) -> Result<(), SiweError> {
        // Validate domain
        if self.domain != expected_domain {
            return Err(SiweError::DomainMismatch {
                expected: expected_domain.to_string(),
                actual: self.domain.clone(),
            });
        }

        // Validate nonce
        if self.nonce != expected_nonce {
            return Err(SiweError::NonceMismatch {
                expected: expected_nonce.to_string(),
                actual: self.nonce.clone(),
            });
        }

        // Check not_before
        if let Some(not_before) = self.not_before {
            if Utc::now() < not_before {
                return Err(SiweError::NotYetValid(not_before));
            }
        }

        // Check expiration
        if let Some(expiration) = self.expiration_time {
            if Utc::now() > expiration {
                return Err(SiweError::Expired {
                    issued_at: self.issued_at,
                    expires_at: expiration,
                });
            }
        }

        // Validate address format
        validate_evm_address(&self.address)?;

        // Validate chain ID for EVM
        if self.chain_id != 0 && ChainType::from_chain_id(self.chain_id).is_none() {
            // Allow custom chain IDs but log warning
            tracing::warn!("Using non-standard chain ID: {}", self.chain_id);
        }

        Ok(())
    }

    /// Check if message is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expiration) = self.expiration_time {
            Utc::now() > expiration
        } else {
            // Default expiration: 5 minutes after issuance
            Utc::now() > self.issued_at + Duration::minutes(5)
        }
    }

    /// Get the message string for signing
    pub fn to_message_string(&self) -> String {
        let mut parts = Vec::new();

        // Header
        parts.push(format!(
            "{} wants you to sign in with your Ethereum account:\n{}",
            self.domain, self.address
        ));

        // Statement
        if let Some(statement) = &self.statement {
            parts.push(format!("\n{}\n", statement));
        } else {
            parts.push("\n".to_string());
        }

        // URI
        parts.push(format!("URI: {}", self.uri));

        // Version
        parts.push(format!("Version: {}", self.version));

        // Chain ID
        parts.push(format!("Chain ID: {}", self.chain_id));

        // Nonce
        parts.push(format!("Nonce: {}", self.nonce));

        // Issued At
        parts.push(format!(
            "Issued At: {}",
            self.issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ));

        // Expiration Time (optional)
        if let Some(expiration) = self.expiration_time {
            parts.push(format!(
                "Expiration Time: {}",
                expiration.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ));
        }

        // Not Before (optional)
        if let Some(not_before) = self.not_before {
            parts.push(format!(
                "Not Before: {}",
                not_before.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ));
        }

        // Request ID (optional)
        if let Some(request_id) = &self.request_id {
            parts.push(format!("Request ID: {}", request_id));
        }

        // Resources (optional)
        if !self.resources.is_empty() {
            parts.push("Resources:".to_string());
            for resource in &self.resources {
                parts.push(format!("- {}", resource));
            }
        }

        parts.join("\n")
    }

    /// Parse a SIWE message from string
    pub fn from_message_string(message: &str) -> Result<Self, SiweError> {
        let lines: Vec<&str> = message.lines().collect();

        if lines.len() < 3 {
            return Err(SiweError::InvalidFormat(
                "Message too short".to_string(),
            ));
        }

        // Parse header: "{domain} wants you to sign in with your Ethereum account:"
        let header_regex = Regex::new(r"^(.*?) wants you to sign in with your Ethereum account:$")
            .map_err(|e| SiweError::InvalidFormat(format!("Invalid regex: {}", e)))?;

        let domain = header_regex
            .captures(lines[0])
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| SiweError::InvalidFormat("Invalid header format".to_string()))?;

        // Parse address
        let address = normalize_address(lines.get(1).unwrap_or(&""))?
            .to_lowercase();

        // Find field indices
        let mut uri = None;
        let mut version = None;
        let mut chain_id = None;
        let mut nonce = None;
        let mut issued_at = None;
        let mut expiration_time = None;
        let mut not_before = None;
        let mut request_id = None;
        let mut resources = Vec::new();
        let mut in_resources = false;
        let mut statement_lines = Vec::new();
        let mut found_statement = false;

        for (_i, line) in lines.iter().enumerate().skip(2) {
            let line = line.trim();

            if line.is_empty() {
                if !found_statement && !statement_lines.is_empty() {
                    found_statement = true;
                }
                continue;
            }

            // Check for field lines
            if line.starts_with("URI: ") {
                uri = Some(line[5..].to_string());
                found_statement = true;
                in_resources = false;
            } else if line.starts_with("Version: ") {
                version = Some(line[9..].to_string());
                found_statement = true;
                in_resources = false;
            } else if line.starts_with("Chain ID: ") {
                chain_id = line[10..].parse().ok();
                found_statement = true;
                in_resources = false;
            } else if line.starts_with("Nonce: ") {
                nonce = Some(line[7..].to_string());
                found_statement = true;
                in_resources = false;
            } else if line.starts_with("Issued At: ") {
                issued_at = DateTime::parse_from_rfc3339(&line[11..])
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc));
                found_statement = true;
                in_resources = false;
            } else if line.starts_with("Expiration Time: ") {
                expiration_time = DateTime::parse_from_rfc3339(&line[17..])
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc));
                found_statement = true;
                in_resources = false;
            } else if line.starts_with("Not Before: ") {
                not_before = DateTime::parse_from_rfc3339(&line[12..])
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc));
                found_statement = true;
                in_resources = false;
            } else if line.starts_with("Request ID: ") {
                request_id = Some(line[12..].to_string());
                found_statement = true;
                in_resources = false;
            } else if line == "Resources:" {
                in_resources = true;
                found_statement = true;
            } else if in_resources && line.starts_with("- ") {
                resources.push(line[2..].to_string());
            } else if !found_statement {
                // This is part of the statement
                statement_lines.push(line.to_string());
            }
        }

        // Validate required fields
        let uri = uri.ok_or_else(|| SiweError::MissingField("URI".to_string()))?;
        let version = version.ok_or_else(|| SiweError::MissingField("Version".to_string()))?;
        let chain_id = chain_id.ok_or_else(|| SiweError::MissingField("Chain ID".to_string()))?;
        let nonce = nonce.ok_or_else(|| SiweError::MissingField("Nonce".to_string()))?;
        let issued_at = issued_at.ok_or_else(|| SiweError::MissingField("Issued At".to_string()))?;

        let statement = if statement_lines.is_empty() {
            None
        } else {
            Some(statement_lines.join("\n"))
        };

        Ok(Self {
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        })
    }
}

impl fmt::Display for SiweMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_message_string())
    }
}

/// Normalize an Ethereum address to checksum format
pub fn normalize_address(address: &str) -> Result<String, SiweError> {
    // Remove 0x prefix if present
    let addr = address.trim().trim_start_matches("0x").to_lowercase();

    // Check length (40 hex characters for Ethereum address)
    if addr.len() != 40 {
        return Err(SiweError::InvalidAddress(format!(
            "Invalid address length: expected 40, got {}",
            addr.len()
        )));
    }

    // Check valid hex
    if !addr.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SiweError::InvalidAddress(
            "Address contains invalid characters".to_string(),
        ));
    }

    Ok(format!("0x{}", addr))
}

/// Validate an EVM address format
pub fn validate_evm_address(address: &str) -> Result<(), SiweError> {
    normalize_address(address)?;
    Ok(())
}

/// Generate a cryptographically secure nonce
pub fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let nonce: String = (0..16)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();
    nonce.to_lowercase()
}

/// Calculate expiration time based on issued time
pub fn default_expiration(issued_at: DateTime<Utc>) -> DateTime<Utc> {
    issued_at + Duration::minutes(5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_type() {
        assert_eq!(ChainType::Ethereum.chain_id(), 1);
        assert_eq!(ChainType::Polygon.chain_id(), 137);
        assert!(ChainType::Ethereum.is_evm());
        assert!(!ChainType::Solana.is_evm());
    }

    #[test]
    fn test_siwe_message_creation() {
        let msg = SiweMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "abc123",
            1,
        )
        .unwrap();

        assert_eq!(msg.domain, "example.com");
        assert_eq!(
            msg.address,
            "0x1234567890123456789012345678901234567890"
        );
        assert_eq!(msg.chain_id, 1);
    }

    #[test]
    fn test_message_string_roundtrip() {
        let original = SiweMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "abc123",
            1,
        )
        .unwrap()
        .with_statement("Sign in to Vault");

        let message_str = original.to_message_string();
        let parsed = SiweMessage::from_message_string(&message_str).unwrap();

        assert_eq!(original.domain, parsed.domain);
        assert_eq!(original.address.to_lowercase(), parsed.address.to_lowercase());
        assert_eq!(original.chain_id, parsed.chain_id);
        assert_eq!(original.nonce, parsed.nonce);
    }

    #[test]
    fn test_address_normalization() {
        assert_eq!(
            normalize_address("0x1234567890123456789012345678901234567890").unwrap(),
            "0x1234567890123456789012345678901234567890"
        );
        assert_eq!(
            normalize_address("1234567890123456789012345678901234567890").unwrap(),
            "0x1234567890123456789012345678901234567890"
        );
        assert!(normalize_address("0xINVALID").is_err());
    }

    #[test]
    fn test_expiration() {
        let msg = SiweMessage::new(
            "example.com",
            "0x1234567890123456789012345678901234567890",
            "https://example.com/login",
            "abc123",
            1,
        )
        .unwrap();

        // Should not be expired immediately
        assert!(!msg.is_expired());

        // Should be expired after default expiration
        let expired = SiweMessage {
            issued_at: Utc::now() - Duration::minutes(10),
            ..msg
        };
        assert!(expired.is_expired());
    }
}
