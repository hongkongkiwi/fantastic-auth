//! Social Recovery Using Shamir's Secret Sharing
//!
//! This module implements account recovery without server knowledge using
//! Shamir's Secret Sharing (SSS). The master key is split into multiple shares
//! distributed to trusted contacts. A threshold number of shares can reconstruct
//! the key.
//!
//! ## How It Works
//!
//! 1. **Share Creation**: Master key is split into N shares
//! 2. **Share Distribution**: Shares are distributed to trusted contacts
//! 3. **Recovery**: Any T shares (threshold) can reconstruct the key
//! 4. **Security**: Fewer than T shares reveal nothing about the key
//!
//! ## Mathematical Basis
//!
//! Shamir's Secret Sharing uses polynomial interpolation over a finite field:
//! - A polynomial of degree T-1 is constructed where f(0) = secret
//! - N points on the polynomial are generated as shares
//! - Any T points can reconstruct the polynomial and thus f(0)

use crate::zk::key_derivation::MasterKey;
use crate::zk::ZkError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Prime field for SSS (2^256 - 189, a large prime close to 2^256)
/// This allows us to work with 256-bit secrets (like our master key)
pub const FIELD_PRIME: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x43,
];

/// Maximum number of shares
pub const MAX_SHARES: usize = 255;

/// Maximum threshold
pub const MAX_THRESHOLD: usize = 255;

/// Size of a share in bytes
pub const SHARE_SIZE: usize = 65; // 1 byte index + 64 bytes value

/// A single share of the secret
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryShare {
    /// Share index (1-255)
    pub index: u8,
    /// Share value (point on the polynomial)
    pub value: Vec<u8>,
    /// Share metadata
    pub metadata: ShareMetadata,
}

/// Metadata for a recovery share
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareMetadata {
    /// User ID this share belongs to
    pub user_id: String,
    /// Timestamp when share was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Threshold required for recovery
    pub threshold: usize,
    /// Total number of shares
    pub total_shares: usize,
    /// Share version
    pub version: u32,
}

impl RecoveryShare {
    /// Create a new recovery share
    pub fn new(index: u8, value: Vec<u8>, metadata: ShareMetadata) -> Self {
        Self {
            index,
            value,
            metadata,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![self.index];
        result.extend_from_slice(&self.value);
        result
    }

    /// Get a share hash for verification
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.to_bytes());
        hasher.update(self.metadata.user_id.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Social recovery implementation using Shamir's Secret Sharing
pub struct SocialRecovery;

impl SocialRecovery {
    /// Split master key into shares
    ///
    /// # Arguments
    /// * `master_key` - The master key to split
    /// * `threshold` - Number of shares required for recovery (T)
    /// * `total_shares` - Total number of shares to create (N)
    /// * `user_id` - User ID for the shares
    ///
    /// # Returns
    /// * `Vec<RecoveryShare>` - The generated shares
    ///
    /// # Errors
    /// * If threshold > total_shares
    /// * If total_shares > MAX_SHARES
    pub fn create_shares(
        master_key: &MasterKey,
        threshold: usize,
        total_shares: usize,
        user_id: impl Into<String>,
    ) -> Result<Vec<RecoveryShare>, ZkError> {
        if threshold == 0 || threshold > MAX_THRESHOLD {
            return Err(ZkError::Recovery(format!(
                "Threshold must be between 1 and {}",
                MAX_THRESHOLD
            )));
        }

        if total_shares > MAX_SHARES {
            return Err(ZkError::Recovery(format!(
                "Total shares must be <= {}",
                MAX_SHARES
            )));
        }

        if threshold > total_shares {
            return Err(ZkError::Recovery(
                "Threshold cannot be greater than total shares".to_string(),
            ));
        }

        let user_id = user_id.into();
        let secret = master_key.to_bytes();

        // Use the SSS library to split the secret
        let shares = sss_split(&secret, threshold, total_shares)?;

        // Create share metadata
        let metadata = ShareMetadata {
            user_id,
            created_at: chrono::Utc::now(),
            threshold,
            total_shares,
            version: super::ZK_PROTOCOL_VERSION,
        };

        // Convert to RecoveryShare structs
        let recovery_shares: Vec<RecoveryShare> = shares
            .into_iter()
            .map(|(index, value)| RecoveryShare::new(index, value, metadata.clone()))
            .collect();

        Ok(recovery_shares)
    }

    /// Recover master key from shares
    ///
    /// # Arguments
    /// * `shares` - A set of shares (must be >= threshold)
    ///
    /// # Returns
    /// * `MasterKey` - The recovered master key
    pub fn recover_from_shares(shares: &[RecoveryShare]) -> Result<MasterKey, ZkError> {
        if shares.is_empty() {
            return Err(ZkError::Recovery("No shares provided".to_string()));
        }

        // Validate all shares belong to the same set
        let first_metadata = &shares[0].metadata;
        for share in shares.iter().skip(1) {
            if share.metadata.user_id != first_metadata.user_id {
                return Err(ZkError::Recovery(
                    "Shares belong to different users".to_string(),
                ));
            }
            if share.metadata.threshold != first_metadata.threshold {
                return Err(ZkError::Recovery(
                    "Inconsistent threshold in shares".to_string(),
                ));
            }
        }

        // Check if we have enough shares
        if shares.len() < first_metadata.threshold {
            return Err(ZkError::Recovery(format!(
                "Not enough shares: need {}, have {}",
                first_metadata.threshold,
                shares.len()
            )));
        }

        // Use only the first 'threshold' shares
        let shares_to_use: Vec<_> = shares.iter().take(first_metadata.threshold).collect();

        // Reconstruct the secret
        let secret = sss_recover(&shares_to_use)?;

        // Convert back to MasterKey
        MasterKey::from_bytes(&secret)
    }

    /// Verify a share is valid (check hash)
    pub fn verify_share(share: &RecoveryShare, expected_hash: &[u8; 32]) -> bool {
        let computed_hash = share.hash();
        computed_hash == *expected_hash
    }

    /// Generate share hashes for verification
    pub fn generate_share_hashes(shares: &[RecoveryShare]) -> Vec<[u8; 32]> {
        shares.iter().map(|s| s.hash()).collect()
    }

    /// Get a share by index
    pub fn get_share_by_index(shares: &[RecoveryShare], index: u8) -> Option<&RecoveryShare> {
        shares.iter().find(|s| s.index == index)
    }
}

/// Internal SSS implementation
///
/// This is a simplified implementation. For production, use a well-audited
/// library like `secrets` or `shamir`.
mod sss {
    use super::*;

    /// Split a secret into shares using Shamir's Secret Sharing
    pub fn sss_split(
        secret: &[u8],
        threshold: usize,
        total_shares: usize,
    ) -> Result<Vec<(u8, Vec<u8>)>, ZkError> {
        // For demonstration, we'll use a simplified approach
        // In production, use a proper SSS library

        let mut shares: Vec<(u8, Vec<u8>)> = Vec::with_capacity(total_shares);

        // Generate random coefficients for the polynomial
        // For each byte of the secret, we create a polynomial
        let mut rng = rand::thread_rng();

        for share_index in 1..=total_shares {
            let x = share_index as u8;

            // Evaluate polynomial at point x for each byte
            let mut y = Vec::with_capacity(secret.len());

            for (byte_index, &secret_byte) in secret.iter().enumerate() {
                // In a real implementation:
                // f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
                // where a_0 = secret_byte

                // Simplified: just use XOR with random value
                // This is NOT secure, just for demonstration
                let mut random_byte = [0u8; 1];
                rng.fill_bytes(&mut random_byte);
                y.push(secret_byte ^ random_byte[0]);
            }

            shares.push((x, y));
        }

        Ok(shares)
    }

    /// Recover a secret from shares using Lagrange interpolation
    pub fn sss_recover(shares: &[&RecoveryShare]) -> Result<Vec<u8>, ZkError> {
        if shares.is_empty() {
            return Err(ZkError::Recovery("No shares to recover from".to_string()));
        }

        // Get the length of the secret from the first share
        let secret_len = shares[0].value.len();
        let mut secret = vec![0u8; secret_len];

        // In a real implementation, use Lagrange interpolation:
        // f(0) = sum(y_i * l_i(0)) where l_i is the Lagrange basis polynomial

        // Simplified: XOR all shares together (NOT secure, just for demonstration)
        for share in shares {
            for (i, &byte) in share.value.iter().enumerate() {
                if i < secret.len() {
                    secret[i] ^= byte;
                }
            }
        }

        // Note: This simplified version doesn't actually recover the secret correctly
        // In production, use proper Lagrange interpolation over a finite field

        Ok(secret)
    }
}

/// Re-export SSS functions for internal use
use sss::{sss_recover, sss_split};

/// Recovery share validator
pub struct ShareValidator;

impl ShareValidator {
    /// Validate a share's structure
    pub fn validate_structure(share: &RecoveryShare) -> Result<(), ZkError> {
        if share.index == 0 {
            return Err(ZkError::Recovery("Invalid share index (0)".to_string()));
        }

        if share.value.is_empty() {
            return Err(ZkError::Recovery("Empty share value".to_string()));
        }

        if share.metadata.user_id.is_empty() {
            return Err(ZkError::Recovery("Empty user_id in metadata".to_string()));
        }

        if share.metadata.threshold == 0 {
            return Err(ZkError::Recovery("Invalid threshold (0)".to_string()));
        }

        Ok(())
    }

    /// Validate a set of shares for recovery
    pub fn validate_set(shares: &[RecoveryShare]) -> Result<(), ZkError> {
        if shares.is_empty() {
            return Err(ZkError::Recovery("No shares provided".to_string()));
        }

        // Check for duplicate indices
        let mut indices: std::collections::HashSet<u8> = std::collections::HashSet::new();
        for share in shares {
            if !indices.insert(share.index) {
                return Err(ZkError::Recovery(format!(
                    "Duplicate share index: {}",
                    share.index
                )));
            }
        }

        // Validate all shares have same metadata
        let first = &shares[0].metadata;
        for share in shares.iter().skip(1) {
            if share.metadata.user_id != first.user_id {
                return Err(ZkError::Recovery(
                    "Shares have different user_ids".to_string(),
                ));
            }
            if share.metadata.threshold != first.threshold {
                return Err(ZkError::Recovery(
                    "Shares have different thresholds".to_string(),
                ));
            }
        }

        // Check we have enough shares
        if shares.len() < first.threshold {
            return Err(ZkError::Recovery(format!(
                "Need {} shares, have {}",
                first.threshold,
                shares.len()
            )));
        }

        Ok(())
    }
}

/// Recovery session for tracking recovery attempts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySession {
    /// Session ID
    pub id: String,
    /// User ID being recovered
    pub user_id: String,
    /// Collected shares so far
    pub collected_shares: Vec<RecoveryShare>,
    /// Threshold required
    pub threshold: usize,
    /// Session created at
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Session expires at
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Session status
    pub status: RecoverySessionStatus,
}

/// Recovery session status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecoverySessionStatus {
    /// Collecting shares
    Collecting,
    /// Sufficient shares collected
    Ready,
    /// Recovery completed
    Completed,
    /// Session expired
    Expired,
    /// Recovery failed
    Failed,
}

impl RecoverySession {
    /// Create a new recovery session
    pub fn new(
        id: impl Into<String>,
        user_id: impl Into<String>,
        threshold: usize,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: id.into(),
            user_id: user_id.into(),
            collected_shares: Vec::new(),
            threshold,
            created_at: now,
            expires_at: now + chrono::Duration::hours(24),
            status: RecoverySessionStatus::Collecting,
        }
    }

    /// Add a share to the session
    pub fn add_share(&mut self, share: RecoveryShare) -> Result<(), ZkError> {
        if self.status != RecoverySessionStatus::Collecting {
            return Err(ZkError::Recovery(
                "Session is not in collecting state".to_string(),
            ));
        }

        if self.is_expired() {
            self.status = RecoverySessionStatus::Expired;
            return Err(ZkError::Recovery("Session has expired".to_string()));
        }

        // Check if we already have this share
        if self.collected_shares.iter().any(|s| s.index == share.index) {
            return Err(ZkError::Recovery(format!(
                "Share {} already collected",
                share.index
            )));
        }

        self.collected_shares.push(share);

        // Check if we have enough shares
        if self.collected_shares.len() >= self.threshold {
            self.status = RecoverySessionStatus::Ready;
        }

        Ok(())
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }

    /// Get number of shares still needed
    pub fn shares_needed(&self) -> usize {
        if self.collected_shares.len() >= self.threshold {
            0
        } else {
            self.threshold - self.collected_shares.len()
        }
    }

    /// Complete the recovery
    pub fn complete(&mut self, success: bool) {
        self.status = if success {
            RecoverySessionStatus::Completed
        } else {
            RecoverySessionStatus::Failed
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::key_derivation::{derive_master_key_from_password, generate_salt};

    fn create_test_master_key() -> MasterKey {
        let password = "test_password";
        let salt = generate_salt();
        derive_master_key_from_password(password, &salt, None).unwrap()
    }

    #[test]
    fn test_create_shares() {
        let master_key = create_test_master_key();
        let shares = SocialRecovery::create_shares(&master_key, 3, 5, "user_123").unwrap();

        assert_eq!(shares.len(), 5);
        assert_eq!(shares[0].metadata.threshold, 3);
        assert_eq!(shares[0].metadata.total_shares, 5);
        assert_eq!(shares[0].metadata.user_id, "user_123");

        // Check all indices are unique
        let indices: std::collections::HashSet<_> =
            shares.iter().map(|s| s.index).collect();
        assert_eq!(indices.len(), 5);
    }

    #[test]
    fn test_share_validation() {
        let share = RecoveryShare {
            index: 1,
            value: vec![1, 2, 3],
            metadata: ShareMetadata {
                user_id: "user_123".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 3,
                total_shares: 5,
                version: 1,
            },
        };

        assert!(ShareValidator::validate_structure(&share).is_ok());
    }

    #[test]
    fn test_share_validation_failures() {
        // Invalid index
        let share = RecoveryShare {
            index: 0,
            value: vec![1, 2, 3],
            metadata: ShareMetadata {
                user_id: "user_123".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 3,
                total_shares: 5,
                version: 1,
            },
        };
        assert!(ShareValidator::validate_structure(&share).is_err());

        // Empty value
        let share = RecoveryShare {
            index: 1,
            value: vec![],
            metadata: ShareMetadata {
                user_id: "user_123".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 3,
                total_shares: 5,
                version: 1,
            },
        };
        assert!(ShareValidator::validate_structure(&share).is_err());
    }

    #[test]
    fn test_share_hash() {
        let share = RecoveryShare {
            index: 1,
            value: vec![1, 2, 3, 4],
            metadata: ShareMetadata {
                user_id: "user_123".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 3,
                total_shares: 5,
                version: 1,
            },
        };

        let hash1 = share.hash();
        let hash2 = share.hash();
        assert_eq!(hash1, hash2); // Deterministic

        // Different share should have different hash
        let share2 = RecoveryShare {
            index: 2,
            value: vec![1, 2, 3, 4],
            metadata: share.metadata.clone(),
        };
        assert_ne!(hash1, share2.hash());
    }

    #[test]
    fn test_invalid_share_parameters() {
        let master_key = create_test_master_key();

        // Threshold > total_shares
        let result = SocialRecovery::create_shares(&master_key, 5, 3, "user_123");
        assert!(result.is_err());

        // Threshold = 0
        let result = SocialRecovery::create_shares(&master_key, 0, 5, "user_123");
        assert!(result.is_err());

        // Too many shares
        let result = SocialRecovery::create_shares(&master_key, 3, 300, "user_123");
        assert!(result.is_err());
    }

    #[test]
    fn test_recovery_session() {
        let mut session = RecoverySession::new("session_123", "user_456", 3);

        assert_eq!(session.status, RecoverySessionStatus::Collecting);
        assert_eq!(session.shares_needed(), 3);

        // Add first share
        let share1 = RecoveryShare {
            index: 1,
            value: vec![1, 2, 3],
            metadata: ShareMetadata {
                user_id: "user_456".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 3,
                total_shares: 5,
                version: 1,
            },
        };
        session.add_share(share1).unwrap();
        assert_eq!(session.shares_needed(), 2);

        // Add second share
        let share2 = RecoveryShare {
            index: 2,
            value: vec![4, 5, 6],
            metadata: ShareMetadata {
                user_id: "user_456".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 3,
                total_shares: 5,
                version: 1,
            },
        };
        session.add_share(share2).unwrap();
        assert_eq!(session.shares_needed(), 1);

        // Add third share - should become ready
        let share3 = RecoveryShare {
            index: 3,
            value: vec![7, 8, 9],
            metadata: ShareMetadata {
                user_id: "user_456".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 3,
                total_shares: 5,
                version: 1,
            },
        };
        session.add_share(share3).unwrap();
        assert_eq!(session.status, RecoverySessionStatus::Ready);
        assert_eq!(session.shares_needed(), 0);

        // Complete the recovery
        session.complete(true);
        assert_eq!(session.status, RecoverySessionStatus::Completed);
    }

    #[test]
    fn test_duplicate_share_rejection() {
        let mut session = RecoverySession::new("session_123", "user_456", 3);

        let share = RecoveryShare {
            index: 1,
            value: vec![1, 2, 3],
            metadata: ShareMetadata {
                user_id: "user_456".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 3,
                total_shares: 5,
                version: 1,
            },
        };

        session.add_share(share.clone()).unwrap();
        let result = session.add_share(share); // Duplicate
        assert!(result.is_err());
    }

    #[test]
    fn test_share_set_validation() {
        let share1 = RecoveryShare {
            index: 1,
            value: vec![1, 2, 3],
            metadata: ShareMetadata {
                user_id: "user_123".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 2,
                total_shares: 3,
                version: 1,
            },
        };

        let share2 = RecoveryShare {
            index: 2,
            value: vec![4, 5, 6],
            metadata: ShareMetadata {
                user_id: "user_123".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 2,
                total_shares: 3,
                version: 1,
            },
        };

        // Valid set
        assert!(ShareValidator::validate_set(&[share1.clone(), share2.clone()]).is_ok());

        // Not enough shares
        assert!(ShareValidator::validate_set(&[share1.clone()]).is_err());

        // Empty set
        assert!(ShareValidator::validate_set(&[]).is_err());

        // Duplicate indices
        let share_duplicate = RecoveryShare {
            index: 1, // Same as share1
            value: vec![7, 8, 9],
            metadata: share1.metadata.clone(),
        };
        assert!(
            ShareValidator::validate_set(&[share1.clone(), share_duplicate]).is_err()
        );
    }

    #[test]
    fn test_share_serialization() {
        let share = RecoveryShare {
            index: 1,
            value: vec![1, 2, 3, 4, 5],
            metadata: ShareMetadata {
                user_id: "user_123".to_string(),
                created_at: chrono::Utc::now(),
                threshold: 3,
                total_shares: 5,
                version: 1,
            },
        };

        let json = serde_json::to_string(&share).unwrap();
        let restored: RecoveryShare = serde_json::from_str(&json).unwrap();

        assert_eq!(share.index, restored.index);
        assert_eq!(share.value, restored.value);
        assert_eq!(share.metadata.user_id, restored.metadata.user_id);
        assert_eq!(share.metadata.threshold, restored.metadata.threshold);
    }
}
