//! Symmetric encryption helpers for sensitive data (AES-256-GCM)

use vault_core::crypto::generate_random_bytes;

pub fn encrypt_to_base64(key: &[u8], plaintext: &[u8]) -> Result<String, EncryptionError> {
    use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM};

    if key.len() != 32 {
        return Err(EncryptionError::InvalidKeyLength);
    }

    let nonce_bytes: [u8; 12] = generate_random_bytes(12)
        .try_into()
        .map_err(|_| EncryptionError::RandomFailed)?;

    struct OneNonce([u8; 12]);
    impl NonceSequence for OneNonce {
        fn advance(&mut self) -> std::result::Result<Nonce, ring::error::Unspecified> {
            Nonce::try_assume_unique_for_key(&self.0)
        }
    }

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| EncryptionError::InvalidKeyLength)?;
    let mut sealing_key = SealingKey::new(unbound_key, OneNonce(nonce_bytes));

    let mut ciphertext = plaintext.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::empty(), &mut ciphertext)
        .map_err(|_| EncryptionError::EncryptFailed)?;

    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    combined.extend_from_slice(tag.as_ref());

    Ok(base64::engine::general_purpose::STANDARD.encode(combined))
}

pub fn decrypt_from_base64(key: &[u8], encoded: &str) -> Result<Vec<u8>, EncryptionError> {
    use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, UnboundKey, AES_256_GCM};

    if key.len() != 32 {
        return Err(EncryptionError::InvalidKeyLength);
    }

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| EncryptionError::InvalidCiphertext)?;

    if ciphertext.len() < 12 + 16 {
        return Err(EncryptionError::InvalidCiphertext);
    }

    let nonce_bytes: [u8; 12] = ciphertext[..12]
        .try_into()
        .map_err(|_| EncryptionError::InvalidCiphertext)?;

    struct OneNonce([u8; 12]);
    impl NonceSequence for OneNonce {
        fn advance(&mut self) -> std::result::Result<Nonce, ring::error::Unspecified> {
            Nonce::try_assume_unique_for_key(&self.0)
        }
    }

    let encrypted = &ciphertext[12..ciphertext.len() - 16];
    let tag = &ciphertext[ciphertext.len() - 16..];

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| EncryptionError::InvalidKeyLength)?;
    let mut opening_key = OpeningKey::new(unbound_key, OneNonce(nonce_bytes));

    let mut in_out = encrypted.to_vec();
    in_out.extend_from_slice(tag);

    let plaintext = opening_key
        .open_in_place(Aad::empty(), &mut in_out)
        .map_err(|_| EncryptionError::DecryptFailed)?;

    Ok(plaintext.to_vec())
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("invalid encryption key length")]
    InvalidKeyLength,
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
    #[error("random generation failed")]
    RandomFailed,
}
