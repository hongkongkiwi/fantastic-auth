//! Symmetric encryption helpers (AES-256-GCM)

use crate::crypto::generate_random_bytes;
use crate::error::VaultError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub fn encrypt_to_base64(key: &[u8], plaintext: &[u8]) -> Result<String, VaultError> {
    use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM};

    if key.len() != 32 {
        return Err(VaultError::crypto("Invalid encryption key length"));
    }

    let nonce_bytes: [u8; 12] = generate_random_bytes(12)
        .try_into()
        .map_err(|_| VaultError::crypto("Failed to generate nonce"))?;

    struct OneNonce([u8; 12]);
    impl NonceSequence for OneNonce {
        fn advance(&mut self) -> std::result::Result<Nonce, ring::error::Unspecified> {
            Nonce::try_assume_unique_for_key(&self.0)
        }
    }

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| VaultError::crypto("Invalid key"))?;
    let mut sealing_key = SealingKey::new(unbound_key, OneNonce(nonce_bytes));

    let mut ciphertext = plaintext.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::empty(), &mut ciphertext)
        .map_err(|_| VaultError::crypto("Encryption failed"))?;

    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    combined.extend_from_slice(tag.as_ref());

    Ok(STANDARD.encode(combined))
}

pub fn decrypt_from_base64(key: &[u8], encoded: &str) -> Result<Vec<u8>, VaultError> {
    use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, UnboundKey, AES_256_GCM};

    if key.len() != 32 {
        return Err(VaultError::crypto("Invalid encryption key length"));
    }

    let ciphertext = STANDARD
        .decode(encoded)
        .map_err(|_| VaultError::crypto("Invalid ciphertext"))?;

    if ciphertext.len() < 12 + 16 {
        return Err(VaultError::crypto("Ciphertext too short"));
    }

    let nonce_bytes: [u8; 12] = ciphertext[..12]
        .try_into()
        .map_err(|_| VaultError::crypto("Invalid nonce"))?;

    struct OneNonce([u8; 12]);
    impl NonceSequence for OneNonce {
        fn advance(&mut self) -> std::result::Result<Nonce, ring::error::Unspecified> {
            Nonce::try_assume_unique_for_key(&self.0)
        }
    }

    let encrypted = &ciphertext[12..ciphertext.len() - 16];
    let tag = &ciphertext[ciphertext.len() - 16..];

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| VaultError::crypto("Invalid key"))?;
    let mut opening_key = OpeningKey::new(unbound_key, OneNonce(nonce_bytes));

    let mut in_out = encrypted.to_vec();
    in_out.extend_from_slice(tag);

    let plaintext = opening_key
        .open_in_place(Aad::empty(), &mut in_out)
        .map_err(|_| VaultError::crypto("Decryption failed"))?;

    Ok(plaintext.to_vec())
}
