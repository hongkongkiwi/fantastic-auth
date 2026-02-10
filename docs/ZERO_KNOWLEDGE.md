# Zero-Knowledge Architecture

Vault implements a true **zero-knowledge architecture** where the server cannot read user data even if fully compromised. This document describes the design, implementation, and security properties.

## Table of Contents

- [Overview](#overview)
- [Security Properties](#security-properties)
- [Architecture](#architecture)
- [Key Derivation](#key-derivation)
- [Client-Side Encryption](#client-side-encryption)
- [Zero-Knowledge Proofs](#zero-knowledge-proofs)
- [Secure Computation](#secure-computation)
- [Social Recovery](#social-recovery)
- [API Reference](#api-reference)
- [Implementation Details](#implementation-details)
- [Security Considerations](#security-considerations)

## Overview

True zero-knowledge means:

1. **Encrypted user data** - Server stores encrypted blobs, cannot decrypt
2. **Client-side encryption** - Data encrypted in browser/app before sending
3. **Zero-knowledge proofs** - Prove identity without revealing secrets
4. **No key escrow** - Server never has access to decryption keys

### Why Zero-Knowledge?

Traditional authentication systems store password hashes on the server. If compromised:

- Attackers can crack password hashes
- All user data is exposed
- No protection against insider threats

With zero-knowledge:

- Server compromise reveals only encrypted data
- Passwords never leave the client
- Even Vault employees cannot read user data
- Cannot comply with requests for plaintext data (we don't have it)

## Security Properties

| Threat Model | Protection |
|--------------|------------|
| Server compromise | Encrypted data only, keys not present |
| Database leak | Useless without user passwords |
| Insider threat | Employees cannot decrypt user data |
| Legal requests | Cannot provide what we don't have |
| Passive network attacks | All data encrypted in transit and at rest |
| Active MITM | ZK proofs prevent credential theft |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          CLIENT                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Password   │→│  Master Key  │→│  RSA Key Pair        │  │
│  │   Input      │  │  Derivation  │  │  (from key material) │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│         │                                        │              │
│         │         ┌──────────────┐               │              │
│         └────────→│  User Data   │←──────────────┘              │
│                   │  Encryption  │                             │
│                   │  (AES-256-GCM│                             │
│                   │   with DEK)  │                             │
│                   └──────────────┘                             │
│                          │                                      │
│                          ↓                                      │
│                   Encrypted Blob                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                          SERVER                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Storage (server cannot decrypt)                         │  │
│  │  • Encrypted user data (AES-256-GCM)                    │  │
│  │  • RSA public key                                       │  │
│  │  • Encrypted RSA private key (wrapped with master key)  │  │
│  │  • Salt for key derivation                              │  │
│  │  • ZK proof commitment                                  │  │
│  │  • Recovery share hashes                                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  What server NEVER has:                                  │  │
│  │  • User password                                         │  │
│  │  • Master key                                            │  │
│  │  • Unwrapped RSA private key                             │  │
│  │  • Data encryption key (DEK)                             │  │
│  │  • Plaintext user data                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Key Derivation

### Master Key Derivation

The master key is derived from the user's password using **Argon2id**, winner of the Password Hashing Competition.

```rust
// Derive master key from password
let master_key = derive_master_key_from_password(
    password,
    &salt,
    Some(Argon2Params::default()),
)?;
```

### Key Splitting

The 64 bytes of key material are split into:

- **Bytes 0-31**: Symmetric encryption key (AES-256)
- **Bytes 32-63**: Authentication key (HMAC-SHA256)

### RSA Key Generation

An RSA-2048 key pair is generated from the encryption key material for wrapping/unwrapping data encryption keys.

### Argon2id Parameters

| Parameter | Default | Conservative | Fast (testing) |
|-----------|---------|--------------|----------------|
| Memory | 64 MB | 256 MB | 16 MB |
| Iterations | 3 | 4 | 2 |
| Parallelism | 4 | 4 | 1 |

## Client-Side Encryption

### Encryption Flow

```
User Data (JSON)
       |
       v
Serialize to bytes
       |
       v
Generate DEK (random 32 bytes)
       |
       +--> Encrypt data with AES-256-GCM
       |    +--> Ciphertext
       |    +--> Nonce (12 bytes)
       |
       v
Wrap DEK with RSA public key (OAEP-SHA256)
       |
       +--> Encrypted DEK
```

### Data Encryption Key (DEK)

Each piece of user data is encrypted with a unique, randomly-generated DEK. This provides:

- **Forward secrecy**: Compromising one DEK doesn't expose other data
- **Key rotation**: Can re-encrypt with new DEK without changing master key
- **Fine-grained access**: Different DEKs for different data types

### Storage Format

```json
{
  "version": 1,
  "ciphertext": "base64(...)",
  "nonce": "base64(12 bytes)",
  "encrypted_dek": {
    "ciphertext": "base64(RSA encrypted)"
  },
  "encrypted_at": "2024-01-15T10:30:00Z"
}
```

## Zero-Knowledge Proofs

### Password Authentication Without Exposure

Traditional password authentication sends the password (or a hash) to the server. Our ZK proof system:

1. Client proves knowledge of password
2. Server verifies without learning password
3. Replay attacks prevented via challenge-response

### Registration

```rust
// Client-side
let commitment = ZkPasswordProver::commit(password, &salt);

// Send to server: salt, commitment (NOT password)
```

### Login

```rust
// 1. Server sends challenge
let challenge = server.generate_challenge();

// 2. Client generates proof
let proof = ZkPasswordProver::prove(password, &salt, Some(challenge));

// 3. Server verifies
let valid = ZkPasswordVerifier::verify(&proof, &commitment, &salt)?;
```

### Security Properties

- **Zero-knowledge**: Server learns nothing about password from proof
- **Soundness**: Cheaters cannot forge valid proofs
- **Completeness**: Valid proofs always verify
- **Non-interactive**: Single round-trip authentication

## Secure Computation

### Homomorphic Operations (Planned)

Enable computations on encrypted data:

```rust
// Verify age >= 18 without decrypting
let is_adult = SecureComputation::verify_age_eligibility(&encrypted_age, 18)?;

// Verify income >= threshold
let qualifies = SecureComputation::verify_income_eligibility(&encrypted_income, 50000)?;

// Range proofs
let good_credit = ZkRangeProof::prove_range(credit_score, 670, 850)?;
```

### Current Implementation

The current implementation provides the API structure. Full homomorphic encryption will be integrated via:

- Microsoft SEAL (BFV/CKKS schemes)
- Zama Concrete (TFHE)
- IBM HELib

### Use Cases

| Verification | Without ZK | With ZK |
|--------------|------------|---------|
| Age check | Server sees birthdate | Server sees only boolean result |
| Income verification | Server sees exact salary | Server sees only threshold pass/fail |
| Credit score | Server sees exact score | Server sees range membership |
| Identity verification | Server sees all PII | Server sees only verification result |

## Social Recovery

### Shamir's Secret Sharing

Account recovery without server knowledge using SSS:

```rust
// Split master key into 5 shares, need 3 to recover
let shares = SocialRecovery::create_shares(
    &master_key,
    3,  // threshold
    5,  // total shares
    "user_123",
)?;

// Distribute shares to trusted contacts
// Any 3 contacts can help recover the account
```

### Recovery Flow

```
User loses password
       |
       v
Initiate recovery → Create recovery session
       |
       v
Collect shares from trusted contacts
       |
       v
Reconstruct master key (T of N shares)
       |
       v
Set new password → Re-encrypt data with new keys
```

### Security Properties

- **Threshold security**: Fewer than T shares reveal nothing
- **No single point of failure**: No single contact can access account
- **Collusion resistance**: Need T contacts to collude
- **Forward secrecy**: Old shares invalid after recovery

## API Reference

### Rust (vault-core)

```rust
use vault_core::zk::*;

// Key derivation
let salt = generate_salt();
let master_key = derive_master_key_from_password(password, &salt, None)?;

// Encryption
let encrypted = encrypt_user_data(&profile, &master_key)?;
let decrypted = decrypt_user_data(&encrypted, &master_key)?;

// ZK proofs
let proof = generate_password_proof(password, &salt, None)?;
let valid = verify_password_proof(&proof, &commitment, &salt)?;

// Recovery
let shares = SocialRecovery::create_shares(&master_key, 3, 5, user_id)?;
let recovered_key = SocialRecovery::recover_from_shares(&collected_shares)?;
```

### JavaScript/TypeScript (app SDK JS package)

```typescript
import {
  deriveMasterKey,
  encryptUserData,
  decryptUserData,
  ZkPasswordProver,
  SocialRecovery,
  generateSalt,
} from '@vault/sdk/zk';

// Key derivation
const salt = generateSalt();
const masterKey = await deriveMasterKey(password, salt);

// Encryption
const encrypted = await encryptUserData(profile, masterKey);
const decrypted = await decryptUserData(encrypted, masterKey);

// ZK proofs
const commitment = await ZkPasswordProver.commit(password, salt);
const proof = await ZkPasswordProver.prove(password, salt, challenge);

// Recovery
const shares = SocialRecovery.createShares(masterKey, 3, 5, userId);
```

## Implementation Details

### File Structure

```
vault-core/src/zk/
├── mod.rs                  # Module exports
├── encryption.rs           # AES-256-GCM + RSA-OAEP
├── key_derivation.rs       # Argon2id key derivation
├── proofs.rs               # ZK password proofs
├── secure_computation.rs   # Homomorphic operations
└── recovery.rs             # Shamir's Secret Sharing

packages/sdks/app-sdks/js/src/zk/
├── index.ts                # Module exports
├── encryption.ts           # Web Crypto API encryption
├── keyDerivation.ts        # Browser key derivation
├── proofs.ts               # ZK proof generation
└── recovery.ts             # Recovery share management
```

### Database Schema

```sql
-- Zero-knowledge user keys
CREATE TABLE zk_user_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    salt BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    encrypted_private_key BYTEA NOT NULL,
    zk_commitment BYTEA NOT NULL,
    recovery_shares_hash BYTEA,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    rotated_at TIMESTAMPTZ
);

-- Encrypted user profiles
CREATE TABLE zk_encrypted_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    encrypted_data BYTEA NOT NULL,
    data_nonce BYTEA NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Recovery shares (stored by guardians)
CREATE TABLE zk_recovery_shares (
    share_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    guardian_id UUID REFERENCES users(id),
    share_hash BYTEA NOT NULL,  -- For verification, not the share itself
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Server compromise | Encrypted data only, no keys |
| Database leak | Useless without passwords |
| Insider threat | No access to decryption keys |
| Legal requests | Cannot provide plaintext |
| Brute force | Argon2id with high memory cost |
| Side-channel | Constant-time operations |
| Quantum computing | Hybrid post-quantum ready |

### Best Practices

1. **Always use HTTPS** - Prevents MITM attacks on key exchange
2. **Secure key storage** - Never store master key in localStorage
3. **Memory clearing** - Clear sensitive data from memory after use
4. **Rate limiting** - Prevent brute force on ZK proofs
5. **Key rotation** - Support periodic re-encryption
6. **Audit logging** - Log recovery attempts, key rotations

### Limitations

1. **Password strength** - Weak passwords can still be brute-forced offline
2. **No password reset** - Without recovery shares, data is lost if password forgotten
3. **Client-side trust** - Users must trust the client code (verifiable builds help)
4. **Performance** - Client-side encryption adds latency
5. **Browser storage** - Session keys need secure storage mechanism

### Future Enhancements

- Hardware security module (HSM) integration
- Threshold signatures for distributed authentication
- Post-quantum ZK proof systems
- Formal verification of cryptographic protocols
- Secure multi-party computation for recovery

## Conclusion

Vault's zero-knowledge architecture provides unprecedented privacy and security:

- **True zero-knowledge**: Server never sees plaintext or keys
- **User control**: Users own their encryption keys
- **Censorship resistance**: Cannot be compelled to decrypt
- **Future-proof**: Ready for post-quantum cryptography

This architecture creates unbeatable differentiation - true privacy that no competitor offers.
