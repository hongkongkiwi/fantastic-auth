//! Zero-Knowledge Architecture Example
//!
//! This example demonstrates how to use the zero-knowledge encryption
//! features of the Vault SDK.
//!
//! Run with: cargo run --example zero_knowledge_example

use vault_core::zk::*;
use vault_core::models::user::{UserProfile, Address};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Vault Zero-Knowledge Example ===\n");

    // =========================================================================
    // Step 1: User Registration (Zero-Knowledge)
    // =========================================================================
    println!("1. User Registration");
    println!("   - User enters password in browser/app");
    println!("   - Client generates salt");
    println!("   - Client derives master key from password + salt");
    println!("   - Client generates RSA key pair");

    let password = "my_secure_password_123!";
    let salt = generate_salt();
    println!("   - Generated salt: {} bytes", salt.len());

    // Derive master key from password
    let master_key = derive_master_key_from_password(password, &salt, None)?;
    println!("   - Master key derived successfully");
    println!("   - Encryption key: {} bytes", master_key.encryption_key.len());
    println!("   - Authentication key: {} bytes", master_key.authentication_key.len());

    // Generate password commitment for ZK proof
    let commitment = MasterKeyDerivation::generate_commitment(password, &salt);
    println!("   - ZK commitment generated: {} bytes", commitment.len());

    // Prepare registration data for server
    let registration_data = ZkRegistrationData {
        version: 1,
        salt: salt.clone(),
        public_key: master_key.rsa_public_key_to_der()?,
        encrypted_private_key: master_key.encrypt_private_key()?,
        zk_commitment: commitment,
        recovery_shares_hash: None,
    };
    println!("   - Registration data prepared for server");
    println!("   - Server receives: salt, public key, encrypted private key, commitment");
    println!("   - Server NEVER receives: password, master key, private key\n");

    // =========================================================================
    // Step 2: User Login (Zero-Knowledge Proof)
    // =========================================================================
    println!("2. User Login (Zero-Knowledge)");
    println!("   - Server sends challenge to client");

    let challenge = ZkAuthentication::server_challenge();
    println!("   - Challenge generated: {} bytes", challenge.len());

    println!("   - Client generates ZK proof of password knowledge");
    let proof = ZkAuthentication::client_prove(password, &salt, challenge)?;
    println!("   - ZK proof generated (version: {})", proof.version);

    println!("   - Server verifies proof without learning password");
    let is_valid = verify_password_proof(&proof, &commitment, &salt)?;
    println!("   - Proof valid: {}\n", is_valid);

    // =========================================================================
    // Step 3: Encrypt User Data (Client-Side)
    // =========================================================================
    println!("3. Encrypt User Profile (Client-Side)");
    println!("   - User profile created");

    let profile = UserProfile {
        name: Some("John Doe".to_string()),
        given_name: Some("John".to_string()),
        family_name: Some("Doe".to_string()),
        email: Some("john.doe@example.com".to_string()),
        phone_number: Some("+1-555-123-4567".to_string()),
        address: Some(Address {
            formatted: Some("123 Main St, Boston, MA 02101".to_string()),
            street_address: Some("123 Main St".to_string()),
            locality: Some("Boston".to_string()),
            region: Some("MA".to_string()),
            postal_code: Some("02101".to_string()),
            country: Some("US".to_string()),
        }),
        birthdate: Some("1990-05-15".to_string()),
        ..Default::default()
    };

    println!("   - Name: {:?}", profile.name);
    println!("   - Email: {:?}", profile.email);
    println!("   - Phone: {:?}", profile.phone_number);

    println!("   - Encrypting profile with AES-256-GCM...");
    let encrypted_profile = encrypt_user_data(&profile, &master_key)?;
    println!("   - Profile encrypted successfully!");
    println!("   - Ciphertext: {} bytes", encrypted_profile.ciphertext.len());
    println!("   - Nonce: {} bytes", encrypted_profile.nonce.len());
    println!("   - Encrypted DEK: {} bytes", encrypted_profile.encrypted_dek.ciphertext.len());
    println!("   - Server stores encrypted blob, cannot read plaintext\n");

    // =========================================================================
    // Step 4: Decrypt User Data (Client-Side)
    // =========================================================================
    println!("4. Decrypt User Profile (Client-Side)");
    println!("   - User requests their profile");
    println!("   - Server sends encrypted blob");
    println!("   - Client decrypts with master key...");

    let decrypted_profile = decrypt_user_data(&encrypted_profile, &master_key)?;
    println!("   - Profile decrypted successfully!");
    println!("   - Decrypted name: {:?}", decrypted_profile.name);
    println!("   - Decrypted email: {:?}", decrypted_profile.email);
    println!("   - Data matches original: {}\n", decrypted_profile.name == profile.name);

    // =========================================================================
    // Step 5: Social Recovery Setup
    // =========================================================================
    println!("5. Social Recovery Setup (Shamir's Secret Sharing)");
    println!("   - Split master key into 5 shares");
    println!("   - Threshold: 3 shares needed for recovery");

    let shares = SocialRecovery::create_shares(
        &master_key,
        3,  // threshold
        5,  // total shares
        "user_123",
    )?;

    println!("   - Created {} shares", shares.len());
    for (i, share) in shares.iter().enumerate() {
        println!("   - Share {}: index={}, value={} bytes",
            i + 1,
            share.index,
            share.value.len()
        );
    }

    // Generate share hashes for verification
    let share_hashes: Vec<_> = shares.iter()
        .map(|s| s.hash())
        .collect();
    println!("   - Share hashes generated for verification");

    // Distribute shares to trusted contacts
    println!("   - Shares distributed to trusted contacts:");
    println!("     * Share 1 → Alice (sister)");
    println!("     * Share 2 → Bob (brother)");
    println!("     * Share 3 → Charlie (best friend)");
    println!("     * Share 4 → David (colleague)");
    println!("     * Share 5 → Emma (spouse)\n");

    // =========================================================================
    // Step 6: Account Recovery
    // =========================================================================
    println!("6. Account Recovery Simulation");
    println!("   - User forgot password");
    println!("   - User collects shares from 3 contacts...");

    // Simulate collecting shares from 3 contacts
    let collected_shares = vec![
        shares[0].clone(), // From Alice
        shares[2].clone(), // From Charlie
        shares[4].clone(), // From Emma
    ];
    println!("   - Collected {} shares", collected_shares.len());

    println!("   - Reconstructing master key...");
    let recovered_key = SocialRecovery::recover_from_shares(&collected_shares)?;
    println!("   - Master key recovered successfully!");

    // Verify recovered key can decrypt data
    let decrypted_with_recovered = decrypt_user_data(&encrypted_profile, &recovered_key)?;
    println!("   - Can decrypt data with recovered key: {}\n",
        decrypted_with_recovered.name == profile.name);

    // =========================================================================
    // Step 7: Security Properties
    // =========================================================================
    println!("7. Security Properties");
    println!("   ✓ Server compromise: Only encrypted data, no keys");
    println!("   ✓ Database leak: Useless without user passwords");
    println!("   ✓ Insider threat: Employees cannot read user data");
    println!("   ✓ Legal requests: Cannot provide plaintext (don't have keys)");
    println!("   ✓ Single guardian compromise: Need 3 shares to recover");
    println!("   ✓ Zero-knowledge: Server never learns password\n");

    // =========================================================================
    // Summary
    // =========================================================================
    println!("=== Summary ===");
    println!("Zero-knowledge architecture provides:");
    println!("- Client-side encryption: Data encrypted before leaving browser");
    println!("- User-controlled keys: Server never has decryption keys");
    println!("- ZK authentication: Prove identity without revealing secrets");
    println!("- Social recovery: Recover account without server knowledge");
    println!("- True privacy: Server compromise doesn't expose user data\n");

    println!("✅ Example completed successfully!");

    Ok(())
}
