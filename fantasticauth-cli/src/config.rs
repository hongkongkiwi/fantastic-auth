//! Configuration management for Fantastic Auth CLI
//!
//! SECURITY: Tokens and API keys are encrypted at rest using AES-256-GCM
//! with a key derived from machine-specific identifiers. This provides
//! protection against casual inspection of the config file while maintaining
//! usability.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// CLI Configuration
///
/// SECURITY NOTE: Sensitive fields (token, refresh_token) are stored encrypted.
/// The encryption key is derived from machine-specific identifiers, providing
//! basic protection against casual inspection but NOT against determined attackers
//! with system access.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    /// Fantastic Auth API URL
    pub api_url: Option<String>,
    /// Default tenant ID
    pub tenant_id: Option<String>,
    /// Saved authentication token (encrypted)
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    /// Token encryption nonce (required for decryption)
    #[serde(skip_serializing_if = "Option::is_none")]
    token_nonce: Option<String>,
    /// Refresh token (encrypted)
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    /// Refresh token encryption nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token_nonce: Option<String>,
    /// Encryption version for future migration
    #[serde(default = "default_encryption_version")]
    encryption_version: u32,
}

fn default_encryption_version() -> u32 {
    1
}

impl Config {
    /// Get configuration directory
    pub fn config_dir() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .context("Could not find config directory")?
            .join("fantasticauth");

        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Get data directory for CLI storage
    pub fn data_dir() -> Result<PathBuf> {
        let dir = dirs::data_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".fantasticauth")))
            .context("Could not find data directory")?;

        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Get configuration file path
    pub fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.toml"))
    }

    /// Get credentials file path (for secure storage)
    pub fn credentials_path() -> Result<PathBuf> {
        Ok(Self::data_dir()?.join("credentials"))
    }

    /// Load configuration from disk
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save configuration to disk
    ///
    /// SECURITY: Saves encrypted tokens to the config file
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        let contents = toml::to_string_pretty(self)?;

        // Set restrictive permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut file = std::fs::File::create(&path)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            file.write_all(contents.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&path, contents)?;
        }

        Ok(())
    }

    /// Get the decrypted authentication token
    ///
    /// SECURITY: Returns decrypted token. Handle with care.
    pub fn token(&self) -> Result<Option<String>> {
        match (&self.token, &self.token_nonce) {
            (Some(encrypted), Some(nonce)) => {
                let decrypted = Self::decrypt_credential(encrypted, nonce)?;
                Ok(Some(decrypted))
            }
            (Some(encrypted), None) => {
                // Legacy: token was stored plaintext, migrate it
                Ok(Some(encrypted.clone()))
            }
            _ => Ok(None),
        }
    }

    /// Set and encrypt the authentication token
    ///
    /// SECURITY: Encrypts token before storage
    pub fn set_token(&mut self, token: &str) -> Result<()> {
        let (encrypted, nonce) = Self::encrypt_credential(token)?;
        self.token = Some(encrypted);
        self.token_nonce = Some(nonce);
        self.save()
    }

    /// Get the decrypted refresh token
    pub fn refresh_token(&self) -> Result<Option<String>> {
        match (&self.refresh_token, &self.refresh_token_nonce) {
            (Some(encrypted), Some(nonce)) => {
                let decrypted = Self::decrypt_credential(encrypted, nonce)?;
                Ok(Some(decrypted))
            }
            (Some(encrypted), None) => {
                // Legacy: stored plaintext
                Ok(Some(encrypted.clone()))
            }
            _ => Ok(None),
        }
    }

    /// Set and encrypt the refresh token
    pub fn set_refresh_token(&mut self, token: &str) -> Result<()> {
        let (encrypted, nonce) = Self::encrypt_credential(token)?;
        self.refresh_token = Some(encrypted);
        self.refresh_token_nonce = Some(nonce);
        self.save()
    }

    /// Set a configuration value (non-sensitive)
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "api_url" => self.api_url = Some(value.to_string()),
            "tenant_id" => self.tenant_id = Some(value.to_string()),
            "token" => return self.set_token(value),
            "refresh_token" => return self.set_refresh_token(value),
            _ => anyhow::bail!("Unknown configuration key: {}", key),
        }
        self.save()
    }

    /// Get configuration value
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        match key {
            "api_url" => Ok(self.api_url.clone()),
            "tenant_id" => Ok(self.tenant_id.clone()),
            "token" => self.token(),
            "refresh_token" => self.refresh_token(),
            _ => Ok(None),
        }
    }

    /// Check if user is logged in
    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    /// Clear authentication tokens
    pub fn logout(&mut self) -> Result<()> {
        self.token = None;
        self.token_nonce = None;
        self.refresh_token = None;
        self.refresh_token_nonce = None;
        self.save()
    }

    // === Encryption Helpers ===

    /// Encrypt a credential using AES-256-GCM
    ///
    /// SECURITY: Uses a key derived from machine-specific identifiers.
    /// This provides basic protection but NOT security against determined attackers.
    fn encrypt_credential(plaintext: &str) -> Result<(String, String)> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;

        let key = Self::derive_encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {:?}", e))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        Ok((
            base64::encode(&ciphertext),
            base64::encode(&nonce_bytes),
        ))
    }

    /// Decrypt a credential using AES-256-GCM
    fn decrypt_credential(ciphertext: &str, nonce: &str) -> Result<String> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce as AesNonce,
        };

        let key = Self::derive_encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {:?}", e))?;

        let nonce_bytes = base64::decode(nonce)?;
        let nonce = AesNonce::from_slice(&nonce_bytes);

        let ciphertext_bytes = base64::decode(ciphertext)?;
        let plaintext = cipher
            .decrypt(nonce, ciphertext_bytes.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

        String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in decrypted data: {}", e))
    }

    /// Derive encryption key from machine-specific identifiers
    ///
    /// SECURITY: This is a best-effort approach. The key is derived from
    /// machine-specific data that should be consistent across runs but
    /// unique to this machine. NOT suitable for high-security scenarios.
    fn derive_encryption_key() -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};

        // Collect machine-specific identifiers
        let mut key_material = String::new();

        // Machine ID (Linux) / Hardware UUID (macOS) / Machine GUID (Windows)
        #[cfg(target_os = "linux")]
        {
            if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
                key_material.push_str(&id.trim());
            }
        }
        #[cfg(target_os = "macos")]
        {
            // Use user's home directory as a stable identifier
            if let Some(home) = dirs::home_dir() {
                key_material.push_str(&home.to_string_lossy());
            }
        }
        #[cfg(target_os = "windows")]
        {
            // Use LOCALAPPDATA path
            if let Some(local_app_data) = dirs::data_local_dir() {
                key_material.push_str(&local_app_data.to_string_lossy());
            }
        }

        // Add user-specific component
        if let Some(user) = dirs::home_dir() {
            key_material.push_str(&user.to_string_lossy());
        }

        // Add a constant salt (this is OK because the key_material is machine-specific)
        key_material.push_str("fantasticauth-cli-v1");

        // Derive 256-bit key using SHA-256
        let hash = Sha256::digest(key_material.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);

        Ok(key)
    }
}

/// Interactive configuration setup
pub async fn init_interactive() -> Result<Config> {
    use dialoguer::{Input, Select};

    println!("🔐 Fantastic Auth CLI Configuration\n");

    // API URL
    let api_url: String = Input::new()
        .with_prompt("Fantastic Auth API URL")
        .default("https://api.fantasticauth.dev".to_string())
        .interact_text()?;

    // Tenant selection
    let tenant_choice = Select::new()
        .with_prompt("Authentication method")
        .items(&["User login (JWT)", "API Key (Service account)"])
        .interact()?;

    let mut config = Config {
        api_url: Some(api_url.clone()),
        ..Default::default()
    };

    if tenant_choice == 1 {
        // API Key auth
        let api_key: String = Input::new()
            .with_prompt("API Key")
            .interact_text()?;

        config.set_token(&api_key)?;

        let tenant_id: String = Input::new()
            .with_prompt("Default Tenant ID")
            .interact_text()?;

        config.tenant_id = Some(tenant_id);
    } else {
        // User login - just set the URL for now
        println!("\nConfiguration saved. Run 'fantasticauth auth login <email>' to authenticate.");
    }

    config.save()?;
    println!("\n✅ Configuration saved to {}", Config::config_path()?.display());

    Ok(config)
}

// Add required imports for encryption
use std::io::Write;
