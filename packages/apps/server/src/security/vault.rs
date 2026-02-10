//! HashiCorp Vault Integration
//!
//! Provides secure secrets management using HashiCorp Vault.
//! Supports KV v2, Transit (encryption as a service), and PKI engines.
//!
//! # Features
//!
//! - Dynamic secrets (database credentials, cloud provider tokens)
//! - Encryption as a Service (Transit secrets engine)
//! - PKI certificate management
//! - Automatic token renewal
//! - Kubernetes auth method support

use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Vault client configuration
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Vault server address
    pub addr: String,
    /// Authentication method
    pub auth: VaultAuthMethod,
    /// Namespace (for Vault Enterprise)
    pub namespace: Option<String>,
    /// TLS configuration
    pub tls: VaultTlsConfig,
    /// Timeout for requests
    pub timeout: Duration,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            addr: "https://127.0.0.1:8200".to_string(),
            auth: VaultAuthMethod::Token {
                token: "".to_string(),
            },
            namespace: None,
            tls: VaultTlsConfig::default(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// TLS configuration for Vault
#[derive(Debug, Clone)]
pub struct VaultTlsConfig {
    /// CA certificate PEM
    pub ca_cert: Option<String>,
    /// Client certificate PEM
    pub client_cert: Option<String>,
    /// Client key PEM
    pub client_key: Option<String>,
    /// Skip TLS verification (NOT for production)
    pub skip_verify: bool,
}

impl Default for VaultTlsConfig {
    fn default() -> Self {
        Self {
            ca_cert: None,
            client_cert: None,
            client_key: None,
            skip_verify: false,
        }
    }
}

/// Vault authentication methods
#[derive(Debug, Clone)]
pub enum VaultAuthMethod {
    /// Static token
    Token { token: String },
    /// Kubernetes JWT
    Kubernetes { role: String, jwt_path: String },
    /// AppRole
    AppRole { role_id: String, secret_id: String },
    /// AWS IAM
    AwsIam { role: String, iam_server_id: Option<String> },
    /// GCP
    Gcp { role: String, jwt: String },
    /// Azure
    Azure { role: String, jwt: String },
}

/// Vault client
pub struct VaultClient {
    config: VaultConfig,
    http_client: reqwest::Client,
    auth_state: Arc<RwLock<AuthState>>,
}

#[derive(Debug)]
struct AuthState {
    token: String,
    expires_at: Option<Instant>,
    renewable: bool,
}

/// Vault errors
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("Secret not found: {0}")]
    SecretNotFound(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Request failed: {0}")]
    RequestFailed(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Token expired")]
    TokenExpired,
    #[error("Not initialized")]
    NotInitialized,
}

/// KV v2 secret response
#[derive(Debug, Deserialize)]
pub struct Kv2Secret {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: i64,
    pub data: Kv2Data,
    pub wrap_info: Option<serde_json::Value>,
    pub warnings: Option<Vec<String>>,
    pub auth: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct Kv2Data {
    pub data: serde_json::Value,
    pub metadata: Kv2Metadata,
}

#[derive(Debug, Deserialize)]
pub struct Kv2Metadata {
    pub created_time: String,
    pub custom_metadata: Option<serde_json::Value>,
    pub deletion_time: String,
    pub destroyed: bool,
    pub version: i64,
}

/// Transit encrypt response
#[derive(Debug, Deserialize)]
pub struct TransitEncryptResponse {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: i64,
    pub data: TransitEncryptData,
}

#[derive(Debug, Deserialize)]
pub struct TransitEncryptData {
    pub ciphertext: String,
}

/// Transit decrypt response
#[derive(Debug, Deserialize)]
pub struct TransitDecryptResponse {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: i64,
    pub data: TransitDecryptData,
}

#[derive(Debug, Deserialize)]
pub struct TransitDecryptData {
    pub plaintext: String,
}

/// Database credentials response
#[derive(Debug, Deserialize)]
pub struct DatabaseCredentials {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: i64,
    pub data: DatabaseCredsData,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseCredsData {
    pub username: String,
    pub password: String,
}

impl VaultClient {
    /// Create a new Vault client
    pub async fn new(config: VaultConfig) -> Result<Self, VaultError> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .danger_accept_invalid_certs(config.tls.skip_verify)
            .build()
            .map_err(|e| VaultError::RequestFailed(format!("HTTP client: {}", e)))?;
        
        let client = Self {
            config: config.clone(),
            http_client,
            auth_state: Arc::new(RwLock::new(AuthState {
                token: String::new(),
                expires_at: None,
                renewable: false,
            })),
        };
        
        // Authenticate
        client.authenticate().await?;
        
        Ok(client)
    }
    
    /// Authenticate with Vault
    async fn authenticate(&self) -> Result<(), VaultError> {
        match &self.config.auth {
            VaultAuthMethod::Token { token } => {
                // Verify the token is valid
                self.verify_token(token).await?;
                
                let mut state = self.auth_state.write().await;
                state.token = token.clone();
                state.renewable = false;
            }
            VaultAuthMethod::Kubernetes { role, jwt_path } => {
                self.auth_kubernetes(role, jwt_path).await?;
            }
            VaultAuthMethod::AppRole { role_id, secret_id } => {
                self.auth_approle(role_id, secret_id).await?;
            }
            _ => {
                return Err(VaultError::AuthenticationFailed(
                    "Auth method not yet implemented".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// Verify a token is valid
    async fn verify_token(&self, token: &str) -> Result<(), VaultError> {
        let url = format!("{}/v1/auth/token/lookup-self", self.config.addr);
        
        let response = self.http_client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| VaultError::RequestFailed(e.to_string()))?;
        
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(VaultError::AuthenticationFailed(
                format!("Token verification failed: {} - {}", status, text)
            ));
        }
        
        Ok(())
    }
    
    /// Authenticate via Kubernetes
    async fn auth_kubernetes(&self, role: &str, jwt_path: &str) -> Result<(), VaultError> {
        // Read JWT from file
        let jwt = tokio::fs::read_to_string(jwt_path)
            .await
            .map_err(|e| VaultError::AuthenticationFailed(
                format!("Failed to read JWT: {}", e)
            ))?;
        
        let url = format!("{}/v1/auth/kubernetes/login", self.config.addr);
        
        let body = serde_json::json!({
            "role": role,
            "jwt": jwt.trim(),
        });
        
        let response = self.http_client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| VaultError::RequestFailed(e.to_string()))?;
        
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(VaultError::AuthenticationFailed(
                format!("Kubernetes auth failed: {} - {}", status, text)
            ));
        }
        
        let auth_response: AuthResponse = response.json()
            .await
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;
        
        let mut state = self.auth_state.write().await;
        state.token = auth_response.auth.client_token;
        state.renewable = auth_response.auth.renewable;
        if auth_response.auth.lease_duration > 0 {
            state.expires_at = Some(Instant::now() + Duration::from_secs(auth_response.auth.lease_duration as u64));
        }
        
        Ok(())
    }
    
    /// Authenticate via AppRole
    async fn auth_approle(&self, role_id: &str, secret_id: &str) -> Result<(), VaultError> {
        let url = format!("{}/v1/auth/approle/login", self.config.addr);
        
        let body = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id,
        });
        
        let response = self.http_client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| VaultError::RequestFailed(e.to_string()))?;
        
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(VaultError::AuthenticationFailed(
                format!("AppRole auth failed: {} - {}", status, text)
            ));
        }
        
        let auth_response: AuthResponse = response.json()
            .await
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;
        
        let mut state = self.auth_state.write().await;
        state.token = auth_response.auth.client_token;
        state.renewable = auth_response.auth.renewable;
        if auth_response.auth.lease_duration > 0 {
            state.expires_at = Some(Instant::now() + Duration::from_secs(auth_response.auth.lease_duration as u64));
        }
        
        Ok(())
    }
    
    /// Get current token
    async fn get_token(&self) -> Result<String, VaultError> {
        let state = self.auth_state.read().await;
        
        if state.token.is_empty() {
            return Err(VaultError::NotInitialized);
        }
        
        // Check if token needs renewal
        let needs_renewal = if let Some(expires_at) = state.expires_at {
            Instant::now() > expires_at && state.renewable
        } else {
            false
        };
        
        let token = state.token.clone();
        drop(state);
        
        if needs_renewal {
            self.renew_token().await?;
            // Re-read state after renewal
            let state = self.auth_state.read().await;
            Ok(state.token.clone())
        } else {
            Ok(token)
        }
    }
    
    /// Renew the current token
    async fn renew_token(&self) -> Result<(), VaultError> {
        let url = format!("{}/v1/auth/token/renew-self", self.config.addr);
        
        // Get token directly without going through get_token to avoid recursion
        let token = {
            let state = self.auth_state.read().await;
            if state.token.is_empty() {
                return Err(VaultError::NotInitialized);
            }
            state.token.clone()
        };
        
        let response = self.http_client
            .post(&url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| VaultError::RequestFailed(e.to_string()))?;
        
        if !response.status().is_success() {
            return Err(VaultError::TokenExpired);
        }
        
        let auth_response: AuthResponse = response.json()
            .await
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;
        
        let mut state = self.auth_state.write().await;
        state.token = auth_response.auth.client_token;
        if auth_response.auth.lease_duration > 0 {
            state.expires_at = Some(Instant::now() + Duration::from_secs(auth_response.auth.lease_duration as u64));
        }
        
        Ok(())
    }
    
    /// Read a secret from KV v2
    pub async fn read_secret(&self, path: &str) -> Result<Kv2Secret, VaultError> {
        let token = self.get_token().await?;
        
        // Convert path to KV v2 API format
        // secret/data/my-secret -> /v1/secret/data/my-secret
        let url = format!("{}/v1/{}", self.config.addr, path);
        
        let mut request = self.http_client
            .get(&url)
            .header("X-Vault-Token", &token);
        
        if let Some(ns) = &self.config.namespace {
            request = request.header("X-Vault-Namespace", ns);
        }
        
        let response = request
            .send()
            .await
            .map_err(|e| VaultError::RequestFailed(e.to_string()))?;
        
        match response.status() {
            status if status.is_success() => {
                response.json()
                    .await
                    .map_err(|e| VaultError::SerializationError(e.to_string()))
            }
            reqwest::StatusCode::NOT_FOUND => {
                Err(VaultError::SecretNotFound(path.to_string()))
            }
            reqwest::StatusCode::FORBIDDEN => {
                Err(VaultError::PermissionDenied(path.to_string()))
            }
            _ => {
                let text = response.text().await.unwrap_or_default();
                Err(VaultError::RequestFailed(text))
            }
        }
    }
    
    /// Write a secret to KV v2
    pub async fn write_secret(
        &self,
        path: &str,
        data: serde_json::Value,
    ) -> Result<(), VaultError> {
        let token = self.get_token().await?;
        
        // Convert path to KV v2 API format
        let url = format!("{}/v1/{}", self.config.addr, path);
        
        let body = serde_json::json!({
            "data": data,
        });
        
        let mut request = self.http_client
            .post(&url)
            .header("X-Vault-Token", &token)
            .json(&body);
        
        if let Some(ns) = &self.config.namespace {
            request = request.header("X-Vault-Namespace", ns);
        }
        
        let response = request
            .send()
            .await
            .map_err(|e| VaultError::RequestFailed(e.to_string()))?;
        
        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(VaultError::RequestFailed(text));
        }
        
        Ok(())
    }
    
    /// Encrypt data using Transit engine
    pub async fn transit_encrypt(
        &self,
        key_name: &str,
        plaintext: &str,
    ) -> Result<String, VaultError> {
        let token = self.get_token().await?;
        
        let url = format!("{}/v1/transit/encrypt/{}", self.config.addr, key_name);
        
        let body = serde_json::json!({
            "plaintext": base64::encode(plaintext),
        });
        
        let response = self.http_client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&body)
            .send()
            .await
            .map_err(|e| VaultError::RequestFailed(e.to_string()))?;
        
        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(VaultError::RequestFailed(text));
        }
        
        let encrypt_response: TransitEncryptResponse = response.json()
            .await
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;
        
        Ok(encrypt_response.data.ciphertext)
    }
    
    /// Decrypt data using Transit engine
    pub async fn transit_decrypt(
        &self,
        key_name: &str,
        ciphertext: &str,
    ) -> Result<String, VaultError> {
        let token = self.get_token().await?;
        
        let url = format!("{}/v1/transit/decrypt/{}", self.config.addr, key_name);
        
        let body = serde_json::json!({
            "ciphertext": ciphertext,
        });
        
        let response = self.http_client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&body)
            .send()
            .await
            .map_err(|e| VaultError::RequestFailed(e.to_string()))?;
        
        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(VaultError::RequestFailed(text));
        }
        
        let decrypt_response: TransitDecryptResponse = response.json()
            .await
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;
        
        let plaintext = base64::decode(&decrypt_response.data.plaintext)
            .map_err(|e| VaultError::SerializationError(format!("Base64 decode: {}", e)))?;
        
        String::from_utf8(plaintext)
            .map_err(|e| VaultError::SerializationError(format!("UTF-8: {}", e)))
    }
    
    /// Generate database credentials
    pub async fn generate_db_credentials(
        &self,
        role: &str,
    ) -> Result<DatabaseCredentials, VaultError> {
        let token = self.get_token().await?;
        
        let url = format!("{}/v1/database/creds/{}", self.config.addr, role);
        
        let response = self.http_client
            .get(&url)
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| VaultError::RequestFailed(e.to_string()))?;
        
        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(VaultError::RequestFailed(text));
        }
        
        response.json()
            .await
            .map_err(|e| VaultError::SerializationError(e.to_string()))
    }
}

/// Auth response structure
#[derive(Debug, Deserialize)]
struct AuthResponse {
    auth: AuthData,
}

#[derive(Debug, Deserialize)]
struct AuthData {
    #[serde(rename = "client_token")]
    client_token: String,
    renewable: bool,
    #[serde(rename = "lease_duration")]
    lease_duration: i64,
}

/// Vault secret storage implementation for the application
pub struct VaultSecretStore {
    client: VaultClient,
    mount_path: String,
}

impl VaultSecretStore {
    /// Create a new Vault secret store
    pub async fn new(client: VaultClient, mount_path: &str) -> Self {
        Self {
            client,
            mount_path: mount_path.to_string(),
        }
    }
    
    /// Get a secret
    pub async fn get(&self, key: &str) -> Result<serde_json::Value, VaultError> {
        let path = format!("{}/data/{}", self.mount_path, key);
        let secret = self.client.read_secret(&path).await?;
        Ok(secret.data.data)
    }
    
    /// Set a secret
    pub async fn set(&self, key: &str, value: serde_json::Value) -> Result<(), VaultError> {
        let path = format!("{}/data/{}", self.mount_path, key);
        self.client.write_secret(&path, value).await
    }
    
    /// Get database credentials
    pub async fn get_db_credentials(&self, role: &str) -> Result<DatabaseCredsData, VaultError> {
        let creds = self.client.generate_db_credentials(role).await?;
        Ok(creds.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Note: These tests require a running Vault instance
    // They're marked as ignored by default
    
    #[tokio::test]
    #[ignore = "Requires Vault server"]
    async fn test_vault_token_auth() {
        let config = VaultConfig {
            addr: "http://127.0.0.1:8200".to_string(),
            auth: VaultAuthMethod::Token {
                token: "test-token".to_string(),
            },
            tls: VaultTlsConfig {
                skip_verify: true,
                ..Default::default()
            },
            ..Default::default()
        };
        
        let client = VaultClient::new(config).await;
        assert!(client.is_ok());
    }
    
    #[test]
    fn test_vault_config_default() {
        let config = VaultConfig::default();
        assert_eq!(config.addr, "https://127.0.0.1:8200");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }
    
    #[test]
    fn test_auth_state() {
        let state = AuthState {
            token: "test".to_string(),
            expires_at: None,
            renewable: true,
        };
        assert_eq!(state.token, "test");
        assert!(state.renewable);
    }
}
