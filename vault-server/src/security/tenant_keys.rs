//! Per-tenant data encryption keys (DEKs) with provider-backed wrapping.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::db::{set_connection_context, Database};
use crate::security::encryption::{decrypt_from_base64, encrypt_to_base64};
use vault_core::crypto::{derive_key, generate_random_bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "kms_provider", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum KmsProviderKind {
    Local,
    AwsKms,
    AzureKv,
    GcpKms,
    AlicloudKms,
    OracleKms,
}

#[derive(Debug, Clone)]
pub struct WrappedKey {
    pub ciphertext_b64: String,
    pub provider_key_id: Option<String>,
    pub metadata: serde_json::Value,
}

#[async_trait]
pub trait KmsProvider: Send + Sync {
    fn kind(&self) -> KmsProviderKind;
    async fn wrap_key(&self, tenant_id: &str, plaintext: &[u8]) -> Result<WrappedKey, TenantKeyError>;
    async fn unwrap_key(&self, tenant_id: &str, wrapped: &WrappedKey) -> Result<Vec<u8>, TenantKeyError>;
}

pub struct KmsRegistry {
    providers: HashMap<KmsProviderKind, Arc<dyn KmsProvider>>,
    default_provider: KmsProviderKind,
}

impl KmsRegistry {
    pub fn new(default_provider: KmsProviderKind) -> Self {
        Self {
            providers: HashMap::new(),
            default_provider,
        }
    }

    pub fn with_provider(mut self, provider: Arc<dyn KmsProvider>) -> Self {
        self.providers.insert(provider.kind(), provider);
        self
    }

    pub fn default_provider(&self) -> KmsProviderKind {
        self.default_provider
    }

    pub fn get(&self, kind: KmsProviderKind) -> Result<Arc<dyn KmsProvider>, TenantKeyError> {
        self.providers
            .get(&kind)
            .cloned()
            .ok_or(TenantKeyError::ProviderUnavailable(kind))
    }

    pub fn supported_providers(&self) -> Vec<KmsProviderKind> {
        self.providers.keys().copied().collect()
    }
}

#[derive(Debug, Clone)]
pub struct LocalMasterKeyProvider {
    master_key: Vec<u8>,
}

impl LocalMasterKeyProvider {
    pub fn new(master_key: Vec<u8>) -> Self {
        Self { master_key }
    }

    fn derive_kek(&self, tenant_id: &str) -> Result<Vec<u8>, TenantKeyError> {
        let context = format!("vault-tenant-dek-wrap-v1:{}", tenant_id);
        Ok(derive_key(&self.master_key, context.as_bytes(), 32)?)
    }
}

#[async_trait]
impl KmsProvider for LocalMasterKeyProvider {
    fn kind(&self) -> KmsProviderKind {
        KmsProviderKind::Local
    }

    async fn wrap_key(&self, tenant_id: &str, plaintext: &[u8]) -> Result<WrappedKey, TenantKeyError> {
        let kek = self.derive_kek(tenant_id)?;
        let ciphertext_b64 = encrypt_to_base64(&kek, plaintext)?;
        Ok(WrappedKey {
            ciphertext_b64,
            provider_key_id: None,
            metadata: serde_json::json!({
                "kek_context": "vault-tenant-dek-wrap-v1",
            }),
        })
    }

    async fn unwrap_key(&self, tenant_id: &str, wrapped: &WrappedKey) -> Result<Vec<u8>, TenantKeyError> {
        let kek = self.derive_kek(tenant_id)?;
        Ok(decrypt_from_base64(&kek, &wrapped.ciphertext_b64)?)
    }
}

#[cfg(feature = "aws-kms")]
pub struct AwsKmsProvider {
    client: aws_sdk_kms::Client,
    key_id: String,
    encryption_context: HashMap<String, String>,
}

#[cfg(feature = "aws-kms")]
impl AwsKmsProvider {
    pub async fn new(
        region: Option<String>,
        key_id: String,
        endpoint: Option<String>,
        tenant_context_key: String,
    ) -> Result<Self, TenantKeyError> {
        let mut config_loader = aws_config::from_env();
        if let Some(region) = region {
            config_loader = config_loader.region(aws_config::Region::new(region));
        }
        if let Some(endpoint) = endpoint {
            config_loader = config_loader.endpoint_url(endpoint);
        }
        let config = config_loader.load().await;
        let client = aws_sdk_kms::Client::new(&config);

        let mut encryption_context = HashMap::new();
        encryption_context.insert(tenant_context_key, "{tenant_id}".to_string());

        Ok(Self {
            client,
            key_id,
            encryption_context,
        })
    }

    fn build_context(&self, tenant_id: &str) -> HashMap<String, String> {
        let mut ctx = self.encryption_context.clone();
        for value in ctx.values_mut() {
            if value == "{tenant_id}" {
                *value = tenant_id.to_string();
            }
        }
        ctx
    }
}

#[cfg(feature = "aws-kms")]
#[async_trait]
impl KmsProvider for AwsKmsProvider {
    fn kind(&self) -> KmsProviderKind {
        KmsProviderKind::AwsKms
    }

    async fn wrap_key(&self, tenant_id: &str, plaintext: &[u8]) -> Result<WrappedKey, TenantKeyError> {
        let context = self.build_context(tenant_id);
        let resp = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(aws_sdk_kms::types::Blob::new(plaintext))
            .set_encryption_context(Some(context.clone()))
            .send()
            .await
            .map_err(|e| TenantKeyError::External(e.to_string()))?;

        let ciphertext = resp
            .ciphertext_blob
            .ok_or_else(|| TenantKeyError::External("KMS returned empty ciphertext".to_string()))?;

        Ok(WrappedKey {
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ciphertext.as_ref()),
            provider_key_id: Some(self.key_id.clone()),
            metadata: serde_json::json!({
                "encryption_context": context,
                "provider": "aws_kms"
            }),
        })
    }

    async fn unwrap_key(&self, tenant_id: &str, wrapped: &WrappedKey) -> Result<Vec<u8>, TenantKeyError> {
        let context = wrapped
            .metadata
            .get("encryption_context")
            .and_then(|v| v.as_object())
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<HashMap<String, String>>()
            })
            .unwrap_or_else(|| self.build_context(tenant_id));

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&wrapped.ciphertext_b64)
            .map_err(|e| TenantKeyError::External(format!("Invalid ciphertext: {}", e)))?;

        let resp = self
            .client
            .decrypt()
            .ciphertext_blob(aws_sdk_kms::types::Blob::new(ciphertext))
            .set_encryption_context(Some(context))
            .send()
            .await
            .map_err(|e| TenantKeyError::External(e.to_string()))?;

        let plaintext = resp
            .plaintext
            .ok_or_else(|| TenantKeyError::External("KMS returned empty plaintext".to_string()))?;
        Ok(plaintext.as_ref().to_vec())
    }
}

#[cfg(feature = "azure-kv")]
pub struct AzureKeyVaultProvider {
    vault_url: String,
    key_name: String,
    key_version: Option<String>,
    tenant_context_key: String,
    credential: azure_identity::DefaultAzureCredential,
}

#[cfg(feature = "azure-kv")]
impl AzureKeyVaultProvider {
    pub fn new(
        vault_url: String,
        key_name: String,
        key_version: Option<String>,
        tenant_context_key: String,
    ) -> Result<Self, TenantKeyError> {
        let credential = azure_identity::DefaultAzureCredential::default();
        Ok(Self {
            vault_url,
            key_name,
            key_version,
            tenant_context_key,
            credential,
        })
    }

    fn wrap_url(&self) -> String {
        let version = self.key_version.as_deref().unwrap_or("");
        if version.is_empty() {
            format!("{}/keys/{}/wrapkey?api-version=7.4", self.vault_url, self.key_name)
        } else {
            format!(
                "{}/keys/{}/{}{}",
                self.vault_url,
                self.key_name,
                version,
                "/wrapkey?api-version=7.4"
            )
        }
    }

    fn unwrap_url(&self) -> String {
        let version = self.key_version.as_deref().unwrap_or("");
        if version.is_empty() {
            format!("{}/keys/{}/unwrapkey?api-version=7.4", self.vault_url, self.key_name)
        } else {
            format!(
                "{}/keys/{}/{}{}",
                self.vault_url,
                self.key_name,
                version,
                "/unwrapkey?api-version=7.4"
            )
        }
    }

    async fn get_token(&self) -> Result<String, TenantKeyError> {
        let scope = "https://vault.azure.net/.default";
        let token = self
            .credential
            .get_token(scope)
            .await
            .map_err(|e| TenantKeyError::External(format!("Azure token error: {}", e)))?;
        Ok(token.token.secret().to_string())
    }
}

#[cfg(feature = "azure-kv")]
#[async_trait]
impl KmsProvider for AzureKeyVaultProvider {
    fn kind(&self) -> KmsProviderKind {
        KmsProviderKind::AzureKv
    }

    async fn wrap_key(&self, tenant_id: &str, plaintext: &[u8]) -> Result<WrappedKey, TenantKeyError> {
        let token = self.get_token().await?;
        let body = serde_json::json!({
            "alg": "RSA-OAEP-256",
            "value": base64::engine::general_purpose::STANDARD.encode(plaintext),
            "context": {
                "tenant_id": tenant_id,
                "context_key": self.tenant_context_key,
            }
        });

        let resp = reqwest::Client::new()
            .post(self.wrap_url())
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| TenantKeyError::External(format!("Azure wrap request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TenantKeyError::External(format!(
                "Azure wrap failed: {} {}",
                status, text
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TenantKeyError::External(format!("Azure wrap response invalid: {}", e)))?;

        let ciphertext_b64 = json
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TenantKeyError::External("Azure wrap missing value".to_string()))?
            .to_string();

        Ok(WrappedKey {
            ciphertext_b64,
            provider_key_id: Some(format!(
                "{}/keys/{}{}",
                self.vault_url,
                self.key_name,
                self.key_version
                    .as_ref()
                    .map(|v| format!("/{}", v))
                    .unwrap_or_default()
            )),
            metadata: serde_json::json!({
                "provider": "azure_kv",
                "context_key": self.tenant_context_key
            }),
        })
    }

    async fn unwrap_key(&self, tenant_id: &str, wrapped: &WrappedKey) -> Result<Vec<u8>, TenantKeyError> {
        let token = self.get_token().await?;
        let context_key = wrapped
            .metadata
            .get("context_key")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.tenant_context_key);
        let body = serde_json::json!({
            "alg": "RSA-OAEP-256",
            "value": wrapped.ciphertext_b64,
            "context": {
                "tenant_id": tenant_id,
                "context_key": context_key
            }
        });

        let resp = reqwest::Client::new()
            .post(self.unwrap_url())
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| TenantKeyError::External(format!("Azure unwrap request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TenantKeyError::External(format!(
                "Azure unwrap failed: {} {}",
                status, text
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TenantKeyError::External(format!("Azure unwrap response invalid: {}", e)))?;
        let plaintext_b64 = json
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TenantKeyError::External("Azure unwrap missing value".to_string()))?;

        let plaintext = base64::engine::general_purpose::STANDARD
            .decode(plaintext_b64)
            .map_err(|e| TenantKeyError::External(format!("Invalid unwrap value: {}", e)))?;
        Ok(plaintext)
    }
}

#[cfg(feature = "gcp-kms")]
pub struct GcpKmsProvider {
    key_name: String,
    tenant_context_key: String,
    auth: gcp_auth::AuthenticationManager,
}

#[cfg(feature = "gcp-kms")]
impl GcpKmsProvider {
    pub async fn new(key_name: String, tenant_context_key: String) -> Result<Self, TenantKeyError> {
        let auth = gcp_auth::AuthenticationManager::new()
            .await
            .map_err(|e| TenantKeyError::External(format!("GCP auth init failed: {}", e)))?;
        Ok(Self {
            key_name,
            tenant_context_key,
            auth,
        })
    }

    async fn token(&self) -> Result<String, TenantKeyError> {
        let token = self
            .auth
            .get_token(&["https://www.googleapis.com/auth/cloud-platform"])
            .await
            .map_err(|e| TenantKeyError::External(format!("GCP token error: {}", e)))?;
        Ok(token.as_str().to_string())
    }
}

#[cfg(feature = "gcp-kms")]
#[async_trait]
impl KmsProvider for GcpKmsProvider {
    fn kind(&self) -> KmsProviderKind {
        KmsProviderKind::GcpKms
    }

    async fn wrap_key(&self, tenant_id: &str, plaintext: &[u8]) -> Result<WrappedKey, TenantKeyError> {
        let token = self.token().await?;
        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}:encrypt",
            self.key_name
        );

        let aad = base64::engine::general_purpose::STANDARD.encode(tenant_id.as_bytes());
        let body = serde_json::json!({
            "plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext),
            "additionalAuthenticatedData": aad,
        });

        let resp = reqwest::Client::new()
            .post(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| TenantKeyError::External(format!("GCP encrypt failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TenantKeyError::External(format!(
                "GCP encrypt failed: {} {}",
                status, text
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TenantKeyError::External(format!("GCP encrypt response invalid: {}", e)))?;

        let ciphertext_b64 = json
            .get("ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TenantKeyError::External("GCP encrypt missing ciphertext".to_string()))?
            .to_string();

        Ok(WrappedKey {
            ciphertext_b64,
            provider_key_id: Some(self.key_name.clone()),
            metadata: serde_json::json!({
                "provider": "gcp_kms",
                "context_key": self.tenant_context_key,
            }),
        })
    }

    async fn unwrap_key(&self, tenant_id: &str, wrapped: &WrappedKey) -> Result<Vec<u8>, TenantKeyError> {
        let token = self.token().await?;
        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}:decrypt",
            self.key_name
        );
        let aad = base64::engine::general_purpose::STANDARD.encode(tenant_id.as_bytes());
        let body = serde_json::json!({
            "ciphertext": wrapped.ciphertext_b64,
            "additionalAuthenticatedData": aad,
        });

        let resp = reqwest::Client::new()
            .post(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| TenantKeyError::External(format!("GCP decrypt failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TenantKeyError::External(format!(
                "GCP decrypt failed: {} {}",
                status, text
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| TenantKeyError::External(format!("GCP decrypt response invalid: {}", e)))?;

        let plaintext_b64 = json
            .get("plaintext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TenantKeyError::External("GCP decrypt missing plaintext".to_string()))?;

        let plaintext = base64::engine::general_purpose::STANDARD
            .decode(plaintext_b64)
            .map_err(|e| TenantKeyError::External(format!("Invalid plaintext: {}", e)))?;

        Ok(plaintext)
    }
}

#[derive(Debug, Clone)]
struct CachedKey {
    dek: Vec<u8>,
    version: i32,
    provider: KmsProviderKind,
    cached_at: std::time::Instant,
}

#[derive(Clone)]
pub struct TenantKeyService {
    db: Database,
    registry: Arc<KmsRegistry>,
    cache: DashMap<String, CachedKey>,
    cache_ttl: std::time::Duration,
    redis: Option<redis::aio::ConnectionManager>,
    platform_key: Arc<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct TenantKeyInfo {
    pub provider: KmsProviderKind,
    pub version: i32,
    pub provider_key_id: Option<String>,
    pub provider_metadata: serde_json::Value,
}

impl TenantKeyService {
    pub fn new(
        db: Database,
        registry: Arc<KmsRegistry>,
        cache_ttl: std::time::Duration,
        redis: Option<redis::aio::ConnectionManager>,
        platform_key: Arc<Vec<u8>>,
    ) -> Self {
        Self {
            db,
            registry,
            cache: DashMap::new(),
            cache_ttl,
            redis,
            platform_key,
        }
    }

    pub async fn get_data_key(&self, tenant_id: &str) -> Result<Vec<u8>, TenantKeyError> {
        if let Some(entry) = self.cache.get(tenant_id) {
            if entry.cached_at.elapsed() < self.cache_ttl {
                return Ok(entry.dek.clone());
            }
            self.cache.remove(tenant_id);
        }

        if let Some(dek) = self.load_dek_from_redis(tenant_id).await? {
            self.cache.insert(
                tenant_id.to_string(),
                CachedKey {
                    dek: dek.clone(),
                    version: 0,
                    provider: self.registry.default_provider(),
                    cached_at: std::time::Instant::now(),
                },
            );
            return Ok(dek);
        }

        let record = self.fetch_active_key(tenant_id).await?;
        let (dek, provider, version) = match record {
            Some(record) => {
                let provider = self.registry.get(record.provider)?;
                let wrapped = WrappedKey {
                    ciphertext_b64: record.encrypted_dek,
                    provider_key_id: record.provider_key_id,
                    metadata: record.provider_metadata,
                };
                let dek = provider.unwrap_key(tenant_id, &wrapped).await?;
                (dek, record.provider, record.version)
            }
            None => {
                let dek = generate_random_bytes(32);
                let provider_kind = self.registry.default_provider();
                let provider = self.registry.get(provider_kind)?;
                let wrapped = provider.wrap_key(tenant_id, &dek).await?;
                let version = self.insert_new_key(tenant_id, provider_kind, &wrapped).await?;
                (dek, provider_kind, version)
            }
        };

        self.cache.insert(
            tenant_id.to_string(),
            CachedKey {
                dek: dek.clone(),
                version,
                provider,
                cached_at: std::time::Instant::now(),
            },
        );
        let _ = self.store_dek_in_redis(tenant_id, &dek).await;

        Ok(dek)
    }

    pub async fn migrate_provider(
        &self,
        tenant_id: &str,
        new_provider: KmsProviderKind,
    ) -> Result<(), TenantKeyError> {
        let dek = self.get_data_key(tenant_id).await?;
        let provider = self.registry.get(new_provider)?;
        let wrapped = provider.wrap_key(tenant_id, &dek).await?;
        self.rotate_key_with_wrapped(tenant_id, new_provider, &wrapped)
            .await?;
        self.cache.remove(tenant_id);
        let _ = self.delete_dek_from_redis(tenant_id).await;
        Ok(())
    }

    pub async fn get_active_key_info(&self, tenant_id: &str) -> Result<Option<TenantKeyInfo>, TenantKeyError> {
        let record = self.fetch_active_key(tenant_id).await?;
        Ok(record.map(|row| TenantKeyInfo {
            provider: row.provider,
            version: row.version,
            provider_key_id: row.provider_key_id,
            provider_metadata: row.provider_metadata,
        }))
    }

    pub fn supported_providers(&self) -> Vec<KmsProviderKind> {
        self.registry.supported_providers()
    }

    async fn load_dek_from_redis(&self, tenant_id: &str) -> Result<Option<Vec<u8>>, TenantKeyError> {
        let Some(redis) = &self.redis else {
            return Ok(None);
        };
        let mut conn = redis.clone();
        let key = format!("tenant:dek:{}", tenant_id);
        let value: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await?;
        if let Some(encoded) = value {
            let bytes = crate::security::encryption::decrypt_from_base64(
                self.platform_key.as_slice(),
                &encoded,
            )
            .map_err(|e| TenantKeyError::External(format!("Invalid cached DEK: {}", e)))?;
            return Ok(Some(bytes));
        }
        Ok(None)
    }

    async fn store_dek_in_redis(&self, tenant_id: &str, dek: &[u8]) -> Result<(), TenantKeyError> {
        let Some(redis) = &self.redis else {
            return Ok(());
        };
        let mut conn = redis.clone();
        let key = format!("tenant:dek:{}", tenant_id);
        let value = crate::security::encryption::encrypt_to_base64(
            self.platform_key.as_slice(),
            dek,
        )?;
        let ttl_secs = self.cache_ttl.as_secs().max(60);
        redis::cmd("SET")
            .arg(&key)
            .arg(value)
            .arg("EX")
            .arg(ttl_secs as usize)
            .query_async(&mut conn)
            .await?;
        Ok(())
    }

    async fn delete_dek_from_redis(&self, tenant_id: &str) -> Result<(), TenantKeyError> {
        let Some(redis) = &self.redis else {
            return Ok(());
        };
        let mut conn = redis.clone();
        let key = format!("tenant:dek:{}", tenant_id);
        let _: () = redis::cmd("DEL").arg(&key).query_async(&mut conn).await?;
        Ok(())
    }

    async fn fetch_active_key(
        &self,
        tenant_id: &str,
    ) -> Result<Option<TenantKeyRow>, TenantKeyError> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| TenantKeyError::External(e.to_string()))?;
        set_connection_context(&mut conn, tenant_id).await?;

        let row = sqlx::query_as::<_, TenantKeyRow>(
            r#"SELECT id, tenant_id, provider, provider_key_id, provider_metadata,
                      encrypted_dek, version, is_active
               FROM tenant_data_keys
               WHERE tenant_id = $1::uuid AND is_active = TRUE
               ORDER BY version DESC
               LIMIT 1"#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row)
    }

    async fn insert_new_key(
        &self,
        tenant_id: &str,
        provider: KmsProviderKind,
        wrapped: &WrappedKey,
    ) -> Result<i32, TenantKeyError> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| TenantKeyError::External(e.to_string()))?;
        set_connection_context(&mut conn, tenant_id).await?;

        let row: (i32,) = sqlx::query_as(
            r#"INSERT INTO tenant_data_keys
               (tenant_id, provider, provider_key_id, provider_metadata, encrypted_dek, version, is_active)
               VALUES ($1::uuid, $2, $3, $4, $5, 1, TRUE)
               RETURNING version"#,
        )
        .bind(tenant_id)
        .bind(provider)
        .bind(&wrapped.provider_key_id)
        .bind(&wrapped.metadata)
        .bind(&wrapped.ciphertext_b64)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.0)
    }

    async fn rotate_key_with_wrapped(
        &self,
        tenant_id: &str,
        provider: KmsProviderKind,
        wrapped: &WrappedKey,
    ) -> Result<i32, TenantKeyError> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| TenantKeyError::External(e.to_string()))?;
        set_connection_context(&mut conn, tenant_id).await?;

        let current_version: Option<(i32,)> = sqlx::query_as(
            r#"SELECT version
               FROM tenant_data_keys
               WHERE tenant_id = $1::uuid AND is_active = TRUE
               ORDER BY version DESC
               LIMIT 1"#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await?;

        let next_version = current_version.map(|v| v.0 + 1).unwrap_or(1);

        sqlx::query(
            r#"UPDATE tenant_data_keys
               SET is_active = FALSE, rotated_at = NOW()
               WHERE tenant_id = $1::uuid AND is_active = TRUE"#,
        )
        .bind(tenant_id)
        .execute(&mut *conn)
        .await?;

        let row: (i32,) = sqlx::query_as(
            r#"INSERT INTO tenant_data_keys
               (tenant_id, provider, provider_key_id, provider_metadata, encrypted_dek, version, is_active)
               VALUES ($1::uuid, $2, $3, $4, $5, $6, TRUE)
               RETURNING version"#,
        )
        .bind(tenant_id)
        .bind(provider)
        .bind(&wrapped.provider_key_id)
        .bind(&wrapped.metadata)
        .bind(&wrapped.ciphertext_b64)
        .bind(next_version)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.0)
    }
}

#[async_trait]
impl vault_core::auth::DataKeyResolver for TenantKeyService {
    async fn resolve_key(&self, tenant_id: &str) -> Result<Vec<u8>, vault_core::error::VaultError> {
        self.get_data_key(tenant_id)
            .await
            .map_err(|e| vault_core::error::VaultError::internal(format!(
                "Failed to resolve tenant data key: {}",
                e
            )))
    }
}

#[derive(Debug, Clone, FromRow)]
struct TenantKeyRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    provider: KmsProviderKind,
    provider_key_id: Option<String>,
    provider_metadata: serde_json::Value,
    encrypted_dek: String,
    version: i32,
    is_active: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum TenantKeyError {
    #[error("kms provider unavailable: {0:?}")]
    ProviderUnavailable(KmsProviderKind),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("crypto error: {0}")]
    Crypto(#[from] vault_core::error::VaultError),
    #[error("encryption error: {0}")]
    Encryption(#[from] crate::security::encryption::EncryptionError),
    #[error("external provider error: {0}")]
    External(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kek_derivation_is_tenant_bound() {
        let provider = LocalMasterKeyProvider::new(vec![7u8; 32]);
        let kek_a = provider.derive_kek("tenant-a").unwrap();
        let kek_b = provider.derive_kek("tenant-b").unwrap();
        assert_ne!(kek_a, kek_b);
    }
}
