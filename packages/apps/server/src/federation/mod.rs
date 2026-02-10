//! Identity Federation Service
//!
//! This module provides identity brokering capabilities, allowing Vault to connect
//! to external Identity Providers (IdPs) and broker authentication as a central hub.
//!
//! ## Features
//!
//! - **Home Realm Discovery**: Auto-detect IdP from email domain
//! - **Multiple Protocols**: Support for SAML, OIDC, and LDAP federation
//! - **Claims Transformation**: Map external claims to Vault format
//! - **JIT Provisioning**: Auto-create users from federated identities
//! - **Account Linking**: Link multiple external identities to one Vault user
//! - **Trust Management**: Configure trust levels and certificate validation
//!
//! ## Architecture
//!
//! ```
//! ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
//! │   Client    │────▶│BrokerRequest │────▶│Home Realm   │
//! └─────────────┘     └──────────────┘     │Discovery    │
//!                                          └──────┬──────┘
//!                                                 │
//!                    ┌────────────────────────────┼────────────────────────────┐
//!                    │                            ▼                            │
//!                    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
//!                    │  │ SAML IdP │  │ OIDC IdP │  │ LDAP IdP │  │ Local   │ │
//!                    │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │
//!                    └───────┼─────────────┼─────────────┼─────────────┼──────┘
//!                            └─────────────┴──────┬──────┴─────────────┘
//!                                                 │
//!                                          ┌──────▼──────┐
//!                                          │   Claims    │
//!                                          │Transformer  │
//!                                          └──────┬──────┘
//!                                                 │
//!                                          ┌──────▼──────┐
//!                                          │    Vault    │
//!                                          │    User     │
//!                                          └─────────────┘
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::db::Database;

pub mod broker;
pub mod claims;
pub mod home_realm;
pub mod providers;
pub mod trust;

pub use broker::{BrokerRequest, BrokerResponse, BrokerResult, IdentityBroker};
pub use claims::{ClaimsTransformer, TransformFunction, VaultClaims};
pub use home_realm::{HomeRealmDiscovery, RealmMapping};
pub use trust::{TrustLevel, TrustManager, TrustRelationship};

/// Errors that can occur during federation operations
#[derive(Debug, Error)]
pub enum FederationError {
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),
    
    #[error("Provider is disabled: {0}")]
    ProviderDisabled(String),
    
    #[error("Invalid provider configuration: {0}")]
    InvalidConfiguration(String),
    
    #[error("Discovery failed: {0}")]
    DiscoveryFailed(String),
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Claims transformation failed: {0}")]
    ClaimsTransformationFailed(String),
    
    #[error("User provisioning failed: {0}")]
    ProvisioningFailed(String),
    
    #[error("Identity linking failed: {0}")]
    LinkingFailed(String),
    
    #[error("Session expired or invalid")]
    InvalidSession,
    
    #[error("Trust validation failed: {0}")]
    TrustValidationFailed(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for federation operations
pub type FederationResult<T> = Result<T, FederationError>;

/// Provider type for federated identity providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    SAML,
    OIDC,
    LDAP,
}

impl ProviderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderType::SAML => "saml",
            ProviderType::OIDC => "oidc",
            ProviderType::LDAP => "ldap",
        }
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "saml" => Some(ProviderType::SAML),
            "oidc" | "openid" => Some(ProviderType::OIDC),
            "ldap" => Some(ProviderType::LDAP),
            _ => None,
        }
    }
}

/// Provider configuration variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "config")]
pub enum ProviderConfig {
    #[serde(rename = "saml")]
    Saml(providers::SamlProviderConfig),
    #[serde(rename = "oidc")]
    Oidc(providers::OidcProviderConfig),
    #[serde(rename = "ldap")]
    Ldap(providers::LdapProviderConfig),
}

/// A federated identity provider configuration
#[derive(Debug, Clone)]
pub struct FederatedProvider {
    pub id: String,
    pub tenant_id: String,
    pub organization_id: Option<String>,
    pub name: String,
    pub provider_type: ProviderType,
    pub config: ProviderConfig,
    pub enabled: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Federation session for tracking authentication flow
#[derive(Debug, Clone)]
pub struct FederationSession {
    pub id: String,
    pub tenant_id: String,
    pub provider_id: String,
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: Option<String>,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Parameters received from IdP callback
#[derive(Debug, Clone, Default)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub id_token: Option<String>,
    pub saml_response: Option<String>,
    pub relay_state: Option<String>,
}

/// Result of federation authentication
#[derive(Debug, Clone)]
pub struct FederationAuthResult {
    pub user_id: String,
    pub external_id: String,
    pub email: String,
    pub claims: VaultClaims,
    pub provider_id: String,
    pub is_new_user: bool,
    pub linked_identities: Vec<String>,
}

/// Federation initiation response
#[derive(Debug, Clone)]
pub struct FederationInitiation {
    pub session_id: String,
    pub redirect_url: String,
    pub state: String,
}

/// Federation service for managing connections to external IdPs
#[derive(Debug, Clone)]
pub struct FederationService {
    db: Database,
}

impl FederationService {
    /// Create a new federation service
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Get a provider by ID
    pub async fn get_provider(&self, provider_id: &str) -> FederationResult<Option<FederatedProvider>> {
        let row = sqlx::query_as::<_, FederatedProviderRow>(
            r#"
            SELECT id, tenant_id, organization_id, name, provider_type, config, 
                   enabled, priority, created_at, updated_at
            FROM federated_providers
            WHERE id = $1
            "#
        )
        .bind(provider_id)
        .fetch_optional(self.db.pool())
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Get the appropriate IdP for an email domain (Home Realm Discovery)
    pub async fn discover_provider(&self, email: &str) -> FederationResult<Option<FederatedProvider>> {
        // Extract domain from email
        let domain = email
            .split('@')
            .nth(1)
            .ok_or_else(|| FederationError::DiscoveryFailed("Invalid email format".to_string()))?;

        // First check realm mappings
        let row = sqlx::query_as::<_, FederatedProviderRow>(
            r#"
            SELECT p.id, p.tenant_id, p.organization_id, p.name, p.provider_type, p.config,
                   p.enabled, p.priority, p.created_at, p.updated_at
            FROM realm_mappings rm
            JOIN federated_providers p ON p.id = rm.provider_id
            WHERE rm.domain = $1 AND p.enabled = true
            ORDER BY rm.is_default DESC, p.priority DESC
            LIMIT 1
            "#
        )
        .bind(domain)
        .fetch_optional(self.db.pool())
        .await?;

        if let Some(provider) = row {
            return Ok(Some(provider.into()));
        }

        // Check idp_domains as fallback
        let row = sqlx::query_as::<_, FederatedProviderRow>(
            r#"
            SELECT p.id, p.tenant_id, p.organization_id, p.name, p.provider_type, p.config,
                   p.enabled, p.priority, p.created_at, p.updated_at
            FROM idp_domains d
            JOIN idp_providers p ON p.id = d.provider_id
            WHERE d.domain = $1 AND p.status = 'active'
            LIMIT 1
            "#
        )
        .bind(domain)
        .fetch_optional(self.db.pool())
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// List all providers for a tenant
    pub async fn list_providers(&self, tenant_id: &str) -> FederationResult<Vec<FederatedProvider>> {
        let rows = sqlx::query_as::<_, FederatedProviderRow>(
            r#"
            SELECT id, tenant_id, organization_id, name, provider_type, config,
                   enabled, priority, created_at, updated_at
            FROM federated_providers
            WHERE tenant_id = $1
            ORDER BY priority DESC, name ASC
            "#
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Create a new federated provider
    pub async fn create_provider(
        &self,
        tenant_id: &str,
        organization_id: Option<&str>,
        name: &str,
        provider_type: ProviderType,
        config: ProviderConfig,
        priority: i32,
    ) -> FederationResult<FederatedProvider> {
        let id = Uuid::new_v4().to_string();
        let config_json = serde_json::to_value(&config)
            .map_err(|e| FederationError::InvalidConfiguration(e.to_string()))?;
        
        let provider_type_str = provider_type.as_str();

        sqlx::query(
            r#"
            INSERT INTO federated_providers 
            (id, tenant_id, organization_id, name, provider_type, config, enabled, priority)
            VALUES ($1, $2, $3, $4, $5, $6, true, $7)
            "#
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(organization_id)
        .bind(name)
        .bind(provider_type_str)
        .bind(config_json)
        .bind(priority)
        .execute(self.db.pool())
        .await?;

        Ok(FederatedProvider {
            id,
            tenant_id: tenant_id.to_string(),
            organization_id: organization_id.map(|s| s.to_string()),
            name: name.to_string(),
            provider_type,
            config,
            enabled: true,
            priority,
            created_at: Utc::now(),
            updated_at: None,
        })
    }

    /// Update a federated provider
    pub async fn update_provider(
        &self,
        provider_id: &str,
        updates: ProviderUpdates,
    ) -> FederationResult<FederatedProvider> {
        if let Some(name) = &updates.name {
            sqlx::query("UPDATE federated_providers SET name = $1 WHERE id = $2")
                .bind(name)
                .bind(provider_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(enabled) = updates.enabled {
            sqlx::query("UPDATE federated_providers SET enabled = $1 WHERE id = $2")
                .bind(enabled)
                .bind(provider_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(config) = &updates.config {
            let config_json = serde_json::to_value(config)
                .map_err(|e| FederationError::InvalidConfiguration(e.to_string()))?;
            sqlx::query("UPDATE federated_providers SET config = $1 WHERE id = $2")
                .bind(config_json)
                .bind(provider_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(priority) = updates.priority {
            sqlx::query("UPDATE federated_providers SET priority = $1 WHERE id = $2")
                .bind(priority)
                .bind(provider_id)
                .execute(self.db.pool())
                .await?;
        }

        self.get_provider(provider_id)
            .await?
            .ok_or_else(|| FederationError::ProviderNotFound(provider_id.to_string()))
    }

    /// Delete a federated provider
    pub async fn delete_provider(&self, provider_id: &str) -> FederationResult<()> {
        sqlx::query("DELETE FROM federated_providers WHERE id = $1")
            .bind(provider_id)
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    /// Create a federation session
    pub async fn create_session(
        &self,
        tenant_id: &str,
        provider_id: &str,
        state: &str,
        nonce: &str,
        pkce_verifier: Option<&str>,
        redirect_uri: &str,
        expires_in_secs: i64,
    ) -> FederationResult<FederationSession> {
        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::seconds(expires_in_secs);

        sqlx::query(
            r#"
            INSERT INTO federation_sessions
            (id, tenant_id, provider_id, state, nonce, pkce_verifier, redirect_uri, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(provider_id)
        .bind(state)
        .bind(nonce)
        .bind(pkce_verifier)
        .bind(redirect_uri)
        .bind(created_at)
        .bind(expires_at)
        .execute(self.db.pool())
        .await?;

        Ok(FederationSession {
            id,
            tenant_id: tenant_id.to_string(),
            provider_id: provider_id.to_string(),
            state: state.to_string(),
            nonce: nonce.to_string(),
            pkce_verifier: pkce_verifier.map(|s| s.to_string()),
            redirect_uri: redirect_uri.to_string(),
            created_at,
            expires_at,
        })
    }

    /// Get and validate a federation session by state
    pub async fn get_session_by_state(&self, state: &str) -> FederationResult<Option<FederationSession>> {
        let row = sqlx::query_as::<_, FederationSessionRow>(
            r#"
            SELECT id, tenant_id, provider_id, state, nonce, pkce_verifier, redirect_uri, 
                   created_at, expires_at
            FROM federation_sessions
            WHERE state = $1 AND expires_at > NOW()
            "#
        )
        .bind(state)
        .fetch_optional(self.db.pool())
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Delete a federation session
    pub async fn delete_session(&self, session_id: &str) -> FederationResult<()> {
        sqlx::query("DELETE FROM federation_sessions WHERE id = $1")
            .bind(session_id)
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    /// Transform external claims to Vault format
    pub fn transform_claims(&self, provider: &FederatedProvider, external_claims: &HashMap<String, String>) -> VaultClaims {
        let transformer = ClaimsTransformer::default();
        
        let mapping = match &provider.config {
            ProviderConfig::Oidc(cfg) => &cfg.claims_mapping,
            ProviderConfig::Saml(cfg) => &cfg.attribute_mappings,
            ProviderConfig::Ldap(cfg) => &cfg.attribute_mappings,
        };

        transformer.transform(external_claims, mapping)
    }

    /// Get the external user ID from claims based on provider type
    pub fn extract_external_id(&self, provider: &FederatedProvider, claims: &VaultClaims) -> Option<String> {
        match provider.provider_type {
            ProviderType::OIDC => claims.sub.clone(),
            ProviderType::SAML => claims.email.clone().or_else(|| claims.sub.clone()),
            ProviderType::LDAP => claims.sub.clone().or_else(|| claims.email.clone()),
        }
    }
}

/// Updates for a federated provider
#[derive(Debug, Clone, Default)]
pub struct ProviderUpdates {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<ProviderConfig>,
    pub priority: Option<i32>,
}

// Database row types

#[derive(sqlx::FromRow)]
struct FederatedProviderRow {
    id: String,
    tenant_id: String,
    organization_id: Option<String>,
    name: String,
    #[sqlx(rename = "provider_type")]
    provider_type_str: String,
    config: serde_json::Value,
    enabled: bool,
    priority: i32,
    created_at: DateTime<Utc>,
    updated_at: Option<DateTime<Utc>>,
}

impl From<FederatedProviderRow> for FederatedProvider {
    fn from(row: FederatedProviderRow) -> Self {
        let provider_type = ProviderType::from_str(&row.provider_type_str)
            .unwrap_or(ProviderType::OIDC);
        
        let config: ProviderConfig = serde_json::from_value(row.config)
            .unwrap_or_else(|_| ProviderConfig::Oidc(providers::OidcProviderConfig::default()));

        FederatedProvider {
            id: row.id,
            tenant_id: row.tenant_id,
            organization_id: row.organization_id,
            name: row.name,
            provider_type,
            config,
            enabled: row.enabled,
            priority: row.priority,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct FederationSessionRow {
    id: String,
    tenant_id: String,
    provider_id: String,
    state: String,
    nonce: Option<String>,
    pkce_verifier: Option<String>,
    redirect_uri: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<FederationSessionRow> for FederationSession {
    fn from(row: FederationSessionRow) -> Self {
        FederationSession {
            id: row.id,
            tenant_id: row.tenant_id,
            provider_id: row.provider_id,
            state: row.state,
            nonce: row.nonce.unwrap_or_default(),
            pkce_verifier: row.pkce_verifier,
            redirect_uri: row.redirect_uri,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_type_from_str() {
        assert_eq!(ProviderType::from_str("saml"), Some(ProviderType::SAML));
        assert_eq!(ProviderType::from_str("OIDC"), Some(ProviderType::OIDC));
        assert_eq!(ProviderType::from_str("ldap"), Some(ProviderType::LDAP));
        assert_eq!(ProviderType::from_str("unknown"), None);
    }

    #[test]
    fn test_provider_type_as_str() {
        assert_eq!(ProviderType::SAML.as_str(), "saml");
        assert_eq!(ProviderType::OIDC.as_str(), "oidc");
        assert_eq!(ProviderType::LDAP.as_str(), "ldap");
    }
}
