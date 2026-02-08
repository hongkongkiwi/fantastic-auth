//! Federation Providers Module
//!
//! This module provides implementations for various federation protocols:
//! - OIDC (OpenID Connect)
//! - SAML 2.0
//! - LDAP

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod ldap_provider;
pub mod oidc_provider;
pub mod saml_provider;

pub use ldap_provider::LdapFederationProvider;
pub use oidc_provider::OidcFederationProvider;
pub use saml_provider::SamlFederationProvider;

/// Base trait for federation providers
#[async_trait::async_trait]
pub trait FederationProvider: Send + Sync {
    /// Get the authorization URL for initiating authentication
    fn get_authorization_url(
        &self,
        state: &str,
        nonce: &str,
        pkce_challenge: Option<&str>,
        redirect_uri: &str,
    ) -> String;

    /// Exchange authorization code for tokens
    async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: Option<&str>,
        redirect_uri: &str,
    ) -> anyhow::Result<TokenResponse>;

    /// Fetch user information from the provider
    async fn get_userinfo(&self, access_token: &str) -> anyhow::Result<HashMap<String, String>>;

    /// Validate an ID token (for OIDC)
    async fn validate_id_token(&self, id_token: &str, nonce: &str) -> anyhow::Result<HashMap<String, String>>;
}

/// Token response from IdP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

/// OIDC Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub claims_mapping: HashMap<String, String>,
    #[serde(default)]
    pub pkce_enabled: bool,
}

impl Default for OidcProviderConfig {
    fn default() -> Self {
        let mut claims_mapping = HashMap::new();
        claims_mapping.insert("sub".to_string(), "sub".to_string());
        claims_mapping.insert("email".to_string(), "email".to_string());
        claims_mapping.insert("name".to_string(), "name".to_string());
        claims_mapping.insert("given_name".to_string(), "given_name".to_string());
        claims_mapping.insert("family_name".to_string(), "family_name".to_string());
        claims_mapping.insert("picture".to_string(), "picture".to_string());
        claims_mapping.insert("groups".to_string(), "groups".to_string());

        Self {
            issuer: String::new(),
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            userinfo_endpoint: String::new(),
            jwks_uri: String::new(),
            client_id: String::new(),
            client_secret: None,
            scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
            claims_mapping,
            pkce_enabled: true,
        }
    }
}

/// SAML Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlProviderConfig {
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub certificate: String,
    pub name_id_format: String,
    #[serde(default)]
    pub attribute_mappings: HashMap<String, String>,
    pub want_assertions_signed: bool,
    pub want_assertions_encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sp_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sp_certificate: Option<String>,
}

impl Default for SamlProviderConfig {
    fn default() -> Self {
        let mut attribute_mappings = HashMap::new();
        attribute_mappings.insert("email".to_string(), "email".to_string());
        attribute_mappings.insert("name".to_string(), "name".to_string());
        attribute_mappings.insert("given_name".to_string(), "firstName".to_string());
        attribute_mappings.insert("family_name".to_string(), "lastName".to_string());
        attribute_mappings.insert("groups".to_string(), "groups".to_string());

        Self {
            entity_id: String::new(),
            sso_url: String::new(),
            slo_url: None,
            certificate: String::new(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            attribute_mappings,
            want_assertions_signed: true,
            want_assertions_encrypted: false,
            sp_private_key: None,
            sp_certificate: None,
        }
    }
}

/// LDAP Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapProviderConfig {
    pub server_url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    pub user_search_filter: String,
    #[serde(default)]
    pub attribute_mappings: HashMap<String, String>,
    pub use_tls: bool,
    pub tls_verify: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
}

impl Default for LdapProviderConfig {
    fn default() -> Self {
        let mut attribute_mappings = HashMap::new();
        attribute_mappings.insert("sub".to_string(), "uid".to_string());
        attribute_mappings.insert("email".to_string(), "mail".to_string());
        attribute_mappings.insert("name".to_string(), "cn".to_string());
        attribute_mappings.insert("given_name".to_string(), "givenName".to_string());
        attribute_mappings.insert("family_name".to_string(), "sn".to_string());
        attribute_mappings.insert("groups".to_string(), "memberOf".to_string());

        Self {
            server_url: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            base_dn: String::new(),
            user_search_filter: "(objectClass=person)".to_string(),
            attribute_mappings,
            use_tls: true,
            tls_verify: true,
            tls_cert: None,
        }
    }
}
