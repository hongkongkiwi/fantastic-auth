//! Identity Broker
//!
//! Coordinates authentication between multiple IdPs, acting as a central hub
//! that routes authentication requests to the appropriate identity provider.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::db::Database;
use vault_core::crypto::generate_secure_random;
use crate::federation::{
    CallbackParams, FederationAuthResult, FederationService,
    FederatedProvider, ProviderType, FederationSession,
};
use crate::federation::providers::{
    OidcFederationProvider, SamlFederationProvider,
};

/// Identity broker for coordinating authentication between multiple IdPs
#[derive(Debug, Clone)]
pub struct IdentityBroker {
    federation_service: Arc<FederationService>,
    db: Database,
}

/// Broker authentication request
#[derive(Debug, Clone)]
pub struct BrokerRequest {
    pub tenant_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Vec<String>,
    pub state: Option<String>,
    pub login_hint: Option<String>,
    pub prompt: Option<String>,
    pub acr_values: Option<Vec<String>>,
}

/// Broker authentication response
#[derive(Debug, Clone)]
pub struct BrokerResponse {
    pub code: String,
    pub state: Option<String>,
}

/// Result of broker authentication
#[derive(Debug, Clone)]
pub enum BrokerResult {
    /// Redirect to external IdP
    Redirect {
        url: String,
        session_id: String,
    },
    /// Direct authentication successful
    Authenticated {
        user: BrokerUser,
        session: BrokerSession,
    },
    /// User selection required (multiple IdPs match)
    SelectionRequired {
        providers: Vec<ProviderInfo>,
    },
    /// Authentication failed
    Failed {
        error: String,
        error_description: Option<String>,
    },
}

/// Provider information for user selection
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    pub id: String,
    pub name: String,
    pub provider_type: ProviderType,
    pub logo_url: Option<String>,
}

/// User information returned by broker
#[derive(Debug, Clone)]
pub struct BrokerUser {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    pub identities: Vec<LinkedIdentity>,
}

/// Session information returned by broker
#[derive(Debug, Clone)]
pub struct BrokerSession {
    pub id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Linked identity information
#[derive(Debug, Clone)]
pub struct LinkedIdentity {
    pub provider_id: String,
    pub provider_name: String,
    pub external_id: String,
    pub linked_at: chrono::DateTime<Utc>,
}

/// Session store for broker sessions
#[derive(Debug, Clone)]
pub struct SessionStore {
    db: Database,
}

impl SessionStore {
    /// Create a new session store
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Store a broker session
    pub async fn store_session(&self, session: &BrokerSessionData) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO broker_sessions 
            (id, tenant_id, user_id, federation_session_id, provider_id, external_id, 
             claims, code, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#
        )
        .bind(&session.id)
        .bind(&session.tenant_id)
        .bind(&session.user_id)
        .bind(&session.federation_session_id)
        .bind(&session.provider_id)
        .bind(&session.external_id)
        .bind(&session.claims)
        .bind(&session.code)
        .bind(session.created_at)
        .bind(session.expires_at)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Get a broker session by code
    pub async fn get_by_code(&self, code: &str) -> anyhow::Result<Option<BrokerSessionData>> {
        let row = sqlx::query_as::<_, BrokerSessionRow>(
            r#"
            SELECT id, tenant_id, user_id, federation_session_id, provider_id, external_id,
                   claims, code, created_at, expires_at, used_at
            FROM broker_sessions
            WHERE code = $1 AND expires_at > NOW() AND used_at IS NULL
            "#
        )
        .bind(code)
        .fetch_optional(self.db.pool())
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Mark a session as used
    pub async fn mark_used(&self, session_id: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE broker_sessions SET used_at = NOW() WHERE id = $1")
            .bind(session_id)
            .execute(self.db.pool())
            .await?;
        Ok(())
    }
}

/// Broker session data
#[derive(Debug, Clone)]
pub struct BrokerSessionData {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub federation_session_id: String,
    pub provider_id: String,
    pub external_id: String,
    pub claims: serde_json::Value,
    pub code: String,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

impl IdentityBroker {
    /// Create a new identity broker
    pub fn new(federation_service: Arc<FederationService>, db: Database) -> Self {
        Self {
            federation_service,
            db,
        }
    }

    /// Main entry point for brokered authentication
    pub async fn authenticate(&self, request: BrokerRequest) -> anyhow::Result<BrokerResult> {
        // Step 1: Home Realm Discovery - determine the IdP
        let provider = match self.select_idp(request.login_hint.as_deref()).await? {
            Some(p) => p,
            None => {
                // No IdP found, list available providers
                let providers = self.list_available_providers(&request.tenant_id).await?;
                return Ok(BrokerResult::SelectionRequired {
                    providers: providers.into_iter().map(|p| ProviderInfo {
                        id: p.id,
                        name: p.name,
                        provider_type: p.provider_type,
                        logo_url: None,
                    }).collect(),
                });
            }
        };

        // Step 2: Handle IdP selection
        match provider.provider_type {
            ProviderType::OIDC => self.initiate_oidc_auth(&provider, &request).await,
            ProviderType::SAML => self.initiate_saml_auth(&provider, &request).await,
            ProviderType::LDAP => {
                // LDAP doesn't support redirect flow, return error
                Ok(BrokerResult::Failed {
                    error: "unsupported_provider".to_string(),
                    error_description: Some("LDAP requires direct authentication".to_string()),
                })
            }
        }
    }

    /// Handle IdP callback after authentication
    pub async fn handle_callback(
        &self,
        provider_id: &str,
        params: CallbackParams,
    ) -> anyhow::Result<BrokerResult> {
        // Get the provider
        let provider = self.federation_service
            .get_provider(provider_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Provider not found: {}", provider_id))?;

        // Validate session
        let session = if let Some(ref state) = params.state {
            self.federation_service
                .get_session_by_state(state)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Invalid or expired session"))?
        } else {
            return Ok(BrokerResult::Failed {
                error: "invalid_request".to_string(),
                error_description: Some("Missing state parameter".to_string()),
            });
        };

        // Check for errors from IdP
        if let Some(ref error) = params.error {
            return Ok(BrokerResult::Failed {
                error: error.clone(),
                error_description: params.error_description.clone(),
            });
        }

        // Process based on provider type
        let fed_result = match provider.provider_type {
            ProviderType::OIDC => self.handle_oidc_callback(&provider, &session, &params).await,
            ProviderType::SAML => self.handle_saml_callback(&provider, &session, &params).await,
            ProviderType::LDAP => Err(anyhow::anyhow!("LDAP not supported for callbacks")),
        }?;

        // Cleanup federation session
        self.federation_service.delete_session(&session.id).await?;

        // Provision or link user
        let user = self.provision_or_link_user(&fed_result, &provider).await?;

        // Create broker session
        let broker_session = self.create_broker_session(&user, &fed_result, &session).await?;

        Ok(BrokerResult::Authenticated {
            user,
            session: broker_session,
        })
    }

    /// Select the appropriate IdP for the login hint
    async fn select_idp(&self, login_hint: Option<&str>) -> anyhow::Result<Option<FederatedProvider>> {
        let Some(hint) = login_hint else {
            return Ok(None);
        };

        // Check if it's an email address
        if hint.contains('@') {
            return self.federation_service
                .discover_provider(hint)
                .await
                .map_err(|e| anyhow::anyhow!("Discovery failed: {}", e));
        }

        // Could be a domain directly
        Ok(None)
    }

    /// List available providers for a tenant
    async fn list_available_providers(&self, tenant_id: &str) -> anyhow::Result<Vec<FederatedProvider>> {
        self.federation_service
            .list_providers(tenant_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to list providers: {}", e))
    }

    /// Initiate OIDC authentication
    async fn initiate_oidc_auth(
        &self,
        provider: &FederatedProvider,
        request: &BrokerRequest,
    ) -> anyhow::Result<BrokerResult> {
        

        let ProviderConfig::Oidc(ref config) = provider.config else {
            return Err(anyhow::anyhow!("Invalid provider configuration"));
        };

        let oidc_provider = OidcFederationProvider::new(config.clone());

        // Generate PKCE if enabled
        let (pkce_verifier, pkce_challenge) = if config.pkce_enabled {
            let verifier = OidcFederationProvider::generate_pkce_verifier();
            let challenge = OidcFederationProvider::generate_pkce_challenge(&verifier);
            (Some(verifier), Some(challenge))
        } else {
            (None, None)
        };

        // Generate state and nonce
        // SECURITY: Use cryptographically secure random for security tokens
        let state = format!("broker_{}", generate_secure_random(16));
        let nonce = format!("nonce_{}", generate_secure_random(16));

        // Create federation session
        let session = self.federation_service
            .create_session(
                &request.tenant_id,
                &provider.id,
                &state,
                &nonce,
                pkce_verifier.as_deref(),
                &request.redirect_uri,
                600, // 10 minutes
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create session: {}", e))?;

        // Build authorization URL
        let redirect_url = oidc_provider.get_authorization_url(
            &state,
            &nonce,
            pkce_challenge.as_deref(),
            &request.redirect_uri,
        );

        Ok(BrokerResult::Redirect {
            url: redirect_url,
            session_id: session.id,
        })
    }

    /// Handle OIDC callback
    async fn handle_oidc_callback(
        &self,
        provider: &FederatedProvider,
        session: &FederationSession,
        params: &CallbackParams,
    ) -> anyhow::Result<FederationAuthResult> {
        

        let ProviderConfig::Oidc(ref config) = provider.config else {
            return Err(anyhow::anyhow!("Invalid provider configuration"));
        };

        let oidc_provider = OidcFederationProvider::new(config.clone());

        // Exchange code for tokens
        let code = params.code.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing authorization code"))?;

        let token_response = oidc_provider
            .exchange_code(code, session.pkce_verifier.as_deref(), &session.redirect_uri)
            .await?;

        // Get user info
        let mut claims = if let Some(ref id_token) = token_response.id_token {
            oidc_provider.validate_id_token(id_token, &session.nonce).await?
        } else {
            HashMap::new()
        };

        // Augment with userinfo if available
        let userinfo = oidc_provider.get_userinfo(&token_response.access_token).await?;
        for (key, value) in userinfo {
            claims.entry(key).or_insert(value);
        }

        // Transform claims to Vault format
        let vault_claims = self.federation_service.transform_claims(provider, &claims);
        
        // Extract external ID
        let external_id = claims.get("sub")
            .cloned()
            .unwrap_or_else(|| session.provider_id.clone());

        Ok(FederationAuthResult {
            user_id: String::new(), // Will be filled after provisioning
            external_id,
            email: vault_claims.email.clone().unwrap_or_default(),
            claims: vault_claims,
            provider_id: provider.id.clone(),
            is_new_user: false, // Will be determined during provisioning
            linked_identities: vec![],
        })
    }

    /// Initiate SAML authentication
    async fn initiate_saml_auth(
        &self,
        provider: &FederatedProvider,
        request: &BrokerRequest,
    ) -> anyhow::Result<BrokerResult> {
        

        let ProviderConfig::Saml(ref config) = provider.config else {
            return Err(anyhow::anyhow!("Invalid provider configuration"));
        };

        let saml_provider = SamlFederationProvider::new(config.clone());

        // Generate state
        // SECURITY: Use cryptographically secure random for security tokens
        let state = format!("broker_{}", generate_secure_random(16));

        // Create federation session
        let session = self.federation_service
            .create_session(
                &request.tenant_id,
                &provider.id,
                &state,
                &generate_secure_random(16), // No nonce for SAML
                None,
                &request.redirect_uri,
                600, // 10 minutes
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create session: {}", e))?;

        // Build redirect URL
        let redirect_url = saml_provider
            .build_redirect_url(Some(state))
            .map_err(|e| anyhow::anyhow!("Failed to build SAML redirect URL: {}", e))?;

        Ok(BrokerResult::Redirect {
            url: redirect_url,
            session_id: session.id,
        })
    }

    /// Handle SAML callback
    async fn handle_saml_callback(
        &self,
        provider: &FederatedProvider,
        session: &FederationSession,
        params: &CallbackParams,
    ) -> anyhow::Result<FederationAuthResult> {
        

        let ProviderConfig::Saml(ref config) = provider.config else {
            return Err(anyhow::anyhow!("Invalid provider configuration"));
        };

        let saml_provider = SamlFederationProvider::new(config.clone());

        // Process SAML response
        let saml_response = params.saml_response.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing SAML response"))?;

        let result = saml_provider
            .process_saml_response(saml_response, params.relay_state.as_deref())
            .await?;

        // Convert to claims
        let claims = result.to_claims();
        let vault_claims = self.federation_service.transform_claims(provider, &claims);

        Ok(FederationAuthResult {
            user_id: String::new(),
            external_id: result.name_id,
            email: vault_claims.email.clone().unwrap_or_default(),
            claims: vault_claims,
            provider_id: provider.id.clone(),
            is_new_user: false,
            linked_identities: vec![],
        })
    }

    /// Provision a new user or link to existing user
    async fn provision_or_link_user(
        &self,
        fed_result: &FederationAuthResult,
        provider: &FederatedProvider,
    ) -> anyhow::Result<BrokerUser> {
        // Check if user already exists with this email
        let existing_user: Option<(String, String)> = sqlx::query_as(
            "SELECT id, email FROM users WHERE email = $1 AND tenant_id = $2"
        )
        .bind(&fed_result.email)
        .bind(&fed_result.provider_id) // This should be tenant_id, fix needed
        .fetch_optional(self.db.pool())
        .await?;

        if let Some((user_id, email)) = existing_user {
            // Link the identity if not already linked
            self.link_identity(&user_id, provider, &fed_result.external_id).await?;

            return Ok(BrokerUser {
                id: user_id,
                email,
                email_verified: fed_result.claims.email_verified.unwrap_or(false),
                name: fed_result.claims.name.clone(),
                given_name: fed_result.claims.given_name.clone(),
                family_name: fed_result.claims.family_name.clone(),
                picture: fed_result.claims.picture.clone(),
                groups: fed_result.claims.groups.clone(),
                roles: fed_result.claims.roles.clone(),
                identities: vec![LinkedIdentity {
                    provider_id: provider.id.clone(),
                    provider_name: provider.name.clone(),
                    external_id: fed_result.external_id.clone(),
                    linked_at: Utc::now(),
                }],
            });
        }

        // Create new user (JIT provisioning)
        let user_id = Uuid::new_v4().to_string();
        
        // Get tenant_id from provider (this needs proper lookup)
        let tenant_id = &provider.tenant_id;

        sqlx::query(
            r#"
            INSERT INTO users (id, tenant_id, email, email_verified, profile, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            "#
        )
        .bind(&user_id)
        .bind(tenant_id)
        .bind(&fed_result.email)
        .bind(fed_result.claims.email_verified.unwrap_or(false))
        .bind(serde_json::json!({
            "name": fed_result.claims.name,
            "given_name": fed_result.claims.given_name,
            "family_name": fed_result.claims.family_name,
            "picture": fed_result.claims.picture,
        }))
        .execute(self.db.pool())
        .await?;

        // Link the federated identity
        self.link_identity(&user_id, provider, &fed_result.external_id).await?;

        Ok(BrokerUser {
            id: user_id,
            email: fed_result.email.clone(),
            email_verified: fed_result.claims.email_verified.unwrap_or(false),
            name: fed_result.claims.name.clone(),
            given_name: fed_result.claims.given_name.clone(),
            family_name: fed_result.claims.family_name.clone(),
            picture: fed_result.claims.picture.clone(),
            groups: fed_result.claims.groups.clone(),
            roles: fed_result.claims.roles.clone(),
            identities: vec![LinkedIdentity {
                provider_id: provider.id.clone(),
                provider_name: provider.name.clone(),
                external_id: fed_result.external_id.clone(),
                linked_at: Utc::now(),
            }],
        })
    }

    /// Link federated identity to existing user
    async fn link_identity(
        &self,
        user_id: &str,
        provider: &FederatedProvider,
        external_id: &str,
    ) -> anyhow::Result<()> {
        // Check if already linked
        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM linked_identities 
             WHERE user_id = $1 AND provider_id = $2 AND external_id = $3"
        )
        .bind(user_id)
        .bind(&provider.id)
        .bind(external_id)
        .fetch_optional(self.db.pool())
        .await?;

        if existing.is_some() {
            // Update last used timestamp
            sqlx::query(
                "UPDATE linked_identities SET last_used_at = NOW() 
                 WHERE user_id = $1 AND provider_id = $2"
            )
            .bind(user_id)
            .bind(&provider.id)
            .execute(self.db.pool())
            .await?;
            return Ok(());
        }

        // Create new link
        sqlx::query(
            r#"
            INSERT INTO linked_identities 
            (id, user_id, tenant_id, provider_id, external_id, linked_at, last_used_at)
            VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
            "#
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(&provider.tenant_id)
        .bind(&provider.id)
        .bind(external_id)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Create a broker session after successful authentication
    async fn create_broker_session(
        &self,
        user: &BrokerUser,
        fed_result: &FederationAuthResult,
        federation_session: &FederationSession,
    ) -> anyhow::Result<BrokerSession> {
        // SECURITY: Use cryptographically secure random tokens
        // UUID v4 is not suitable for security tokens as it has limited entropy
        let session_id = Uuid::new_v4().to_string();
        let access_token = generate_secure_random(32);
        let refresh_token = generate_secure_random(32);
        let code = format!("code_{}", generate_secure_random(16));
        
        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::hours(24);

        let session_data = BrokerSessionData {
            id: session_id.clone(),
            tenant_id: federation_session.tenant_id.clone(),
            user_id: user.id.clone(),
            federation_session_id: federation_session.id.clone(),
            provider_id: federation_session.provider_id.clone(),
            external_id: fed_result.external_id.clone(),
            claims: serde_json::to_value(&fed_result.claims)?,
            code: code.clone(),
            created_at,
            expires_at,
        };

        let store = SessionStore::new(self.db.clone());
        store.store_session(&session_data).await?;

        Ok(BrokerSession {
            id: session_id,
            access_token,
            refresh_token,
            expires_at,
        })
    }

    /// Exchange broker code for tokens
    pub async fn exchange_code(&self, code: &str) -> anyhow::Result<Option<BrokerSessionData>> {
        let store = SessionStore::new(self.db.clone());
        
        if let Some(session) = store.get_by_code(code).await? {
            store.mark_used(&session.id).await?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }
}

// Need to import ProviderConfig
use crate::federation::ProviderConfig;

// Database row types

#[derive(sqlx::FromRow)]
struct BrokerSessionRow {
    id: String,
    tenant_id: String,
    user_id: String,
    federation_session_id: String,
    provider_id: String,
    external_id: String,
    claims: serde_json::Value,
    code: String,
    created_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
    used_at: Option<chrono::DateTime<Utc>>,
}

impl From<BrokerSessionRow> for BrokerSessionData {
    fn from(row: BrokerSessionRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            user_id: row.user_id,
            federation_session_id: row.federation_session_id,
            provider_id: row.provider_id,
            external_id: row.external_id,
            claims: row.claims,
            code: row.code,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}
