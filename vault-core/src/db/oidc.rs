use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::crypto::VaultPasswordHasher;
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OauthClient {
    pub id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub name: String,
    pub client_type: String,
    pub redirect_uris: serde_json::Value,
    pub allowed_scopes: serde_json::Value,
    pub pkce_required: bool,
    pub token_endpoint_auth_method: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthorizationCode {
    pub id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub user_id: String,
    pub code_hash: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OauthToken {
    pub id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub access_token_jti: String,
    pub refresh_token_hash: Option<String>,
    pub scope: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub struct OidcRepository {
    pool: Arc<PgPool>,
}

impl OidcRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub async fn create_client(
        &self,
        tenant_id: &str,
        client_id: &str,
        client_secret: Option<&str>,
        name: &str,
        client_type: &str,
        redirect_uris: &[String],
        allowed_scopes: &[String],
        pkce_required: bool,
        token_endpoint_auth_method: &str,
    ) -> Result<OauthClient> {
        let secret_hash = match client_secret {
            Some(secret) => Some(VaultPasswordHasher::hash(secret)?),
            None => None,
        };

        let client = sqlx::query_as::<_, OauthClient>(
            r#"
            INSERT INTO oauth_clients (
                tenant_id, client_id, client_secret_hash, name, client_type,
                redirect_uris, allowed_scopes, pkce_required, token_endpoint_auth_method,
                created_at, updated_at
            ) VALUES ($1::uuid, $2, $3, $4, $5::oauth_client_type, $6, $7, $8, $9, NOW(), NOW())
            RETURNING id::text, tenant_id::text, client_id, client_secret_hash, name, client_type::text,
                      redirect_uris, allowed_scopes, pkce_required, token_endpoint_auth_method, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(secret_hash)
        .bind(name)
        .bind(client_type)
        .bind(serde_json::json!(redirect_uris))
        .bind(serde_json::json!(allowed_scopes))
        .bind(pkce_required)
        .bind(token_endpoint_auth_method)
        .fetch_one(&*self.pool)
        .await?;

        Ok(client)
    }

    pub async fn list_clients(&self, tenant_id: &str) -> Result<Vec<OauthClient>> {
        let clients = sqlx::query_as::<_, OauthClient>(
            r#"
            SELECT id::text, tenant_id::text, client_id, client_secret_hash, name, client_type::text,
                   redirect_uris, allowed_scopes, pkce_required, token_endpoint_auth_method, created_at, updated_at
            FROM oauth_clients
            WHERE tenant_id = $1::uuid
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(clients)
    }

    pub async fn get_client(&self, tenant_id: &str, client_id: &str) -> Result<Option<OauthClient>> {
        let client = sqlx::query_as::<_, OauthClient>(
            r#"
            SELECT id::text, tenant_id::text, client_id, client_secret_hash, name, client_type::text,
                   redirect_uris, allowed_scopes, pkce_required, token_endpoint_auth_method, created_at, updated_at
            FROM oauth_clients
            WHERE tenant_id = $1::uuid AND client_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(client)
    }

    pub async fn update_client(
        &self,
        tenant_id: &str,
        client_id: &str,
        name: Option<&str>,
        redirect_uris: Option<&[String]>,
        allowed_scopes: Option<&[String]>,
        pkce_required: Option<bool>,
    ) -> Result<OauthClient> {
        let client = sqlx::query_as::<_, OauthClient>(
            r#"
            UPDATE oauth_clients
            SET name = COALESCE($3, name),
                redirect_uris = COALESCE($4, redirect_uris),
                allowed_scopes = COALESCE($5, allowed_scopes),
                pkce_required = COALESCE($6, pkce_required),
                updated_at = NOW()
            WHERE tenant_id = $1::uuid AND client_id = $2
            RETURNING id::text, tenant_id::text, client_id, client_secret_hash, name, client_type::text,
                      redirect_uris, allowed_scopes, pkce_required, token_endpoint_auth_method, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(name)
        .bind(redirect_uris.map(|v| serde_json::json!(v)))
        .bind(allowed_scopes.map(|v| serde_json::json!(v)))
        .bind(pkce_required)
        .fetch_one(&*self.pool)
        .await?;

        Ok(client)
    }

    pub async fn delete_client(&self, tenant_id: &str, client_id: &str) -> Result<()> {
        sqlx::query(
            r#"DELETE FROM oauth_clients WHERE tenant_id = $1::uuid AND client_id = $2"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_authorization_code(
        &self,
        tenant_id: &str,
        client_id: &str,
        user_id: &str,
        code: &str,
        redirect_uri: &str,
        scope: Option<&str>,
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
        nonce: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<AuthorizationCode> {
        let code_hash = VaultPasswordHasher::hash(code)?;

        let record = sqlx::query_as::<_, AuthorizationCode>(
            r#"
            INSERT INTO oauth_authorization_codes (
                tenant_id, client_id, user_id, code_hash, redirect_uri, scope,
                code_challenge, code_challenge_method, nonce, expires_at, created_at
            ) VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10, NOW())
            RETURNING id::text, tenant_id::text, client_id, user_id::text, code_hash, redirect_uri,
                      scope, code_challenge, code_challenge_method, nonce, expires_at, created_at, consumed_at
            "#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(user_id)
        .bind(code_hash)
        .bind(redirect_uri)
        .bind(scope)
        .bind(code_challenge)
        .bind(code_challenge_method)
        .bind(nonce)
        .bind(expires_at)
        .fetch_one(&*self.pool)
        .await?;

        Ok(record)
    }

    pub async fn consume_authorization_code(
        &self,
        tenant_id: &str,
        client_id: &str,
        code: &str,
    ) -> Result<Option<AuthorizationCode>> {
        let codes = sqlx::query_as::<_, AuthorizationCode>(
            r#"
            SELECT id::text, tenant_id::text, client_id, user_id::text, code_hash, redirect_uri,
                   scope, code_challenge, code_challenge_method, nonce, expires_at, created_at, consumed_at
            FROM oauth_authorization_codes
            WHERE tenant_id = $1::uuid AND client_id = $2 AND consumed_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .fetch_all(&*self.pool)
        .await?;

        for code_record in codes {
            if VaultPasswordHasher::verify(code, &code_record.code_hash)? {
                sqlx::query(
                    r#"UPDATE oauth_authorization_codes SET consumed_at = NOW() WHERE id = $1::uuid"#,
                )
                .bind(&code_record.id)
                .execute(&*self.pool)
                .await?;
                return Ok(Some(code_record));
            }
        }

        Ok(None)
    }

    pub async fn store_token(
        &self,
        tenant_id: &str,
        client_id: &str,
        user_id: Option<&str>,
        access_token_jti: &str,
        refresh_token: Option<&str>,
        scope: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<OauthToken> {
        let refresh_token_hash = match refresh_token {
            Some(token) => Some(VaultPasswordHasher::hash(token)?),
            None => None,
        };

        let record = sqlx::query_as::<_, OauthToken>(
            r#"
            INSERT INTO oauth_tokens (
                tenant_id, client_id, user_id, access_token_jti, refresh_token_hash, scope, expires_at, created_at
            ) VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, NOW())
            RETURNING id::text, tenant_id::text, client_id, user_id::text, access_token_jti, refresh_token_hash,
                      scope, expires_at, revoked_at, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(user_id)
        .bind(access_token_jti)
        .bind(refresh_token_hash)
        .bind(scope)
        .bind(expires_at)
        .fetch_one(&*self.pool)
        .await?;

        Ok(record)
    }

    pub async fn revoke_token_by_refresh(&self, tenant_id: &str, refresh_token: &str) -> Result<bool> {
        let tokens = sqlx::query_as::<_, OauthToken>(
            r#"
            SELECT id::text, tenant_id::text, client_id, user_id::text, access_token_jti, refresh_token_hash,
                   scope, expires_at, revoked_at, created_at
            FROM oauth_tokens
            WHERE tenant_id = $1::uuid AND revoked_at IS NULL AND refresh_token_hash IS NOT NULL
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&*self.pool)
        .await?;

        for token in tokens {
            if let Some(hash) = token.refresh_token_hash.as_ref() {
                if VaultPasswordHasher::verify(refresh_token, hash)? {
                    sqlx::query(
                        r#"UPDATE oauth_tokens SET revoked_at = NOW() WHERE id = $1::uuid"#,
                    )
                    .bind(&token.id)
                    .execute(&*self.pool)
                    .await?;
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    pub async fn get_token_by_jti(&self, tenant_id: &str, jti: &str) -> Result<Option<OauthToken>> {
        let token = sqlx::query_as::<_, OauthToken>(
            r#"
            SELECT id::text, tenant_id::text, client_id, user_id::text, access_token_jti, refresh_token_hash,
                   scope, expires_at, revoked_at, created_at
            FROM oauth_tokens
            WHERE tenant_id = $1::uuid AND access_token_jti = $2
            "#,
        )
        .bind(tenant_id)
        .bind(jti)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(token)
    }
}
