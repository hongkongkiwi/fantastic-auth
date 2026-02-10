//! SCIM Authentication Module
//!
//! Handles Bearer token authentication for SCIM API endpoints.
//! SCIM tokens are long-lived tokens issued by administrators for
//! integration with identity providers like Okta, Azure AD, etc.

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;

use crate::state::AppState;
use vault_core::db::set_connection_context;

/// SCIM Token record stored in the database
#[derive(Debug, Clone, FromRow)]
pub struct ScimTokenRecord {
    pub id: String,
    pub tenant_id: String,
    pub token_hash: String,
    pub name: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_by: Option<String>,
}

/// SCIM Token returned in API responses (hash excluded)
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ScimToken {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_by: Option<String>,
}

impl From<ScimTokenRecord> for ScimToken {
    fn from(record: ScimTokenRecord) -> Self {
        Self {
            id: record.id,
            tenant_id: record.tenant_id,
            name: record.name,
            status: record.status,
            created_at: record.created_at,
            expires_at: record.expires_at,
            last_used_at: record.last_used_at,
            created_by: record.created_by,
        }
    }
}

/// SCIM Token with the actual token value (only returned once at creation)
#[derive(Debug, Clone, Serialize)]
pub struct ScimTokenWithValue {
    #[serde(flatten)]
    pub token: ScimToken,
    #[serde(rename = "token")]
    pub token_value: String,
}

/// Request to create a new SCIM token
#[derive(Debug, Deserialize)]
pub struct CreateScimTokenRequest {
    pub name: String,
    #[serde(default)]
    pub expires_in_days: Option<i32>,
}

/// Response for listing SCIM tokens
#[derive(Debug, Serialize)]
pub struct ListScimTokensResponse {
    pub tokens: Vec<ScimToken>,
}

/// SCIM authentication context extracted from valid token
#[derive(Debug, Clone)]
pub struct ScimAuthContext {
    pub token_id: String,
    pub tenant_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Generate a new SCIM token
///
/// Returns the token value which should be shown to the user only once.
/// The token is stored as a hash in the database.
pub fn generate_scim_token() -> String {
    // Generate a secure random token: scim_<32 random hex chars>_<16 random hex chars>
    let part1 = generate_random_hex(32);
    let part2 = generate_random_hex(16);
    format!("scim_{}_{}", part1, part2)
}

/// Generate random hex string
/// 
/// SECURITY: Uses OsRng (operating system's CSPRNG) for generating SCIM tokens.
/// SCIM tokens grant administrative access to identity management operations,
/// so they must be cryptographically secure and unpredictable.
fn generate_random_hex(length: usize) -> String {
    use rand::RngCore;
    use rand_core::OsRng;
    
    let mut bytes = vec![0u8; length / 2];
    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Hash a SCIM token for storage
/// 
/// SECURITY: Uses SHA-256 for token hashing. The implementation relies on 
/// rate limiting to prevent brute force attacks (see validate_scim_token).
/// For enhanced security, future versions could use Argon2id with per-token salts.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Rate limit key for SCIM token validation
fn scim_rate_limit_key(token_prefix: &str) -> String {
    format!("scim:ratelimit:{}", token_prefix)
}

/// Create a new SCIM token in the database
pub async fn create_scim_token(
    state: &AppState,
    tenant_id: &str,
    name: &str,
    expires_in_days: Option<i32>,
    created_by: Option<&str>,
) -> anyhow::Result<ScimTokenWithValue> {
    let token_value = generate_scim_token();
    let token_hash = hash_token(&token_value);
    let id = uuid::Uuid::new_v4().to_string();

    let expires_at = expires_in_days.map(|days| Utc::now() + chrono::Duration::days(days as i64));

    let mut conn = state.db.pool().acquire().await?;
    set_connection_context(&mut conn, tenant_id).await?;

    let token = sqlx::query_as::<_, ScimToken>(
        r#"
        INSERT INTO scim_tokens (id, tenant_id, token_hash, name, status, created_at, expires_at, created_by)
        VALUES ($1, $2, $3, $4, 'active', NOW(), $5, $6)
        RETURNING id, tenant_id, name, status, created_at, expires_at, last_used_at, created_by
        "#
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(&token_hash)
    .bind(name)
    .bind(expires_at)
    .bind(created_by)
    .fetch_one(&mut *conn)
    .await?;

    Ok(ScimTokenWithValue { token, token_value })
}

/// Validate a SCIM token
///
/// Returns the token if valid, None otherwise
/// 
/// SECURITY: Implements rate limiting to prevent brute force attacks against tokens.
/// Allows 5 attempts per 15-minute window per token prefix.
pub async fn validate_scim_token(state: &AppState, token: &str) -> Option<ScimToken> {
    // Extract token prefix for rate limiting (first 16 chars after "scim_")
    let rate_limit_key = if token.len() > 20 {
        scim_rate_limit_key(&token[..20])
    } else {
        scim_rate_limit_key(token)
    };
    
    // SECURITY: Check rate limit before attempting validation
    // This prevents brute force attacks against SCIM tokens
    if let Some(ref redis) = state.redis {
        let mut conn = redis.clone();
        let attempts: Option<i32> = redis::cmd("INCR")
            .arg(&rate_limit_key)
            .query_async(&mut conn)
            .await
            .ok()
            .flatten();
        
        // Set expiry on first attempt
        if attempts == Some(1) {
            let _: Result<(), _> = redis::cmd("EXPIRE")
                .arg(&rate_limit_key)
                .arg(900) // 15 minutes
                .query_async(&mut conn)
                .await;
        }
        
        // Block if more than 5 attempts in window
        if attempts.map_or(false, |a| a > 5) {
            tracing::warn!(
                token_prefix = %rate_limit_key,
                "SCIM token validation rate limited - possible brute force attack"
            );
            return None;
        }
    }

    // Hash the provided token
    let token_hash = hash_token(token);

    // Look up the token
    let result = sqlx::query_as::<_, ScimTokenRecord>(
        r#"
        SELECT id, tenant_id, token_hash, name, status, created_at, expires_at, last_used_at, created_by
        FROM get_scim_token_by_hash($1)
        "#
    )
    .bind(&token_hash)
    .fetch_optional(state.db.pool())
    .await;

    match result {
        Ok(Some(token)) => {
            // Check if token is expired
            if let Some(expires_at) = token.expires_at {
                if Utc::now() > expires_at {
                    return None;
                }
            }
            
            // Reset rate limit on successful validation
            if let Some(ref redis) = state.redis {
                let mut conn = redis.clone();
                let _: Result<(), _> = redis::cmd("DEL")
                    .arg(&rate_limit_key)
                    .query_async(&mut conn)
                    .await;
            }
            
            Some(token.into())
        }
        _ => None,
    }
}

/// Update last used timestamp for a token
pub async fn update_token_last_used(
    state: &AppState,
    tenant_id: &str,
    token_id: &str,
) -> anyhow::Result<()> {
    let mut conn = state.db.pool().acquire().await?;
    set_connection_context(&mut conn, tenant_id).await?;

    sqlx::query(
        r#"
        UPDATE scim_tokens
        SET last_used_at = NOW()
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(token_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// Revoke a SCIM token
pub async fn revoke_scim_token(
    state: &AppState,
    tenant_id: &str,
    token_id: &str,
) -> anyhow::Result<bool> {
    let mut conn = state.db.pool().acquire().await?;
    set_connection_context(&mut conn, tenant_id).await?;

    let result = sqlx::query(
        r#"
        UPDATE scim_tokens
        SET status = 'revoked'
        WHERE id = $1 AND tenant_id = $2 AND status = 'active'
        "#,
    )
    .bind(token_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// List active SCIM tokens for a tenant
pub async fn list_scim_tokens(state: &AppState, tenant_id: &str) -> anyhow::Result<Vec<ScimToken>> {
    let mut conn = state.db.pool().acquire().await?;
    set_connection_context(&mut conn, tenant_id).await?;

    let tokens = sqlx::query_as::<_, ScimToken>(
        r#"
        SELECT id, tenant_id, name, status, created_at, expires_at, last_used_at, created_by
        FROM scim_tokens
        WHERE tenant_id = $1 AND status = 'active'
        ORDER BY created_at DESC
        "#
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(tokens)
}

/// Delete a SCIM token (hard delete)
pub async fn delete_scim_token(
    state: &AppState,
    tenant_id: &str,
    token_id: &str,
) -> anyhow::Result<bool> {
    let mut conn = state.db.pool().acquire().await?;
    set_connection_context(&mut conn, tenant_id).await?;

    let result = sqlx::query(
        r#"
        DELETE FROM scim_tokens
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(token_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Extract Bearer token from Authorization header
fn extract_bearer_token(request: &Request) -> Option<String> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;

    if auth_header.starts_with("Bearer ") {
        Some(auth_header[7..].to_string())
    } else {
        None
    }
}

fn extract_ip_address(request: &Request) -> Option<String> {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
}

fn extract_user_agent(request: &Request) -> Option<String> {
    request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// SCIM Authentication Middleware
///
/// Validates Bearer tokens for SCIM endpoints and sets the tenant context.
/// This is different from regular JWT auth - SCIM uses long-lived tokens.
pub async fn scim_auth_middleware(
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract state from extensions
    let state = request
        .extensions()
        .get::<AppState>()
        .cloned()
        .ok_or_else(|| {
            tracing::error!("AppState not found in request extensions");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Extract Bearer token
    let token = match extract_bearer_token(&request) {
        Some(t) => t,
        None => {
            tracing::warn!("SCIM request missing Bearer token");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Validate token
    let scim_token = match validate_scim_token(&state, &token).await {
        Some(t) => t,
        None => {
            tracing::warn!("SCIM request with invalid token");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Update last used timestamp (fire and forget)
    let state_clone = state.clone();
    let tenant_id = scim_token.tenant_id.clone();
    let token_id = scim_token.id.clone();
    tokio::spawn(async move {
        let _ = update_token_last_used(&state_clone, &tenant_id, &token_id).await;
    });

    // Set tenant context
    if let Err(e) = state.set_tenant_context(&scim_token.tenant_id).await {
        tracing::error!("Failed to set tenant context: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let tenant_id_for_ctx = scim_token.tenant_id.clone();
    let ip_address = extract_ip_address(&request);
    let user_agent = extract_user_agent(&request);
    // Create auth context
    let auth_context = ScimAuthContext {
        token_id: scim_token.id,
        tenant_id: scim_token.tenant_id,
        ip_address,
        user_agent,
    };

    // Add auth context to request extensions
    request.extensions_mut().insert(auth_context);

    // Also set request context for RLS
    let ctx = vault_core::db::RequestContext {
        tenant_id: Some(tenant_id_for_ctx),
        user_id: None,
        role: Some("scim".to_string()),
    };

    Ok(vault_core::db::with_request_context(ctx, next.run(request)).await)
}

/// Optional SCIM auth middleware
///
/// Same as scim_auth_middleware but doesn't fail if no token is present.
/// Used for discovery endpoints that don't require authentication.
pub async fn optional_scim_auth_middleware(mut request: Request, next: Next) -> Response {
    // Extract state from extensions
    let state = match request.extensions().get::<AppState>() {
        Some(s) => s.clone(),
        None => {
            let ctx = vault_core::db::RequestContext::default();
            return vault_core::db::with_request_context(ctx, next.run(request)).await;
        }
    };

    // Try to extract Bearer token
    if let Some(token) = extract_bearer_token(&request) {
        if let Some(scim_token) = validate_scim_token(&state, &token).await {
            // Set tenant context
            let _ = state.set_tenant_context(&scim_token.tenant_id).await;

            let tenant_id = scim_token.tenant_id.clone();
            let tenant_id_for_ctx = scim_token.tenant_id.clone();
            let ip_address = extract_ip_address(&request);
            let user_agent = extract_user_agent(&request);
            // Create auth context
            let auth_context = ScimAuthContext {
                token_id: scim_token.id.clone(),
                tenant_id: scim_token.tenant_id,
                ip_address,
                user_agent,
            };

            request.extensions_mut().insert(auth_context);

            // Update last used timestamp (fire and forget)
            let state_clone = state.clone();
            let token_id = scim_token.id.clone();
            tokio::spawn(async move {
                let _ = update_token_last_used(&state_clone, &tenant_id, &token_id).await;
            });

            let ctx = vault_core::db::RequestContext {
                tenant_id: Some(tenant_id_for_ctx),
                user_id: None,
                role: Some("scim".to_string()),
            };

            return vault_core::db::with_request_context(ctx, next.run(request)).await;
        }
    }

    let ctx = vault_core::db::RequestContext::default();
    vault_core::db::with_request_context(ctx, next.run(request)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_format() {
        let token = generate_scim_token();
        assert!(token.starts_with("scim_"));
        let parts: Vec<&str> = token.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1].len(), 32);
        assert_eq!(parts[2].len(), 16);
    }

    #[test]
    fn test_hash_token() {
        let token = "test_token_123";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_hash_token_different() {
        let hash1 = hash_token("token1");
        let hash2 = hash_token("token2");
        assert_ne!(hash1, hash2);
    }
}
