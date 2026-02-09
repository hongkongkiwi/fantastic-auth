//! Anonymous/Guest Authentication
//!
//! Allows users to use the app without registering, then convert to full accounts later.
//! Anonymous users have limited permissions and shorter session durations.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::net::IpAddr;
use uuid::Uuid;

use vault_core::crypto::{Claims, HybridJwt, HybridSigningKey, TokenType, VaultPasswordHasher};
use vault_core::error::{Result, VaultError};
use vault_core::db::sessions::Session as DbSession;
use vault_core::models::user::{User, UserProfile, UserStatus};

use crate::state::AppState;

/// Anonymous session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousSession {
    /// Unique session ID (also the user ID for anonymous users)
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Anonymous session token (temporary identifier)
    pub anonymous_session_id: String,
    /// IP address that created the session
    pub created_from_ip: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Session created at
    pub created_at: DateTime<Utc>,
    /// Session expires at (shorter than regular sessions)
    pub expires_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity_at: DateTime<Utc>,
    /// Whether this session has been converted to a full account
    pub converted_to_user_id: Option<String>,
    /// When the session was converted
    pub converted_at: Option<DateTime<Utc>>,
    /// Session metadata (for tracking feature usage)
    pub metadata: serde_json::Value,
}

impl AnonymousSession {
    /// Create a new anonymous session
    pub fn new(tenant_id: impl Into<String>, ip: Option<IpAddr>, user_agent: Option<String>) -> Self {
        let now = Utc::now();
        let expires_at = now + Duration::hours(24); // 24 hour default expiry

        Self {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.into(),
            anonymous_session_id: format!("anon_{}", Uuid::new_v4().to_string().replace("-", "")),
            created_from_ip: ip.map(|i| i.to_string()),
            user_agent,
            created_at: now,
            expires_at,
            last_activity_at: now,
            converted_to_user_id: None,
            converted_at: None,
            metadata: serde_json::json!({}),
        }
    }

    /// Check if the session is still valid
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at && self.converted_to_user_id.is_none()
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Mark the session as converted to a full user account
    pub fn mark_converted(&mut self, user_id: impl Into<String>) {
        self.converted_to_user_id = Some(user_id.into());
        self.converted_at = Some(Utc::now());
    }

    /// Record activity
    pub fn record_activity(&mut self) {
        self.last_activity_at = Utc::now();
    }

    /// Extend session expiration (up to max limit)
    pub fn extend_expiration(&mut self, hours: i64) {
        let max_expiry = self.created_at + Duration::hours(24 * 7); // Max 7 days from creation
        let proposed_expiry = Utc::now() + Duration::hours(hours);
        
        self.expires_at = if proposed_expiry > max_expiry {
            max_expiry
        } else {
            proposed_expiry
        };
    }
}

/// Anonymous user creation request
#[derive(Debug, Deserialize, Validate)]
pub struct CreateAnonymousSessionRequest {
    /// Optional: Client device information
    pub device_info: Option<serde_json::Value>,
    /// Optional: Consent to terms (if required by tenant)
    #[serde(rename = "termsAccepted")]
    pub terms_accepted: Option<bool>,
}

/// Response for anonymous session creation
#[derive(Debug, Serialize)]
pub struct AnonymousSessionResponse {
    /// Access token for the anonymous session
    #[serde(rename = "access_token")]
    pub access_token: String,
    /// Refresh token (optional for anonymous users)
    #[serde(rename = "refresh_token")]
    pub refresh_token: String,
    /// Anonymous session ID
    #[serde(rename = "anonymous_id")]
    pub anonymous_id: String,
    /// Session expiration time
    #[serde(rename = "expires_at")]
    pub expires_at: DateTime<Utc>,
    /// Whether this is a new session or continuation
    pub is_new: bool,
}

/// Request to convert anonymous session to full account
#[derive(Debug, Deserialize, Validate)]
pub struct ConvertAnonymousRequest {
    /// Anonymous session ID
    #[serde(rename = "anonymous_id")]
    pub anonymous_id: String,
    /// Email address for the new account
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    /// Password for the new account
    #[validate(length(min = 12, message = "Password must be at least 12 characters"))]
    pub password: String,
    /// Optional: Full name
    pub name: Option<String>,
    /// Required: Consent to Terms of Service
    #[serde(rename = "termsAccepted")]
    pub terms_accepted: bool,
    /// Required: Consent to Privacy Policy
    #[serde(rename = "privacyAccepted")]
    pub privacy_accepted: bool,
}

/// Response for anonymous conversion
#[derive(Debug, Serialize)]
pub struct AnonymousConversionResponse {
    /// New access token for the full account
    #[serde(rename = "access_token")]
    pub access_token: String,
    /// New refresh token
    #[serde(rename = "refresh_token")]
    pub refresh_token: String,
    /// User information
    pub user: AnonymousConversionUser,
    /// Whether data migration was successful
    #[serde(rename = "data_migrated")]
    pub data_migrated: bool,
}

/// User info in conversion response
#[derive(Debug, Serialize)]
pub struct AnonymousConversionUser {
    pub id: String,
    pub email: String,
    #[serde(rename = "email_verified")]
    pub email_verified: bool,
    pub name: Option<String>,
    #[serde(rename = "is_anonymous")]
    pub is_anonymous: bool,
    #[serde(rename = "previous_anonymous_id")]
    pub previous_anonymous_id: String,
}

/// Anonymous user rate limit key
pub fn anonymous_rate_limit_key(ip: &IpAddr) -> String {
    format!("anon:rate_limit:ip:{}", ip)
}

/// Create a new anonymous session
pub async fn create_anonymous_session(
    state: &AppState,
    tenant_id: &str,
    ip: Option<IpAddr>,
    user_agent: Option<String>,
) -> Result<AnonymousSessionResponse> {
    // Check anonymous user rate limits
    if let Some(ref ip_addr) = ip {
        let allowed = state
            .rate_limiter
            .is_allowed(
                &anonymous_rate_limit_key(ip_addr),
                state.config.rate_limit.anonymous_per_hour,
                3600, // 1 hour window
            )
            .await;

        if !allowed {
            return Err(VaultError::rate_limit(3600)); // Retry after 1 hour
        }
    }

    // Create the anonymous session
    let session = AnonymousSession::new(tenant_id, ip, user_agent.clone());

    // Store the anonymous user in the database
    let user = create_anonymous_user(state, tenant_id, &session).await?;

    // Create a regular session for the anonymous user
    let db_session = create_anonymous_db_session(
        state,
        tenant_id,
        &user.id,
        ip,
        user_agent,
    ).await?;

    // Generate tokens
    let (access_token, refresh_token) = generate_anonymous_tokens(
        state,
        tenant_id,
        &user.id,
        &db_session.id,
        &session.anonymous_session_id,
    ).await?;

    // Store anonymous session metadata in Redis if available
    store_anonymous_session(state, &session).await;

    Ok(AnonymousSessionResponse {
        access_token,
        refresh_token,
        anonymous_id: session.anonymous_session_id.clone(),
        expires_at: session.expires_at,
        is_new: true,
    })
}

/// Create an anonymous user in the database
async fn create_anonymous_user(
    state: &AppState,
    tenant_id: &str,
    anon_session: &AnonymousSession,
) -> Result<User> {
    // Generate a placeholder email for anonymous users
    let placeholder_email = format!("{}@anonymous.vault", anon_session.id);

    let create_req = vault_core::db::users::CreateUserRequest {
        tenant_id: tenant_id.to_string(),
        email: placeholder_email,
        password_hash: None, // Anonymous users have no password
        email_verified: false,
        profile: Some(serde_json::json!({
            "is_anonymous": true,
            "anonymous_session_id": anon_session.anonymous_session_id,
            "created_from_ip": anon_session.created_from_ip,
        })),
        metadata: Some(serde_json::json!({
            "anonymous_session_id": anon_session.anonymous_session_id,
            "anonymous_created_at": anon_session.created_at,
            "anonymous_expires_at": anon_session.expires_at,
        })),
    };

    let user = state.db.users().create(create_req).await?;

    // Mark user as anonymous using raw SQL since we need to set is_anonymous
    sqlx::query(
        r#"UPDATE users 
           SET is_anonymous = true, 
               anonymous_session_id = $1,
               status = 'active'::user_status
           WHERE id = $2"#,
    )
    .bind(&anon_session.anonymous_session_id)
    .bind(&user.id)
    .execute(state.db.pool())
    .await
    .map_err(|e| VaultError::internal(format!("Failed to mark user as anonymous: {}", e)))?;

    Ok(user)
}

/// Create a database session for anonymous user
async fn create_anonymous_db_session(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    ip: Option<IpAddr>,
    user_agent: Option<String>,
) -> Result<DbSession> {
    let access_token_jti = Uuid::new_v4().to_string();
    let refresh_token_hash = format!("anon_refresh_{}", Uuid::new_v4());
    let token_family = format!("anon_family_{}", Uuid::new_v4());

    let expires_at = Utc::now() + Duration::hours(24);

    let session_req = vault_core::db::sessions::CreateSessionRequest {
        tenant_id: tenant_id.to_string(),
        user_id: user_id.to_string(),
        access_token_jti: access_token_jti.clone(),
        refresh_token_hash: refresh_token_hash.clone(),
        token_family: token_family.clone(),
        ip_address: ip,
        user_agent: user_agent.clone(),
        device_fingerprint: None,
        device_info: serde_json::json!({
            "type": "anonymous",
            "user_agent": user_agent,
        }),
        location: None,
        mfa_verified: false,
        expires_at,
        bind_to_ip: state.config.security.session_binding.bind_to_ip,
        bind_to_device: state.config.security.session_binding.bind_to_device,
    };

    state.db.sessions().create(session_req).await
}

/// Generate tokens for anonymous session
async fn generate_anonymous_tokens(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    session_id: &str,
    anonymous_session_id: &str,
) -> Result<(String, String)> {
    let now = Utc::now();
    let access_expires = now + Duration::minutes(60); // 1 hour for anonymous
    let refresh_expires = now + Duration::hours(24); // 24 hours for anonymous

    // Access token claims
    let access_claims = Claims::new(
        user_id,
        tenant_id,
        TokenType::Access,
        &state.config.jwt.issuer,
        &state.config.jwt.audience,
    )
    .with_expiry(access_expires)
    .with_session(session_id)
    .with_custom("is_anonymous", true)
    .with_custom("anonymous_session_id", anonymous_session_id)
    .with_custom("auth_method", "anonymous")
    .with_roles(vec!["anonymous".to_string()]);

    // Refresh token claims
    let refresh_claims = Claims::new(
        user_id,
        tenant_id,
        TokenType::Refresh,
        &state.config.jwt.issuer,
        &state.config.jwt.audience,
    )
    .with_expiry(refresh_expires)
    .with_session(session_id)
    .with_custom("is_anonymous", true);

    let signing_key = state.auth_service.signing_key();

    let access_token = HybridJwt::encode(&access_claims, signing_key)?;
    let refresh_token = HybridJwt::encode(&refresh_claims, signing_key)?;

    Ok((access_token, refresh_token))
}

/// Store anonymous session metadata
async fn store_anonymous_session(state: &AppState, session: &AnonymousSession) {
    if let Some(ref redis) = state.redis {
        let key = format!("anon:session:{}", session.anonymous_session_id);
        let value = match serde_json::to_string(session) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to serialize anonymous session: {}", e);
                return;
            }
        };

        let expiry_secs = (session.expires_at - Utc::now()).num_seconds() as u64;

        let mut conn = redis.clone();
    let _: redis::RedisResult<()> = redis::cmd("SETEX")
        .arg(&key)
        .arg(expiry_secs)
        .arg(&value)
        .query_async(&mut conn)
        .await;
    }
}

/// Convert anonymous session to full account
pub async fn convert_to_full_account(
    state: &AppState,
    tenant_id: &str,
    req: ConvertAnonymousRequest,
    ip: Option<IpAddr>,
) -> Result<AnonymousConversionResponse> {
    // Find the anonymous session
    let anon_user = find_anonymous_user(state, tenant_id, &req.anonymous_id).await?;

    if anon_user.is_none() {
        return Err(VaultError::not_found("Anonymous session", &req.anonymous_id));
    }

    let (mut anon_user, anon_session_id) = anon_user.unwrap();

    // Check if already converted
    if !is_anonymous_user(&anon_user) {
        return Err(VaultError::validation("Anonymous session has already been converted"));
    }

    // Validate password against policy
    let user_info = crate::security::UserInfo {
        email: req.email.clone(),
        name: req.name.clone(),
        user_id: anon_user.id.clone(),
    };

    let validation_result = state
        .security_service
        .validate_password(&req.password, Some(&user_info))
        .await;

    if !validation_result.is_valid {
        return Err(VaultError::validation(format!(
            "Password does not meet policy requirements: {:?}",
            validation_result.error_messages()
        )));
    }

    // Check if email already exists
    let existing_user = state.db.users().find_by_email(tenant_id, &req.email).await?;
    if existing_user.is_some() {
        return Err(VaultError::conflict("Email address is already registered"));
    }

    // Hash the password
    let password_hash = VaultPasswordHasher::hash(&req.password)
        .map_err(|e| VaultError::crypto(format!("Failed to hash password: {}", e)))?;

    // Update the user to a full account
    let now = Utc::now();
    
    // Build updated profile
    let mut profile = anon_user.profile.clone();
    profile.name = req.name.clone();

    // Update user in database
    sqlx::query(
        r#"UPDATE users 
           SET email = $1,
               password_hash = $2,
               is_anonymous = false,
               anonymous_session_id = NULL,
               email_verified = false,
               status = 'pending'::user_status,
               profile = $3,
               metadata = jsonb_set(
                   COALESCE(metadata, '{}'::jsonb),
                   '{converted_from_anonymous}',
                   $4::jsonb
               ),
               updated_at = $5
           WHERE id = $6 AND tenant_id = $7::uuid"#,
    )
    .bind(&req.email)
    .bind(&password_hash)
    .bind(serde_json::to_value(&profile)?)
    .bind(serde_json::json!({
        "anonymous_id": anon_session_id,
        "converted_at": now,
    }))
    .bind(now)
    .bind(&anon_user.id)
    .bind(tenant_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| VaultError::internal(format!("Failed to convert anonymous user: {}", e)))?;

    // Migrate anonymous data to full account
    let data_migrated = migrate_anonymous_data(state, tenant_id, &anon_user.id).await.unwrap_or(false);

    // Mark anonymous session as converted in Redis
    mark_session_converted(state, &anon_session_id, &anon_user.id).await;

    // Create new session for the converted user
    let new_session = create_anonymous_db_session(
        state,
        tenant_id,
        &anon_user.id,
        ip,
        None,
    ).await?;

    // Generate new tokens for full account
    let (access_token, refresh_token) = generate_full_account_tokens(
        state,
        tenant_id,
        &anon_user.id,
        &req.email,
        &new_session.id,
    ).await?;

    // Update the user object to reflect changes
    anon_user.email = req.email.clone();
    anon_user.email_verified = false;

    Ok(AnonymousConversionResponse {
        access_token,
        refresh_token,
        user: AnonymousConversionUser {
            id: anon_user.id.clone(),
            email: req.email,
            email_verified: false,
            name: req.name,
            is_anonymous: false,
            previous_anonymous_id: anon_session_id.to_string(),
        },
        data_migrated,
    })
}

/// Find anonymous user by session ID
async fn find_anonymous_user(
    state: &AppState,
    tenant_id: &str,
    anonymous_session_id: &str,
) -> Result<Option<(User, String)>> {
    // Try to find by anonymous_session_id
    let row = sqlx::query_as::<_, (String, String, serde_json::Value, serde_json::Value)>(
        r#"SELECT id::text, email, profile, metadata 
           FROM users 
           WHERE tenant_id = $1::uuid 
             AND anonymous_session_id = $2 
             AND is_anonymous = true
             AND deleted_at IS NULL"#,
    )
    .bind(tenant_id)
    .bind(anonymous_session_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| VaultError::internal(format!("Failed to find anonymous user: {}", e)))?;

    match row {
        Some((id, email, profile, metadata)) => {
            let user = User {
                id,
                tenant_id: tenant_id.to_string(),
                email,
                email_verified: false,
                status: UserStatus::Active,
                profile: serde_json::from_value(profile).unwrap_or_default(),
                ..Default::default()
            };
            Ok(Some((user, anonymous_session_id.to_string())))
        }
        None => Ok(None),
    }
}

/// Check if a user is anonymous
fn is_anonymous_user(user: &User) -> bool {
    // Check metadata for anonymous flag
    if let Some(metadata) = user.metadata.as_object() {
        if let Some(is_anon) = metadata.get("is_anonymous") {
            return is_anon.as_bool().unwrap_or(false);
        }
    }
    // Also check profile
    if let Some(profile) = user.metadata.as_object() {
        if let Some(is_anon) = profile.get("is_anonymous") {
            return is_anon.as_bool().unwrap_or(false);
        }
    }
    user.email.ends_with("@anonymous.vault")
}

/// Migrate data from anonymous session to full account
async fn migrate_anonymous_data(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
) -> anyhow::Result<bool> {
    // This is a placeholder for data migration logic
    // In a real implementation, you would migrate:
    // - User preferences
    // - Saved items/wishlists
    // - Cart contents
    // - Draft content
    // - Activity history
    // - etc.
    
    tracing::info!(
        "Migrating anonymous data for user {} in tenant {}",
        user_id,
        tenant_id
    );

    // For now, we just return success
    // The actual migration depends on what data your app stores for anonymous users
    Ok(true)
}

/// Mark anonymous session as converted in Redis
async fn mark_session_converted(state: &AppState, anonymous_session_id: &str, user_id: &str) {
    if let Some(ref redis) = state.redis {
        let key = format!("anon:session:{}", anonymous_session_id);
        let converted_key = format!("anon:converted:{}", anonymous_session_id);

        let mut conn = redis.clone();
        
        // Delete the original session
        let _: redis::RedisResult<()> = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut conn)
            .await;

        // Store conversion record
        let _: redis::RedisResult<()> = redis::cmd("SETEX")
            .arg(&converted_key)
            .arg(86400 * 7) // Keep for 7 days
            .arg(user_id)
            .query_async(&mut conn)
            .await;
    }
}

/// Generate tokens for full account after conversion
async fn generate_full_account_tokens(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    email: &str,
    session_id: &str,
) -> Result<(String, String)> {
    let now = Utc::now();
    let access_expires = now + Duration::minutes(15); // Standard 15 min for full accounts
    let refresh_expires = now + Duration::days(7); // Standard 7 days for full accounts

    // Access token claims
    let access_claims = Claims::new(
        user_id,
        tenant_id,
        TokenType::Access,
        &state.config.jwt.issuer,
        &state.config.jwt.audience,
    )
    .with_expiry(access_expires)
    .with_session(session_id)
    .with_email(email, false)
    .with_roles(vec!["user".to_string()]);

    // Refresh token claims
    let refresh_claims = Claims::new(
        user_id,
        tenant_id,
        TokenType::Refresh,
        &state.config.jwt.issuer,
        &state.config.jwt.audience,
    )
    .with_expiry(refresh_expires)
    .with_session(session_id);

    let signing_key = state.auth_service.signing_key();

    let access_token = HybridJwt::encode(&access_claims, signing_key)?;
    let refresh_token = HybridJwt::encode(&refresh_claims, signing_key)?;

    Ok((access_token, refresh_token))
}

/// Validate anonymous token claims
pub fn validate_anonymous_claims(claims: &Claims) -> Result<()> {
    // Check if this is an anonymous token
    let is_anonymous = claims
        .custom
        .get("is_anonymous")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_anonymous {
        return Err(VaultError::authentication("Not an anonymous session token"));
    }

    // Check token expiration
    if claims.is_expired() {
        return Err(VaultError::authentication("Anonymous session has expired"));
    }

    Ok(())
}

/// Extend anonymous session
pub async fn extend_anonymous_session(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    session_id: &str,
) -> Result<bool> {
    // Check if user is still anonymous
    let user = state.db.users().find_by_id(tenant_id, user_id).await?;
    
    match user {
        Some(u) if is_anonymous_user(&u) => {
            // Extend the session by updating expires_at
            let new_expires = Utc::now() + Duration::hours(24);
            
            sqlx::query(
                "UPDATE sessions SET expires_at = $1, updated_at = $2 
                 WHERE id = $3::uuid AND tenant_id = $4::uuid"
            )
            .bind(new_expires)
            .bind(Utc::now())
            .bind(session_id)
            .bind(tenant_id)
            .execute(state.db.pool())
            .await
            .map_err(|e| VaultError::internal(format!("Failed to extend session: {}", e)))?;

            Ok(true)
        }
        _ => Ok(false), // User no longer anonymous or not found
    }
}

/// Cleanup expired anonymous sessions
pub async fn cleanup_expired_anonymous_sessions(state: &AppState) -> anyhow::Result<(u64, u64)> {
    // Find and delete expired anonymous sessions
    let result = sqlx::query(
        r#"WITH deleted_sessions AS (
            DELETE FROM sessions 
            WHERE user_id IN (
                SELECT id FROM users 
                WHERE is_anonymous = true 
                AND created_at < NOW() - INTERVAL '7 days'
            )
            AND expires_at < NOW()
            RETURNING id
        ),
        deleted_users AS (
            UPDATE users 
            SET deleted_at = NOW(), 
                status = 'deleted'::user_status,
                updated_at = NOW()
            WHERE is_anonymous = true 
            AND created_at < NOW() - INTERVAL '7 days'
            AND deleted_at IS NULL
            RETURNING id
        )
        SELECT 
            (SELECT COUNT(*) FROM deleted_sessions) as sessions,
            (SELECT COUNT(*) FROM deleted_users) as users"#,
    )
    .fetch_one(state.db.pool())
    .await?;

    let sessions: i64 = result.try_get("sessions")?;
    let users: i64 = result.try_get("users")?;

    Ok((sessions as u64, users as u64))
}

use validator::Validate;
