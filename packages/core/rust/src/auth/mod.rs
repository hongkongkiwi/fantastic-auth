//! Authentication service
//!
//! Main coordinator for authentication flows including:
//! - User registration
//! - Login with password
//! - Token refresh
//! - Session management
//! - MFA verification

use crate::crypto::{
    generate_secure_random, Claims, HybridJwt, HybridSigningKey, HybridVerifyingKey, TokenType,
    VaultPasswordHasher,
};
use crate::db::sessions::SessionStatus as DbSessionStatus;
use sha2::{Sha256, Digest};

use crate::db::users::CreateUserRequest;
use crate::db::DbContext;
use crate::email::templates::{
    EmailTemplate, MagicLinkEmail, PasswordResetEmail, VerificationEmail,
};
use crate::error::{Result, VaultError};
use crate::models::session::Session;
use crate::models::user::{User, UserStatus};
use crate::sms::SmsService;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::sync::Arc;

pub mod biometric;
pub mod email;
pub mod mfa;
pub mod oauth;
pub mod password;
pub mod token_store;

#[async_trait]
pub trait DataKeyResolver: Send + Sync {
    async fn resolve_key(&self, tenant_id: &str) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait SmsServiceResolver: Send + Sync {
    async fn resolve_sms_service(&self, tenant_id: &str) -> Option<Arc<SmsService>>;
}

pub use biometric::{
    verify_ecdsa_signature, BiometricAuthSuccess, BiometricChallenge, BiometricError, BiometricKey,
    BiometricKeyStore, BiometricType, ChallengeStore, RegisterBiometricKeyRequest,
};

use token_store::{InMemoryTokenStore, StoredTokenData, StoredTokenType, TokenStore};

/// Login credentials
#[derive(Debug, Clone)]
pub struct LoginCredentials {
    /// Email address
    pub email: String,
    /// Password
    pub password: String,
    /// MFA code (if required)
    pub mfa_code: Option<String>,
}

/// Email payload for sending
#[derive(Debug, Clone)]
pub struct EmailPayload {
    pub tenant_id: String,
    pub to: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}

/// Authentication service
pub struct AuthService {
    signing_key: HybridSigningKey,
    verifying_key: HybridVerifyingKey,
    jwt_issuer: String,
    jwt_audience: String,
    db: Arc<DbContext>,
    /// Email sender callback
    email_sender: Option<
        Arc<
            dyn Fn(
                    EmailPayload,
                )
                    -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
                + Send
                + Sync,
        >,
    >,
    /// Base URL for email links
    base_url: String,
    /// Token storage backend
    token_store: Arc<dyn TokenStore>,
    /// Optional data encryption key (AES-256-GCM)
    data_encryption_key: Option<Vec<u8>>,
    /// Optional per-tenant data key resolver (DEK provider)
    data_key_resolver: Option<Arc<dyn DataKeyResolver>>,
    /// Optional SMS service for MFA
    sms_service: Option<Arc<SmsService>>,
    /// Optional SMS service resolver (per-tenant)
    sms_service_resolver: Option<Arc<dyn SmsServiceResolver>>,
}

impl AuthService {
    /// Create new auth service with generated keys and in-memory token store
    pub fn new(
        jwt_issuer: impl Into<String>,
        jwt_audience: impl Into<String>,
        db: Arc<DbContext>,
        base_url: impl Into<String>,
    ) -> Self {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        Self {
            signing_key,
            verifying_key,
            jwt_issuer: jwt_issuer.into(),
            jwt_audience: jwt_audience.into(),
            db,
            email_sender: None,
            base_url: base_url.into(),
            token_store: Arc::new(InMemoryTokenStore::new()),
            data_encryption_key: None,
            data_key_resolver: None,
            sms_service: None,
            sms_service_resolver: None,
        }
    }

    /// Create new auth service with Redis token store
    pub async fn with_redis(
        jwt_issuer: impl Into<String>,
        jwt_audience: impl Into<String>,
        db: Arc<DbContext>,
        base_url: impl Into<String>,
        redis_url: &str,
    ) -> Result<Self> {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        let token_store = token_store::RedisTokenStore::new(redis_url)
            .await
            .map_err(|e| {
                VaultError::Config(format!("Failed to create Redis token store: {}", e))
            })?;

        Ok(Self {
            signing_key,
            verifying_key,
            jwt_issuer: jwt_issuer.into(),
            jwt_audience: jwt_audience.into(),
            db,
            email_sender: None,
            base_url: base_url.into(),
            token_store: Arc::new(token_store),
            data_encryption_key: None,
            data_key_resolver: None,
            sms_service: None,
            sms_service_resolver: None,
        })
    }

    /// Create with custom token store
    pub fn with_token_store(
        jwt_issuer: impl Into<String>,
        jwt_audience: impl Into<String>,
        db: Arc<DbContext>,
        base_url: impl Into<String>,
        token_store: Arc<dyn TokenStore>,
    ) -> Self {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        Self {
            signing_key,
            verifying_key,
            jwt_issuer: jwt_issuer.into(),
            jwt_audience: jwt_audience.into(),
            db,
            email_sender: None,
            base_url: base_url.into(),
            token_store,
            data_encryption_key: None,
            data_key_resolver: None,
            sms_service: None,
            sms_service_resolver: None,
        }
    }

    /// Set data encryption key (AES-256-GCM)
    pub fn with_data_encryption_key(mut self, key: Vec<u8>) -> Self {
        self.data_encryption_key = Some(key);
        self
    }

    /// Set per-tenant data key resolver (DEK provider)
    pub fn with_data_key_resolver(mut self, resolver: Arc<dyn DataKeyResolver>) -> Self {
        self.data_key_resolver = Some(resolver);
        self
    }

    /// Set SMS service for MFA
    pub fn with_sms_service(mut self, sms_service: Arc<SmsService>) -> Self {
        self.sms_service = Some(sms_service);
        self
    }

    pub fn with_sms_service_resolver(mut self, resolver: Arc<dyn SmsServiceResolver>) -> Self {
        self.sms_service_resolver = Some(resolver);
        self
    }

    /// Set email sender callback
    pub fn with_email_sender<F, Fut>(mut self, sender: F) -> Self
    where
        F: Fn(EmailPayload) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        self.email_sender = Some(Arc::new(move |payload| Box::pin(sender(payload))));
        self
    }

    /// Send email using configured sender
    async fn send_email(&self, payload: EmailPayload) -> Result<()> {
        if let Some(sender) = &self.email_sender {
            sender(payload).await
        } else {
            // Email service not configured - log and continue
            tracing::info!("Email would be sent to {}: {}", payload.to, payload.subject);
            Ok(())
        }
    }

    /// Register a new user
    pub async fn register(
        &self,
        tenant_id: impl Into<String>,
        email: impl Into<String>,
        password: impl Into<String>,
        name: Option<String>,
    ) -> Result<(User, String)> {
        let tenant_id = tenant_id.into();
        let email = email.into();
        let password = password.into();

        // Check if user already exists
        if self.db.users().email_exists(&tenant_id, &email).await? {
            return Err(VaultError::conflict(format!(
                "User with email {} already exists",
                email
            )));
        }

        // Check password strength
        password::validate_password_strength(&password)?;

        // Hash password
        let password_hash = VaultPasswordHasher::hash(&password)?;

        // Create profile
        let profile = name.clone().map(|n| {
            serde_json::json!({
                "name": n,
                "preferred_username": n.to_lowercase().replace(' ', "_")
            })
        });

        // Create user in database
        let create_req = CreateUserRequest {
            tenant_id: tenant_id.clone(),
            email: email.clone(),
            password_hash: Some(password_hash),
            email_verified: false,
            profile,
            metadata: None,
        };

        let user = self
            .db
            .users()
            .create(create_req)
            .await
            .map_err(|e| VaultError::internal(format!("Failed to create user: {}", e)))?;

        // Generate email verification token
        let verification_token = generate_secure_random(32);

        // Store token
        self.store_token(
            &verification_token,
            StoredTokenData {
                user_id: user.id.clone(),
                tenant_id: tenant_id.clone(),
                token_type: StoredTokenType::EmailVerification,
                expires_at: Utc::now() + Duration::hours(24),
                metadata: None,
            },
        )
        .await?;

        // Send verification email
        let template = VerificationEmail {
            name: name.unwrap_or_else(|| email.clone()),
            verification_url: format!("{}/verify?token={}", self.base_url, verification_token),
            expires_in_hours: 24,
        };

        let _ = self
            .send_email(EmailPayload {
                tenant_id: tenant_id.clone(),
                to: user.email.clone(),
                subject: template.subject(),
                html_body: template.render_html_simple(),
                text_body: template.render_text_simple(),
            })
            .await;

        Ok((user, verification_token))
    }

    /// Authenticate user with credentials
    pub async fn authenticate(
        &self,
        tenant_id: impl Into<String>,
        credentials: LoginCredentials,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<AuthResult> {
        let tenant_id = tenant_id.into();

        // Fetch user from database with password
        let (user, password_hash) = self
            .db
            .users()
            .find_by_email_with_password_legacy(&tenant_id, &credentials.email)
            .await
            .map_err(|_| VaultError::authentication("Invalid credentials"))?;

        // Check if user is active
        if user.status != UserStatus::Active {
            return Err(VaultError::authentication("Account is not active"));
        }

        // Check if locked
        if user.is_locked() {
            return Err(VaultError::authentication("Account is temporarily locked"));
        }

        // Verify password
        let hash =
            password_hash.ok_or_else(|| VaultError::authentication("Invalid credentials"))?;

        if !VaultPasswordHasher::verify(&credentials.password, &hash)? {
            // Record failed attempt
            self.db
                .users()
                .record_login_failure(&tenant_id, &user.id)
                .await
                .ok();
            return Err(VaultError::authentication("Invalid credentials"));
        }

        // Record successful login
        let ip = ip_address.as_ref().and_then(|ip| ip.parse().ok());
        self.db
            .users()
            .record_login_success(&tenant_id, &user.id, ip)
            .await
            .ok();

        // Check MFA if enabled
        let mfa_required = user.mfa_enabled;
        if mfa_required {
            if let Some(code) = credentials.mfa_code {
                if !self.verify_mfa_code(&user, &code).await? {
                    return Err(VaultError::authentication("Invalid MFA code"));
                }
            } else {
                // Return partial auth result requiring MFA
                return Ok(AuthResult {
                    user,
                    session: Session::default(),
                    access_token: String::new(),
                    refresh_token: String::new(),
                    mfa_required: true,
                });
            }
        }

        // Load tenant roles for JWT claims
        let mut roles = self
            .db
            .tenant_admins()
            .get_roles_for_user(&tenant_id, &user.id)
            .await
            .unwrap_or_default();
        if roles.is_empty() {
            roles.push("user".to_string());
        }

        // Generate tokens BEFORE creating session so we can store the correct hash
        let token_pair = self.generate_tokens_with_roles(&user, "pending", roles)?;
        
        // Compute hash of the actual refresh token for storage
        let refresh_token_hash = format!("{:x}", Sha256::digest(token_pair.refresh_token.as_bytes()));
        let access_token_jti = generate_secure_random(16);
        let token_family = generate_secure_random(16);

        // Create session with the actual token hash
        let session = self
            .create_session_with_hashes(&user, ip_address.clone(), user_agent.clone(), access_token_jti, refresh_token_hash, token_family)
            .await?;

        // Store session in database
        let session_req = crate::db::sessions::CreateSessionRequest {
            tenant_id: tenant_id.clone(),
            user_id: user.id.clone(),
            access_token_jti: session.access_token_jti.clone(),
            refresh_token_hash: session.refresh_token_hash.clone(),
            token_family: session.token_family.clone(),
            ip_address: ip_address.clone().and_then(|ip| ip.parse().ok()),
            user_agent: user_agent.clone(),
            device_fingerprint: None,
            device_info: serde_json::json!({
                "user_agent": user_agent,
                "ip_address": ip_address,
            }),
            location: None,
            mfa_verified: !mfa_required,
            expires_at: session.expires_at,
            bind_to_ip: false, // Can be configured based on user/org settings
            bind_to_device: false,
        };

        self.db
            .sessions()
            .create(session_req)
            .await
            .map_err(|e| VaultError::internal(format!("Failed to create session: {}", e)))?;

        Ok(AuthResult {
            user,
            session,
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            mfa_required: false,
        })
    }

    /// Refresh access token with rotation
    /// 
    /// SECURITY: Implements refresh token rotation to prevent replay attacks.
    /// Each refresh token can only be used once. If an old token is presented,
    /// the entire session family is revoked (token theft detection).
    pub async fn refresh_token(
        &self,
        _tenant_id: impl Into<String>,
        refresh_token: &str,
    ) -> Result<AuthResult> {
        use sha2::{Sha256, Digest};

        // Validate refresh token JWT signature and claims
        let claims = HybridJwt::decode(refresh_token, &self.verifying_key)?;

        if claims.token_type != TokenType::Refresh {
            return Err(VaultError::authentication("Invalid token type"));
        }

        let tenant_id = claims.tenant_id.clone();
        let session_id = claims
            .session_id
            .clone()
            .ok_or_else(|| VaultError::authentication("Invalid session"))?;

        // Compute hash of the presented refresh token for verification
        let token_hash = format!("{:x}", Sha256::digest(refresh_token.as_bytes()));

        // Generate new token pair BEFORE rotation (we need the new hashes)
        let user = self
            .db
            .users()
            .find_by_id(&tenant_id, &claims.sub)
            .await
            .map_err(|_| VaultError::authentication("User not found"))?
            .ok_or_else(|| VaultError::authentication("User not found"))?;

        // Load tenant roles for JWT claims
        let mut roles = self
            .db
            .tenant_admins()
            .get_roles_for_user(&tenant_id, &user.id)
            .await
            .unwrap_or_default();
        if roles.is_empty() {
            roles.push("user".to_string());
        }

        // Generate new tokens
        let new_access_token_jti = generate_secure_random(16);

        // Create claims for new tokens
        let access_claims = Claims::new(
            &user.id,
            &user.tenant_id,
            TokenType::Access,
            &self.jwt_issuer,
            &self.jwt_audience,
        )
        .with_session(&session_id)
        .with_email(&user.email, user.email_verified)
        .with_roles(roles);

        let refresh_claims = Claims::new(
            &user.id,
            &user.tenant_id,
            TokenType::Refresh,
            &self.jwt_issuer,
            &self.jwt_audience,
        )
        .with_session(&session_id);

        // Sign new tokens
        let access_token = HybridJwt::encode(&access_claims, &self.signing_key)?;
        let new_refresh_token = HybridJwt::encode(&refresh_claims, &self.signing_key)?;

        // Compute hash of the new refresh token for storage
        let new_refresh_token_hash_computed = format!("{:x}", Sha256::digest(new_refresh_token.as_bytes()));

        // SECURITY: Atomically rotate tokens - this validates the old hash and updates to new
        let session_model = match self
            .db
            .sessions()
            .rotate_tokens(
                &tenant_id,
                &session_id,
                &token_hash,
                new_access_token_jti,
                new_refresh_token_hash_computed,
            )
            .await
        {
            Ok(s) => s,
            Err(_) => {
                // Token rotation failed - old token may have been reused (theft!)
                // Revoke the entire session for security
                tracing::warn!(
                    "SECURITY: Refresh token reuse detected for session {}. Possible token theft!",
                    session_id
                );
                let _ = self
                    .db
                    .sessions()
                    .revoke(&tenant_id, &session_id, Some("Token reuse detected - possible theft"))
                    .await;
                return Err(VaultError::authentication("Token has been revoked"));
            }
        };

        // Convert session model
        let session = self.db_session_to_model(session_model);

        Ok(AuthResult {
            user,
            session,
            access_token,
            refresh_token: new_refresh_token,
            mfa_required: false,
        })
    }

    /// Logout user (revoke session)
    pub async fn logout(
        &self,
        tenant_id: impl Into<String>,
        session_id: impl Into<String>,
        all_sessions: bool,
    ) -> Result<()> {
        let tenant_id = tenant_id.into();
        let session_id = session_id.into();

        if all_sessions {
            // Get session to find user_id
            let session = self
                .db
                .sessions()
                .find_by_id(&tenant_id, &session_id)
                .await
                .map_err(|e| VaultError::internal(format!("Session not found: {}", e)))?;

            self.db
                .sessions()
                .revoke_all_for_user(&tenant_id, &session.user_id, Some("User logout"))
                .await
                .map_err(|e| VaultError::internal(format!("Failed to revoke sessions: {}", e)))?;
        } else {
            self.db
                .sessions()
                .revoke(&tenant_id, &session_id, Some("User logout"))
                .await
                .map_err(|e| VaultError::internal(format!("Failed to revoke session: {}", e)))?;
        }

        Ok(())
    }

    /// Send magic link email
    pub async fn send_magic_link(&self, tenant_id: impl Into<String>, email: &str) -> Result<()> {
        let tenant_id = tenant_id.into();

        // Check if user exists (don't reveal if not)
        if let Ok(Some(user)) = self.db.users().find_by_email(&tenant_id, email).await {
            // Generate magic link token
            let token = generate_secure_random(32);

            // Store token
            self.store_token(
                &token,
                StoredTokenData {
                    user_id: user.id.clone(),
                    tenant_id: tenant_id.clone(),
                    token_type: StoredTokenType::MagicLink,
                    expires_at: Utc::now() + Duration::minutes(15),
                    metadata: None,
                },
            )
            .await?;

            // Send email
            let template = MagicLinkEmail {
                name: user
                    .profile
                    .name
                    .clone()
                    .unwrap_or_else(|| email.to_string()),
                login_url: format!("{}/magic?token={}", self.base_url, token),
                expires_in_minutes: 15,
            };

            let _ = self
                .send_email(EmailPayload {
                    tenant_id: tenant_id.clone(),
                    to: user.email.clone(),
                    subject: template.subject(),
                    html_body: template.render_html_simple(),
                    text_body: template.render_text_simple(),
                })
                .await;
        }

        // Always return success to prevent email enumeration
        Ok(())
    }

    /// Verify magic link token and authenticate
    pub async fn verify_magic_link(
        &self,
        token: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<AuthResult> {
        // Validate token
        let token_data = self
            .get_and_remove_token(token)
            .await?
            .ok_or_else(|| VaultError::authentication("Invalid or expired token"))?;

        if token_data.token_type != StoredTokenType::MagicLink {
            return Err(VaultError::authentication("Invalid token type"));
        }

        if token_data.expires_at < Utc::now() {
            return Err(VaultError::authentication("Token has expired"));
        }

        // Get user
        let user = self
            .db
            .users()
            .find_by_id(&token_data.tenant_id, &token_data.user_id)
            .await
            .map_err(|e| VaultError::internal(format!("Database error: {}", e)))?
            .ok_or_else(|| VaultError::authentication("User not found"))?;

        // Generate tokens BEFORE creating session so we can store the correct hash
        let token_pair = self.generate_tokens(&user, "pending")?;
        
        // Compute hash of the actual refresh token for storage
        let refresh_token_hash = format!("{:x}", Sha256::digest(token_pair.refresh_token.as_bytes()));
        let access_token_jti = generate_secure_random(16);
        let token_family = generate_secure_random(16);

        // Create session with the actual token hash
        let session = self
            .create_session_with_hashes(&user, ip_address.clone(), user_agent.clone(), access_token_jti, refresh_token_hash, token_family)
            .await?;

        let session_req = crate::db::sessions::CreateSessionRequest {
            tenant_id: token_data.tenant_id.clone(),
            user_id: user.id.clone(),
            access_token_jti: session.access_token_jti.clone(),
            refresh_token_hash: session.refresh_token_hash.clone(),
            token_family: session.token_family.clone(),
            ip_address: ip_address.clone().and_then(|ip| ip.parse().ok()),
            user_agent: user_agent.clone(),
            device_fingerprint: None,
            device_info: serde_json::json!({
                "user_agent": user_agent,
                "ip_address": ip_address,
            }),
            location: None,
            mfa_verified: false,
            expires_at: session.expires_at,
            bind_to_ip: false, // Can be configured based on user/org settings
            bind_to_device: false,
        };

        self.db
            .sessions()
            .create(session_req)
            .await
            .map_err(|e| VaultError::internal(format!("Failed to create session: {}", e)))?;

        Ok(AuthResult {
            user,
            session,
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            mfa_required: false,
        })
    }

    /// Request password reset
    pub async fn request_password_reset(
        &self,
        tenant_id: impl Into<String>,
        email: &str,
    ) -> Result<()> {
        let tenant_id = tenant_id.into();

        // Check if user exists (don't reveal if not)
        if let Ok(Some(user)) = self.db.users().find_by_email(&tenant_id, email).await {
            // Generate reset token
            let token = generate_secure_random(32);

            // Store token
            self.store_token(
                &token,
                StoredTokenData {
                    user_id: user.id.clone(),
                    tenant_id: tenant_id.clone(),
                    token_type: StoredTokenType::PasswordReset,
                    expires_at: Utc::now() + Duration::hours(1),
                    metadata: None,
                },
            )
            .await?;

            // Send email
            let template = PasswordResetEmail {
                name: user
                    .profile
                    .name
                    .clone()
                    .unwrap_or_else(|| email.to_string()),
                reset_url: format!("{}/reset-password?token={}", self.base_url, token),
                expires_in_hours: 1,
            };

            let _ = self
                .send_email(EmailPayload {
                    tenant_id: tenant_id.clone(),
                    to: user.email.clone(),
                    subject: template.subject(),
                    html_body: template.render_html_simple(),
                    text_body: template.render_text_simple(),
                })
                .await;
        }

        // Always return success to prevent email enumeration
        Ok(())
    }

    /// Reset password with token
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<()> {
        // Validate password strength
        password::validate_password_strength(new_password)?;

        // Validate token
        let token_data = self
            .get_and_remove_token(token)
            .await?
            .ok_or_else(|| VaultError::authentication("Invalid or expired token"))?;

        if token_data.token_type != StoredTokenType::PasswordReset {
            return Err(VaultError::authentication("Invalid token type"));
        }

        if token_data.expires_at < Utc::now() {
            return Err(VaultError::authentication("Token has expired"));
        }

        // Hash new password
        let password_hash = VaultPasswordHasher::hash(new_password)?;

        // Update user password
        self.db
            .users()
            .update_password(&token_data.tenant_id, &token_data.user_id, &password_hash)
            .await
            .map_err(|e| VaultError::internal(format!("Failed to update password: {}", e)))?;

        // Revoke all sessions for security
        self.db
            .sessions()
            .revoke_all_for_user(
                &token_data.tenant_id,
                &token_data.user_id,
                Some("Password reset"),
            )
            .await
            .ok();

        Ok(())
    }

    /// Verify email address
    pub async fn verify_email(&self, token: &str) -> Result<User> {
        // Validate token
        let token_data = self
            .get_and_remove_token(token)
            .await?
            .ok_or_else(|| VaultError::authentication("Invalid or expired token"))?;

        if token_data.token_type != StoredTokenType::EmailVerification {
            return Err(VaultError::authentication("Invalid token type"));
        }

        if token_data.expires_at < Utc::now() {
            return Err(VaultError::authentication("Token has expired"));
        }

        // Update user email verification status
        self.db
            .users()
            .verify_email(&token_data.tenant_id, &token_data.user_id)
            .await
            .map_err(|e| VaultError::internal(format!("Failed to verify email: {}", e)))?;

        // Get updated user
        let user = self
            .db
            .users()
            .find_by_id(&token_data.tenant_id, &token_data.user_id)
            .await
            .map_err(|_| VaultError::not_found("User", &token_data.user_id))?
            .ok_or_else(|| VaultError::not_found("User", &token_data.user_id))?;

        Ok(user)
    }

    /// Get current user
    pub async fn get_current_user(&self, tenant_id: &str, user_id: &str) -> Result<User> {
        let user = self
            .db
            .users()
            .find_by_id(tenant_id, user_id)
            .await
            .map_err(|e| VaultError::internal(format!("Database error: {}", e)))?
            .ok_or_else(|| VaultError::not_found("User", user_id))?;

        Ok(user)
    }

    /// Generate access and refresh tokens
    pub fn generate_tokens(&self, user: &User, session_id: &str) -> Result<TokenPair> {
        // Access token claims
        let access_claims = Claims::new(
            &user.id,
            &user.tenant_id,
            TokenType::Access,
            &self.jwt_issuer,
            &self.jwt_audience,
        )
        .with_session(session_id)
        .with_email(&user.email, user.email_verified);

        // Refresh token claims
        let refresh_claims = Claims::new(
            &user.id,
            &user.tenant_id,
            TokenType::Refresh,
            &self.jwt_issuer,
            &self.jwt_audience,
        )
        .with_session(session_id);

        // Sign tokens
        let access_token = HybridJwt::encode(&access_claims, &self.signing_key)?;
        let refresh_token = HybridJwt::encode(&refresh_claims, &self.signing_key)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: 900, // 15 minutes
        })
    }

    /// Generate access and refresh tokens with explicit roles
    pub fn generate_tokens_with_roles(
        &self,
        user: &User,
        session_id: &str,
        roles: Vec<String>,
    ) -> Result<TokenPair> {
        let access_claims = Claims::new(
            &user.id,
            &user.tenant_id,
            TokenType::Access,
            &self.jwt_issuer,
            &self.jwt_audience,
        )
        .with_session(session_id)
        .with_email(&user.email, user.email_verified)
        .with_roles(roles);

        let refresh_claims = Claims::new(
            &user.id,
            &user.tenant_id,
            TokenType::Refresh,
            &self.jwt_issuer,
            &self.jwt_audience,
        )
        .with_session(session_id);

        let access_token = HybridJwt::encode(&access_claims, &self.signing_key)?;
        let refresh_token = HybridJwt::encode(&refresh_claims, &self.signing_key)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: 900,
        })
    }

    /// Generate impersonation tokens for admin to act as another user
    pub fn generate_impersonation_tokens(
        &self,
        target_user: &User,
        impersonator_id: &str,
        session_id: &str,
        duration_minutes: i64,
    ) -> Result<TokenPair> {
        let now = Utc::now();
        let expiry = now + Duration::minutes(duration_minutes);

        // Access token claims with impersonation metadata
        let access_claims = Claims::new(
            &target_user.id,
            &target_user.tenant_id,
            TokenType::Access,
            &self.jwt_issuer,
            &self.jwt_audience,
        )
        .with_session(session_id)
        .with_email(&target_user.email, target_user.email_verified)
        .with_expiry(expiry)
        .with_custom("impersonator_id", impersonator_id)
        .with_custom("is_impersonation", true);

        // Refresh token claims with impersonation metadata
        let refresh_claims = Claims::new(
            &target_user.id,
            &target_user.tenant_id,
            TokenType::Refresh,
            &self.jwt_issuer,
            &self.jwt_audience,
        )
        .with_session(session_id)
        .with_expiry(expiry)
        .with_custom("impersonator_id", impersonator_id)
        .with_custom("is_impersonation", true);

        // Sign tokens
        let access_token = HybridJwt::encode(&access_claims, &self.signing_key)?;
        let refresh_token = HybridJwt::encode(&refresh_claims, &self.signing_key)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: duration_minutes * 60,
        })
    }

    /// Get verifying key for token validation
    pub fn verifying_key(&self) -> &HybridVerifyingKey {
        &self.verifying_key
    }

    /// Get signing key for token generation
    pub fn signing_key(&self) -> &HybridSigningKey {
        &self.signing_key
    }

    /// Get database context reference
    pub fn db(&self) -> &DbContext {
        &self.db
    }

    // Helper methods

    async fn create_session(
        &self,
        user: &User,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Session> {
        let now = Utc::now();
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: user.tenant_id.clone(),
            user_id: user.id.clone(),
            status: crate::models::session::SessionStatus::Active,
            access_token_jti: generate_secure_random(16),
            refresh_token_hash: generate_secure_random(32),
            token_family: generate_secure_random(16),
            ip_address,
            user_agent,
            device_fingerprint: None,
            device_info: None,
            location: None,
            mfa_verified: false,
            mfa_verified_at: None,
            created_at: now,
            updated_at: now,
            last_activity_at: now,
            expires_at: now + Duration::days(7),
            revoked_at: None,
            revoked_reason: None,
        };

        Ok(session)
    }

    /// Create a new session with specific token hashes
    /// 
    /// SECURITY: This ensures the stored refresh_token_hash matches the actual token,
    /// enabling proper token rotation and theft detection.
    async fn create_session_with_hashes(
        &self,
        user: &User,
        ip_address: Option<String>,
        user_agent: Option<String>,
        access_token_jti: String,
        refresh_token_hash: String,
        token_family: String,
    ) -> Result<Session> {
        let now = Utc::now();
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: user.tenant_id.clone(),
            user_id: user.id.clone(),
            status: crate::models::session::SessionStatus::Active,
            access_token_jti,
            refresh_token_hash,
            token_family,
            ip_address,
            user_agent,
            device_fingerprint: None,
            device_info: None,
            location: None,
            mfa_verified: false,
            mfa_verified_at: None,
            created_at: now,
            updated_at: now,
            last_activity_at: now,
            expires_at: now + Duration::days(7),
            revoked_at: None,
            revoked_reason: None,
        };

        Ok(session)
    }

    /// Verify MFA code against user's configured methods
    ///
    /// Supports TOTP, Email OTP, and Backup Codes
    async fn verify_mfa_code(&self, user: &User, code: &str) -> Result<bool> {
        use crate::auth::mfa::{verify_backup_code, TotpConfig};
        use crate::models::user::MfaMethod;

        // Get user's MFA configuration from profile
        let tenant_id = user.tenant_id.clone();
        let mfa_config: serde_json::Value = self
            .db
            .users()
            .get_mfa_config(&tenant_id, &user.id)
            .await
            .map_err(|e| VaultError::internal(format!("Failed to fetch MFA config: {}", e)))?;

        // Try each configured MFA method
        for method in &user.mfa_methods {
            match method {
                MfaMethod::Totp => {
                    if let Some(totp_config) = mfa_config.get("totp") {
                        let mut secret = totp_config
                            .get("secret")
                            .and_then(|s| s.as_str())
                            .ok_or_else(|| {
                                VaultError::authentication("Invalid TOTP configuration")
                            })?;

                        let resolved_key = if let Some(resolver) = &self.data_key_resolver {
                            Some(resolver.resolve_key(&tenant_id).await?)
                        } else {
                            self.data_encryption_key.clone()
                        };

                        let secret = if let Some(key) = resolved_key {
                            let decrypted = crate::crypto::decrypt_from_base64(&key, secret)
                                .map_err(|_| VaultError::authentication("Invalid TOTP secret"))?;
                            String::from_utf8(decrypted)
                                .map_err(|_| VaultError::authentication("Invalid TOTP secret"))?
                        } else {
                            secret.to_string()
                        };

                        let config = TotpConfig {
                            secret,
                            issuer: "Vault".to_string(),
                            account_name: user.email.clone(),
                            algorithm: totp_config
                                .get("algorithm")
                                .and_then(|a| a.as_str())
                                .unwrap_or("SHA1")
                                .to_string(),
                            digits: totp_config
                                .get("digits")
                                .and_then(|d| d.as_u64())
                                .unwrap_or(6) as u8,
                            period: totp_config
                                .get("period")
                                .and_then(|p| p.as_u64())
                                .unwrap_or(30) as u32,
                        };

                        // Verify with 1-step window (±30 seconds)
                        if config.verify(code, 1) {
                            return Ok(true);
                        }
                    }
                }
                MfaMethod::Email => {
                    // Email OTP codes are stored temporarily
                    if let Some(email_config) = mfa_config.get("email") {
                        let expected_code =
                            email_config.get("current_code").and_then(|c| c.as_str());
                        let expires_at = email_config
                            .get("expires_at")
                            .and_then(|v| v.as_str())
                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| dt.with_timezone(&chrono::Utc));
                        let attempts = email_config.get("attempts").and_then(|v| v.as_u64());
                        let max_attempts =
                            email_config.get("max_attempts").and_then(|v| v.as_u64());

                        if let Some(expires) = expires_at {
                            if chrono::Utc::now() > expires {
                                self.db
                                    .users()
                                    .clear_email_otp(&tenant_id, &user.id)
                                    .await
                                    .ok();
                                continue;
                            }
                        }

                        if let (Some(attempts), Some(max)) = (attempts, max_attempts) {
                            if attempts >= max {
                                self.db
                                    .users()
                                    .clear_email_otp(&tenant_id, &user.id)
                                    .await
                                    .ok();
                                continue;
                            }
                        }

                        if let Some(expected) = expected_code {
                            if crate::crypto::secure_compare(code.as_bytes(), expected.as_bytes()) {
                                // Clear the used code
                                self.db
                                    .users()
                                    .clear_email_otp(&tenant_id, &user.id)
                                    .await
                                    .ok();
                                return Ok(true);
                            } else {
                                // Increment attempts
                                if let Ok((attempts, max)) = self
                                    .db
                                    .users()
                                    .increment_email_otp_attempt(&tenant_id, &user.id)
                                    .await
                                {
                                    if max > 0 && attempts >= max {
                                        self.db
                                            .users()
                                            .clear_email_otp(&tenant_id, &user.id)
                                            .await
                                            .ok();
                                    }
                                }
                            }
                        }
                    }
                }
                MfaMethod::BackupCodes => {
                    // Backup codes are stored as hashed values
                    if let Some(backup_config) = mfa_config.get("backup_codes") {
                        let hashed_codes: Vec<String> = backup_config
                            .get("codes")
                            .and_then(|c| c.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();

                        if verify_backup_code(code, &hashed_codes) {
                            // Remove the used backup code
                            self.db
                                .users()
                                .consume_backup_code(&tenant_id, &user.id, code)
                                .await
                                .ok();
                            return Ok(true);
                        }
                    }
                }
                MfaMethod::Webauthn => {
                    // WebAuthn requires challenge-response, not a simple code
                    // This is handled separately in the WebAuthn flow
                    continue;
                }
                MfaMethod::Sms => {
                    // Prefer SMS service verification if configured
                    let resolved_service = if let Some(resolver) = &self.sms_service_resolver {
                        resolver.resolve_sms_service(&tenant_id).await
                    } else {
                        self.sms_service.clone()
                    };

                    if let Some(service) = resolved_service {
                        if let Ok(Some(phone)) = self
                            .db
                            .mfa()
                            .get_sms_phone_number(&tenant_id, &user.id)
                            .await
                        {
                            if let Ok(valid) = service.verify_code(&phone, &code).await {
                                if valid {
                                    return Ok(true);
                                }
                            }
                        }
                    } else if let Some(sms_config) = mfa_config.get("sms") {
                        // Fallback to stored OTP if present
                        let expected_code = sms_config.get("current_code").and_then(|c| c.as_str());

                        if let Some(expected) = expected_code {
                            if crate::crypto::secure_compare(code.as_bytes(), expected.as_bytes()) {
                                self.db
                                    .users()
                                    .clear_sms_otp(&tenant_id, &user.id)
                                    .await
                                    .ok();
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    async fn store_token(&self, token: &str, data: StoredTokenData) -> Result<()> {
        self.token_store.store(token, data).await
    }

    async fn get_and_remove_token(&self, token: &str) -> Result<Option<StoredTokenData>> {
        let data = self.token_store.get(token).await?;
        if data.is_some() {
            self.token_store.remove(token).await?;
        }
        Ok(data)
    }

    /// Clean up expired tokens (call periodically)
    pub async fn cleanup_expired_tokens(&self) -> Result<u64> {
        self.token_store.cleanup_expired().await
    }

    /// Create a session for OAuth user (public method for OAuth flows)
    pub async fn create_session_for_oauth_user(
        &self,
        user: &User,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Session> {
        self.create_session(user, ip_address, user_agent).await
    }

    /// Convert database session model to our Session model
    fn db_session_to_model(&self, db_session: crate::db::sessions::Session) -> Session {
        Session {
            id: db_session.id,
            tenant_id: db_session.tenant_id,
            user_id: db_session.user_id,
            status: match db_session.status {
                DbSessionStatus::Active => crate::models::session::SessionStatus::Active,
                DbSessionStatus::Expired => crate::models::session::SessionStatus::Expired,
                DbSessionStatus::Revoked => crate::models::session::SessionStatus::Revoked,
                DbSessionStatus::Rotated => crate::models::session::SessionStatus::Rotated,
            },
            access_token_jti: db_session.access_token_jti,
            refresh_token_hash: db_session.refresh_token_hash,
            token_family: db_session.token_family,
            ip_address: db_session.ip_address,
            user_agent: db_session.user_agent,
            device_fingerprint: db_session.device_fingerprint,
            device_info: serde_json::from_value(db_session.device_info).ok(),
            location: db_session
                .location
                .and_then(|v| serde_json::from_value(v).ok()),
            mfa_verified: db_session.mfa_verified,
            mfa_verified_at: db_session.mfa_verified_at,
            created_at: db_session.created_at,
            updated_at: db_session.updated_at,
            last_activity_at: db_session.last_activity_at,
            expires_at: db_session.expires_at,
            revoked_at: db_session.revoked_at,
            revoked_reason: db_session.revoked_reason,
        }
    }
}

/// Authentication result
#[derive(Debug)]
pub struct AuthResult {
    /// User
    pub user: User,
    /// Session
    pub session: Session,
    /// Access token
    pub access_token: String,
    /// Refresh token
    pub refresh_token: String,
    /// MFA required
    pub mfa_required: bool,
}

/// Token pair
#[derive(Debug, Clone)]
pub struct TokenPair {
    /// Access token
    pub access_token: String,
    /// Refresh token
    pub refresh_token: String,
    /// Expires in (seconds)
    pub expires_in: i64,
}

/// Biometric authentication service
///
/// Handles registration and authentication using device biometrics
/// such as Face ID, Touch ID, and fingerprint.
pub struct BiometricAuthService {
    key_store: Box<dyn biometric::BiometricKeyStore>,
    challenge_store: Box<dyn biometric::ChallengeStore>,
}

impl BiometricAuthService {
    /// Create a new biometric authentication service
    pub fn new(
        key_store: Box<dyn biometric::BiometricKeyStore>,
        challenge_store: Box<dyn biometric::ChallengeStore>,
    ) -> Self {
        Self {
            key_store,
            challenge_store,
        }
    }

    /// Register a new biometric key for a user
    ///
    /// # Arguments
    /// * `user_id` - The user ID
    /// * `tenant_id` - The tenant ID
    /// * `public_key` - The ECDSA P-256 public key (raw format)
    /// * `key_id` - Unique identifier for the key (client-generated)
    /// * `device_name` - Human-readable device name
    /// * `biometric_type` - Type of biometric (FaceId, TouchId, etc.)
    pub async fn register_key(
        &self,
        user_id: impl Into<String>,
        tenant_id: impl Into<String>,
        public_key: Vec<u8>,
        key_id: impl Into<String>,
        device_name: impl Into<String>,
        biometric_type: biometric::BiometricType,
    ) -> std::result::Result<biometric::BiometricKey, biometric::BiometricError> {
        let user_id = user_id.into();
        let tenant_id = tenant_id.into();
        let key_id = key_id.into();
        let device_name = device_name.into();

        // Validate public key format (should be a valid ECDSA P-256 key)
        if let Err(_) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key) {
            return Err(biometric::BiometricError::InvalidPublicKey);
        }

        // Check if key already exists
        if let Some(_) = self.key_store.get_key_by_key_id(&key_id).await? {
            return Err(biometric::BiometricError::KeyAlreadyExists);
        }

        // Create the biometric key record
        let key = biometric::BiometricKey {
            id: uuid::Uuid::new_v4().to_string(),
            user_id,
            tenant_id,
            public_key,
            key_id: key_id.clone(),
            device_name,
            biometric_type,
            created_at: Utc::now(),
            last_used_at: None,
        };

        // Store the key
        self.key_store.store_key(&key).await?;

        tracing::info!(
            "Registered biometric key {} for user {} (type: {:?})",
            key_id,
            key.user_id,
            biometric_type
        );

        Ok(key)
    }

    /// Generate a challenge for biometric authentication
    ///
    /// This should be called before the client attempts to authenticate,
    /// to get a challenge that the client will sign with their private key.
    pub async fn generate_challenge(
        &self,
        key_id: impl Into<String>,
    ) -> std::result::Result<biometric::BiometricChallenge, biometric::BiometricError> {
        let key_id = key_id.into();

        // Verify the key exists
        if self.key_store.get_key_by_key_id(&key_id).await?.is_none() {
            return Err(biometric::BiometricError::KeyNotFound);
        }

        // Generate challenge with 5-minute expiry
        let challenge = biometric::BiometricChallenge::with_expiry(5);

        // Store the challenge
        self.challenge_store
            .store_challenge(&key_id, &challenge)
            .await?;

        tracing::debug!("Generated challenge for biometric key {}", key_id);

        Ok(challenge)
    }

    /// Authenticate with a biometric key
    ///
    /// # Arguments
    /// * `key_id` - The key ID
    /// * `signature` - ECDSA signature of the challenge
    /// * `challenge` - The challenge that was signed
    pub async fn authenticate(
        &self,
        key_id: impl Into<String>,
        signature: Vec<u8>,
        challenge: impl Into<String>,
    ) -> std::result::Result<biometric::BiometricAuthSuccess, biometric::BiometricError> {
        let key_id = key_id.into();
        let challenge_str = challenge.into();

        // Get the stored challenge
        let stored_challenge = self
            .challenge_store
            .get_challenge(&key_id)
            .await?
            .ok_or(biometric::BiometricError::ChallengeNotFound)?;

        // Verify the challenge hasn't expired
        if stored_challenge.is_expired() {
            return Err(biometric::BiometricError::ChallengeExpired);
        }

        // Verify the challenge matches
        if !stored_challenge.verify(&challenge_str) {
            return Err(biometric::BiometricError::InvalidChallenge);
        }

        // Get the biometric key
        let key = self
            .key_store
            .get_key_by_key_id(&key_id)
            .await?
            .ok_or(biometric::BiometricError::KeyNotFound)?;

        // Verify the signature
        let valid = biometric::verify_ecdsa_signature(
            &key.public_key,
            challenge_str.as_bytes(),
            &signature,
        )?;

        if !valid {
            tracing::warn!("Invalid biometric signature for key {}", key_id);
            return Err(biometric::BiometricError::InvalidSignature);
        }

        // Update last used timestamp
        self.key_store.update_last_used(&key_id).await?;

        tracing::info!(
            "Successful biometric authentication for user {} with key {} (type: {:?})",
            key.user_id,
            key_id,
            key.biometric_type
        );

        Ok(biometric::BiometricAuthSuccess {
            user_id: key.user_id,
            tenant_id: key.tenant_id,
            key_id: key.key_id,
            biometric_type: key.biometric_type,
        })
    }

    /// List all registered biometric keys for a user
    pub async fn list_keys(
        &self,
        user_id: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> std::result::Result<Vec<biometric::BiometricKey>, biometric::BiometricError> {
        let user_id = user_id.into();
        let tenant_id = tenant_id.into();

        self.key_store.get_keys_for_user(&user_id, &tenant_id).await
    }

    /// Revoke a biometric key
    pub async fn revoke_key(
        &self,
        key_id: impl Into<String>,
    ) -> std::result::Result<(), biometric::BiometricError> {
        let key_id = key_id.into();

        // Verify the key exists
        if self.key_store.get_key_by_key_id(&key_id).await?.is_none() {
            return Err(biometric::BiometricError::KeyNotFound);
        }

        // Delete the key
        self.key_store.delete_key(&key_id).await?;

        tracing::info!("Revoked biometric key {}", key_id);

        Ok(())
    }

    /// Clean up expired challenges
    pub async fn cleanup_expired_challenges(
        &self,
    ) -> std::result::Result<u64, biometric::BiometricError> {
        self.challenge_store.cleanup_expired().await
    }
}
