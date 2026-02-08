//! Client MFA Routes

use axum::{
    extract::State,
    middleware,
    routing::{delete, get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vault_core::email::EmailRequest;

use crate::auth::SensitiveOperation;
use crate::middleware::require_step_up_for_operation;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// MFA routes
///
/// Sensitive operations (enable/disable MFA, generate backup codes) require step-up authentication.
pub fn routes() -> Router<AppState> {
    // Standard routes (no step-up required)
    let standard_routes = Router::new()
        .route("/me/mfa", get(get_mfa_status))
        .route("/me/mfa/totp/verify", post(verify_totp_setup))
        .route("/me/mfa/totp/verify-code", post(verify_totp_code))
        .route("/me/mfa/backup-codes/verify", post(verify_backup_code))
        .route("/me/mfa/email/send", post(send_email_code))
        .route("/me/mfa/email/verify-code", post(verify_email_code))
        .route("/me/mfa/sms/send", post(send_sms_code))
        .route("/me/mfa/sms/verify-code", post(verify_sms_code));

    // Routes requiring elevated step-up (setup/enable MFA)
    let elevated_routes = Router::new()
        .route("/me/mfa", post(enable_mfa))
        .route("/me/mfa/totp/setup", post(setup_totp))
        .route("/me/mfa/webauthn/register/begin", post(begin_webauthn_registration))
        .route("/me/mfa/webauthn/register/finish", post(finish_webauthn_registration))
        .route("/me/mfa/backup-codes", post(generate_backup_codes))
        .route("/me/mfa/email/setup", post(setup_email))
        .route("/me/mfa/email/verify", post(verify_email_setup))
        .route("/me/mfa/sms/setup", post(setup_sms))
        .route("/me/mfa/sms/verify", post(verify_sms_setup))
        .route_layer(middleware::from_fn(require_step_up_enable_mfa));

    // Routes requiring high assurance step-up (disable MFA)
    let high_assurance_routes = Router::new()
        .route("/me/mfa", delete(disable_mfa))
        .route("/me/mfa/sms", delete(disable_sms_mfa))
        .route_layer(middleware::from_fn(require_step_up_disable_mfa));

    // Combine all routes
    Router::new()
        .merge(standard_routes)
        .merge(elevated_routes)
        .merge(high_assurance_routes)
}

/// Middleware for enable MFA step-up
async fn require_step_up_enable_mfa(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    require_step_up_for_operation(State(state), request, next, SensitiveOperation::EnableMfa).await
}

/// Middleware for disable MFA step-up
async fn require_step_up_disable_mfa(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    require_step_up_for_operation(State(state), request, next, SensitiveOperation::DisableMfa).await
}

#[derive(Debug, Serialize)]
struct MfaStatusResponse {
    #[serde(rename = "mfaEnabled")]
    mfa_enabled: bool,
    #[serde(rename = "mfaMethods")]
    mfa_methods: Vec<MfaMethodResponse>,
}

#[derive(Debug, Serialize)]
struct MfaMethodResponse {
    id: String,
    #[serde(rename = "type")]
    method_type: String,
    verified: bool,
    enabled: bool,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "lastUsedAt")]
    last_used_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EnableMfaRequest {
    method: String,
}

#[derive(Debug, Deserialize)]
struct VerifyTotpRequest {
    code: String,
}

#[derive(Debug, Deserialize)]
struct VerifyTotpSetupRequest {
    code: String,
    secret: String,
}

#[derive(Debug, Serialize)]
struct TotpSetupResponse {
    secret: String,
    #[serde(rename = "qrCodeUri")]
    qr_code_uri: String,
    #[serde(rename = "backupCodes")]
    backup_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WebauthnFinishRequest {
    credential: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct BackupCodesResponse {
    codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BackupCodeVerifyRequest {
    code: String,
}

#[derive(Debug, Deserialize)]
struct SmsSetupRequest {
    phone_number: String,
}

#[derive(Debug, Serialize)]
struct SmsSetupResponse {
    message: String,
    #[serde(rename = "phoneNumber")]
    phone_number: String,
    #[serde(rename = "remainingAttempts")]
    remaining_attempts: u32,
}

#[derive(Debug, Deserialize)]
struct SmsVerifySetupRequest {
    phone_number: String,
    code: String,
}

#[derive(Debug, Serialize)]
struct SmsStatusResponse {
    enabled: bool,
    #[serde(rename = "phoneNumber")]
    phone_number: Option<String>,
    #[serde(rename = "phoneVerified")]
    phone_verified: bool,
}

#[derive(Debug, Deserialize)]
struct SmsSendRequest {
    #[serde(rename = "phoneNumber")]
    phone_number: Option<String>, // Optional - uses registered number if not provided
}

#[derive(Debug, Serialize)]
struct EmailSetupResponse {
    message: String,
    #[serde(rename = "expiresInMinutes")]
    expires_in_minutes: i64,
}

#[derive(Debug, Deserialize)]
struct EmailVerifyRequest {
    code: String,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

#[derive(Debug, Serialize)]
struct VerifyCodeResponse {
    valid: bool,
    message: String,
}

/// Get current MFA status for user
async fn get_mfa_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<MfaStatusResponse>, ApiError> {
    let methods = state
        .db
        .mfa()
        .get_user_methods(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get MFA methods: {}", e);
            ApiError::Internal
        })?;

    let mfa_enabled = methods.iter().any(|m| m.enabled);

    let method_responses: Vec<MfaMethodResponse> = methods
        .into_iter()
        .map(|m| MfaMethodResponse {
            id: m.id,
            method_type: format!("{:?}", m.method_type).to_lowercase(),
            verified: m.verified,
            enabled: m.enabled,
            created_at: m.created_at.to_rfc3339(),
            last_used_at: m.last_used_at.map(|d| d.to_rfc3339()),
        })
        .collect();

    Ok(Json(MfaStatusResponse {
        mfa_enabled,
        mfa_methods: method_responses,
    }))
}

/// Setup TOTP MFA (generate secret)
async fn setup_totp(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<TotpSetupResponse>, ApiError> {
    // Generate TOTP config
    let totp_config = vault_core::auth::mfa::TotpConfig::generate("Vault", &current_user.email);

    // Encrypt the secret for storage
    let secret_encrypted = encrypt_secret(&state, &totp_config.secret)?;

    // Store in database
    state
        .db
        .mfa()
        .create_totp_method(
            &current_user.tenant_id,
            &current_user.user_id,
            &secret_encrypted,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create TOTP method: {}", e);
            ApiError::Internal
        })?;

    // Generate backup codes
    let backup_codes = vault_core::auth::mfa::generate_backup_codes(10);
    let code_hashes = vault_core::auth::mfa::hash_backup_codes(&backup_codes);

    state
        .db
        .mfa()
        .create_backup_codes(&current_user.tenant_id, &current_user.user_id, &code_hashes)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create backup codes: {}", e);
            ApiError::Internal
        })?;

    update_backup_codes_config(&state, &current_user.tenant_id, &current_user.user_id, &code_hashes).await?;

    sync_user_mfa_methods(&state, &current_user.tenant_id, &current_user.user_id).await?;

    // Trigger webhook
    crate::webhooks::events::trigger_mfa_enabled(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &current_user.email,
        "totp",
    )
    .await;

    Ok(Json(TotpSetupResponse {
        secret: totp_config.secret,
        qr_code_uri: totp_config.qr_uri(),
        backup_codes,
    }))
}

/// Verify TOTP setup code
async fn verify_totp_setup(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<VerifyTotpSetupRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    // Create temporary TOTP config to verify code
    let totp_config = vault_core::auth::mfa::TotpConfig {
        secret: req.secret,
        issuer: "Vault".to_string(),
        account_name: current_user.email.clone(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
    };

    // Verify the code
    if !totp_config.verify(&req.code, 1) {
        return Ok(Json(MessageResponse {
            message: "Invalid verification code".to_string(),
        }));
    }

    // Enable TOTP method
    state
        .db
        .mfa()
        .verify_totp_method(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to verify TOTP method: {}", e);
            ApiError::Internal
        })?;

    let encrypted_secret = encrypt_secret(&state, &totp_config.secret)?;
    let mut mfa_config = state
        .db
        .users()
        .get_mfa_config(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load MFA config: {}", e);
            ApiError::Internal
        })?;
    let totp_json = serde_json::json!({
        "secret": encrypted_secret,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30
    });
    match mfa_config.as_object_mut() {
        Some(obj) => {
            obj.insert("totp".to_string(), totp_json);
        }
        None => {
            mfa_config = serde_json::json!({ "totp": totp_json });
        }
    }
    state
        .db
        .users()
        .update_mfa_config(&current_user.tenant_id, &current_user.user_id, &mfa_config)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update MFA config: {}", e);
            ApiError::Internal
        })?;

    sync_user_mfa_methods(&state, &current_user.tenant_id, &current_user.user_id).await?;

    Ok(Json(MessageResponse {
        message: "TOTP MFA enabled successfully".to_string(),
    }))
}

/// Verify a TOTP code (for login)
async fn verify_totp_code(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<VerifyTotpRequest>,
) -> Result<Json<VerifyCodeResponse>, ApiError> {
    // Get user's TOTP secret
    let secret_encrypted = match state
        .db
        .mfa()
        .get_totp_secret(&current_user.tenant_id, &current_user.user_id)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return Ok(Json(VerifyCodeResponse {
                valid: false,
                message: "TOTP not enabled".to_string(),
            }));
        }
        Err(e) => {
            tracing::error!("Failed to get TOTP secret: {}", e);
            return Err(ApiError::Internal);
        }
    };

    // Decrypt secret
    let secret = decrypt_secret(&state, &secret_encrypted)?;

    // Create TOTP config and verify
    let totp_config = vault_core::auth::mfa::TotpConfig {
        secret,
        issuer: "Vault".to_string(),
        account_name: current_user.email.clone(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
    };

    let valid = totp_config.verify(&req.code, 1);

    if valid {
        // Mark as used
        state
            .db
            .mfa()
            .mark_method_used(
                &current_user.tenant_id,
                &current_user.user_id,
                vault_core::db::mfa::MfaMethodType::Totp,
            )
            .await
            .ok(); // Don't fail if this errors
    }

    Ok(Json(VerifyCodeResponse {
        valid,
        message: if valid {
            "Code verified".to_string()
        } else {
            "Invalid code".to_string()
        },
    }))
}

/// Enable MFA (generic endpoint)
async fn enable_mfa(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(_req): Json<EnableMfaRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    // This is handled by specific endpoints (setup_totp, etc.)
    Ok(Json(MessageResponse {
        message: "Use specific setup endpoints".to_string(),
    }))
}

/// Disable MFA
async fn disable_mfa(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<EnableMfaRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let method_type = match req.method.as_str() {
        "totp" => vault_core::db::mfa::MfaMethodType::Totp,
        "webauthn" => vault_core::db::mfa::MfaMethodType::Webauthn,
        "sms" => vault_core::db::mfa::MfaMethodType::Sms,
        "email" => vault_core::db::mfa::MfaMethodType::Email,
        _ => return Err(ApiError::BadRequest("Invalid method type".to_string())),
    };

    state
        .db
        .mfa()
        .disable_method(&current_user.tenant_id, &current_user.user_id, method_type)
        .await
        .map_err(|e| {
            tracing::error!("Failed to disable MFA method: {}", e);
            ApiError::Internal
        })?;

    sync_user_mfa_methods(&state, &current_user.tenant_id, &current_user.user_id).await?;

    // Trigger webhook
    crate::webhooks::events::trigger_mfa_disabled(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &current_user.email,
        &req.method,
    )
    .await;

    Ok(Json(MessageResponse {
        message: format!("{} MFA disabled", req.method),
    }))
}

/// Begin WebAuthn registration
async fn begin_webauthn_registration(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Begin registration using WebAuthn service
    let options = state
        .webauthn_service
        .begin_registration(
            &current_user.user_id,
            &current_user.tenant_id,
            &current_user.email,
            &current_user.email,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to begin WebAuthn registration: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(
        serde_json::to_value(options).map_err(|_| ApiError::Internal)?,
    ))
}

/// Finish WebAuthn registration
async fn finish_webauthn_registration(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<WebauthnFinishRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    // Parse credential response
    let credential_response: vault_core::webauthn::RegistrationCredentialResponse =
        serde_json::from_value(req.credential).map_err(|e| {
            tracing::error!("Failed to parse credential: {}", e);
            ApiError::BadRequest("Invalid credential format".to_string())
        })?;

    // Finish registration
    let credential = state
        .webauthn_service
        .finish_registration(credential_response)
        .await
        .map_err(|e| {
            tracing::error!("Failed to finish WebAuthn registration: {}", e);
            ApiError::BadRequest("Invalid credential".to_string())
        })?;

    // Store in database
    let public_key =
        serde_json::to_string(&credential.public_key).map_err(|_| ApiError::Internal)?;

    state
        .db
        .mfa()
        .create_webauthn_method(
            &current_user.tenant_id,
            &current_user.user_id,
            &credential.credential_id,
            &public_key,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to store WebAuthn credential: {}", e);
            ApiError::Internal
        })?;

    sync_user_mfa_methods(&state, &current_user.tenant_id, &current_user.user_id).await?;

    // Trigger webhook
    crate::webhooks::events::trigger_mfa_enabled(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &current_user.email,
        "webauthn",
    )
    .await;

    Ok(Json(MessageResponse {
        message: "WebAuthn device registered".to_string(),
    }))
}

/// Generate new backup codes
async fn generate_backup_codes(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<BackupCodesResponse>, ApiError> {
    // Delete old backup codes
    state
        .db
        .mfa()
        .delete_backup_codes(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete old backup codes: {}", e);
            ApiError::Internal
        })?;

    // Generate new codes
    let backup_codes = vault_core::auth::mfa::generate_backup_codes(10);
    let code_hashes = vault_core::auth::mfa::hash_backup_codes(&backup_codes);

    // Store in database
    state
        .db
        .mfa()
        .create_backup_codes(&current_user.tenant_id, &current_user.user_id, &code_hashes)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create backup codes: {}", e);
            ApiError::Internal
        })?;

    update_backup_codes_config(&state, &current_user.tenant_id, &current_user.user_id, &code_hashes).await?;

    Ok(Json(BackupCodesResponse {
        codes: backup_codes,
    }))
}

/// Verify a backup code
async fn verify_backup_code(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<BackupCodeVerifyRequest>,
) -> Result<Json<VerifyCodeResponse>, ApiError> {
    let valid = state
        .db
        .mfa()
        .verify_backup_code(&current_user.tenant_id, &current_user.user_id, &req.code)
        .await
        .map_err(|e| {
            tracing::error!("Failed to verify backup code: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(VerifyCodeResponse {
        valid,
        message: if valid {
            "Backup code accepted".to_string()
        } else {
            "Invalid or already used backup code".to_string()
        },
    }))
}

/// Setup Email MFA - send verification code
async fn setup_email(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<EmailSetupResponse>, ApiError> {
    send_email_otp(&state, &current_user.tenant_id, &current_user.user_id, &current_user.email)
        .await
}

/// Verify Email MFA setup code and enable Email MFA
async fn verify_email_setup(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<EmailVerifyRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let valid = verify_email_otp(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &req.code,
    )
    .await?;

    if !valid {
        return Ok(Json(MessageResponse {
            message: "Invalid verification code".to_string(),
        }));
    }

    state
        .db
        .mfa()
        .create_email_method(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create Email MFA method: {}", e);
            ApiError::Internal
        })?;

    sync_user_mfa_methods(&state, &current_user.tenant_id, &current_user.user_id).await?;

    crate::webhooks::events::trigger_mfa_enabled(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &current_user.email,
        "email",
    )
    .await;

    Ok(Json(MessageResponse {
        message: "Email MFA enabled successfully".to_string(),
    }))
}

/// Send Email MFA code for login verification
async fn send_email_code(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<EmailSetupResponse>, ApiError> {
    // Ensure email MFA is enabled
    let methods = state
        .db
        .mfa()
        .get_enabled_methods(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load MFA methods: {}", e);
            ApiError::Internal
        })?;

    let has_email = methods.iter().any(|m| {
        matches!(m.method_type, vault_core::db::mfa::MfaMethodType::Email) && m.enabled
    });

    if !has_email {
        return Err(ApiError::BadRequest("Email MFA not enabled".to_string()));
    }

    send_email_otp(&state, &current_user.tenant_id, &current_user.user_id, &current_user.email)
        .await
}

/// Verify Email MFA code for login
async fn verify_email_code(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<EmailVerifyRequest>,
) -> Result<Json<VerifyCodeResponse>, ApiError> {
    let valid = verify_email_otp(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &req.code,
    )
    .await?;

    if valid {
        state
            .db
            .mfa()
            .mark_method_used(
                &current_user.tenant_id,
                &current_user.user_id,
                vault_core::db::mfa::MfaMethodType::Email,
            )
            .await
            .ok();
    }

    Ok(Json(VerifyCodeResponse {
        valid,
        message: if valid {
            "Code verified".to_string()
        } else {
            "Invalid or expired code".to_string()
        },
    }))
}

/// Setup SMS MFA - send verification code
async fn setup_sms(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<SmsSetupRequest>,
) -> Result<Json<SmsSetupResponse>, ApiError> {
    // Validate phone number format
    let normalized_phone = vault_core::sms::SmsService::validate_phone_number(&req.phone_number)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Get or create SMS service from state
    // For now, we'll use a simple approach - in production this should be initialized in AppState
    let sms_service = get_sms_service(&state)?;

    // Send verification code
    sms_service
        .send_code(&normalized_phone)
        .await
        .map_err(|e| {
            tracing::error!("Failed to send SMS code: {}", e);
            match e {
                vault_core::sms::SmsError::RateLimitExceeded(_) => ApiError::TooManyRequests(
                    "Rate limit exceeded. Please try again later.".to_string(),
                ),
                vault_core::sms::SmsError::InvalidPhoneNumber(msg) => {
                    ApiError::BadRequest(format!("Invalid phone number: {}", msg))
                }
                _ => ApiError::Internal,
            }
        })?;

    // Store pending phone number in user's profile for verification
    // This would typically be stored in a temporary location
    if let Err(e) = state
        .db
        .users()
        .update_pending_phone(
            &current_user.tenant_id,
            &current_user.user_id,
            &normalized_phone,
        )
        .await
    {
        tracing::error!("Failed to store pending phone: {}", e);
        // Don't fail - we can still proceed with verification
    }

    // Get remaining attempts
    let remaining_attempts = sms_service
        .get_remaining_attempts(&normalized_phone)
        .await
        .unwrap_or(0);

    Ok(Json(SmsSetupResponse {
        message: "Verification code sent".to_string(),
        phone_number: normalized_phone,
        remaining_attempts,
    }))
}

/// Verify SMS setup code and enable SMS MFA
async fn verify_sms_setup(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<SmsVerifySetupRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    // Validate phone number
    let normalized_phone = vault_core::sms::SmsService::validate_phone_number(&req.phone_number)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Create SMS service
    let sms_service = get_sms_service(&state)?;

    // Verify the code
    let valid = sms_service
        .verify_code(&normalized_phone, &req.code)
        .await
        .map_err(|e| {
            tracing::error!("Failed to verify SMS code: {}", e);
            match e {
                vault_core::sms::SmsError::InvalidCode => {
                    ApiError::BadRequest("Invalid verification code".to_string())
                }
                vault_core::sms::SmsError::CodeNotFound => {
                    ApiError::BadRequest("Code expired or not found".to_string())
                }
                _ => ApiError::Internal,
            }
        })?;

    if !valid {
        return Ok(Json(MessageResponse {
            message: "Invalid verification code".to_string(),
        }));
    }

    // Update user's phone number and mark as verified
    state
        .db
        .users()
        .update_phone_number(
            &current_user.tenant_id,
            &current_user.user_id,
            &normalized_phone,
            true,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to update phone number: {}", e);
            ApiError::Internal
        })?;

    // Create SMS MFA method in database
    state
        .db
        .mfa()
        .create_sms_method(
            &current_user.tenant_id,
            &current_user.user_id,
            &normalized_phone,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create SMS MFA method: {}", e);
            ApiError::Internal
        })?;

    sync_user_mfa_methods(&state, &current_user.tenant_id, &current_user.user_id).await?;

    // Trigger webhook
    crate::webhooks::events::trigger_mfa_enabled(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &current_user.email,
        "sms",
    )
    .await;

    Ok(Json(MessageResponse {
        message: "SMS MFA enabled successfully".to_string(),
    }))
}

/// Send SMS code for login verification
async fn send_sms_code(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<SmsSendRequest>,
) -> Result<Json<SmsSetupResponse>, ApiError> {
    // Get phone number - either from request or from user's profile
    let phone_number = match req.phone_number {
        Some(phone) => phone,
        None => {
            // Get from user's MFA method
            let methods = state
                .db
                .mfa()
                .get_user_methods(&current_user.tenant_id, &current_user.user_id)
                .await
                .map_err(|_| ApiError::Internal)?;

            let sms_method = methods.iter().find(|m| {
                matches!(m.method_type, vault_core::db::mfa::MfaMethodType::Sms) && m.enabled
            });

            match sms_method {
                Some(method) => {
                    // Get phone number from method metadata
                    state
                        .db
                        .mfa()
                        .get_sms_phone_number(&current_user.tenant_id, &current_user.user_id)
                        .await
                        .map_err(|_| ApiError::Internal)?
                        .ok_or_else(|| ApiError::BadRequest("SMS MFA not configured".to_string()))?
                }
                None => return Err(ApiError::BadRequest("SMS MFA not enabled".to_string())),
            }
        }
    };

    // Validate phone number
    let normalized_phone = vault_core::sms::SmsService::validate_phone_number(&phone_number)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Create SMS service
    let sms_service = get_sms_service(&state)?;

    // Send code
    sms_service
        .send_code(&normalized_phone)
        .await
        .map_err(|e| {
            tracing::error!("Failed to send SMS code: {}", e);
            match e {
                vault_core::sms::SmsError::RateLimitExceeded(_) => ApiError::TooManyRequests(
                    "Rate limit exceeded. Please try again later.".to_string(),
                ),
                _ => ApiError::Internal,
            }
        })?;

    let remaining_attempts = sms_service
        .get_remaining_attempts(&normalized_phone)
        .await
        .unwrap_or(0);

    Ok(Json(SmsSetupResponse {
        message: "Verification code sent".to_string(),
        phone_number: normalized_phone,
        remaining_attempts,
    }))
}

/// Verify SMS code for login
async fn verify_sms_code(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<VerifyTotpRequest>, // Reuse the same request structure
) -> Result<Json<VerifyCodeResponse>, ApiError> {
    // Get user's registered phone number
    let phone_number = state
        .db
        .mfa()
        .get_sms_phone_number(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get SMS phone number: {}", e);
            ApiError::Internal
        })?
        .ok_or_else(|| ApiError::BadRequest("SMS MFA not configured".to_string()))?;

    // Create SMS service
    let sms_service = get_sms_service(&state)?;

    // Verify code
    let valid = sms_service
        .verify_code(&phone_number, &req.code)
        .await
        .map_err(|e| {
            tracing::error!("Failed to verify SMS code: {}", e);
            match e {
                vault_core::sms::SmsError::InvalidCode => {
                    return Ok(Json(VerifyCodeResponse {
                        valid: false,
                        message: "Invalid verification code".to_string(),
                    }));
                }
                vault_core::sms::SmsError::CodeNotFound => {
                    return Ok(Json(VerifyCodeResponse {
                        valid: false,
                        message: "Code expired or not found".to_string(),
                    }));
                }
                _ => ApiError::Internal,
            }
        })?;

    if valid {
        // Mark method as used
        state
            .db
            .mfa()
            .mark_method_used(
                &current_user.tenant_id,
                &current_user.user_id,
                vault_core::db::mfa::MfaMethodType::Sms,
            )
            .await
            .ok();
    }

    Ok(Json(VerifyCodeResponse {
        valid,
        message: if valid {
            "Code verified".to_string()
        } else {
            "Invalid code".to_string()
        },
    }))
}

/// Disable SMS MFA
async fn disable_sms_mfa(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .db
        .mfa()
        .disable_method(
            &current_user.tenant_id,
            &current_user.user_id,
            vault_core::db::mfa::MfaMethodType::Sms,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to disable SMS MFA: {}", e);
            ApiError::Internal
        })?;

    sync_user_mfa_methods(&state, &current_user.tenant_id, &current_user.user_id).await?;

    // Trigger webhook
    crate::webhooks::events::trigger_mfa_disabled(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &current_user.email,
        "sms",
    )
    .await;

    Ok(Json(MessageResponse {
        message: "SMS MFA disabled".to_string(),
    }))
}

/// Get SMS service from app state
/// Returns error if SMS service is not configured
fn get_sms_service(state: &AppState) -> Result<std::sync::Arc<vault_core::sms::SmsService>, ApiError> {
    state.sms_service.clone()
        .ok_or_else(|| ApiError::BadRequest("SMS service not configured".to_string()))
}

fn get_email_service(state: &AppState) -> Result<std::sync::Arc<dyn vault_core::email::EmailService>, ApiError> {
    state
        .email_service
        .clone()
        .ok_or_else(|| ApiError::BadRequest("Email service not configured".to_string()))
}

const EMAIL_OTP_CODE_LENGTH: usize = 6;
const EMAIL_OTP_EXPIRY_MINUTES: i64 = 10;
const EMAIL_OTP_MAX_ATTEMPTS: u32 = 5;

fn generate_email_otp_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut code = String::with_capacity(EMAIL_OTP_CODE_LENGTH);
    for _ in 0..EMAIL_OTP_CODE_LENGTH {
        let digit = rng.gen_range(0..10);
        code.push(char::from(b'0' + digit));
    }
    code
}

async fn send_email_otp(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    email: &str,
) -> Result<Json<EmailSetupResponse>, ApiError> {
    let code = generate_email_otp_code();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(EMAIL_OTP_EXPIRY_MINUTES);

    state
        .db
        .users()
        .set_email_otp(tenant_id, user_id, &code, expires_at, EMAIL_OTP_MAX_ATTEMPTS)
        .await
        .map_err(|e| {
            tracing::error!("Failed to store email OTP: {}", e);
            ApiError::Internal
        })?;

    let email_service = get_email_service(state)?;
    let smtp_config = state
        .config
        .smtp
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("Email service not configured".to_string()))?;

    let subject = "Your verification code".to_string();
    let html_body = format!(
        r#"<p>Your verification code is: <strong>{}</strong></p>
<p>This code will expire in {} minutes.</p>"#,
        code, EMAIL_OTP_EXPIRY_MINUTES
    );
    let text_body = format!(
        "Your verification code is: {}\nThis code will expire in {} minutes.",
        code, EMAIL_OTP_EXPIRY_MINUTES
    );

    email_service
        .send_email(EmailRequest {
            to: email.to_string(),
            to_name: None,
            subject,
            html_body,
            text_body,
            from: smtp_config.from_address.clone(),
            from_name: smtp_config.from_name.clone(),
            reply_to: None,
            headers: HashMap::new(),
        })
        .await
        .map_err(|e| {
            tracing::error!("Failed to send email OTP: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(EmailSetupResponse {
        message: "Verification code sent".to_string(),
        expires_in_minutes: EMAIL_OTP_EXPIRY_MINUTES,
    }))
}

async fn verify_email_otp(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    code: &str,
) -> Result<bool, ApiError> {
    let mfa_config = state
        .db
        .users()
        .get_mfa_config(tenant_id, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load MFA config: {}", e);
            ApiError::Internal
        })?;

    let Some(email_config) = mfa_config.get("email") else {
        return Ok(false);
    };

    let expires_at = email_config
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    if let Some(expires) = expires_at {
        if chrono::Utc::now() > expires {
            state
                .db
                .users()
                .clear_email_otp(tenant_id, user_id)
                .await
                .ok();
            return Ok(false);
        }
    }

    let expected = email_config
        .get("current_code")
        .and_then(|c| c.as_str())
        .unwrap_or("");

    let valid = vault_core::crypto::secure_compare(code.as_bytes(), expected.as_bytes());
    if valid {
        state
            .db
            .users()
            .clear_email_otp(tenant_id, user_id)
            .await
            .ok();
        return Ok(true);
    }

    if let Ok((attempts, max)) = state
        .db
        .users()
        .increment_email_otp_attempt(tenant_id, user_id)
        .await
    {
        if max > 0 && attempts >= max {
            state
                .db
                .users()
                .clear_email_otp(tenant_id, user_id)
                .await
                .ok();
        }
    }

    Ok(false)
}

// Helper functions

async fn sync_user_mfa_methods(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
) -> Result<(), ApiError> {
    let methods = state
        .db
        .mfa()
        .get_enabled_methods(tenant_id, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load MFA methods: {}", e);
            ApiError::Internal
        })?;

    let mut method_names: Vec<String> = methods
        .iter()
        .filter_map(|m| {
            // Only methods verified by core auth flow
            match m.method_type {
                vault_core::db::mfa::MfaMethodType::Totp => Some("totp".to_string()),
                vault_core::db::mfa::MfaMethodType::Email => Some("email".to_string()),
                vault_core::db::mfa::MfaMethodType::Sms => Some("sms".to_string()),
                vault_core::db::mfa::MfaMethodType::Webauthn => Some("webauthn".to_string()),
                _ => None,
            }
        })
        .collect();

    let backup_codes = state
        .db
        .mfa()
        .get_backup_codes(tenant_id, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load backup codes: {}", e);
            ApiError::Internal
        })?;

    if !backup_codes.is_empty() {
        method_names.push("backup_codes".to_string());
    }

    method_names.sort();
    method_names.dedup();

    state
        .db
        .users()
        .set_mfa_methods(tenant_id, user_id, &method_names)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update user MFA methods: {}", e);
            ApiError::Internal
        })?;

    Ok(())
}

async fn update_backup_codes_config(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    code_hashes: &[String],
) -> Result<(), ApiError> {
    let mut mfa_config = state
        .db
        .users()
        .get_mfa_config(tenant_id, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load MFA config: {}", e);
            ApiError::Internal
        })?;

    let backup_json = serde_json::json!({
        "codes": code_hashes,
        "used_count": 0
    });

    match mfa_config.as_object_mut() {
        Some(obj) => {
            obj.insert("backup_codes".to_string(), backup_json);
        }
        None => {
            mfa_config = serde_json::json!({ "backup_codes": backup_json });
        }
    }

    state
        .db
        .users()
        .update_mfa_config(tenant_id, user_id, &mfa_config)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update MFA config: {}", e);
            ApiError::Internal
        })?;

    Ok(())
}

fn encrypt_secret(state: &AppState, secret: &str) -> Result<String, ApiError> {
    crate::security::encryption::encrypt_to_base64(&state.data_encryption_key, secret.as_bytes())
        .map_err(|e| {
            tracing::error!("Failed to encrypt secret: {}", e);
            ApiError::Internal
        })
}

fn decrypt_secret(state: &AppState, encrypted: &str) -> Result<String, ApiError> {
    let bytes =
        crate::security::encryption::decrypt_from_base64(&state.data_encryption_key, encrypted)
            .map_err(|e| {
                tracing::error!("Failed to decrypt secret: {}", e);
                ApiError::Internal
            })?;
    String::from_utf8(bytes).map_err(|_| ApiError::Internal)
}
