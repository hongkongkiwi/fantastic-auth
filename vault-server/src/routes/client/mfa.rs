//! Client MFA Routes

use axum::{
    extract::State,
    middleware,
    routing::{delete, get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

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
        .route("/me/mfa/sms/send", post(send_sms_code))
        .route("/me/mfa/sms/verify-code", post(verify_sms_code));

    // Routes requiring elevated step-up (setup/enable MFA)
    let elevated_routes = Router::new()
        .route("/me/mfa", post(enable_mfa))
        .route("/me/mfa/totp/setup", post(setup_totp))
        .route("/me/mfa/webauthn/register/begin", post(begin_webauthn_registration))
        .route("/me/mfa/webauthn/register/finish", post(finish_webauthn_registration))
        .route("/me/mfa/backup-codes", post(generate_backup_codes))
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
    let secret_encrypted = encrypt_secret(&totp_config.secret)?;

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
    let code_hashes: Vec<String> = backup_codes
        .iter()
        .map(|code| hash_backup_code(code))
        .collect();

    state
        .db
        .mfa()
        .create_backup_codes(&current_user.tenant_id, &current_user.user_id, &code_hashes)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create backup codes: {}", e);
            ApiError::Internal
        })?;

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
    let secret = decrypt_secret(&secret_encrypted)?;

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
    let code_hashes: Vec<String> = backup_codes
        .iter()
        .map(|code| hash_backup_code(code))
        .collect();

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
    let code_hash = hash_backup_code(&req.code);

    let valid = state
        .db
        .mfa()
        .verify_backup_code(&current_user.tenant_id, &current_user.user_id, &code_hash)
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

// Helper functions

fn encrypt_secret(secret: &str) -> Result<String, ApiError> {
    // In production, use AES-256-GCM with a key from KMS
    // For now, base64 encode (NOT secure, just for structure)
    // TODO: Implement proper encryption
    Ok(base64::encode(secret.as_bytes()))
}

fn decrypt_secret(encrypted: &str) -> Result<String, ApiError> {
    // TODO: Implement proper decryption
    let bytes = base64::decode(encrypted).map_err(|_| ApiError::Internal)?;
    String::from_utf8(bytes).map_err(|_| ApiError::Internal)
}

fn hash_backup_code(code: &str) -> String {
    // Normalize: uppercase and remove dashes
    let normalized = code.to_uppercase().replace('-', "");
    // Use Argon2id in production
    // For now, use a simple hash (NOT secure, just for structure)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    format!("{:x}", hasher.finalize())
}

// Simple base64 module for compatibility
mod base64 {
    use base64::{engine::general_purpose::STANDARD, Engine};

    pub fn encode(input: impl AsRef<[u8]>) -> String {
        STANDARD.encode(input)
    }

    pub fn decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, base64::DecodeError> {
        STANDARD.decode(input)
    }
}
