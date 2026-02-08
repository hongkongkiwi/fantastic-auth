//! Admin Password Policy Routes
//!
//! Manage tenant-wide password policy settings.
//!
//! Endpoints:
//! - GET /api/v1/admin/settings/password-policy - Get current policy
//! - PUT /api/v1/admin/settings/password-policy - Update policy

use axum::{
    extract::State,
    routing::{get, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::config::{PasswordEnforcementMode, PasswordPolicyConfig};
use crate::routes::ApiError;
use crate::security::{EnforcementMode, PasswordPolicy, UserInfo};
use crate::state::{AppState, CurrentUser};

/// Password policy routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/settings/password-policy", get(get_password_policy))
        .route("/settings/password-policy", put(update_password_policy))
        .route("/settings/password-policy/test", post(test_password_policy))
}

/// Password policy response
#[derive(Debug, Serialize)]
pub struct PasswordPolicyResponse {
    /// Minimum password length
    #[serde(rename = "minLength")]
    pub min_length: usize,
    /// Maximum password length
    #[serde(rename = "maxLength")]
    pub max_length: usize,
    /// Require uppercase letters
    #[serde(rename = "requireUppercase")]
    pub require_uppercase: bool,
    /// Require lowercase letters
    #[serde(rename = "requireLowercase")]
    pub require_lowercase: bool,
    /// Require numbers
    #[serde(rename = "requireNumbers")]
    pub require_numbers: bool,
    /// Require special characters
    #[serde(rename = "requireSpecial")]
    pub require_special: bool,
    /// Special characters allowed
    #[serde(rename = "specialChars")]
    pub special_chars: String,
    /// Maximum consecutive identical characters
    #[serde(rename = "maxConsecutiveChars")]
    pub max_consecutive_chars: usize,
    /// Prevent common passwords
    #[serde(rename = "preventCommonPasswords")]
    pub prevent_common_passwords: bool,
    /// Password history count
    #[serde(rename = "historyCount")]
    pub history_count: usize,
    /// Password expiry days
    #[serde(rename = "expiryDays")]
    pub expiry_days: Option<u32>,
    /// Check breach database
    #[serde(rename = "checkBreach")]
    pub check_breach: bool,
    /// Enforcement mode
    #[serde(rename = "enforcementMode")]
    pub enforcement_mode: String,
    /// Minimum entropy
    #[serde(rename = "minEntropy")]
    pub min_entropy: f64,
    /// Prevent user info in password
    #[serde(rename = "preventUserInfo")]
    pub prevent_user_info: bool,
}

impl From<PasswordPolicyConfig> for PasswordPolicyResponse {
    fn from(config: PasswordPolicyConfig) -> Self {
        Self {
            min_length: config.min_length,
            max_length: config.max_length,
            require_uppercase: config.require_uppercase,
            require_lowercase: config.require_lowercase,
            require_numbers: config.require_numbers,
            require_special: config.require_special,
            special_chars: config.special_chars,
            max_consecutive_chars: config.max_consecutive_chars,
            prevent_common_passwords: config.prevent_common_passwords,
            history_count: config.history_count,
            expiry_days: config.expiry_days,
            check_breach: config.check_breach,
            enforcement_mode: match config.enforcement_mode {
                PasswordEnforcementMode::Block => "block".to_string(),
                PasswordEnforcementMode::Warn => "warn".to_string(),
                PasswordEnforcementMode::Audit => "audit".to_string(),
            },
            min_entropy: config.min_entropy,
            prevent_user_info: config.prevent_user_info,
        }
    }
}

impl From<&PasswordPolicy> for PasswordPolicyResponse {
    fn from(policy: &PasswordPolicy) -> Self {
        Self {
            min_length: policy.min_length,
            max_length: policy.max_length,
            require_uppercase: policy.require_uppercase,
            require_lowercase: policy.require_lowercase,
            require_numbers: policy.require_numbers,
            require_special: policy.require_special_chars,
            special_chars: policy.special_chars.clone(),
            max_consecutive_chars: policy.max_consecutive_chars,
            prevent_common_passwords: policy.prevent_common_passwords,
            history_count: policy.password_history_count,
            expiry_days: policy.expiry_days,
            check_breach: policy.check_breach_database,
            enforcement_mode: match policy.enforcement_mode {
                EnforcementMode::Block => "block".to_string(),
                EnforcementMode::Warn => "warn".to_string(),
                EnforcementMode::Audit => "audit".to_string(),
            },
            min_entropy: policy.min_entropy,
            prevent_user_info: policy.prevent_user_info,
        }
    }
}

/// Update password policy request
#[derive(Debug, Deserialize)]
pub struct UpdatePasswordPolicyRequest {
    /// Minimum password length
    #[serde(rename = "minLength")]
    pub min_length: Option<usize>,
    /// Maximum password length
    #[serde(rename = "maxLength")]
    pub max_length: Option<usize>,
    /// Require uppercase letters
    #[serde(rename = "requireUppercase")]
    pub require_uppercase: Option<bool>,
    /// Require lowercase letters
    #[serde(rename = "requireLowercase")]
    pub require_lowercase: Option<bool>,
    /// Require numbers
    #[serde(rename = "requireNumbers")]
    pub require_numbers: Option<bool>,
    /// Require special characters
    #[serde(rename = "requireSpecial")]
    pub require_special: Option<bool>,
    /// Special characters allowed
    #[serde(rename = "specialChars")]
    pub special_chars: Option<String>,
    /// Maximum consecutive identical characters
    #[serde(rename = "maxConsecutiveChars")]
    pub max_consecutive_chars: Option<usize>,
    /// Prevent common passwords
    #[serde(rename = "preventCommonPasswords")]
    pub prevent_common_passwords: Option<bool>,
    /// Password history count
    #[serde(rename = "historyCount")]
    pub history_count: Option<usize>,
    /// Password expiry days
    #[serde(rename = "expiryDays")]
    pub expiry_days: Option<Option<u32>>,
    /// Check breach database
    #[serde(rename = "checkBreach")]
    pub check_breach: Option<bool>,
    /// Enforcement mode
    #[serde(rename = "enforcementMode")]
    pub enforcement_mode: Option<String>,
    /// Minimum entropy
    #[serde(rename = "minEntropy")]
    pub min_entropy: Option<f64>,
    /// Prevent user info in password
    #[serde(rename = "preventUserInfo")]
    pub prevent_user_info: Option<bool>,
}

/// Test password policy request
#[derive(Debug, Deserialize)]
pub struct TestPasswordPolicyRequest {
    /// Password to test
    pub password: String,
    /// User email for contextual checking
    pub email: Option<String>,
    /// User name for contextual checking
    pub name: Option<String>,
}

/// Test password policy response
#[derive(Debug, Serialize)]
pub struct TestPasswordPolicyResponse {
    /// Whether password is valid
    pub valid: bool,
    /// List of errors if invalid
    pub errors: Vec<PasswordPolicyErrorDetail>,
    /// Entropy score
    pub entropy: f64,
    /// Strength score (0-4)
    #[serde(rename = "strengthScore")]
    pub strength_score: u8,
    /// Strength description
    pub strength: String,
}

/// Password policy error detail
#[derive(Debug, Serialize)]
pub struct PasswordPolicyErrorDetail {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Whether this is a security violation
    #[serde(rename = "isSecurityViolation")]
    pub is_security_violation: bool,
}

/// Get current password policy
async fn get_password_policy(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<PasswordPolicyResponse>, ApiError> {
    // Return the current password policy from config
    let policy = &state.config.security.password_policy;
    Ok(Json(PasswordPolicyResponse::from(policy.clone())))
}

/// Update password policy
async fn update_password_policy(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(req): Json<UpdatePasswordPolicyRequest>,
) -> Result<Json<PasswordPolicyResponse>, ApiError> {
    // Build new policy config from request
    // Note: In a production system, this would persist to database
    // For now, we return the merged policy but don't actually modify the config
    // since it's loaded from environment at startup

    let current = &state.config.security.password_policy;

    // Validate the request
    if let Some(min) = req.min_length {
        if min < 8 {
            return Err(ApiError::BadRequest(
                "Minimum password length must be at least 8".to_string(),
            ));
        }
    }

    if let (Some(min), Some(max)) = (req.min_length, req.max_length) {
        if min > max {
            return Err(ApiError::BadRequest(
                "Minimum length cannot exceed maximum length".to_string(),
            ));
        }
    }

    // Create merged policy (this would be saved to database in production)
    let merged = PasswordPolicyConfig {
        min_length: req.min_length.unwrap_or(current.min_length),
        max_length: req.max_length.unwrap_or(current.max_length),
        require_uppercase: req.require_uppercase.unwrap_or(current.require_uppercase),
        require_lowercase: req.require_lowercase.unwrap_or(current.require_lowercase),
        require_numbers: req.require_numbers.unwrap_or(current.require_numbers),
        require_special: req.require_special.unwrap_or(current.require_special),
        special_chars: req
            .special_chars
            .unwrap_or_else(|| current.special_chars.clone()),
        max_consecutive_chars: req
            .max_consecutive_chars
            .unwrap_or(current.max_consecutive_chars),
        prevent_common_passwords: req
            .prevent_common_passwords
            .unwrap_or(current.prevent_common_passwords),
        history_count: req.history_count.unwrap_or(current.history_count),
        expiry_days: req.expiry_days.unwrap_or(current.expiry_days),
        check_breach: req.check_breach.unwrap_or(current.check_breach),
        enforcement_mode: req
            .enforcement_mode
            .and_then(|m| match m.as_str() {
                "block" => Some(PasswordEnforcementMode::Block),
                "warn" => Some(PasswordEnforcementMode::Warn),
                "audit" => Some(PasswordEnforcementMode::Audit),
                _ => None,
            })
            .unwrap_or(current.enforcement_mode),
        min_entropy: req.min_entropy.unwrap_or(current.min_entropy),
        prevent_user_info: req.prevent_user_info.unwrap_or(current.prevent_user_info),
    };

    // TODO: Persist to database in production
    tracing::info!("Password policy update requested (not persisted in this implementation)");

    Ok(Json(PasswordPolicyResponse::from(merged)))
}

/// Test a password against the current policy
async fn test_password_policy(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(req): Json<TestPasswordPolicyRequest>,
) -> Result<Json<TestPasswordPolicyResponse>, ApiError> {
    let policy = state.security_service.policy();

    let user_info = req.email.as_ref().map(|email| UserInfo {
        email: email.clone(),
        name: req.name.clone(),
        user_id: "test-user-id".to_string(),
    });

    let result = state
        .security_service
        .validate_password(&req.password, user_info.as_ref())
        .await;

    let errors: Vec<PasswordPolicyErrorDetail> = result
        .errors
        .iter()
        .map(|e| PasswordPolicyErrorDetail {
            code: e.code().to_string(),
            message: e.message(),
            is_security_violation: e.is_security_violation(),
        })
        .collect();

    let strength = match result.strength_score {
        0 => "very_weak",
        1 => "weak",
        2 => "fair",
        3 => "strong",
        _ => "very_strong",
    };

    Ok(Json(TestPasswordPolicyResponse {
        valid: result.is_valid,
        errors,
        entropy: result.entropy,
        strength_score: result.strength_score,
        strength: strength.to_string(),
    }))
}

// Import the post function for the router
use axum::routing::post;
