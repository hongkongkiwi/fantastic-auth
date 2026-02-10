//! Step-up Authentication (Sudo Mode)
//!
//! Step-up authentication requires users to re-authenticate with higher
//! assurance for sensitive operations. This is also known as "sudo mode"
//! inspired by Unix sudo command.
//!
//! # Example Flow
//! 1. User logs in normally (Standard level)
//! 2. User tries to change password
//! 3. API returns 403: `{ "error": "step_up_required", "level": "elevated", "methods": ["password", "mfa"] }`
//! 4. User submits password again to `/auth/step-up`
//! 5. System returns short-lived elevated token
//! 6. User retries change password with elevated token
//! 7. Success

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use vault_core::crypto::{AuthMethod, StepUpLevel};
pub use vault_core::crypto::StepUpSession;

/// Step-up challenge response
///
/// Returned when an operation requires step-up authentication
#[derive(Debug, Clone, Serialize)]
pub struct StepUpChallengeResponse {
    /// Error type - always "step_up_required"
    pub error: String,
    /// Required step-up level
    pub level: String,
    /// Available authentication methods
    pub methods: Vec<String>,
    /// Maximum age (in minutes) before step-up expires
    pub max_age_minutes: u32,
    /// Optional message explaining why step-up is required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl StepUpChallengeResponse {
    /// Create a new step-up challenge response
    pub fn new(level: StepUpLevel, methods: Vec<StepUpChallenge>, max_age_minutes: u32) -> Self {
        Self {
            error: "step_up_required".to_string(),
            level: format!("{:?}", level).to_lowercase(),
            methods: methods.iter().map(|m| m.as_str().to_string()).collect(),
            max_age_minutes,
            message: None,
        }
    }

    /// Create with a custom message
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}

/// Step-up challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpChallenge {
    /// Password verification required
    Password,
    /// MFA verification required
    Mfa,
    /// Both password and MFA required
    Both,
}

impl StepUpChallenge {
    /// Get the challenge type as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            StepUpChallenge::Password => "password",
            StepUpChallenge::Mfa => "mfa",
            StepUpChallenge::Both => "both",
        }
    }
}

/// Step-up verification request
#[derive(Debug, Deserialize)]
pub struct StepUpRequest {
    /// Authentication method used
    pub method: StepUpAuthMethod,
    /// Credentials for verification
    pub credentials: StepUpCredentials,
}

/// Step-up authentication methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpAuthMethod {
    /// Password verification
    Password,
    /// TOTP code verification
    Totp,
    /// WebAuthn/Passkey verification
    Webauthn,
    /// Backup code verification
    BackupCode,
}

/// Credentials for step-up authentication
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum StepUpCredentials {
    /// Password credentials
    Password {
        /// Current password
        password: String,
    },
    /// TOTP credentials
    Totp {
        /// TOTP code
        code: String,
    },
    /// WebAuthn credentials
    Webauthn {
        /// WebAuthn assertion response
        assertion: serde_json::Value,
    },
    /// Backup code credentials
    BackupCode {
        /// Backup code
        code: String,
    },
}

/// Step-up verification result
#[derive(Debug, Clone)]
pub enum StepUpResult {
    /// Step-up successful - returns the new session
    Success(StepUpSession),
    /// Step-up failed
    Failed(StepUpFailureReason),
}

/// Step-up failure reasons
#[derive(Debug, Clone)]
pub enum StepUpFailureReason {
    /// Invalid credentials
    InvalidCredentials,
    /// Method not available for user
    MethodNotAvailable,
    /// MFA not configured
    MfaNotConfigured,
    /// Account locked
    AccountLocked,
    /// Rate limited
    RateLimited,
    /// Internal error
    InternalError(String),
}

impl StepUpFailureReason {
    /// Get the error message
    pub fn message(&self) -> String {
        match self {
            StepUpFailureReason::InvalidCredentials => "Invalid credentials".to_string(),
            StepUpFailureReason::MethodNotAvailable => {
                "Authentication method not available".to_string()
            }
            StepUpFailureReason::MfaNotConfigured => {
                "MFA not configured for this account".to_string()
            }
            StepUpFailureReason::AccountLocked => "Account is locked".to_string(),
            StepUpFailureReason::RateLimited => {
                "Too many attempts. Please try again later.".to_string()
            }
            StepUpFailureReason::InternalError(msg) => format!("Internal error: {}", msg),
        }
    }

    /// Get the error code
    pub fn code(&self) -> String {
        match self {
            StepUpFailureReason::InvalidCredentials => "INVALID_CREDENTIALS".to_string(),
            StepUpFailureReason::MethodNotAvailable => "METHOD_NOT_AVAILABLE".to_string(),
            StepUpFailureReason::MfaNotConfigured => "MFA_NOT_CONFIGURED".to_string(),
            StepUpFailureReason::AccountLocked => "ACCOUNT_LOCKED".to_string(),
            StepUpFailureReason::RateLimited => "RATE_LIMITED".to_string(),
            StepUpFailureReason::InternalError(_) => "INTERNAL_ERROR".to_string(),
        }
    }
}

/// Step-up token response
#[derive(Debug, Serialize)]
pub struct StepUpTokenResponse {
    /// Short-lived elevated access token
    #[serde(rename = "accessToken")]
    pub access_token: String,
    /// Token type (always "Bearer")
    #[serde(rename = "tokenType")]
    pub token_type: String,
    /// Expiration time in seconds
    #[serde(rename = "expiresIn")]
    pub expires_in: u64,
    /// The achieved authentication level
    pub level: String,
    /// When the step-up expires (ISO 8601)
    #[serde(rename = "stepUpExpiresAt")]
    pub step_up_expires_at: String,
}

/// Step-up service
pub struct StepUpService;

impl StepUpService {
    /// Create a new step-up service
    pub fn new() -> Self {
        Self
    }

    /// Calculate step-up session expiration time
    pub fn calculate_expiry(&self, max_age_minutes: u32) -> DateTime<Utc> {
        Utc::now() + Duration::minutes(max_age_minutes as i64)
    }

    /// Create a step-up session after successful verification
    ///
    /// # Arguments
    /// * `level` - The achieved authentication level
    /// * `max_age_minutes` - How long the step-up remains valid
    /// * `methods` - The authentication methods used
    pub fn create_session(
        &self,
        level: StepUpLevel,
        max_age_minutes: u32,
        methods: Vec<AuthMethod>,
    ) -> StepUpSession {
        let expires_at = self.calculate_expiry(max_age_minutes);
        StepUpSession::new(level, expires_at.timestamp(), methods)
    }

    /// Determine required challenge methods based on user configuration
    ///
    /// # Arguments
    /// * `user_has_mfa` - Whether the user has MFA configured
    /// * `operation_sensitivity` - How sensitive the operation is (0-3)
    ///
    /// # Returns
    /// Vector of challenge types required
    pub fn determine_challenge(
        &self,
        user_has_mfa: bool,
        operation_sensitivity: u8,
    ) -> Vec<StepUpChallenge> {
        match operation_sensitivity {
            0 => vec![], // No step-up required
            1 => vec![StepUpChallenge::Password],
            2 => {
                if user_has_mfa {
                    vec![StepUpChallenge::Password, StepUpChallenge::Mfa]
                } else {
                    vec![StepUpChallenge::Password]
                }
            }
            _ => {
                if user_has_mfa {
                    vec![StepUpChallenge::Both]
                } else {
                    vec![StepUpChallenge::Password]
                }
            }
        }
    }
}

impl Default for StepUpService {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a step-up session is valid for the required level
///
/// This is a convenience function for middleware
pub fn is_step_up_valid(session: Option<&StepUpSession>, required_level: &StepUpLevel) -> bool {
    match session {
        Some(session) => session.satisfies_level(required_level),
        None => {
            // If no session provided, check if standard auth is sufficient
            required_level.acr_value() <= StepUpLevel::Standard.acr_value()
        }
    }
}

/// Convert authentication methods to AMR strings
pub fn methods_to_amr(methods: &[AuthMethod]) -> Vec<String> {
    methods.iter().map(|m| m.as_str().to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step_up_service_create_session() {
        let service = StepUpService::new();
        let session = service.create_session(
            StepUpLevel::Elevated,
            10,
            vec![AuthMethod::Pwd, AuthMethod::Totp],
        );

        assert_eq!(session.level, StepUpLevel::Elevated);
        assert!(session.is_valid());
        assert!(session.satisfies_level(&StepUpLevel::Standard));
        assert!(session.satisfies_level(&StepUpLevel::Elevated));
        assert!(!session.satisfies_level(&StepUpLevel::HighAssurance));
    }

    #[test]
    fn test_step_up_challenge_response() {
        let response = StepUpChallengeResponse::new(
            StepUpLevel::Elevated,
            vec![StepUpChallenge::Password, StepUpChallenge::Mfa],
            10,
        );

        assert_eq!(response.error, "step_up_required");
        assert_eq!(response.level, "elevated");
        assert_eq!(response.methods, vec!["password", "mfa"]);
        assert_eq!(response.max_age_minutes, 10);
    }

    #[test]
    fn test_determine_challenge() {
        let service = StepUpService::new();

        // Low sensitivity - no challenge
        let challenges = service.determine_challenge(true, 0);
        assert!(challenges.is_empty());

        // Medium sensitivity - password only
        let challenges = service.determine_challenge(false, 1);
        assert_eq!(challenges, vec![StepUpChallenge::Password]);

        // High sensitivity with MFA - password or MFA
        let challenges = service.determine_challenge(true, 2);
        assert!(challenges.contains(&StepUpChallenge::Password));
        assert!(challenges.contains(&StepUpChallenge::Mfa));

        // Critical sensitivity without MFA - password only
        let challenges = service.determine_challenge(false, 3);
        assert_eq!(challenges, vec![StepUpChallenge::Password]);

        // Critical sensitivity with MFA - both required
        let challenges = service.determine_challenge(true, 3);
        assert_eq!(challenges, vec![StepUpChallenge::Both]);
    }

    #[test]
    fn test_is_step_up_valid() {
        let future = Utc::now() + Duration::minutes(10);
        let valid_session = StepUpSession::new(
            StepUpLevel::Elevated,
            future.timestamp(),
            vec![AuthMethod::Pwd],
        );

        // Valid session meets elevated requirement
        assert!(is_step_up_valid(
            Some(&valid_session),
            &StepUpLevel::Elevated
        ));
        // Valid session meets standard requirement
        assert!(is_step_up_valid(
            Some(&valid_session),
            &StepUpLevel::Standard
        ));

        // No session - standard auth is sufficient for standard level
        assert!(is_step_up_valid(None, &StepUpLevel::Standard));
        // No session - not sufficient for elevated
        assert!(!is_step_up_valid(None, &StepUpLevel::Elevated));
    }

    #[test]
    fn test_step_up_failure_reason() {
        let reason = StepUpFailureReason::InvalidCredentials;
        assert_eq!(reason.code(), "INVALID_CREDENTIALS");
        assert_eq!(reason.message(), "Invalid credentials");

        let reason = StepUpFailureReason::MfaNotConfigured;
        assert_eq!(reason.code(), "MFA_NOT_CONFIGURED");
    }
}
