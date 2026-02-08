//! Risk-Based Actions
//!
//! Defines actions to take based on risk assessment results:
//! - Allow: Low risk - proceed with login
//! - StepUp: Medium risk - require MFA
//! - Challenge: High risk - require CAPTCHA + email verification
//! - Block: Critical risk - deny login

use serde::{Deserialize, Serialize};

/// Action to take based on risk assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    /// Allow login without additional verification
    Allow,
    /// Require step-up authentication (MFA)
    StepUp,
    /// Require challenge (CAPTCHA + email verification)
    Challenge,
    /// Block login completely
    Block,
}

impl RiskAction {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskAction::Allow => "allow",
            RiskAction::StepUp => "step_up",
            RiskAction::Challenge => "challenge",
            RiskAction::Block => "block",
        }
    }

    /// Parse action from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "allow" => RiskAction::Allow,
            "step_up" | "stepup" | "step-up" => RiskAction::StepUp,
            "challenge" => RiskAction::Challenge,
            "block" | "deny" => RiskAction::Block,
            _ => RiskAction::Allow, // Default to allow for unknown actions
        }
    }

    /// Check if action blocks login
    pub fn is_blocking(&self) -> bool {
        matches!(self, RiskAction::Block)
    }

    /// Check if action requires additional verification
    pub fn requires_verification(&self) -> bool {
        matches!(self, RiskAction::StepUp | RiskAction::Challenge)
    }

    /// Check if action requires MFA
    pub fn requires_mfa(&self) -> bool {
        matches!(self, RiskAction::StepUp)
    }

    /// Check if action requires CAPTCHA
    pub fn requires_captcha(&self) -> bool {
        matches!(self, RiskAction::Challenge)
    }

    /// Get HTTP status code for this action
    pub fn http_status(&self) -> u16 {
        match self {
            RiskAction::Allow => 200,
            RiskAction::StepUp => 403,
            RiskAction::Challenge => 403,
            RiskAction::Block => 403,
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            RiskAction::Allow => "Login allowed",
            RiskAction::StepUp => "Additional verification required (MFA)",
            RiskAction::Challenge => "Strong verification required (CAPTCHA + email)",
            RiskAction::Block => "Login blocked due to high risk",
        }
    }
}

impl Default for RiskAction {
    fn default() -> Self {
        RiskAction::Allow
    }
}

impl std::fmt::Display for RiskAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Risk action response for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskActionResponse {
    /// Action to take
    pub action: RiskAction,
    /// Risk score
    pub risk_score: u8,
    /// Risk level
    pub risk_level: String,
    /// Message for user
    pub message: String,
    /// Additional requirements (e.g., MFA, CAPTCHA)
    pub requirements: Vec<VerificationRequirement>,
    /// Challenge token (for Challenge action)
    pub challenge_token: Option<String>,
}

impl RiskActionResponse {
    /// Create a new action response
    pub fn new(action: RiskAction, risk_score: u8) -> Self {
        let level = match risk_score {
            0..=30 => "low",
            31..=60 => "medium",
            61..=80 => "high",
            _ => "critical",
        };

        Self {
            action,
            risk_score,
            risk_level: level.to_string(),
            message: action.description().to_string(),
            requirements: Self::requirements_for_action(action),
            challenge_token: None,
        }
    }

    /// Add challenge token
    pub fn with_challenge_token(mut self, token: impl Into<String>) -> Self {
        self.challenge_token = Some(token.into());
        self
    }

    /// Get requirements for an action
    fn requirements_for_action(action: RiskAction) -> Vec<VerificationRequirement> {
        match action {
            RiskAction::Allow => vec![],
            RiskAction::StepUp => vec![VerificationRequirement::Mfa],
            RiskAction::Challenge => vec![
                VerificationRequirement::Captcha,
                VerificationRequirement::EmailVerification,
            ],
            RiskAction::Block => vec![VerificationRequirement::Blocked],
        }
    }
}

/// Verification requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRequirement {
    /// Multi-factor authentication
    Mfa,
    /// CAPTCHA verification
    Captcha,
    /// Email verification
    EmailVerification,
    /// Phone/SMS verification
    SmsVerification,
    /// Account blocked
    Blocked,
}

impl VerificationRequirement {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationRequirement::Mfa => "mfa",
            VerificationRequirement::Captcha => "captcha",
            VerificationRequirement::EmailVerification => "email_verification",
            VerificationRequirement::SmsVerification => "sms_verification",
            VerificationRequirement::Blocked => "blocked",
        }
    }
}

/// Risk action executor
///
/// Executes the appropriate action based on risk assessment
pub struct RiskActionExecutor;

impl RiskActionExecutor {
    /// Create a new action executor
    pub fn new() -> Self {
        Self
    }

    /// Execute action for a login attempt
    ///
    /// Returns Ok(()) if login should proceed, Err if blocked
    pub async fn execute(
        &self,
        action: RiskAction,
        context: &ActionContext,
    ) -> Result<ActionResult, ActionError> {
        match action {
            RiskAction::Allow => {
                tracing::info!("Risk action: Allow login for user {}", context.user_id);
                Ok(ActionResult::Allowed)
            }
            RiskAction::StepUp => {
                tracing::info!(
                    "Risk action: Require step-up authentication for user {}",
                    context.user_id
                );
                Ok(ActionResult::RequiresStepUp)
            }
            RiskAction::Challenge => {
                tracing::info!(
                    "Risk action: Require challenge verification for user {}",
                    context.user_id
                );
                
                // Generate challenge token
                let challenge_token = self.generate_challenge_token();
                
                Ok(ActionResult::RequiresChallenge { challenge_token })
            }
            RiskAction::Block => {
                tracing::warn!(
                    "Risk action: Block login for user {} from IP {}",
                    context.user_id,
                    context.ip_address
                );
                Err(ActionError::Blocked)
            }
        }
    }

    /// Generate a challenge token
    fn generate_challenge_token(&self) -> String {
        use base64::Engine;
        let bytes = vault_core::crypto::generate_random_bytes(32);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Check if challenge response is valid
    pub fn verify_challenge(&self, _token: &str, _response: &str) -> bool {
        // In a real implementation, this would validate the challenge response
        // against a stored challenge
        true
    }
}

impl Default for RiskActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Context for action execution
#[derive(Debug, Clone)]
pub struct ActionContext {
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// IP address
    pub ip_address: String,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Email
    pub email: String,
}

impl ActionContext {
    /// Create new action context
    pub fn new(
        user_id: impl Into<String>,
        tenant_id: impl Into<String>,
        email: impl Into<String>,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            tenant_id: tenant_id.into(),
            ip_address: String::new(),
            device_fingerprint: None,
            email: email.into(),
        }
    }

    /// Set IP address
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = ip.into();
        self
    }

    /// Set device fingerprint
    pub fn with_device_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.device_fingerprint = Some(fingerprint.into());
        self
    }
}

/// Result of executing a risk action
#[derive(Debug, Clone)]
pub enum ActionResult {
    /// Login allowed
    Allowed,
    /// Requires step-up authentication
    RequiresStepUp,
    /// Requires challenge verification
    RequiresChallenge { challenge_token: String },
}

/// Error from executing a risk action
#[derive(Debug, Clone, thiserror::Error)]
pub enum ActionError {
    /// Login blocked
    #[error("Login blocked due to high risk")]
    Blocked,
    /// Invalid challenge response
    #[error("Invalid challenge response")]
    InvalidChallenge,
    /// Challenge expired
    #[error("Challenge expired")]
    ChallengeExpired,
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Risk challenge for high-risk logins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskChallenge {
    /// Challenge ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Challenge type
    pub challenge_type: ChallengeType,
    /// Challenge data (e.g., CAPTCHA site key)
    pub data: serde_json::Value,
    /// Expires at
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Whether challenge has been completed
    pub completed: bool,
}

/// Types of challenges
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    /// CAPTCHA challenge
    Captcha,
    /// Email verification
    Email,
    /// SMS verification
    Sms,
    /// Multi-step verification
    MultiStep,
}

/// Risk action history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskActionHistory {
    /// History entry ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Action taken
    pub action: RiskAction,
    /// Risk score at time of action
    pub risk_score: u8,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// IP address
    pub ip_address: String,
    /// Whether action was successful
    pub successful: bool,
    /// Error message if failed
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_action_from_str() {
        assert_eq!(RiskAction::from_str("allow"), RiskAction::Allow);
        assert_eq!(RiskAction::from_str("step_up"), RiskAction::StepUp);
        assert_eq!(RiskAction::from_str("stepup"), RiskAction::StepUp);
        assert_eq!(RiskAction::from_str("challenge"), RiskAction::Challenge);
        assert_eq!(RiskAction::from_str("block"), RiskAction::Block);
        assert_eq!(RiskAction::from_str("deny"), RiskAction::Block);
        assert_eq!(RiskAction::from_str("unknown"), RiskAction::Allow);
    }

    #[test]
    fn test_risk_action_properties() {
        assert!(!RiskAction::Allow.is_blocking());
        assert!(RiskAction::Block.is_blocking());

        assert!(!RiskAction::Allow.requires_verification());
        assert!(RiskAction::StepUp.requires_verification());
        assert!(RiskAction::Challenge.requires_verification());

        assert!(RiskAction::StepUp.requires_mfa());
        assert!(!RiskAction::Challenge.requires_mfa());

        assert!(RiskAction::Challenge.requires_captcha());
        assert!(!RiskAction::StepUp.requires_captcha());
    }

    #[test]
    fn test_risk_action_as_str() {
        assert_eq!(RiskAction::Allow.as_str(), "allow");
        assert_eq!(RiskAction::StepUp.as_str(), "step_up");
        assert_eq!(RiskAction::Challenge.as_str(), "challenge");
        assert_eq!(RiskAction::Block.as_str(), "block");
    }

    #[test]
    fn test_risk_action_response() {
        let response = RiskActionResponse::new(RiskAction::Challenge, 75);

        assert_eq!(response.action, RiskAction::Challenge);
        assert_eq!(response.risk_score, 75);
        assert_eq!(response.risk_level, "high");
        assert!(response.requirements.contains(&VerificationRequirement::Captcha));
        assert!(response.requirements.contains(&VerificationRequirement::EmailVerification));
    }

    #[test]
    fn test_action_context_builder() {
        let context = ActionContext::new("user-123", "tenant-456", "user@example.com")
            .with_ip("192.168.1.1")
            .with_device_fingerprint("abc123");

        assert_eq!(context.user_id, "user-123");
        assert_eq!(context.tenant_id, "tenant-456");
        assert_eq!(context.email, "user@example.com");
        assert_eq!(context.ip_address, "192.168.1.1");
        assert_eq!(context.device_fingerprint, Some("abc123".to_string()));
    }

    #[tokio::test]
    async fn test_action_executor() {
        let executor = RiskActionExecutor::new();
        let context = ActionContext::new("user-123", "tenant-456", "user@example.com")
            .with_ip("192.168.1.1");

        // Test Allow
        let result = executor.execute(RiskAction::Allow, &context).await;
        assert!(matches!(result, Ok(ActionResult::Allowed)));

        // Test StepUp
        let result = executor.execute(RiskAction::StepUp, &context).await;
        assert!(matches!(result, Ok(ActionResult::RequiresStepUp)));

        // Test Challenge
        let result = executor.execute(RiskAction::Challenge, &context).await;
        assert!(matches!(result, Ok(ActionResult::RequiresChallenge { .. })));

        // Test Block
        let result = executor.execute(RiskAction::Block, &context).await;
        assert!(matches!(result, Err(ActionError::Blocked)));
    }

    #[test]
    fn test_verification_requirement_as_str() {
        assert_eq!(VerificationRequirement::Mfa.as_str(), "mfa");
        assert_eq!(VerificationRequirement::Captcha.as_str(), "captcha");
        assert_eq!(
            VerificationRequirement::EmailVerification.as_str(),
            "email_verification"
        );
    }
}
