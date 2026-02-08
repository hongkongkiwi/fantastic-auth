//! Security module for Vault Server
//!
//! Provides password policy enforcement, breach detection, bot protection,
//! password history management, session binding, and risk-based authentication.

pub mod bot_protection;
pub mod device_fingerprint;
pub mod encryption;
pub mod geo;
pub mod hibp;
pub mod password_policy;
pub mod risk;
pub mod session_binding;
pub mod session_binding_notifications;

pub use bot_protection::{verify_captcha_token, BotProtectionError, BotProtectionResult};
pub use device_fingerprint::{
    parse_device_info, DeviceFingerprinter, FingerprintComponents, ParsedDeviceInfo,
};
pub use geo::{
    common_country_codes, normalize_country_code, validate_country_code, CachedGeoIpLookup,
    CountryCode, GeoAccessResult, GeoError, GeoIpLookup, GeoIpLookupResult, GeoRestrictionConfig,
    GeoRestrictionPolicy, GeoRestrictionService, GeoServiceFactory, MaxMindGeoIp, VpnDetector,
};
pub use hibp::{HibpClient, HibpConfig, HibpError};
pub use password_policy::{
    EnforcementMode, PasswordPolicy, PasswordPolicyValidator, PasswordValidationError,
    PasswordValidationResult, UserInfo,
};
pub use risk::{
    actions::{ActionContext, ActionError, ActionResult, RiskAction, RiskActionExecutor, RiskActionResponse, RiskChallenge},
    factors::{RiskFactor, RiskFactorResult, RiskFactorType},
    scoring::{RiskScore, RiskScoringEngine, ScoringStrategy, ScoringWeights},
    EnabledFactors, LoginContext, RiskAnalytics, RiskAssessment, RiskEngine, RiskEngineConfig,
    RiskThresholds,
};
pub use session_binding::{
    BindingAction, BindingLevel, BindingRequestContext, BindingResult, SessionBindingChecker,
    SessionBindingConfig, SessionBindingInfo, ViolationDetails, ViolationType,
};
pub use session_binding_notifications::SessionBindingNotificationService;

use std::sync::Arc;

/// Security service that combines password policy and breach checking
pub struct SecurityService {
    /// Password policy validator
    pub policy_validator: PasswordPolicyValidator,
    /// HIBP client (optional)
    pub hibp_client: Option<Arc<HibpClient>>,
}

impl SecurityService {
    /// Create a new security service
    pub fn new(policy: PasswordPolicy, enable_hibp: bool) -> Self {
        let hibp_client = if enable_hibp && policy.check_breach_database {
            Some(Arc::new(HibpClient::new()))
        } else {
            None
        };

        Self {
            policy_validator: PasswordPolicyValidator::new(policy),
            hibp_client,
        }
    }

    /// Create with custom HIBP configuration
    pub fn with_hibp_config(policy: PasswordPolicy, hibp_config: HibpConfig) -> Self {
        let hibp_client = if policy.check_breach_database {
            Some(Arc::new(HibpClient::with_config(hibp_config)))
        } else {
            None
        };

        Self {
            policy_validator: PasswordPolicyValidator::new(policy),
            hibp_client,
        }
    }

    /// Validate a password
    pub async fn validate_password(
        &self,
        password: &str,
        user_info: Option<&UserInfo>,
    ) -> PasswordValidationResult {
        self.policy_validator
            .validate(
                password,
                user_info,
                None::<&dyn password_policy::PasswordHistoryChecker>,
                self.hibp_client.as_deref(),
            )
            .await
    }

    /// Validate a password with history checking
    pub async fn validate_password_with_history(
        &self,
        password: &str,
        user_info: Option<&UserInfo>,
        history_checker: Option<&dyn password_policy::PasswordHistoryChecker>,
    ) -> PasswordValidationResult {
        self.policy_validator
            .validate(
                password,
                user_info,
                history_checker,
                self.hibp_client.as_deref(),
            )
            .await
    }

    /// Get current policy
    pub fn policy(&self) -> &PasswordPolicy {
        self.policy_validator.policy()
    }

    /// Update policy
    pub fn update_policy(&mut self, policy: PasswordPolicy) {
        // Update HIBP client if breach checking setting changed
        if policy.check_breach_database && self.hibp_client.is_none() {
            self.hibp_client = Some(Arc::new(HibpClient::new()));
        } else if !policy.check_breach_database {
            self.hibp_client = None;
        }

        self.policy_validator = PasswordPolicyValidator::new(policy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_service() {
        let policy = PasswordPolicy::default();
        let service = SecurityService::new(policy, false);

        let result = service.validate_password("Str0ng!Passw0rd$", None).await;
        assert!(result.is_valid);

        let result = service.validate_password("weak", None).await;
        assert!(!result.is_valid);
    }
}
