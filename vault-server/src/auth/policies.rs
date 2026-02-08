//! Step-up Authentication Policies
//!
//! This module defines policies for which operations require step-up authentication
//! and at what level. Policies can be configured per tenant.
//!
//! # Default Policy
//! The default policy requires:
//! - **Standard** (level 1): Normal operations like viewing profile
//! - **Elevated** (level 2): Sensitive operations like changing password
//! - **HighAssurance** (level 3): Critical operations like deleting account
//!
//! # Configuration
//! Policies can be configured per tenant via the database or environment variables.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vault_core::crypto::StepUpLevel;

/// Default max age for step-up authentication (in minutes)
pub const DEFAULT_STEP_UP_MAX_AGE_MINUTES: u32 = 10;

/// Default max age for high assurance operations (in minutes)
pub const DEFAULT_HIGH_ASSURANCE_MAX_AGE_MINUTES: u32 = 5;

/// Operation types that can require step-up authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveOperation {
    /// Change password
    ChangePassword,
    /// Delete account
    DeleteAccount,
    /// Enable MFA
    EnableMfa,
    /// Disable MFA
    DisableMfa,
    /// Add MFA method
    AddMfaMethod,
    /// Remove MFA method
    RemoveMfaMethod,
    /// View sensitive data (e.g., API keys, secrets)
    ViewSensitiveData,
    /// High-value transactions
    HighValueTransaction,
    /// Modify billing information
    ModifyBilling,
    /// Change email address
    ChangeEmail,
    /// Revoke all sessions
    RevokeAllSessions,
    /// Export user data
    ExportUserData,
    /// Admin operations
    AdminOperation,
    /// Superadmin operations
    SuperadminOperation,
}

impl SensitiveOperation {
    /// Get the operation as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            SensitiveOperation::ChangePassword => "change_password",
            SensitiveOperation::DeleteAccount => "delete_account",
            SensitiveOperation::EnableMfa => "enable_mfa",
            SensitiveOperation::DisableMfa => "disable_mfa",
            SensitiveOperation::AddMfaMethod => "add_mfa_method",
            SensitiveOperation::RemoveMfaMethod => "remove_mfa_method",
            SensitiveOperation::ViewSensitiveData => "view_sensitive_data",
            SensitiveOperation::HighValueTransaction => "high_value_transaction",
            SensitiveOperation::ModifyBilling => "modify_billing",
            SensitiveOperation::ChangeEmail => "change_email",
            SensitiveOperation::RevokeAllSessions => "revoke_all_sessions",
            SensitiveOperation::ExportUserData => "export_user_data",
            SensitiveOperation::AdminOperation => "admin_operation",
            SensitiveOperation::SuperadminOperation => "superadmin_operation",
        }
    }

    /// Parse an operation from a string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "change_password" => Some(SensitiveOperation::ChangePassword),
            "delete_account" => Some(SensitiveOperation::DeleteAccount),
            "enable_mfa" => Some(SensitiveOperation::EnableMfa),
            "disable_mfa" => Some(SensitiveOperation::DisableMfa),
            "add_mfa_method" => Some(SensitiveOperation::AddMfaMethod),
            "remove_mfa_method" => Some(SensitiveOperation::RemoveMfaMethod),
            "view_sensitive_data" => Some(SensitiveOperation::ViewSensitiveData),
            "high_value_transaction" => Some(SensitiveOperation::HighValueTransaction),
            "modify_billing" => Some(SensitiveOperation::ModifyBilling),
            "change_email" => Some(SensitiveOperation::ChangeEmail),
            "revoke_all_sessions" => Some(SensitiveOperation::RevokeAllSessions),
            "export_user_data" => Some(SensitiveOperation::ExportUserData),
            "admin_operation" => Some(SensitiveOperation::AdminOperation),
            "superadmin_operation" => Some(SensitiveOperation::SuperadminOperation),
            _ => None,
        }
    }
}

/// Step-up requirement for an operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpRequirement {
    /// Required authentication level
    pub level: StepUpLevel,
    /// Maximum age in minutes before step-up expires
    pub max_age_minutes: u32,
    /// Whether MFA is required in addition to password
    pub require_mfa: bool,
}

impl StepUpRequirement {
    /// Create a new step-up requirement
    pub fn new(level: StepUpLevel, max_age_minutes: u32, require_mfa: bool) -> Self {
        Self {
            level,
            max_age_minutes,
            require_mfa,
        }
    }

    /// Create a standard requirement (level 1) - no step-up needed
    pub fn standard() -> Self {
        Self {
            level: StepUpLevel::Standard,
            max_age_minutes: DEFAULT_STEP_UP_MAX_AGE_MINUTES,
            require_mfa: false,
        }
    }

    /// Create an elevated requirement (level 2)
    pub fn elevated() -> Self {
        Self {
            level: StepUpLevel::Elevated,
            max_age_minutes: DEFAULT_STEP_UP_MAX_AGE_MINUTES,
            require_mfa: true,
        }
    }

    /// Create a high assurance requirement (level 3)
    pub fn high_assurance() -> Self {
        Self {
            level: StepUpLevel::HighAssurance,
            max_age_minutes: DEFAULT_HIGH_ASSURANCE_MAX_AGE_MINUTES,
            require_mfa: true,
        }
    }

    /// Create with custom max age
    pub fn with_max_age(mut self, minutes: u32) -> Self {
        self.max_age_minutes = minutes;
        self
    }

    /// Create without MFA requirement
    pub fn without_mfa(mut self) -> Self {
        self.require_mfa = false;
        self
    }
}

impl Default for StepUpRequirement {
    fn default() -> Self {
        Self::standard()
    }
}

/// Step-up policy for a tenant
///
/// Defines which operations require step-up authentication and at what level.
/// Can be configured per tenant for flexibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpPolicy {
    /// Whether step-up authentication is enabled
    pub enabled: bool,
    /// Map of operations to their requirements
    pub requirements: HashMap<SensitiveOperation, StepUpRequirement>,
    /// Default requirement for operations not in the map
    pub default_requirement: StepUpRequirement,
    /// Global max age override (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_max_age_minutes: Option<u32>,
}

impl StepUpPolicy {
    /// Create a new default policy
    pub fn new() -> Self {
        let mut requirements = HashMap::new();

        // Critical operations - High Assurance
        requirements.insert(
            SensitiveOperation::DeleteAccount,
            StepUpRequirement::high_assurance(),
        );
        requirements.insert(
            SensitiveOperation::DisableMfa,
            StepUpRequirement::high_assurance(),
        );
        requirements.insert(
            SensitiveOperation::RemoveMfaMethod,
            StepUpRequirement::high_assurance(),
        );
        requirements.insert(
            SensitiveOperation::SuperadminOperation,
            StepUpRequirement::high_assurance(),
        );

        // Sensitive operations - Elevated
        requirements.insert(
            SensitiveOperation::ChangePassword,
            StepUpRequirement::elevated(),
        );
        requirements.insert(SensitiveOperation::EnableMfa, StepUpRequirement::elevated());
        requirements.insert(
            SensitiveOperation::AddMfaMethod,
            StepUpRequirement::elevated(),
        );
        requirements.insert(
            SensitiveOperation::ViewSensitiveData,
            StepUpRequirement::elevated(),
        );
        requirements.insert(
            SensitiveOperation::HighValueTransaction,
            StepUpRequirement::elevated(),
        );
        requirements.insert(
            SensitiveOperation::ModifyBilling,
            StepUpRequirement::elevated(),
        );
        requirements.insert(
            SensitiveOperation::ChangeEmail,
            StepUpRequirement::elevated(),
        );
        requirements.insert(
            SensitiveOperation::RevokeAllSessions,
            StepUpRequirement::elevated(),
        );
        requirements.insert(
            SensitiveOperation::ExportUserData,
            StepUpRequirement::elevated(),
        );
        requirements.insert(
            SensitiveOperation::AdminOperation,
            StepUpRequirement::elevated(),
        );

        Self {
            enabled: true,
            requirements,
            default_requirement: StepUpRequirement::standard(),
            global_max_age_minutes: None,
        }
    }

    /// Create a disabled policy (no step-up required)
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            requirements: HashMap::new(),
            default_requirement: StepUpRequirement::standard(),
            global_max_age_minutes: None,
        }
    }

    /// Get the requirement for an operation
    pub fn get_requirement(&self, operation: &SensitiveOperation) -> &StepUpRequirement {
        if !self.enabled {
            return &self.default_requirement;
        }

        self.requirements
            .get(operation)
            .unwrap_or(&self.default_requirement)
    }

    /// Check if an operation requires step-up
    pub fn requires_step_up(&self, operation: &SensitiveOperation) -> bool {
        if !self.enabled {
            return false;
        }

        let req = self.get_requirement(operation);
        req.level != StepUpLevel::Standard
    }

    /// Set a custom requirement for an operation
    pub fn set_requirement(
        &mut self,
        operation: SensitiveOperation,
        requirement: StepUpRequirement,
    ) -> &mut Self {
        self.requirements.insert(operation, requirement);
        self
    }

    /// Remove a requirement (falls back to default)
    pub fn remove_requirement(&mut self, operation: &SensitiveOperation) -> &mut Self {
        self.requirements.remove(operation);
        self
    }

    /// Disable step-up for a specific operation
    pub fn disable_for_operation(&mut self, operation: &SensitiveOperation) -> &mut Self {
        self.requirements
            .insert(operation.clone(), StepUpRequirement::standard());
        self
    }

    /// Enable step-up authentication
    pub fn enable(&mut self) -> &mut Self {
        self.enabled = true;
        self
    }

    /// Disable step-up authentication globally
    pub fn disable(&mut self) -> &mut Self {
        self.enabled = false;
        self
    }

    /// Set global max age for all operations
    pub fn set_global_max_age(&mut self, minutes: u32) -> &mut Self {
        self.global_max_age_minutes = Some(minutes);
        self
    }

    /// Get effective max age for an operation
    pub fn get_max_age(&self, operation: &SensitiveOperation) -> u32 {
        if let Some(global) = self.global_max_age_minutes {
            return global;
        }
        self.get_requirement(operation).max_age_minutes
    }
}

impl Default for StepUpPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy service for managing tenant-specific policies
pub struct StepUpPolicyService {
    /// Default policy used when tenant policy is not found
    default_policy: StepUpPolicy,
    /// Tenant-specific policies (in production, these would be in database)
    tenant_policies: HashMap<String, StepUpPolicy>,
}

impl StepUpPolicyService {
    /// Create a new policy service
    pub fn new() -> Self {
        Self {
            default_policy: StepUpPolicy::new(),
            tenant_policies: HashMap::new(),
        }
    }

    /// Get policy for a tenant
    pub fn get_policy(&self, tenant_id: &str) -> &StepUpPolicy {
        self.tenant_policies
            .get(tenant_id)
            .unwrap_or(&self.default_policy)
    }

    /// Set policy for a tenant
    pub fn set_policy(&mut self, tenant_id: impl Into<String>, policy: StepUpPolicy) {
        self.tenant_policies.insert(tenant_id.into(), policy);
    }

    /// Remove tenant-specific policy (falls back to default)
    pub fn remove_policy(&mut self, tenant_id: &str) {
        self.tenant_policies.remove(tenant_id);
    }

    /// Check if a tenant has a custom policy
    pub fn has_custom_policy(&self, tenant_id: &str) -> bool {
        self.tenant_policies.contains_key(tenant_id)
    }

    /// Get default policy
    pub fn default_policy(&self) -> &StepUpPolicy {
        &self.default_policy
    }

    /// Set default policy
    pub fn set_default_policy(&mut self, policy: StepUpPolicy) {
        self.default_policy = policy;
    }
}

impl Default for StepUpPolicyService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = StepUpPolicy::new();

        assert!(policy.enabled);

        // Delete account should require high assurance
        let req = policy.get_requirement(&SensitiveOperation::DeleteAccount);
        assert_eq!(req.level, StepUpLevel::HighAssurance);
        assert!(req.require_mfa);

        // Change password should require elevated
        let req = policy.get_requirement(&SensitiveOperation::ChangePassword);
        assert_eq!(req.level, StepUpLevel::Elevated);
        assert!(req.require_mfa);

        // Unknown operation should use default (standard)
        // Note: We test with an operation that's not in the default requirements
        let req = policy.get_requirement(&SensitiveOperation::ViewSensitiveData);
        assert_eq!(req.level, StepUpLevel::Elevated);
    }

    #[test]
    fn test_disabled_policy() {
        let policy = StepUpPolicy::disabled();

        assert!(!policy.enabled);
        assert!(!policy.requires_step_up(&SensitiveOperation::DeleteAccount));
        assert!(!policy.requires_step_up(&SensitiveOperation::ChangePassword));
    }

    #[test]
    fn test_custom_requirement() {
        let mut policy = StepUpPolicy::new();

        // Make change password require high assurance
        policy.set_requirement(
            SensitiveOperation::ChangePassword,
            StepUpRequirement::high_assurance().with_max_age(5),
        );

        let req = policy.get_requirement(&SensitiveOperation::ChangePassword);
        assert_eq!(req.level, StepUpLevel::HighAssurance);
        assert_eq!(req.max_age_minutes, 5);
    }

    #[test]
    fn test_policy_service() {
        let mut service = StepUpPolicyService::new();

        // Default policy requires step-up for delete account
        let policy = service.get_policy("tenant_1");
        assert!(policy.requires_step_up(&SensitiveOperation::DeleteAccount));

        // Set custom policy for tenant_2
        let mut custom_policy = StepUpPolicy::disabled();
        custom_policy.enable();
        service.set_policy("tenant_2", custom_policy);

        // tenant_2's policy is disabled
        let policy = service.get_policy("tenant_2");
        assert!(!policy.requires_step_up(&SensitiveOperation::DeleteAccount));

        // tenant_3 still uses default
        let policy = service.get_policy("tenant_3");
        assert!(policy.requires_step_up(&SensitiveOperation::DeleteAccount));
    }

    #[test]
    fn test_sensitive_operation_from_str() {
        assert_eq!(
            SensitiveOperation::from_str("change_password"),
            Some(SensitiveOperation::ChangePassword)
        );
        assert_eq!(
            SensitiveOperation::from_str("delete_account"),
            Some(SensitiveOperation::DeleteAccount)
        );
        assert_eq!(SensitiveOperation::from_str("unknown_operation"), None);
    }

    #[test]
    fn test_step_up_requirement_builder() {
        let req = StepUpRequirement::elevated().with_max_age(20).without_mfa();

        assert_eq!(req.level, StepUpLevel::Elevated);
        assert_eq!(req.max_age_minutes, 20);
        assert!(!req.require_mfa);
    }

    #[test]
    fn test_global_max_age() {
        let mut policy = StepUpPolicy::new();
        policy.set_global_max_age(15);

        let max_age = policy.get_max_age(&SensitiveOperation::ChangePassword);
        assert_eq!(max_age, 15);
    }
}
