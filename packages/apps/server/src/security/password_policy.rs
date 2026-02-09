//! Configurable password policy for Vault
//!
//! Provides comprehensive password validation with:
//! - Configurable length and character requirements
//! - Common password checking
//! - Consecutive character prevention
//! - Password history checking
//! - Breach detection (HIBP integration)
//! - Gradual enforcement (warn vs block)

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// User info for contextual password validation
#[derive(Debug, Clone, Default)]
pub struct UserInfo {
    /// User email
    pub email: String,
    /// User name
    pub name: Option<String>,
    /// User ID
    pub user_id: String,
}

/// Password policy configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PasswordPolicy {
    /// Minimum password length (default: 12)
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    /// Maximum password length (default: 128)
    #[serde(default = "default_max_length")]
    pub max_length: usize,
    /// Require uppercase letters (default: true)
    #[serde(default = "default_true")]
    pub require_uppercase: bool,
    /// Require lowercase letters (default: true)
    #[serde(default = "default_true")]
    pub require_lowercase: bool,
    /// Require numbers (default: true)
    #[serde(default = "default_true")]
    pub require_numbers: bool,
    /// Require special characters (default: true)
    #[serde(default = "default_true")]
    pub require_special_chars: bool,
    /// Special characters allowed (default: "!@#$%^&*...")
    #[serde(default = "default_special_chars")]
    pub special_chars: String,
    /// Maximum consecutive identical characters (default: 3)
    #[serde(default = "default_max_consecutive")]
    pub max_consecutive_chars: usize,
    /// Prevent common passwords (default: true)
    #[serde(default = "default_true")]
    pub prevent_common_passwords: bool,
    /// Password history count to prevent reuse (default: 5)
    #[serde(default = "default_password_history_count")]
    pub password_history_count: usize,
    /// Password expiry in days (default: None, 90 for enterprise)
    #[serde(default)]
    pub expiry_days: Option<u32>,
    /// Check breach database (Have I Been Pwned) (default: true)
    #[serde(default = "default_true")]
    pub check_breach_database: bool,
    /// Enforcement mode (default: Block)
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
    /// Minimum entropy bits (default: 50.0)
    #[serde(default = "default_min_entropy")]
    pub min_entropy: f64,
    /// Prevent password from containing email/username (default: true)
    #[serde(default = "default_true")]
    pub prevent_user_info: bool,
}

/// Enforcement mode for password policy
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Strict - reject passwords that don't meet policy
    Block,
    /// Lenient - allow but warn
    Warn,
    /// Audit only - log violations but allow
    Audit,
}

impl Default for EnforcementMode {
    fn default() -> Self {
        EnforcementMode::Block
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: default_min_length(),
            max_length: default_max_length(),
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: true,
            special_chars: default_special_chars(),
            max_consecutive_chars: default_max_consecutive(),
            prevent_common_passwords: true,
            password_history_count: default_password_history_count(),
            expiry_days: None,
            check_breach_database: true,
            enforcement_mode: EnforcementMode::Block,
            min_entropy: default_min_entropy(),
            prevent_user_info: true,
        }
    }
}

// Default functions for serde
fn default_min_length() -> usize {
    12
}
fn default_max_length() -> usize {
    128
}
fn default_true() -> bool {
    true
}
fn default_special_chars() -> String {
    "!@#$%^&*()_+-=[]{}|;':\",./<>?`~".to_string()
}
fn default_max_consecutive() -> usize {
    3
}
fn default_password_history_count() -> usize {
    5
}
fn default_min_entropy() -> f64 {
    50.0
}

/// Password validation error with specific violation details
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordValidationError {
    /// Password too short
    TooShort { min: usize, actual: usize },
    /// Password too long
    TooLong { max: usize, actual: usize },
    /// Missing uppercase letters
    MissingUppercase,
    /// Missing lowercase letters
    MissingLowercase,
    /// Missing numbers
    MissingNumbers,
    /// Missing special characters
    MissingSpecialChars,
    /// Too many consecutive identical characters
    TooManyConsecutive { max: usize },
    /// Common password detected
    CommonPassword,
    /// Password found in breach database
    Breached { count: u64 },
    /// Password reused from history
    ReusedFromHistory,
    /// Password contains user info (email, name, etc.)
    ContainsUserInfo,
    /// Password does not meet minimum entropy
    InsufficientEntropy { min: f64, actual: f64 },
    /// External service error (HIBP API failure)
    ExternalServiceError(String),
}

impl PasswordValidationError {
    /// Get human-readable error message
    pub fn message(&self) -> String {
        match self {
            Self::TooShort { min, actual } => {
                format!(
                    "Password must be at least {} characters long (current: {})",
                    min, actual
                )
            }
            Self::TooLong { max, actual } => {
                format!(
                    "Password must not exceed {} characters (current: {})",
                    max, actual
                )
            }
            Self::MissingUppercase => {
                "Password must contain at least one uppercase letter (A-Z)".to_string()
            }
            Self::MissingLowercase => {
                "Password must contain at least one lowercase letter (a-z)".to_string()
            }
            Self::MissingNumbers => "Password must contain at least one number (0-9)".to_string(),
            Self::MissingSpecialChars => {
                "Password must contain at least one special character".to_string()
            }
            Self::TooManyConsecutive { max } => {
                format!(
                    "Password must not contain more than {} identical characters in a row",
                    max
                )
            }
            Self::CommonPassword => {
                "Password is too common and easily guessed. Please choose a more unique password."
                    .to_string()
            }
            Self::Breached { count } => {
                format!("This password has been found in {} data breaches. Please choose a different password.", count)
            }
            Self::ReusedFromHistory => {
                "Password was used recently. Please choose a different password.".to_string()
            }
            Self::ContainsUserInfo => {
                "Password must not contain your email address or username".to_string()
            }
            Self::InsufficientEntropy { min, actual } => {
                format!(
                    "Password is not strong enough (strength: {:.1}/{})",
                    actual, min
                )
            }
            Self::ExternalServiceError(msg) => {
                format!("Unable to verify password safety: {}", msg)
            }
        }
    }

    /// Get error code for API responses
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooShort { .. } => "PASSWORD_TOO_SHORT",
            Self::TooLong { .. } => "PASSWORD_TOO_LONG",
            Self::MissingUppercase => "PASSWORD_MISSING_UPPERCASE",
            Self::MissingLowercase => "PASSWORD_MISSING_LOWERCASE",
            Self::MissingNumbers => "PASSWORD_MISSING_NUMBERS",
            Self::MissingSpecialChars => "PASSWORD_MISSING_SPECIAL",
            Self::TooManyConsecutive { .. } => "PASSWORD_TOO_MANY_CONSECUTIVE",
            Self::CommonPassword => "PASSWORD_TOO_COMMON",
            Self::Breached { .. } => "PASSWORD_BREACHED",
            Self::ReusedFromHistory => "PASSWORD_REUSED",
            Self::ContainsUserInfo => "PASSWORD_CONTAINS_USER_INFO",
            Self::InsufficientEntropy { .. } => "PASSWORD_INSUFFICIENT_ENTROPY",
            Self::ExternalServiceError(_) => "PASSWORD_CHECK_ERROR",
        }
    }

    /// Check if this error is a security violation (vs validation error)
    pub fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Self::Breached { .. } | Self::CommonPassword | Self::ReusedFromHistory
        )
    }
}

impl std::fmt::Display for PasswordValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for PasswordValidationError {}

/// Validation result that can contain multiple violations
#[derive(Debug, Clone, Default)]
pub struct PasswordValidationResult {
    /// List of validation errors
    pub errors: Vec<PasswordValidationError>,
    /// Whether password passed all checks
    pub is_valid: bool,
    /// Entropy score
    pub entropy: f64,
    /// Strength score (0-4)
    pub strength_score: u8,
}

impl PasswordValidationResult {
    /// Create a new validation result
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            is_valid: true,
            entropy: 0.0,
            strength_score: 0,
        }
    }

    /// Add an error
    pub fn add_error(&mut self, error: PasswordValidationError) {
        self.errors.push(error);
        self.is_valid = false;
    }

    /// Convert to a single result
    pub fn into_result(self) -> Result<(), Vec<PasswordValidationError>> {
        if self.is_valid {
            Ok(())
        } else {
            Err(self.errors)
        }
    }

    /// Get all error messages
    pub fn error_messages(&self) -> Vec<String> {
        self.errors.iter().map(|e| e.message()).collect()
    }

    /// Get all error codes
    pub fn error_codes(&self) -> Vec<&'static str> {
        self.errors.iter().map(|e| e.code()).collect()
    }
}

/// Password policy validator
pub struct PasswordPolicyValidator {
    policy: PasswordPolicy,
    common_passwords: HashSet<&'static str>,
}

impl PasswordPolicyValidator {
    /// Create a new validator with the given policy
    pub fn new(policy: PasswordPolicy) -> Self {
        let common_passwords = Self::load_common_passwords();
        Self {
            policy,
            common_passwords,
        }
    }

    /// Load common passwords list
    fn load_common_passwords() -> HashSet<&'static str> {
        let mut set = HashSet::new();
        // Top common passwords
        set.insert("password");
        set.insert("password123");
        set.insert("123456");
        set.insert("12345678");
        set.insert("123456789");
        set.insert("qwerty");
        set.insert("abc123");
        set.insert("letmein");
        set.insert("welcome");
        set.insert("admin");
        set.insert("root");
        set.insert("toor");
        set.insert("guest");
        set.insert("default");
        set.insert("changeme");
        set.insert("passw0rd");
        set.insert("login");
        set.insert("master");
        set.insert("secret");
        set.insert("password1");
        set.insert("1234567890");
        set.insert("iloveyou");
        set.insert("monkey");
        set.insert("dragon");
        set.insert("baseball");
        set.insert("football");
        set.insert("superman");
        set.insert("batman");
        set.insert("trustno1");
        set.insert("sunshine");
        set.insert("princess");
        set.insert("admin123");
        set.insert("welcome123");
        set.insert("password!");
        set.insert("p@ssw0rd");
        set.insert("qwerty123");
        set.insert("lovely");
        set.insert("whatever");
        set.insert("starwars");
        set
    }

    /// Validate a password synchronously (without external checks)
    pub fn validate_sync(
        &self,
        password: &str,
        user_info: Option<&UserInfo>,
    ) -> PasswordValidationResult {
        let mut result = PasswordValidationResult::new();

        // Calculate entropy first
        result.entropy = self.calculate_entropy(password);
        result.strength_score = self.calculate_strength_score(result.entropy);

        // Check length
        if password.len() < self.policy.min_length {
            result.add_error(PasswordValidationError::TooShort {
                min: self.policy.min_length,
                actual: password.len(),
            });
        }

        if password.len() > self.policy.max_length {
            result.add_error(PasswordValidationError::TooLong {
                max: self.policy.max_length,
                actual: password.len(),
            });
        }

        // Check character classes
        if self.policy.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
            result.add_error(PasswordValidationError::MissingUppercase);
        }

        if self.policy.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
            result.add_error(PasswordValidationError::MissingLowercase);
        }

        if self.policy.require_numbers && !password.chars().any(|c| c.is_ascii_digit()) {
            result.add_error(PasswordValidationError::MissingNumbers);
        }

        if self.policy.require_special_chars {
            let has_special = password
                .chars()
                .any(|c| self.policy.special_chars.contains(c));
            if !has_special {
                result.add_error(PasswordValidationError::MissingSpecialChars);
            }
        }

        // Check consecutive characters
        if self.policy.max_consecutive_chars > 0 {
            if let Some(max_consecutive) = self.max_consecutive_chars(password) {
                if max_consecutive > self.policy.max_consecutive_chars {
                    result.add_error(PasswordValidationError::TooManyConsecutive {
                        max: self.policy.max_consecutive_chars,
                    });
                }
            }
        }

        // Check common passwords
        if self.policy.prevent_common_passwords {
            let lower = password.to_lowercase();
            if self.common_passwords.contains(lower.as_str()) {
                result.add_error(PasswordValidationError::CommonPassword);
            }
        }

        // Check user info
        if self.policy.prevent_user_info {
            if let Some(user) = user_info {
                if self.contains_user_info(password, user) {
                    result.add_error(PasswordValidationError::ContainsUserInfo);
                }
            }
        }

        // Check entropy
        if result.entropy < self.policy.min_entropy {
            result.add_error(PasswordValidationError::InsufficientEntropy {
                min: self.policy.min_entropy,
                actual: result.entropy,
            });
        }

        result
    }

    /// Full validation including external checks (HIBP)
    pub async fn validate(
        &self,
        password: &str,
        user_info: Option<&UserInfo>,
        history_checker: Option<&dyn PasswordHistoryChecker>,
        hibp_checker: Option<&super::hibp::HibpClient>,
    ) -> PasswordValidationResult {
        let mut result = self.validate_sync(password, user_info);

        // Check password history
        if let Some(checker) = history_checker {
            if let Some(user) = user_info {
                match checker.is_password_used(&user.user_id, password).await {
                    Ok(true) => {
                        result.add_error(PasswordValidationError::ReusedFromHistory);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!("Failed to check password history: {}", e);
                    }
                }
            }
        }

        // Check breach database
        if self.policy.check_breach_database {
            if let Some(hibp) = hibp_checker {
                match hibp.check_password(password).await {
                    Ok(Some(count)) => {
                        if count > 0 {
                            result.add_error(PasswordValidationError::Breached { count });
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!("Failed to check HIBP: {}", e);
                        // In block mode, we might want to fail closed
                        if self.policy.enforcement_mode == EnforcementMode::Block {
                            result.add_error(PasswordValidationError::ExternalServiceError(
                                e.to_string(),
                            ));
                        }
                    }
                }
            }
        }

        result
    }

    /// Calculate maximum consecutive identical characters
    fn max_consecutive_chars(&self, password: &str) -> Option<usize> {
        if password.is_empty() {
            return None;
        }

        let mut max_count = 1;
        let mut current_count = 1;
        let mut prev_char: Option<char> = None;

        for c in password.chars() {
            if let Some(p) = prev_char {
                if c.to_ascii_lowercase() == p.to_ascii_lowercase() {
                    current_count += 1;
                    max_count = max_count.max(current_count);
                } else {
                    current_count = 1;
                }
            }
            prev_char = Some(c);
        }

        Some(max_count)
    }

    /// Check if password contains user info
    fn contains_user_info(&self, password: &str, user_info: &UserInfo) -> bool {
        let lower_pass = password.to_lowercase();

        // Check email parts
        if !user_info.email.is_empty() {
            let email_lower = user_info.email.to_lowercase();
            if lower_pass.contains(&email_lower) {
                return true;
            }

            // Check local part of email (before @)
            if let Some(local) = email_lower.split('@').next() {
                if local.len() > 3 && lower_pass.contains(local) {
                    return true;
                }
            }
        }

        // Check name
        if let Some(name) = &user_info.name {
            let name_lower = name.to_lowercase();
            if name_lower.len() > 3 && lower_pass.contains(&name_lower) {
                return true;
            }

            // Check name parts
            for part in name_lower.split_whitespace() {
                if part.len() > 3 && lower_pass.contains(part) {
                    return true;
                }
            }
        }

        // Check user ID (if not a UUID)
        if user_info.user_id.len() < 20 && lower_pass.contains(&user_info.user_id.to_lowercase()) {
            return true;
        }

        false
    }

    /// Calculate password entropy
    fn calculate_entropy(&self, password: &str) -> f64 {
        let mut charset_size = 0usize;

        if password.chars().any(|c| c.is_ascii_uppercase()) {
            charset_size += 26;
        }
        if password.chars().any(|c| c.is_ascii_lowercase()) {
            charset_size += 26;
        }
        if password.chars().any(|c| c.is_ascii_digit()) {
            charset_size += 10;
        }
        if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
            charset_size += 32;
        }

        if charset_size == 0 {
            return 0.0;
        }

        let length = password.len() as f64;
        let charset = charset_size as f64;

        length * charset.log2()
    }

    /// Calculate strength score (0-4)
    fn calculate_strength_score(&self, entropy: f64) -> u8 {
        if entropy < 28.0 {
            0
        } else if entropy < 36.0 {
            1
        } else if entropy < 60.0 {
            2
        } else if entropy < 80.0 {
            3
        } else {
            4
        }
    }

    /// Get policy reference
    pub fn policy(&self) -> &PasswordPolicy {
        &self.policy
    }

    /// Get policy mutable reference
    pub fn policy_mut(&mut self) -> &mut PasswordPolicy {
        &mut self.policy
    }
}

/// Trait for checking password history
#[async_trait::async_trait]
pub trait PasswordHistoryChecker: Send + Sync {
    /// Check if password was used before
    async fn is_password_used(&self, user_id: &str, password: &str) -> anyhow::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_policy_default() {
        let policy = PasswordPolicy::default();
        assert_eq!(policy.min_length, 12);
        assert_eq!(policy.max_length, 128);
        assert!(policy.require_uppercase);
        assert!(policy.check_breach_database);
    }

    #[test]
    fn test_validate_password_too_short() {
        let policy = PasswordPolicy::default();
        let validator = PasswordPolicyValidator::new(policy);
        let result = validator.validate_sync("Short1!", None);

        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, PasswordValidationError::TooShort { .. })));
    }

    #[test]
    fn test_validate_password_missing_requirements() {
        let policy = PasswordPolicy::default();
        let validator = PasswordPolicyValidator::new(policy);

        let result = validator.validate_sync("lowercaseonly!", None);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, PasswordValidationError::MissingUppercase)));
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, PasswordValidationError::MissingNumbers)));

        let result = validator.validate_sync("UPPERCASEONLY!", None);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, PasswordValidationError::MissingLowercase)));
    }

    #[test]
    fn test_validate_password_consecutive_chars() {
        let policy = PasswordPolicy::default();
        let validator = PasswordPolicyValidator::new(policy);

        let result = validator.validate_sync("StrongPass1111!", None);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, PasswordValidationError::TooManyConsecutive { .. })));
    }

    #[test]
    fn test_validate_password_common() {
        let policy = PasswordPolicy::default();
        let validator = PasswordPolicyValidator::new(policy);

        let result = validator.validate_sync("password123", None);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, PasswordValidationError::CommonPassword)));
    }

    #[test]
    fn test_validate_password_contains_user_info() {
        let policy = PasswordPolicy::default();
        let validator = PasswordPolicyValidator::new(policy);

        let user_info = UserInfo {
            email: "john.doe@example.com".to_string(),
            name: Some("John Doe".to_string()),
            user_id: "user123".to_string(),
        };

        let result = validator.validate_sync("JohnDoe2024!A", Some(&user_info));
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, PasswordValidationError::ContainsUserInfo)));
    }

    #[test]
    fn test_validate_password_valid() {
        let policy = PasswordPolicy::default();
        let validator = PasswordPolicyValidator::new(policy);

        let result = validator.validate_sync("Str0ng!Passw0rd$", None);
        assert!(result.is_valid);
        assert!(result.entropy > 50.0);
    }

    #[test]
    fn test_error_messages() {
        let err = PasswordValidationError::TooShort { min: 12, actual: 8 };
        assert!(err.message().contains("12"));
        assert!(err.message().contains("8"));

        let err = PasswordValidationError::Breached { count: 5000 };
        assert!(err.message().contains("5000"));
    }
}
