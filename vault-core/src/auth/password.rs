//! Password validation and strength checking

use crate::error::{Result, VaultError};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;

/// Minimum password length
const MIN_LENGTH: usize = 12;
/// Maximum password length (prevent DoS)
const MAX_LENGTH: usize = 128;

/// Password requirements
#[derive(Debug, Clone)]
pub struct PasswordRequirements {
    /// Minimum length
    pub min_length: usize,
    /// Maximum length
    pub max_length: usize,
    /// Require uppercase letters
    pub require_uppercase: bool,
    /// Require lowercase letters
    pub require_lowercase: bool,
    /// Require digits
    pub require_digits: bool,
    /// Require special characters
    pub require_special: bool,
    /// Minimum entropy bits
    pub min_entropy: f64,
    /// Check against common passwords
    pub check_common: bool,
}

impl Default for PasswordRequirements {
    fn default() -> Self {
        Self {
            min_length: MIN_LENGTH,
            max_length: MAX_LENGTH,
            require_uppercase: true,
            require_lowercase: true,
            require_digits: true,
            require_special: true,
            min_entropy: 50.0,
            check_common: true,
        }
    }
}

lazy_static! {
    /// Common passwords (in production, load from file/API)
    static ref COMMON_PASSWORDS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("password");
        set.insert("password123");
        set.insert("123456");
        set.insert("12345678");
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
        set
    };

    /// Character class regexes
    static ref UPPERCASE_RE: Regex = Regex::new(r"[A-Z]").unwrap();
    static ref LOWERCASE_RE: Regex = Regex::new(r"[a-z]").unwrap();
    static ref DIGIT_RE: Regex = Regex::new(r"[0-9]").unwrap();
    static ref SPECIAL_RE: Regex = Regex::new("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?`~]").unwrap();
}

/// Validate password strength
pub fn validate_password_strength(password: &str) -> Result<()> {
    let requirements = PasswordRequirements::default();
    validate_password(password, &requirements)
}

/// Validate password with custom requirements
pub fn validate_password(password: &str, requirements: &PasswordRequirements) -> Result<()> {
    // Check length
    if password.len() < requirements.min_length {
        return Err(VaultError::validation(format!(
            "Password must be at least {} characters long",
            requirements.min_length
        )));
    }

    if password.len() > requirements.max_length {
        return Err(VaultError::validation(format!(
            "Password must not exceed {} characters",
            requirements.max_length
        )));
    }

    // Check character classes
    if requirements.require_uppercase && !UPPERCASE_RE.is_match(password) {
        return Err(VaultError::validation(
            "Password must contain at least one uppercase letter",
        ));
    }

    if requirements.require_lowercase && !LOWERCASE_RE.is_match(password) {
        return Err(VaultError::validation(
            "Password must contain at least one lowercase letter",
        ));
    }

    if requirements.require_digits && !DIGIT_RE.is_match(password) {
        return Err(VaultError::validation(
            "Password must contain at least one digit",
        ));
    }

    if requirements.require_special && !SPECIAL_RE.is_match(password) {
        return Err(VaultError::validation(
            "Password must contain at least one special character (!@#$%^&* etc.)",
        ));
    }

    // Check against common passwords
    if requirements.check_common {
        let lower = password.to_lowercase();
        if COMMON_PASSWORDS.contains(lower.as_str()) {
            return Err(VaultError::validation(
                "Password is too common. Please choose a more unique password.",
            ));
        }
    }

    // Check entropy
    let entropy = calculate_entropy(password);
    if entropy < requirements.min_entropy {
        return Err(VaultError::validation(format!(
            "Password is not strong enough (entropy: {:.1} bits, required: {:.1} bits)",
            entropy, requirements.min_entropy
        )));
    }

    Ok(())
}

/// Calculate password entropy in bits
///
/// Entropy = length * log2(charset_size)
fn calculate_entropy(password: &str) -> f64 {
    let mut charset_size = 0usize;

    if UPPERCASE_RE.is_match(password) {
        charset_size += 26;
    }
    if LOWERCASE_RE.is_match(password) {
        charset_size += 26;
    }
    if DIGIT_RE.is_match(password) {
        charset_size += 10;
    }
    if SPECIAL_RE.is_match(password) {
        charset_size += 32;
    }

    if charset_size == 0 {
        return 0.0;
    }

    let length = password.len() as f64;
    let charset = charset_size as f64;

    length * charset.log2()
}

/// Check if password has been breached using HIBP API
///
/// This is an async function that queries the Have I Been Pwned API
pub async fn check_breach(password: &str) -> Result<bool> {
    use sha1::{Digest, Sha1};

    // Calculate SHA-1 hash
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = hex::encode(hasher.finalize());

    // Split into prefix (5 chars) and suffix
    let prefix = &hash[..5];
    let suffix = &hash[5..].to_uppercase();

    // Query HIBP API
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

    let response = reqwest::get(&url)
        .await
        .map_err(|e| VaultError::ExternalService {
            service: "HIBP".into(),
            message: e.to_string(),
        })?;

    if !response.status().is_success() {
        return Err(VaultError::ExternalService {
            service: "HIBP".into(),
            message: "Failed to check breach database".into(),
        });
    }

    let text = response
        .text()
        .await
        .map_err(|e| VaultError::ExternalService {
            service: "HIBP".into(),
            message: e.to_string(),
        })?;

    // Check if suffix exists in response
    for line in text.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() == 2 && parts[0] == suffix {
            return Ok(true); // Password found in breach database
        }
    }

    Ok(false) // Password not found
}

/// Password strength score (0-4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    /// Very weak (0)
    VeryWeak = 0,
    /// Weak (1)
    Weak = 1,
    /// Fair (2)
    Fair = 2,
    /// Strong (3)
    Strong = 3,
    /// Very strong (4)
    VeryStrong = 4,
}

impl PasswordStrength {
    /// Get strength as string
    pub fn as_str(&self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => "very_weak",
            PasswordStrength::Weak => "weak",
            PasswordStrength::Fair => "fair",
            PasswordStrength::Strong => "strong",
            PasswordStrength::VeryStrong => "very_strong",
        }
    }

    /// Get feedback message
    pub fn feedback(&self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => "This password is very weak and easily guessable",
            PasswordStrength::Weak => "This password is weak - add more variety",
            PasswordStrength::Fair => "This password is acceptable but could be stronger",
            PasswordStrength::Strong => "This password is strong",
            PasswordStrength::VeryStrong => "This password is very strong",
        }
    }
}

/// Calculate password strength score
pub fn calculate_strength(password: &str) -> PasswordStrength {
    let entropy = calculate_entropy(password);

    if entropy < 28.0 {
        PasswordStrength::VeryWeak
    } else if entropy < 36.0 {
        PasswordStrength::Weak
    } else if entropy < 60.0 {
        PasswordStrength::Fair
    } else if entropy < 80.0 {
        PasswordStrength::Strong
    } else {
        PasswordStrength::VeryStrong
    }
}

/// Generate a strong password
///
/// SECURITY: Uses OsRng (operating system's CSPRNG) for cryptographically secure
/// password generation. This ensures passwords are unpredictable and resistant to
/// brute-force attacks. Character selection uses uniform distribution to avoid bias.
pub fn generate_password(length: usize) -> String {
    use rand::Rng;
    use rand_core::OsRng;

    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &[u8] = b"0123456789";
    const SPECIAL: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    let mut rng = OsRng;
    let mut password = Vec::with_capacity(length);

    // Ensure at least one of each character class
    password.push(UPPERCASE[rng.gen_range(0..UPPERCASE.len())]);
    password.push(LOWERCASE[rng.gen_range(0..LOWERCASE.len())]);
    password.push(DIGITS[rng.gen_range(0..DIGITS.len())]);
    password.push(SPECIAL[rng.gen_range(0..SPECIAL.len())]);

    // Fill remaining with random characters from all classes
    let all: Vec<u8> = [UPPERCASE, LOWERCASE, DIGITS, SPECIAL].concat();

    for _ in 4..length {
        password.push(all[rng.gen_range(0..all.len())]);
    }

    // Shuffle using Fisher-Yates with secure RNG
    for i in (1..password.len()).rev() {
        let j = rng.gen_range(0..=i);
        password.swap(i, j);
    }

    String::from_utf8(password).expect("Password contains only valid UTF-8 characters")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_validation() {
        assert!(validate_password_strength("StrongP@ssw0rd123!").is_ok());
        assert!(validate_password_strength("short").is_err());
        assert!(validate_password_strength("nouppercase123!").is_err());
        assert!(validate_password_strength("NOLOWERCASE123!").is_err());
        assert!(validate_password_strength("NoSpecialChar123").is_err());
        assert!(validate_password_strength("password123!").is_err()); // Common password
    }

    #[test]
    fn test_entropy_calculation() {
        let entropy = calculate_entropy("StrongP@ssw0rd123!");
        assert!(entropy > 100.0);

        let weak_entropy = calculate_entropy("password");
        assert!(weak_entropy < 50.0);
    }

    #[test]
    fn test_strength_calculation() {
        assert_eq!(calculate_strength("abc"), PasswordStrength::VeryWeak);
        assert_eq!(
            calculate_strength("StrongP@ssw0rd123!"),
            PasswordStrength::VeryStrong
        );
    }

    #[test]
    fn test_password_generation() {
        let password = generate_password(16);
        assert_eq!(password.len(), 16);
        assert!(validate_password_strength(&password).is_ok());

        // Ensure variety
        assert!(UPPERCASE_RE.is_match(&password));
        assert!(LOWERCASE_RE.is_match(&password));
        assert!(DIGIT_RE.is_match(&password));
        assert!(SPECIAL_RE.is_match(&password));
    }
}
