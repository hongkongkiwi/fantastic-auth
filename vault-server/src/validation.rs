//! Validation utilities

use once_cell::sync::Lazy;
use regex::Regex;

/// Regex for validating tenant/user slugs
/// Allows lowercase letters, numbers, and hyphens
pub static SLUG_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9-]+$").unwrap());

/// Regex for validating feature flag keys
/// Allows lowercase letters, numbers, and underscores
pub static FLAG_KEY_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9_]+$").unwrap());

/// Validate a slug
pub fn is_valid_slug(slug: &str) -> bool {
    SLUG_REGEX.is_match(slug)
}

/// Validate a feature flag key
pub fn is_valid_flag_key(key: &str) -> bool {
    FLAG_KEY_REGEX.is_match(key)
}
