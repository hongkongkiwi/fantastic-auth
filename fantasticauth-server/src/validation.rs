//! Validation utilities

use once_cell::sync::Lazy;
use regex::Regex;

/// Regex for validating tenant/user slugs
/// Allows lowercase letters, numbers, and hyphens
pub static SLUG_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9-]+$").unwrap());

/// Regex for validating feature flag keys
/// Allows lowercase letters, numbers, and underscores
pub static FLAG_KEY_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9_]+$").unwrap());

/// Regex for validating domain names
/// Supports internationalized domain names (IDN) and standard domains
pub static DOMAIN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$").unwrap()
});

/// Regex for validating email addresses
pub static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
});

/// Regex for validating IP addresses (IPv4)
pub static IPV4_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$").unwrap()
});

/// Regex for validating URL slugs/paths
pub static URL_SLUG_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9._~!$&'()*+,;=:@/-]+$").unwrap()
});

/// Validate a slug
pub fn is_valid_slug(slug: &str) -> bool {
    SLUG_REGEX.is_match(slug)
}

/// Validate a feature flag key
pub fn is_valid_flag_key(key: &str) -> bool {
    FLAG_KEY_REGEX.is_match(key)
}

/// Validate a domain name
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.len() > 253 {
        return false;
    }
    DOMAIN_REGEX.is_match(domain)
}

/// Validate an email address
pub fn is_valid_email(email: &str) -> bool {
    EMAIL_REGEX.is_match(email)
}

/// Validate an IPv4 address
pub fn is_valid_ipv4(ip: &str) -> bool {
    IPV4_REGEX.is_match(ip)
}

/// Validate a URL slug/path
pub fn is_valid_url_slug(slug: &str) -> bool {
    URL_SLUG_REGEX.is_match(slug)
}

/// Validate a UUID string
pub fn is_valid_uuid(uuid: &str) -> bool {
    uuid::Uuid::parse_str(uuid).is_ok()
}

/// Validate a hex color code (e.g., #FF0000 or #f00)
pub fn is_valid_hex_color(color: &str) -> bool {
    color.len() == 7 && color.starts_with('#') && color[1..].chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slug_validation() {
        assert!(is_valid_slug("my-slug"));
        assert!(is_valid_slug("test123"));
        assert!(!is_valid_slug("MySlug")); // uppercase not allowed
        assert!(!is_valid_slug("my_slug")); // underscore not allowed
    }

    #[test]
    fn test_domain_validation() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("my-domain.org"));
        assert!(!is_valid_domain("-invalid.com"));
        assert!(!is_valid_domain("invalid-.com"));
    }

    #[test]
    fn test_email_validation() {
        assert!(is_valid_email("test@example.com"));
        assert!(is_valid_email("user.name@sub.domain.co.uk"));
        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@example.com"));
    }

    #[test]
    fn test_ipv4_validation() {
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(is_valid_ipv4("10.0.0.1"));
        assert!(is_valid_ipv4("255.255.255.255"));
        assert!(!is_valid_ipv4("256.1.1.1"));
        assert!(!is_valid_ipv4("192.168.1"));
    }

    #[test]
    fn test_hex_color_validation() {
        assert!(is_valid_hex_color("#FF0000"));
        assert!(is_valid_hex_color("#00ff00"));
        assert!(!is_valid_hex_color("FF0000")); // missing #
        assert!(!is_valid_hex_color("#GG0000")); // invalid hex
    }
}
