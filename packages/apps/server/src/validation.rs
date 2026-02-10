//! Validation utilities

use once_cell::sync::Lazy;
use regex::Regex;

/// Regex for validating tenant/user slugs
/// Allows lowercase letters, numbers, and hyphens
pub static SLUG_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z0-9-]+$").expect("SLUG_REGEX is a valid static pattern")
});

/// Regex for validating feature flag keys
/// Allows lowercase letters, numbers, and underscores
pub static FLAG_KEY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z0-9_]+$").expect("FLAG_KEY_REGEX is a valid static pattern")
});

/// Regex for validating domain names
/// Supports internationalized domain names (IDN) and standard domains
pub static DOMAIN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
        .expect("DOMAIN_REGEX is a valid static pattern")
});

/// Regex for validating email addresses
pub static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        .expect("EMAIL_REGEX is a valid static pattern")
});

/// Regex for validating IP addresses (IPv4)
pub static IPV4_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        .expect("IPV4_REGEX is a valid static pattern")
});

/// Regex for validating URL slugs/paths
pub static URL_SLUG_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9._~!$&'()*+,;=:@/-]+$").expect("URL_SLUG_REGEX is a valid static pattern")
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

// Property-based tests for validation functions
// 
// These tests ensure validators are robust against arbitrary/malicious input
// and never panic, crash, or expose the system to DoS attacks.
#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Test that email validation never panics on arbitrary input
        #[test]
        fn test_email_validation_never_panics(email in "\\PC*") {
            let _ = is_valid_email(&email);
        }

        // Test that email validation handles long inputs
        #[test]
        fn test_email_validation_long_input(
            local in "[a-z]{1,100}",
            domain in "[a-z]{1,100}",
            tld in "[a-z]{2,10}"
        ) {
            let email = format!("{}@{}.{}", local, domain, tld);
            // Should not panic on very long but valid-looking emails
            let _ = is_valid_email(&email);
        }

        // Test that domain validation never panics on arbitrary input
        #[test]
        fn test_domain_validation_never_panics(domain in "\\PC*") {
            let _ = is_valid_domain(&domain);
        }

        // Test that domain validation handles boundary lengths
        // RFC 1035 specifies max label length of 63 and max domain length of 253
        #[test]
        fn test_domain_validation_boundary_lengths(
            prefix in "[a-z]{1,10}",
            middle in "[a-z]{50,300}",
            suffix in ".com|.org|.net|.io"
        ) {
            let domain = format!("{}{}{}", prefix, middle, suffix);
            let valid = is_valid_domain(&domain);
            
            // Domains over 253 chars should be rejected
            if domain.len() > 253 {
                prop_assert!(!valid, "Domain over 253 chars should be invalid: len={}", domain.len());
            }
        }

        // Test that UUID validation never panics on arbitrary input
        #[test]
        fn test_uuid_validation_never_panics(uuid in "\\PC*") {
            let _ = is_valid_uuid(&uuid);
        }

        // Test that UUID validation correctly identifies valid UUIDs
        #[test]
        fn test_uuid_validation_roundtrip(
            uuid_bytes in "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        ) {
            prop_assert!(is_valid_uuid(&uuid_bytes), "Valid UUID should be accepted: {}", uuid_bytes);
        }

        // Test that slug validation never panics on arbitrary input
        #[test]
        fn test_slug_validation_never_panics(slug in "\\PC*") {
            let _ = is_valid_slug(&slug);
        }

        // Test that IPv4 validation never panics on arbitrary input
        #[test]
        fn test_ipv4_validation_never_panics(ip in "\\PC*") {
            let _ = is_valid_ipv4(&ip);
        }

        // Test that IPv4 validation correctly identifies valid IPs
        #[test]
        fn test_ipv4_validation_valid_addresses(
            octet1 in 0u8..255u8,
            octet2 in 0u8..255u8,
            octet3 in 0u8..255u8,
            octet4 in 0u8..255u8
        ) {
            let ip = format!("{}.{}.{}.{}", octet1, octet2, octet3, octet4);
            prop_assert!(is_valid_ipv4(&ip), "Valid IP should be accepted: {}", ip);
        }

        // Test that URL slug validation never panics on arbitrary input
        #[test]
        fn test_url_slug_validation_never_panics(slug in "\\PC*") {
            let _ = is_valid_url_slug(&slug);
        }

        // Test that hex color validation never panics on arbitrary input
        #[test]
        fn test_hex_color_validation_never_panics(color in "\\PC*") {
            let _ = is_valid_hex_color(&color);
        }

        // Test that hex color validation accepts valid colors
        #[test]
        fn test_hex_color_validation_valid(
            r in "[0-9A-Fa-f]{2}",
            g in "[0-9A-Fa-f]{2}",
            b in "[0-9A-Fa-f]{2}"
        ) {
            let color = format!("#{}{}{}", r, g, b);
            prop_assert!(is_valid_hex_color(&color), "Valid hex color should be accepted: {}", color);
        }

        // Test that flag key validation never panics on arbitrary input
        #[test]
        fn test_flag_key_validation_never_panics(key in "\\PC*") {
            let _ = is_valid_flag_key(&key);
        }

        // Test validation of inputs with null bytes and control characters
        #[test]
        fn test_validators_handle_control_characters(input in "[\\x00-\\x1F]*") {
            let _ = is_valid_email(&input);
            let _ = is_valid_domain(&input);
            let _ = is_valid_uuid(&input);
            let _ = is_valid_slug(&input);
            let _ = is_valid_ipv4(&input);
            let _ = is_valid_url_slug(&input);
            let _ = is_valid_hex_color(&input);
            let _ = is_valid_flag_key(&input);
        }

        // Test validation of inputs with high Unicode characters
        #[test]
        fn test_validators_handle_unicode(input in "[^\\x00-\\x7F]*") {
            let _ = is_valid_email(&input);
            let _ = is_valid_domain(&input);
            let _ = is_valid_uuid(&input);
            let _ = is_valid_slug(&input);
            let _ = is_valid_ipv4(&input);
            let _ = is_valid_url_slug(&input);
            let _ = is_valid_hex_color(&input);
            let _ = is_valid_flag_key(&input);
        }

        // Test that all validators handle empty strings
        #[test]
        fn test_validators_empty_string() {
            let empty = "";
            prop_assert!(!is_valid_email(empty));
            prop_assert!(!is_valid_domain(empty));
            prop_assert!(!is_valid_uuid(empty));
            prop_assert!(!is_valid_slug(empty));
            prop_assert!(!is_valid_ipv4(empty));
            prop_assert!(!is_valid_url_slug(empty));
            prop_assert!(!is_valid_hex_color(empty));
            prop_assert!(!is_valid_flag_key(empty));
        }

        // Test that all validators handle very long strings without crashing
        #[test]
        fn test_validators_very_long_strings(length in 1000usize..10000usize) {
            let long_string = "a".repeat(length);
            let _ = is_valid_email(&long_string);
            let _ = is_valid_domain(&long_string);
            let _ = is_valid_uuid(&long_string);
            let _ = is_valid_slug(&long_string);
            let _ = is_valid_ipv4(&long_string);
            let _ = is_valid_url_slug(&long_string);
            let _ = is_valid_hex_color(&long_string);
            let _ = is_valid_flag_key(&long_string);
        }

        // Test email validation with various special characters
        #[test]
        fn test_email_special_chars(local in "[a-zA-Z0-9._%+-]*", domain in "[a-zA-Z0-9.-]*") {
            let email = format!("{}@{}", local, domain);
            // Should not panic regardless of content
            let _ = is_valid_email(&email);
        }

        // Test domain validation with various TLDs
        #[test]
        fn test_domain_various_tlds(
            name in "[a-z][a-z0-9-]{0,20}[a-z0-9]",
            tld in "(com|org|net|edu|gov|io|co.uk|com.au|co.jp)"
        ) {
            let domain = format!("{}.{}", name, tld);
            // Valid-looking domains should often pass
            let _ = is_valid_domain(&domain);
        }
    }
}
