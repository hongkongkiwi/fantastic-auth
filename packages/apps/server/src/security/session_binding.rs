//! Session binding for detecting session hijacking
//!
//! Session binding detects when a session is used from a different IP
//! or device than it was created from, potentially indicating session
//! hijacking or token theft.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

use super::device_fingerprint::{
    parse_device_info, DeviceFingerprinter, FingerprintComponents, ParsedDeviceInfo,
};

/// Session binding security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BindingLevel {
    /// No binding - sessions can be used from any device/IP
    None,
    /// Advisory - log anomalies and notify user, but allow access
    #[default]
    Advisory,
    /// Strict - terminate session on mismatch, force re-login
    Strict,
}

impl BindingLevel {
    /// Parse from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "none" => Self::None,
            "strict" => Self::Strict,
            _ => Self::Advisory,
        }
    }

    /// Get as string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Advisory => "advisory",
            Self::Strict => "strict",
        }
    }
}

impl std::fmt::Display for BindingLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Type of binding violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    /// IP address mismatch
    IpMismatch,
    /// Device fingerprint mismatch
    DeviceMismatch,
    /// Both IP and device mismatch
    Both,
}

impl ViolationType {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IpMismatch => "ip_mismatch",
            Self::DeviceMismatch => "device_mismatch",
            Self::Both => "both",
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            Self::IpMismatch => "IP address changed",
            Self::DeviceMismatch => "Device changed",
            Self::Both => "Both IP and device changed",
        }
    }
}

/// Action taken when a binding violation is detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingAction {
    /// Allow the request, just log
    Allow,
    /// Block the request and invalidate the session
    Block,
    /// Require additional verification (step-up auth)
    RequireVerification,
}

/// Session binding check result
#[derive(Debug, Clone)]
pub enum BindingResult {
    /// Binding check passed - session is valid
    Valid,
    /// Binding violation detected with action taken
    Violation {
        violation_type: ViolationType,
        action: BindingAction,
        details: ViolationDetails,
    },
}

/// Details about a binding violation
#[derive(Debug, Clone, Serialize)]
pub struct ViolationDetails {
    /// Expected IP (from session creation)
    pub expected_ip: Option<String>,
    /// Actual IP (current request)
    pub actual_ip: Option<String>,
    /// Expected device hash
    pub expected_device: Option<String>,
    /// Actual device hash
    pub actual_device: Option<String>,
    /// Whether this is a suspicious change
    pub is_suspicious: bool,
    /// Risk score (0-100)
    pub risk_score: u8,
}

/// Error type for session binding operations
#[derive(Debug, Error)]
pub enum SessionBindingError {
    #[error("Invalid fingerprint")]
    InvalidFingerprint,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Database error: {0}")]
    Database(String),
}

/// Session binding configuration
#[derive(Debug, Clone)]
pub struct SessionBindingConfig {
    /// Binding level (none, advisory, strict)
    pub level: BindingLevel,
    /// Whether to bind to IP address
    pub bind_ip: bool,
    /// Whether to bind to device fingerprint
    pub bind_device: bool,
    /// Whether to allow users to opt-in to stricter binding
    pub allow_user_opt_in: bool,
    /// Notify user on new device detection
    pub notify_on_new_device: bool,
    /// Require email verification for new devices
    pub require_verification_for_new_device: bool,
    /// IP subnet mask for matching (e.g., /24 for Class C)
    /// None means exact match required
    pub ip_subnet_mask: Option<u8>,
    /// Whether to ignore private IP changes (for users on dynamic IPs)
    pub ignore_private_ip_changes: bool,
    /// Maximum violations before auto-revocation
    pub max_violations_before_revoke: u32,
}

impl Default for SessionBindingConfig {
    fn default() -> Self {
        Self {
            level: BindingLevel::Advisory,
            bind_ip: true,
            bind_device: true,
            allow_user_opt_in: true,
            notify_on_new_device: true,
            require_verification_for_new_device: false,
            ip_subnet_mask: None,
            ignore_private_ip_changes: true,
            max_violations_before_revoke: 5,
        }
    }
}

impl SessionBindingConfig {
    /// Create a strict configuration
    pub fn strict() -> Self {
        Self {
            level: BindingLevel::Strict,
            bind_ip: true,
            bind_device: true,
            allow_user_opt_in: false,
            notify_on_new_device: true,
            require_verification_for_new_device: true,
            ip_subnet_mask: None,
            ignore_private_ip_changes: false,
            max_violations_before_revoke: 1,
        }
    }

    /// Create a configuration with no binding
    pub fn none() -> Self {
        Self {
            level: BindingLevel::None,
            bind_ip: false,
            bind_device: false,
            ..Default::default()
        }
    }
}

/// Session information for binding checks
#[derive(Debug, Clone)]
pub struct SessionBindingInfo {
    pub session_id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub created_ip: Option<String>,
    pub created_device_hash: Option<String>,
    pub bind_to_ip: bool,
    pub bind_to_device: bool,
    pub violation_count: u32,
}

/// Request context for binding checks
#[derive(Debug, Clone)]
pub struct BindingRequestContext {
    pub ip_address: Option<IpAddr>,
    pub headers: HeaderMap,
    pub device_fingerprint: Option<String>,
}

impl BindingRequestContext {
    /// Create from request parts
    pub fn new(ip: Option<IpAddr>, headers: HeaderMap) -> Self {
        Self {
            ip_address: ip,
            headers,
            device_fingerprint: None,
        }
    }

    /// With pre-computed device fingerprint
    pub fn with_fingerprint(mut self, fingerprint: String) -> Self {
        self.device_fingerprint = Some(fingerprint);
        self
    }
}

/// Session binding checker
#[derive(Debug, Clone)]
pub struct SessionBindingChecker {
    config: SessionBindingConfig,
    fingerprinter: DeviceFingerprinter,
}

impl SessionBindingChecker {
    /// Create a new checker with default configuration
    pub fn new() -> Self {
        Self {
            config: SessionBindingConfig::default(),
            fingerprinter: DeviceFingerprinter::new(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: SessionBindingConfig) -> Self {
        Self {
            config,
            fingerprinter: DeviceFingerprinter::new(),
        }
    }

    /// Create with strict settings
    pub fn strict() -> Self {
        Self {
            config: SessionBindingConfig::strict(),
            fingerprinter: DeviceFingerprinter::strict(),
        }
    }

    /// Update configuration
    pub fn with_config_mut(&mut self, config: SessionBindingConfig) -> &mut Self {
        self.config = config;
        self
    }

    /// Check if a session's binding is valid for the current request
    pub fn check_binding(
        &self,
        session: &SessionBindingInfo,
        request: &BindingRequestContext,
    ) -> BindingResult {
        // Skip check if binding is disabled
        if self.config.level == BindingLevel::None {
            return BindingResult::Valid;
        }

        // Skip if session doesn't have binding enabled
        if !session.bind_to_ip && !session.bind_to_device {
            return BindingResult::Valid;
        }

        // Get current request fingerprint if not provided
        let current_device = request.device_fingerprint.clone().or_else(|| {
            self.fingerprinter
                .generate_from_headers(&request.headers, request.ip_address)
        });

        let current_ip = request.ip_address.map(|ip| ip.to_string());

        // Check for violations
        let ip_mismatch = self.check_ip_mismatch(session.bind_to_ip, &session.created_ip, &current_ip);
        let device_mismatch = self.check_device_mismatch(
            session.bind_to_device,
            &session.created_device_hash,
            &current_device,
        );

        // Determine violation type
        let violation_type = match (ip_mismatch, device_mismatch) {
            (true, true) => ViolationType::Both,
            (true, false) => ViolationType::IpMismatch,
            (false, true) => ViolationType::DeviceMismatch,
            (false, false) => return BindingResult::Valid,
        };

        // Calculate risk score
        let risk_score = self.calculate_risk_score(
            &violation_type,
            &session.created_ip,
            &current_ip,
            &session.created_device_hash,
            &current_device,
        );

        let is_suspicious = self.is_suspicious_change(
            session.created_ip.as_deref(),
            current_ip.as_deref(),
            session.created_device_hash.as_deref(),
            current_device.as_deref(),
        );

        let details = ViolationDetails {
            expected_ip: session.created_ip.clone(),
            actual_ip: current_ip,
            expected_device: session.created_device_hash.clone(),
            actual_device: current_device,
            is_suspicious,
            risk_score,
        };

        // Determine action based on level and violations
        let action = match self.config.level {
            BindingLevel::None => BindingAction::Allow,
            BindingLevel::Advisory => BindingAction::Allow,
            BindingLevel::Strict => {
                if session.violation_count >= self.config.max_violations_before_revoke {
                    BindingAction::Block
                } else {
                    BindingAction::RequireVerification
                }
            }
        };

        BindingResult::Violation {
            violation_type,
            action,
            details,
        }
    }

    /// Check if IP addresses match
    fn check_ip_mismatch(
        &self,
        session_bind_to_ip: bool,
        expected: &Option<String>,
        actual: &Option<String>,
    ) -> bool {
        // A session only mismatches on IP when this specific session is bound to IP.
        if !session_bind_to_ip {
            return false;
        }

        // If no expected IP, can't mismatch
        let expected = match expected {
            Some(ip) => ip,
            None => return false,
        };

        // If no actual IP, treat as mismatch
        let actual = match actual {
            Some(ip) => ip,
            None => return true,
        };

        // Check if we should ignore private IP changes
        if self.config.ignore_private_ip_changes {
            if is_private_ip(expected) && is_private_ip(actual) {
                return false;
            }
        }

        // Check subnet match if configured
        if let Some(mask) = self.config.ip_subnet_mask {
            return !ips_in_same_subnet(expected, actual, mask);
        }

        // Exact match required
        expected != actual
    }

    /// Check if device fingerprints match
    fn check_device_mismatch(
        &self,
        session_bind_to_device: bool,
        expected: &Option<String>,
        actual: &Option<String>,
    ) -> bool {
        // A session only mismatches on device when this specific session is bound to a device.
        if !session_bind_to_device {
            return false;
        }

        // If no expected device hash, can't mismatch
        let expected = match expected {
            Some(hash) => hash,
            None => return false,
        };

        // If no actual device hash, treat as mismatch
        let actual = match actual {
            Some(hash) => hash,
            None => return true,
        };

        expected != actual
    }

    /// Determine if a change is suspicious (high risk)
    pub fn is_suspicious_change(
        &self,
        old_ip: Option<&str>,
        new_ip: Option<&str>,
        old_device: Option<&str>,
        new_device: Option<&str>,
    ) -> bool {
        // Both IP and device changed = very suspicious
        if old_ip.is_some()
            && new_ip.is_some()
            && old_ip != new_ip
            && old_device.is_some()
            && new_device.is_some()
            && old_device != new_device
        {
            return true;
        }

        // Check for rapid changes (would require history, simplified here)
        // In practice, you'd check against recent violations

        // Public IP to private IP change is suspicious
        if let (Some(old), Some(new)) = (old_ip, new_ip) {
            let was_public = !is_private_ip(old);
            let now_private = is_private_ip(new);
            if was_public && now_private {
                return true;
            }
        }

        // Different countries would be suspicious (requires GeoIP)
        // For now, simplified check

        false
    }

    /// Calculate a risk score (0-100) for a binding change
    fn calculate_risk_score(
        &self,
        violation_type: &ViolationType,
        old_ip: &Option<String>,
        new_ip: &Option<String>,
        old_device: &Option<String>,
        new_device: &Option<String>,
    ) -> u8 {
        let mut score: u8 = 0;

        // Base score by violation type
        match violation_type {
            ViolationType::IpMismatch => score += 30,
            ViolationType::DeviceMismatch => score += 40,
            ViolationType::Both => score += 70,
        }

        // Additional risk if both IP and device changed simultaneously
        if old_ip != new_ip && old_device != new_device {
            score += 15;
        }

        // Public to private IP is high risk
        if let (Some(old), Some(new)) = (old_ip, new_ip) {
            if !is_private_ip(old) && is_private_ip(new) {
                score += 10;
            }
        }

        // Missing device fingerprint is moderate risk
        if new_device.is_none() {
            score += 5;
        }

        score.min(100)
    }

    /// Generate a device fingerprint from request
    pub fn generate_fingerprint(&self, headers: &HeaderMap, ip: Option<IpAddr>) -> Option<String> {
        self.fingerprinter.generate_from_headers(headers, ip)
    }

    /// Get the configuration
    pub fn config(&self) -> &SessionBindingConfig {
        &self.config
    }

    /// Check if binding is effectively enabled
    pub fn is_enabled(&self) -> bool {
        self.config.level != BindingLevel::None
    }
}

/// Check if an IP is in a private range
fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // 10.0.0.0/8
                if octets[0] == 10 {
                    return true;
                }
                // 172.16.0.0/12
                if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                    return true;
                }
                // 192.168.0.0/16
                if octets[0] == 192 && octets[1] == 168 {
                    return true;
                }
                // 127.0.0.0/8 (loopback)
                if octets[0] == 127 {
                    return true;
                }
                // 169.254.0.0/16 (link-local)
                if octets[0] == 169 && octets[1] == 254 {
                    return true;
                }
            }
            IpAddr::V6(ipv6) => {
                // Check for loopback (::1) and unique local addresses (fc00::/7)
                let segments = ipv6.segments();
                if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
                    return true; // ::1
                }
                if (segments[0] & 0xfe00) == 0xfc00 {
                    return true; // fc00::/7
                }
            }
        }
    }
    false
}

/// Check if two IPs are in the same subnet
fn ips_in_same_subnet(ip1: &str, ip2: &str, mask_bits: u8) -> bool {
    if let (Ok(addr1), Ok(addr2)) = (ip1.parse::<IpAddr>(), ip2.parse::<IpAddr>()) {
        match (addr1, addr2) {
            (IpAddr::V4(v4_1), IpAddr::V4(v4_2)) => {
                let mask = !((1u32 << (32 - mask_bits)) - 1);
                let ip1_bits = u32::from(v4_1);
                let ip2_bits = u32::from(v4_2);
                (ip1_bits & mask) == (ip2_bits & mask)
            }
            (IpAddr::V6(v6_1), IpAddr::V6(v6_2)) => {
                // Simplified IPv6 subnet check
                let mask = !((1u128 << (128 - mask_bits)) - 1);
                let ip1_bits = u128::from(v6_1);
                let ip2_bits = u128::from(v6_2);
                (ip1_bits & mask) == (ip2_bits & mask)
            }
            _ => false, // Different address families
        }
    } else {
        false
    }
}

/// Notification context for new device/location detection
#[derive(Debug, Clone)]
pub struct NewDeviceNotification {
    pub user_id: String,
    pub email: String,
    pub device_info: ParsedDeviceInfo,
    pub location: Option<String>,
    pub ip_address: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_trusted: bool,
    pub verification_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binding_level_from_str() {
        assert_eq!(BindingLevel::from_str("none"), BindingLevel::None);
        assert_eq!(BindingLevel::from_str("strict"), BindingLevel::Strict);
        assert_eq!(BindingLevel::from_str("advisory"), BindingLevel::Advisory);
        assert_eq!(BindingLevel::from_str("unknown"), BindingLevel::Advisory);
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("169.254.0.1"));

        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(!is_private_ip("203.0.113.1"));
    }

    #[test]
    fn test_ips_in_same_subnet() {
        assert!(ips_in_same_subnet("192.168.1.1", "192.168.1.100", 24));
        assert!(!ips_in_same_subnet("192.168.1.1", "192.168.2.1", 24));
        assert!(ips_in_same_subnet("10.0.0.1", "10.0.0.254", 24));
        assert!(!ips_in_same_subnet("10.0.0.1", "10.0.1.1", 24));
    }

    #[test]
    fn test_session_binding_check_valid() {
        let checker = SessionBindingChecker::new();
        let session = SessionBindingInfo {
            session_id: "sess_123".to_string(),
            user_id: "user_456".to_string(),
            tenant_id: "tenant_789".to_string(),
            created_ip: Some("192.168.1.1".to_string()),
            created_device_hash: Some("abc123".to_string()),
            bind_to_ip: true,
            bind_to_device: true,
            violation_count: 0,
        };

        let request = BindingRequestContext {
            ip_address: "192.168.1.1".parse().ok(),
            headers: axum::http::HeaderMap::new(),
            device_fingerprint: Some("abc123".to_string()),
        };

        let result = checker.check_binding(&session, &request);
        assert!(matches!(result, BindingResult::Valid));
    }

    #[test]
    fn test_session_binding_ip_mismatch() {
        let checker = SessionBindingChecker::strict();
        let session = SessionBindingInfo {
            session_id: "sess_123".to_string(),
            user_id: "user_456".to_string(),
            tenant_id: "tenant_789".to_string(),
            created_ip: Some("8.8.8.8".to_string()),
            created_device_hash: Some("abc123".to_string()),
            bind_to_ip: true,
            bind_to_device: false,
            violation_count: 0,
        };

        let request = BindingRequestContext {
            ip_address: "1.1.1.1".parse().ok(),
            headers: axum::http::HeaderMap::new(),
            device_fingerprint: Some("abc123".to_string()),
        };

        let result = checker.check_binding(&session, &request);
        match result {
            BindingResult::Violation { violation_type, .. } => {
                assert_eq!(violation_type, ViolationType::IpMismatch);
            }
            _ => panic!("Expected violation"),
        }
    }

    #[test]
    fn test_session_binding_device_mismatch() {
        let checker = SessionBindingChecker::new();
        let session = SessionBindingInfo {
            session_id: "sess_123".to_string(),
            user_id: "user_456".to_string(),
            tenant_id: "tenant_789".to_string(),
            created_ip: Some("192.168.1.1".to_string()),
            created_device_hash: Some("abc123".to_string()),
            bind_to_ip: false,
            bind_to_device: true,
            violation_count: 0,
        };

        let request = BindingRequestContext {
            ip_address: "192.168.1.1".parse().ok(),
            headers: axum::http::HeaderMap::new(),
            device_fingerprint: Some("xyz789".to_string()),
        };

        let result = checker.check_binding(&session, &request);
        match result {
            BindingResult::Violation { violation_type, .. } => {
                assert_eq!(violation_type, ViolationType::DeviceMismatch);
            }
            _ => panic!("Expected violation"),
        }
    }

    #[test]
    fn test_session_binding_both_mismatch() {
        let checker = SessionBindingChecker::strict();
        let session = SessionBindingInfo {
            session_id: "sess_123".to_string(),
            user_id: "user_456".to_string(),
            tenant_id: "tenant_789".to_string(),
            created_ip: Some("8.8.8.8".to_string()),
            created_device_hash: Some("abc123".to_string()),
            bind_to_ip: true,
            bind_to_device: true,
            violation_count: 0,
        };

        let request = BindingRequestContext {
            ip_address: "10.0.0.1".parse().ok(),
            headers: axum::http::HeaderMap::new(),
            device_fingerprint: Some("xyz789".to_string()),
        };

        let result = checker.check_binding(&session, &request);
        match result {
            BindingResult::Violation { violation_type, .. } => {
                assert_eq!(violation_type, ViolationType::Both);
            }
            _ => panic!("Expected violation"),
        }
    }

    #[test]
    fn test_ignore_private_ip_changes() {
        let config = SessionBindingConfig {
            ignore_private_ip_changes: true,
            bind_ip: true,
            ..Default::default()
        };
        let checker = SessionBindingChecker::with_config(config);
        let session = SessionBindingInfo {
            session_id: "sess_123".to_string(),
            user_id: "user_456".to_string(),
            tenant_id: "tenant_789".to_string(),
            created_ip: Some("192.168.1.1".to_string()),
            created_device_hash: Some("abc123".to_string()),
            bind_to_ip: true,
            bind_to_device: true,
            violation_count: 0,
        };

        // Different private IPs should be OK
        let request = BindingRequestContext {
            ip_address: "192.168.1.100".parse().ok(),
            headers: axum::http::HeaderMap::new(),
            device_fingerprint: Some("abc123".to_string()),
        };

        let result = checker.check_binding(&session, &request);
        assert!(matches!(result, BindingResult::Valid));
    }

    #[test]
    fn test_strict_binding_blocks() {
        let checker = SessionBindingChecker::strict();
        let session = SessionBindingInfo {
            session_id: "sess_123".to_string(),
            user_id: "user_456".to_string(),
            tenant_id: "tenant_789".to_string(),
            created_ip: Some("192.168.1.1".to_string()),
            created_device_hash: Some("abc123".to_string()),
            bind_to_ip: true,
            bind_to_device: true,
            violation_count: 1, // Already has violations
        };

        let request = BindingRequestContext {
            ip_address: "10.0.0.1".parse().ok(),
            headers: axum::http::HeaderMap::new(),
            device_fingerprint: Some("xyz789".to_string()),
        };

        let result = checker.check_binding(&session, &request);
        match result {
            BindingResult::Violation { action, .. } => {
                assert_eq!(action, BindingAction::Block);
            }
            _ => panic!("Expected block action"),
        }
    }

    #[test]
    fn test_is_suspicious_change() {
        let checker = SessionBindingChecker::new();

        // Both changed = suspicious
        assert!(checker.is_suspicious_change(
            Some("8.8.8.8"),
            Some("1.1.1.1"),
            Some("device1"),
            Some("device2")
        ));

        // Only IP changed = not suspicious by this check
        assert!(!checker.is_suspicious_change(
            Some("8.8.8.8"),
            Some("1.1.1.1"),
            Some("device1"),
            Some("device1")
        ));

        // Public to private = suspicious
        assert!(checker.is_suspicious_change(
            Some("8.8.8.8"),
            Some("192.168.1.1"),
            Some("device1"),
            Some("device1")
        ));
    }
}
