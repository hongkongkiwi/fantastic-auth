//! Device fingerprinting for session binding
//!
//! Generates unique fingerprints from browser/device characteristics
//! to detect when a session is used from a different device.

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Components that can be used to generate a device fingerprint
#[derive(Debug, Clone, Default)]
pub struct FingerprintComponents {
    /// User agent string
    pub user_agent: String,
    /// Accept header
    pub accept: String,
    /// Accept-Language header
    pub accept_language: String,
    /// Accept-Encoding header
    pub accept_encoding: String,
    /// DNT (Do Not Track) header
    pub dnt: Option<String>,
    /// Screen resolution (from JS or client-side detection)
    pub screen_resolution: Option<String>,
    /// Color depth
    pub color_depth: Option<String>,
    /// Timezone
    pub timezone: Option<String>,
    /// Platform (from JS navigator.platform)
    pub platform: Option<String>,
    /// Canvas fingerprint (hash of canvas rendering, from JS)
    pub canvas_hash: Option<String>,
    /// WebGL fingerprint (hash of WebGL renderer info, from JS)
    pub webgl_hash: Option<String>,
    /// Fonts detected (from JS)
    pub fonts: Option<String>,
    /// Touch support
    pub touch_support: Option<bool>,
}

impl FingerprintComponents {
    /// Extract components from HTTP headers
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            user_agent: get_header_value(headers, "user-agent"),
            accept: get_header_value(headers, "accept"),
            accept_language: get_header_value(headers, "accept-language"),
            accept_encoding: get_header_value(headers, "accept-encoding"),
            dnt: get_header_opt(headers, "dnt"),
            screen_resolution: get_header_opt(headers, "x-screen-resolution"),
            color_depth: get_header_opt(headers, "x-color-depth"),
            timezone: get_header_opt(headers, "x-timezone"),
            platform: get_header_opt(headers, "x-platform"),
            canvas_hash: get_header_opt(headers, "x-canvas-fingerprint"),
            webgl_hash: get_header_opt(headers, "x-webgl-fingerprint"),
            fonts: get_header_opt(headers, "x-fonts"),
            touch_support: get_header_opt(headers, "x-touch-support").map(|v| v == "true"),
        }
    }

    /// Add client-side components (called when client provides additional fingerprint data)
    pub fn with_client_data(
        mut self,
        screen_resolution: Option<String>,
        timezone: Option<String>,
        canvas_hash: Option<String>,
    ) -> Self {
        self.screen_resolution = screen_resolution;
        self.timezone = timezone;
        self.canvas_hash = canvas_hash;
        self
    }
}

/// Device fingerprinter for generating and comparing fingerprints
#[derive(Debug, Clone)]
pub struct DeviceFingerprinter {
    /// Whether to include IP in fingerprint (makes it more strict)
    include_ip: bool,
    /// Whether to include canvas fingerprinting (requires JS)
    include_canvas: bool,
    /// Minimum components required for a valid fingerprint
    min_components: usize,
}

impl Default for DeviceFingerprinter {
    fn default() -> Self {
        Self {
            include_ip: false,
            include_canvas: true,
            min_components: 2,
        }
    }
}

impl DeviceFingerprinter {
    /// Create a new fingerprinter with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a strict fingerprinter (includes IP)
    pub fn strict() -> Self {
        Self {
            include_ip: true,
            include_canvas: true,
            min_components: 3,
        }
    }

    /// Create a lenient fingerprinter (fewer requirements)
    pub fn lenient() -> Self {
        Self {
            include_ip: false,
            include_canvas: false,
            min_components: 1,
        }
    }

    /// Configure whether to include IP in fingerprint
    pub fn with_ip(mut self, include: bool) -> Self {
        self.include_ip = include;
        self
    }

    /// Configure whether to require canvas fingerprint
    pub fn with_canvas(mut self, include: bool) -> Self {
        self.include_canvas = include;
        self
    }

    /// Generate a fingerprint from components
    pub fn generate(
        &self,
        components: &FingerprintComponents,
        ip: Option<IpAddr>,
    ) -> Option<String> {
        // Check if we have enough components for a reliable fingerprint
        let mut component_count = 0;

        if !components.user_agent.is_empty() {
            component_count += 1;
        }
        if !components.accept_language.is_empty() {
            component_count += 1;
        }
        if components.screen_resolution.is_some() {
            component_count += 1;
        }
        if components.canvas_hash.is_some() {
            component_count += 1;
        }

        if component_count < self.min_components {
            return None;
        }

        // Build fingerprint input
        let mut hasher = Sha256::new();

        // Always include user agent (primary identifier)
        hasher.update(b"ua:");
        hasher.update(components.user_agent.as_bytes());

        // Include accept headers (browser characteristics)
        hasher.update(b"|accept:");
        hasher.update(components.accept.as_bytes());
        hasher.update(b"|lang:");
        hasher.update(components.accept_language.as_bytes());

        // Include optional components if available
        if let Some(ref resolution) = components.screen_resolution {
            hasher.update(b"|res:");
            hasher.update(resolution.as_bytes());
        }

        if let Some(ref timezone) = components.timezone {
            hasher.update(b"|tz:");
            hasher.update(timezone.as_bytes());
        }

        if let Some(ref platform) = components.platform {
            hasher.update(b"|plat:");
            hasher.update(platform.as_bytes());
        }

        if self.include_canvas {
            if let Some(ref canvas) = components.canvas_hash {
                hasher.update(b"|canvas:");
                hasher.update(canvas.as_bytes());
            }
        }

        if let Some(ref webgl) = components.webgl_hash {
            hasher.update(b"|webgl:");
            hasher.update(webgl.as_bytes());
        }

        if let Some(ref fonts) = components.fonts {
            hasher.update(b"|fonts:");
            hasher.update(fonts.as_bytes());
        }

        if let Some(touch) = components.touch_support {
            hasher.update(b"|touch:");
            hasher.update(if touch { b"1" } else { b"0" });
        }

        // Include IP if configured
        if self.include_ip {
            if let Some(ip_addr) = ip {
                hasher.update(b"|ip:");
                hasher.update(ip_addr.to_string().as_bytes());
            }
        }

        // Take first 16 bytes (32 hex chars) for compact representation
        let hash = hasher.finalize();
        Some(hex::encode(&hash[..16]))
    }

    /// Generate a fingerprint directly from headers
    pub fn generate_from_headers(&self, headers: &HeaderMap, ip: Option<IpAddr>) -> Option<String> {
        let components = FingerprintComponents::from_headers(headers);
        self.generate(&components, ip)
    }

    /// Generate a fingerprint with IP included
    pub fn generate_with_ip(&self, headers: &HeaderMap, ip: IpAddr) -> Option<String> {
        let components = FingerprintComponents::from_headers(headers);
        self.generate(&components, Some(ip))
    }

    /// Generate a simple fingerprint (user-agent + IP only)
    pub fn generate_simple(&self, user_agent: &str, ip: Option<IpAddr>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"ua:");
        hasher.update(user_agent.as_bytes());

        if let Some(ip_addr) = ip {
            hasher.update(b"|ip:");
            hasher.update(ip_addr.to_string().as_bytes());
        }

        let hash = hasher.finalize();
        hex::encode(&hash[..16])
    }

    /// Compare two fingerprints and return similarity score (0.0 - 1.0)
    /// 1.0 = exact match, 0.0 = completely different
    pub fn compare(&self, fp1: &str, fp2: &str) -> f64 {
        if fp1 == fp2 {
            return 1.0;
        }

        // For partial matching, we could implement fuzzy comparison
        // For now, exact match required
        0.0
    }

    /// Check if a fingerprint is valid (not empty, proper length)
    pub fn is_valid(&self, fingerprint: &str) -> bool {
        !fingerprint.is_empty() && fingerprint.len() == 32
    }
}

/// Extract a header value as string
fn get_header_value(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Extract an optional header value
fn get_header_opt(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Parse device info from user agent string
pub fn parse_device_info(user_agent: &str) -> ParsedDeviceInfo {
    let ua = user_agent.to_lowercase();

    // Detect device type
    let device_type = if ua.contains("mobile") || ua.contains("iphone") || ua.contains("android") {
        "mobile"
    } else if ua.contains("tablet") || ua.contains("ipad") {
        "tablet"
    } else {
        "desktop"
    };

    // Detect OS
    let os = if ua.contains("windows") {
        "Windows"
    } else if ua.contains("ios") || ua.contains("iphone") || ua.contains("ipad") {
        "iOS"
    } else if ua.contains("macintosh") || ua.contains("mac os") {
        "macOS"
    } else if ua.contains("linux") {
        "Linux"
    } else if ua.contains("android") {
        "Android"
    } else {
        "Unknown"
    };

    // Detect browser
    let browser = if ua.contains("firefox") && !ua.contains("seammonkey") {
        "Firefox"
    } else if ua.contains("seammonkey") {
        "Seamonkey"
    } else if ua.contains("chrome") && !ua.contains("chromium") && !ua.contains("edg") {
        "Chrome"
    } else if ua.contains("chromium") {
        "Chromium"
    } else if ua.contains("safari") && !ua.contains("chrome") && !ua.contains("chromium") {
        "Safari"
    } else if ua.contains("edg") {
        "Edge"
    } else if ua.contains("opera") || ua.contains("opr") {
        "Opera"
    } else {
        "Unknown"
    };

    ParsedDeviceInfo {
        device_type: device_type.to_string(),
        os: os.to_string(),
        browser: browser.to_string(),
        is_mobile: device_type == "mobile",
    }
}

/// Parsed device information
#[derive(Debug, Clone)]
pub struct ParsedDeviceInfo {
    pub device_type: String,
    pub os: String,
    pub browser: String,
    pub is_mobile: bool,
}

impl ParsedDeviceInfo {
    /// Get a human-readable device description
    pub fn description(&self) -> String {
        format!("{} on {} ({})", self.browser, self.os, self.device_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn create_test_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0"),
        );
        headers.insert(
            "accept",
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        headers.insert(
            "accept-language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert(
            "accept-encoding",
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers
    }

    #[test]
    fn test_fingerprint_components_from_headers() {
        let headers = create_test_headers();
        let components = FingerprintComponents::from_headers(&headers);

        assert!(!components.user_agent.is_empty());
        assert!(!components.accept.is_empty());
        assert!(!components.accept_language.is_empty());
    }

    #[test]
    fn test_device_fingerprinter_generate() {
        let fingerprinter = DeviceFingerprinter::new();
        let components = FingerprintComponents {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
            accept_language: "en-US".to_string(),
            accept: "text/html".to_string(),
            ..Default::default()
        };

        let fingerprint = fingerprinter.generate(&components, None);
        assert!(fingerprint.is_some());

        let fp = fingerprint.unwrap();
        assert_eq!(fp.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_fingerprint_consistency() {
        let fingerprinter = DeviceFingerprinter::new();
        let components = FingerprintComponents {
            user_agent: "Test UA".to_string(),
            accept_language: "en".to_string(),
            ..Default::default()
        };

        let fp1 = fingerprinter.generate(&components, None).unwrap();
        let fp2 = fingerprinter.generate(&components, None).unwrap();

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_different_components() {
        let fingerprinter = DeviceFingerprinter::new();

        let components1 = FingerprintComponents {
            user_agent: "UA1".to_string(),
            accept_language: "en".to_string(),
            ..Default::default()
        };

        let components2 = FingerprintComponents {
            user_agent: "UA2".to_string(),
            accept_language: "en".to_string(),
            ..Default::default()
        };

        let fp1 = fingerprinter.generate(&components1, None).unwrap();
        let fp2 = fingerprinter.generate(&components2, None).unwrap();

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_insufficient_components() {
        let fingerprinter = DeviceFingerprinter::new();
        let components = FingerprintComponents {
            user_agent: "".to_string(),
            accept_language: "".to_string(),
            ..Default::default()
        };

        let fingerprint = fingerprinter.generate(&components, None);
        assert!(fingerprint.is_none());
    }

    #[test]
    fn test_parse_device_info() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.0";
        let info = parse_device_info(ua);

        assert_eq!(info.device_type, "desktop");
        assert_eq!(info.os, "Windows");
        assert_eq!(info.browser, "Chrome");
        assert!(!info.is_mobile);
    }

    #[test]
    fn test_parse_mobile_device() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";
        let info = parse_device_info(ua);

        assert_eq!(info.device_type, "mobile");
        assert_eq!(info.os, "iOS");
        assert!(info.is_mobile);
    }

    #[test]
    fn test_fingerprint_with_ip() {
        let fingerprinter = DeviceFingerprinter::strict();
        let components = FingerprintComponents {
            user_agent: "Test".to_string(),
            accept: "text/html".to_string(),
            accept_language: "en".to_string(),
            screen_resolution: Some("1920x1080".to_string()),
            canvas_hash: Some("canvas-hash".to_string()),
            ..Default::default()
        };

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let fp1 = fingerprinter.generate(&components, Some(ip)).unwrap();
        let fp2 = fingerprinter.generate(&components, None);

        // With strict mode, IP is required
        assert!(fp2.is_none() || fp1 != fp2.unwrap());
    }
}
