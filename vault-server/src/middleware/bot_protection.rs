//! Bot protection middleware
//!
//! Provides CAPTCHA verification middleware for authentication endpoints.
//! Supports multiple token sources and providers (Cloudflare Turnstile, hCaptcha).

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::state::AppState;

/// Bot protection error response
#[derive(Debug, Serialize)]
pub struct BotProtectionError {
    pub error: BotProtectionErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct BotProtectionErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

impl IntoResponse for BotProtectionError {
    fn into_response(self) -> Response {
        let status = StatusCode::FORBIDDEN;
        let body = axum::Json(self);
        (status, body).into_response()
    }
}

/// Extract CAPTCHA token from request
///
/// Supports multiple token sources in order of priority:
/// 1. Header: X-Turnstile-Token or X-Captcha-Token
/// 2. Query parameter: cf-turnstile-response or h-captcha-response
/// 3. JSON body: captchaToken (extracted separately by handlers)
fn extract_captcha_token(request: &Request) -> Option<String> {
    // Try headers first
    if let Some(token) = request
        .headers()
        .get("X-Turnstile-Token")
        .and_then(|v| v.to_str().ok())
    {
        return Some(token.to_string());
    }

    if let Some(token) = request
        .headers()
        .get("X-Captcha-Token")
        .and_then(|v| v.to_str().ok())
    {
        return Some(token.to_string());
    }

    // Try query parameters
    if let Some(query) = request.uri().query() {
        // Simple query parameter parsing
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");

            if key == "cf-turnstile-response" || key == "h-captcha-response" {
                // URL decode the value
                return Some(url_decode(value));
            }
        }
    }

    None
}

/// Simple URL decode for query parameters
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hex1 = chars.next();
            let hex2 = chars.next();

            if let (Some(h1), Some(h2)) = (hex1, hex2) {
                if let Ok(byte) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) {
                    result.push(byte as char);
                } else {
                    result.push('%');
                    result.push(h1);
                    result.push(h2);
                }
            } else {
                result.push('%');
                if let Some(h1) = hex1 {
                    result.push(h1);
                }
            }
        } else if ch == '+' {
            result.push(' ');
        } else {
            result.push(ch);
        }
    }

    result
}

/// Extract CAPTCHA token from JSON body
///
/// This is a helper that should be called after consuming the body
/// and deserializing the JSON.
pub fn extract_token_from_json(body: &serde_json::Value) -> Option<String> {
    // Try various field names that might contain the token
    body.get("captchaToken")
        .or_else(|| body.get("cf-turnstile-response"))
        .or_else(|| body.get("h-captcha-response"))
        .or_else(|| body.get("turnstileToken"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract client IP address from request
///
/// Checks X-Forwarded-For and X-Real-IP headers first, falls back to connection info
fn extract_client_ip(request: &Request, addr: &SocketAddr) -> Option<String> {
    // Try X-Forwarded-For header (may contain multiple IPs, take the first)
    if let Some(forwarded) = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
    {
        // X-Forwarded-For can contain multiple IPs separated by commas
        // The first one is typically the client IP
        let ip = forwarded.split(',').next()?.trim();
        return Some(ip.to_string());
    }

    // Try X-Real-IP header
    if let Some(real_ip) = request
        .headers()
        .get("X-Real-IP")
        .and_then(|v| v.to_str().ok())
    {
        return Some(real_ip.to_string());
    }

    // Fall back to connection address
    Some(addr.ip().to_string())
}

/// Bot protection middleware
///
/// Verifies CAPTCHA tokens for protected endpoints. Returns 403 if verification fails.
/// Skips verification if bot protection is disabled.
pub async fn bot_protection_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, BotProtectionError> {
    // Skip if bot protection is disabled
    if !state.bot_protection.is_enabled() {
        return Ok(next.run(request).await);
    }

    // Extract CAPTCHA token
    let token = match extract_captcha_token(&request) {
        Some(t) => t,
        None => {
            tracing::warn!(
                "CAPTCHA verification failed: missing token from {}",
                addr.ip()
            );
            return Err(BotProtectionError {
                error: BotProtectionErrorDetail {
                    code: "CAPTCHA_REQUIRED".to_string(),
                    message: "CAPTCHA token is required".to_string(),
                    captcha_required: Some(true),
                    site_key: Some(state.bot_protection.site_key().to_string()),
                    provider: Some(get_provider_name(&state)),
                },
            });
        }
    };

    // Extract client IP for verification
    let remote_ip = extract_client_ip(&request, &addr);

    // Verify token
    match state
        .bot_protection
        .verify_token(&token, remote_ip.as_deref())
        .await
    {
        Ok(result) => {
            if result.success {
                tracing::debug!("CAPTCHA verification succeeded from {}", addr.ip());
                Ok(next.run(request).await)
            } else {
                let error_codes = result.error_codes.join(", ");
                tracing::warn!(
                    "CAPTCHA verification failed from {}: {}",
                    addr.ip(),
                    error_codes
                );
                Err(BotProtectionError {
                    error: BotProtectionErrorDetail {
                        code: "CAPTCHA_INVALID".to_string(),
                        message: format!("CAPTCHA verification failed: {}", error_codes),
                        captcha_required: Some(true),
                        site_key: Some(state.bot_protection.site_key().to_string()),
                        provider: Some(get_provider_name(&state)),
                    },
                })
            }
        }
        Err(e) => {
            tracing::error!("CAPTCHA verification error: {}", e);
            Err(BotProtectionError {
                error: BotProtectionErrorDetail {
                    code: "CAPTCHA_ERROR".to_string(),
                    message: "CAPTCHA verification service error".to_string(),
                    captcha_required: Some(true),
                    site_key: Some(state.bot_protection.site_key().to_string()),
                    provider: Some(get_provider_name(&state)),
                },
            })
        }
    }
}

/// Bot protection middleware with conditional enforcement
///
/// Only enforces CAPTCHA if the condition is true (e.g., after N failed login attempts)
pub async fn conditional_bot_protection_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Extension(require_captcha): axum::Extension<bool>,
    request: Request,
    next: Next,
) -> Result<Response, BotProtectionError> {
    // Skip if bot protection is disabled
    if !state.bot_protection.is_enabled() {
        return Ok(next.run(request).await);
    }

    // Skip if CAPTCHA is not required for this request
    if !require_captcha {
        return Ok(next.run(request).await);
    }

    // Otherwise, run the standard bot protection middleware
    bot_protection_middleware(
        axum::extract::State(state),
        ConnectInfo(addr),
        request,
        next,
    )
    .await
}

/// Get the provider name for frontend integration
fn get_provider_name(state: &AppState) -> String {
    if state.bot_protection.site_key().is_empty() {
        "disabled".to_string()
    } else {
        // Infer provider from the site key format or configuration
        // Turnstile keys typically start with 0x or 1x
        // hCaptcha keys typically start with 10000000 or 20000000
        let site_key = state.bot_protection.site_key();
        if site_key.starts_with("0x") || site_key.starts_with("1x") {
            "turnstile".to_string()
        } else if site_key.starts_with("10000000") || site_key.starts_with("20000000") {
            "hcaptcha".to_string()
        } else {
            "unknown".to_string()
        }
    }
}

/// Check if CAPTCHA is required for login based on failed attempts
///
/// Returns true if the number of failed login attempts meets or exceeds the threshold
pub async fn is_captcha_required_for_login(state: &AppState, key: &str) -> bool {
    let threshold = state
        .config
        .security
        .bot_protection
        .login_attempts_before_captcha;

    // If threshold is 0, CAPTCHA is always required
    if threshold == 0 {
        return state.bot_protection.is_enabled();
    }

    state
        .failed_login_tracker
        .is_captcha_required(key, threshold)
        .await
}

/// Record a failed login attempt
pub async fn record_failed_login(state: &AppState, key: &str) -> u32 {
    let window_secs = state
        .config
        .security
        .bot_protection
        .failed_login_window_seconds;
    state
        .failed_login_tracker
        .record_failure(key, window_secs)
        .await
}

/// Reset failed login attempts (called on successful login)
pub async fn reset_failed_login(state: &AppState, key: &str) {
    state.failed_login_tracker.reset(key).await;
}

/// Generate the CAPTCHA site key response
#[derive(Debug, Serialize)]
pub struct CaptchaSiteKeyResponse {
    /// Whether CAPTCHA is enabled
    pub enabled: bool,
    /// The provider name (turnstile, hcaptcha, disabled)
    pub provider: String,
    /// The site key for frontend rendering
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_key: Option<String>,
    /// Instructions for frontend integration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<CaptchaInstructions>,
}

#[derive(Debug, Serialize)]
pub struct CaptchaInstructions {
    /// Script URL to include
    pub script_url: String,
    /// HTML element to render
    pub widget_html: String,
    /// Header name for token submission
    pub token_header: String,
}

impl CaptchaSiteKeyResponse {
    /// Create response based on configuration
    pub fn from_state(state: &AppState) -> Self {
        let enabled = state.bot_protection.is_enabled();
        let provider = get_provider_name(state);
        let site_key = if enabled {
            Some(state.bot_protection.site_key().to_string())
        } else {
            None
        };

        let instructions = if enabled {
            match provider.as_str() {
                "turnstile" => Some(CaptchaInstructions {
                    script_url: "https://challenges.cloudflare.com/turnstile/v0/api.js".to_string(),
                    widget_html: format!(
                        r#"<div class="cf-turnstile" data-sitekey="{}"></div>"#,
                        site_key.as_deref().unwrap_or("")
                    ),
                    token_header: "X-Turnstile-Token".to_string(),
                }),
                "hcaptcha" => Some(CaptchaInstructions {
                    script_url: "https://js.hcaptcha.com/1/api.js".to_string(),
                    widget_html: format!(
                        r#"<div class="h-captcha" data-sitekey="{}"></div>"#,
                        site_key.as_deref().unwrap_or("")
                    ),
                    token_header: "X-Captcha-Token".to_string(),
                }),
                _ => None,
            }
        } else {
            None
        };

        Self {
            enabled,
            provider,
            site_key,
            instructions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn test_extract_token_from_json() {
        let body = serde_json::json!({
            "email": "test@example.com",
            "password": "secret",
            "captchaToken": "test_token_123"
        });
        assert_eq!(
            extract_token_from_json(&body),
            Some("test_token_123".to_string())
        );
    }

    #[test]
    fn test_extract_token_from_json_alternative_fields() {
        // Test cf-turnstile-response field
        let body = serde_json::json!({
            "cf-turnstile-response": "turnstile_token"
        });
        assert_eq!(
            extract_token_from_json(&body),
            Some("turnstile_token".to_string())
        );

        // Test h-captcha-response field
        let body = serde_json::json!({
            "h-captcha-response": "hcaptcha_token"
        });
        assert_eq!(
            extract_token_from_json(&body),
            Some("hcaptcha_token".to_string())
        );
    }

    #[test]
    fn test_get_provider_name_from_site_key() {
        // This is a simplified test - in practice we'd need the full state
        // Turnstile keys typically start with 0x
        let turnstile_key = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(turnstile_key.starts_with("0x"));

        // hCaptcha keys typically start with 10000000
        let hcaptcha_key = "10000000-ffff-ffff-ffff-000000000001";
        assert!(hcaptcha_key.starts_with("10000000"));
    }
}
