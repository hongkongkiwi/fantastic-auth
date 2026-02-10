//! AI Security Middleware
//!
//! Provides Axum middleware for AI-powered security:
//! - Real-time risk scoring on authentication
//! - Automatic threat detection and blocking
//! - Behavioral analysis integration
//! - Step-up authentication triggers

use std::net::IpAddr;

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use tracing::{debug, info, warn};

use vault_core::ai::{
    Action, AuthContext, BehavioralData, RiskDecision, RiskLevel,
};
use vault_core::ai::features::AuthMethod;

use crate::routes::ApiError;
use crate::state::AppState;

/// AI Security middleware layer
///
/// This middleware analyzes authentication requests in real-time and:
/// - Calculates risk scores
/// - Detects anomalies
/// - Triggers step-up authentication when needed
/// - Blocks high-risk requests
pub async fn ai_security_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Skip AI checks for non-auth endpoints if configured
    let path = request.uri().path();
    if should_skip_ai_check(path) {
        return Ok(next.run(request).await);
    }

    // Check if AI engine is available
    let ai_engine = match &state.ai_engine {
        Some(engine) => engine,
        None => {
            // AI not available, continue normally
            return Ok(next.run(request).await);
        }
    };

    // Build auth context from request
    let auth_context = build_auth_context(&state, &request, addr.ip()).await?;

    // Evaluate the authentication attempt
    let user_id = extract_user_id(&request);
    
    match ai_engine.evaluate_auth_attempt(user_id.as_deref(), &auth_context).await {
        Ok(decision) => {
            // Log the decision
            log_risk_decision(&decision, path);

            // Handle based on decision
            match decision.action {
                Action::Allow => {
                    // Continue with request
                    Ok(next.run(request).await)
                }
                Action::StepUp => {
                    // Add step-up header but continue
                    let response = next.run(request).await;
                    let (parts, body) = response.into_parts();
                    
                    let mut response = Response::from_parts(parts, body);
                    response.headers_mut().insert(
                        "X-Step-Up-Required",
                        "true".parse().unwrap(),
                    );
                    
                    Ok(response)
                }
                Action::RequireMfa => {
                    // Return 403 with MFA requirement
                    Err(ApiError::mfa_required(
                        "Additional verification required due to risk assessment",
                    ))
                }
                Action::Block => {
                    // Log blocked attempt
                    warn!(
                        "Blocked authentication attempt from {} due to high risk (score: {})",
                        addr.ip(),
                        decision.score
                    );

                    // Return 403
                    Err(ApiError::forbidden(
                        "Authentication blocked due to security concerns",
                    ))
                }
            }
        }
        Err(e) => {
            // AI evaluation failed, log but don't block
            warn!("AI risk evaluation failed: {}", e);
            Ok(next.run(request).await)
        }
    }
}

/// AI Security middleware with behavioral biometrics
///
/// Enhanced version that also captures and analyzes behavioral data
pub async fn ai_security_with_biometrics_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let path = request.uri().path();
    
    // Skip non-auth endpoints
    if should_skip_ai_check(path) {
        return Ok(next.run(request).await);
    }

    // Extract behavioral data from headers if present
    let behavioral_data = extract_behavioral_data(&request);
    
    // Store in request extensions for later use
    if let Some(ref data) = behavioral_data {
        request.extensions_mut().insert(data.clone());
    }

    // Continue with standard AI security check
    ai_security_middleware(State(state), ConnectInfo(addr), request, next).await
}

/// Build authentication context from HTTP request
async fn build_auth_context(
    _state: &AppState,
    request: &Request,
    ip: IpAddr,
) -> Result<AuthContext, ApiError> {
    let headers = request.headers();
    
    // Extract user agent
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract device fingerprint
    let device_fingerprint = headers
        .get("x-device-fingerprint")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract tenant ID
    let tenant_id = headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default")
        .to_string();

    // Determine auth method from path/content
    let auth_method = determine_auth_method(request.uri().path());

    // Build headers map
    let mut headers_map = std::collections::HashMap::new();
    for (key, value) in headers.iter() {
        if let Ok(val) = value.to_str() {
            headers_map.insert(key.to_string(), val.to_string());
        }
    }

    let context = AuthContext {
        user_id: None, // Will be set after authentication
        ip_address: Some(ip),
        user_agent,
        device_fingerprint,
        timestamp: chrono::Utc::now(),
        geo_location: None, // Would be determined from IP
        country_code: None,
        is_anonymous_ip: false, // Would be checked against threat intel
        is_hosting_provider: false,
        previous_location: None,
        previous_login_at: None,
        failed_attempts: 0,
        successful_attempts: 0,
        mfa_used: false,
        tenant_id,
        behavioral_data: None,
        headers: headers_map,
        session_id: None,
        auth_method,
    };

    Ok(context)
}

/// Determine authentication method from request path
fn determine_auth_method(path: &str) -> AuthMethod {
    if path.contains("/oauth") {
        AuthMethod::OAuth
    } else if path.contains("/webauthn") {
        AuthMethod::WebAuthn
    } else if path.contains("/mfa") || path.contains("/totp") {
        AuthMethod::Totp
    } else if path.contains("/magic-link") {
        AuthMethod::MagicLink
    } else if path.contains("/biometric") {
        AuthMethod::Biometric
    } else if path.contains("/api-key") {
        AuthMethod::ApiKey
    } else {
        AuthMethod::Password
    }
}

/// Extract user ID from request (if available in token/session)
fn extract_user_id(request: &Request) -> Option<String> {
    // Check for authorization header
    if let Some(auth) = request.headers().get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            // Extract from Bearer token (simplified)
            if auth_str.starts_with("Bearer ") {
                // In production, would decode JWT and extract sub claim
                return None;
            }
        }
    }

    // Check for session cookie
    // In production, would look up session
    None
}

/// Extract behavioral data from request headers
fn extract_behavioral_data(request: &Request) -> Option<BehavioralData> {
    let headers = request.headers();
    
    // Check for behavioral data header
    let behavioral_header = headers.get("x-behavioral-data")?;
    let behavioral_str = behavioral_header.to_str().ok()?;
    
    // Parse behavioral data
    serde_json::from_str(behavioral_str).ok()
}

/// Check if path should skip AI security checks
fn should_skip_ai_check(path: &str) -> bool {
    // Skip health checks and static assets
    if path == "/health" || path.starts_with("/static/") || path.starts_with("/assets/") {
        return true;
    }

    // Skip admin endpoints that are already protected
    if path.starts_with("/admin/ai/") {
        return true;
    }

    // Skip webhooks (they have their own validation)
    if path.starts_with("/webhooks/") {
        return true;
    }

    // Skip OIDC discovery endpoints
    if path == "/.well-known/openid-configuration" || path == "/oauth/jwks" {
        return true;
    }

    false
}

/// Log risk decision for monitoring
fn log_risk_decision(decision: &RiskDecision, path: &str) {
    match decision.risk_level {
        RiskLevel::Low => {
            debug!(
                "Low risk auth attempt to {} (score: {})",
                path, decision.score
            );
        }
        RiskLevel::Medium => {
            info!(
                "Medium risk auth attempt to {} (score: {}, action: {:?})",
                path, decision.score, decision.action
            );
        }
        RiskLevel::High => {
            warn!(
                "High risk auth attempt to {} (score: {}, action: {:?})",
                path, decision.score, decision.action
            );
        }
        RiskLevel::Critical => {
            warn!(
                "CRITICAL risk auth attempt to {} (score: {}, BLOCKED)",
                path, decision.score
            );
        }
    }
}

/// Middleware factory for AI security
pub struct AiSecurityMiddleware;

impl AiSecurityMiddleware {
    /// Create new AI security middleware
    pub fn new() -> Self {
        Self
    }
}

impl Default for AiSecurityMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiting response for high-risk clients
#[derive(Debug, serde::Serialize)]
struct RateLimitResponse {
    error: String,
    retry_after: u64,
    risk_score: u8,
}

/// Check if IP should be rate limited based on risk
async fn should_rate_limit(
    _state: &AppState,
    _ip: IpAddr,
    _user_id: Option<&str>,
) -> Option<u64> {
    // In production, would check recent risk scores for IP/user
    // and return retry_after seconds if rate limited
    None
}

/// Error response for blocked requests
#[derive(Debug, serde::Serialize)]
struct BlockedResponse {
    error: String,
    error_code: String,
    risk_score: u8,
    factors: Vec<String>,
    support_url: Option<String>,
}

impl IntoResponse for BlockedResponse {
    fn into_response(self) -> Response {
        let body = serde_json::to_string(&self).unwrap_or_default();
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }
}

/// Challenge response for step-up auth
#[derive(Debug, serde::Serialize)]
struct ChallengeResponse {
    error: String,
    error_code: String,
    challenge_type: String,
    challenge_url: String,
}

impl IntoResponse for ChallengeResponse {
    fn into_response(self) -> Response {
        let body = serde_json::to_string(&self).unwrap_or_default();
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Uri;

    #[test]
    fn test_determine_auth_method() {
        assert_eq!(
            determine_auth_method("/oauth/authorize"),
            AuthMethod::OAuth
        );
        assert_eq!(
            determine_auth_method("/webauthn/register"),
            AuthMethod::WebAuthn
        );
        assert_eq!(
            determine_auth_method("/mfa/verify"),
            AuthMethod::Totp
        );
        assert_eq!(
            determine_auth_method("/auth/login"),
            AuthMethod::Password
        );
    }

    #[test]
    fn test_should_skip_ai_check() {
        assert!(should_skip_ai_check("/health"));
        assert!(should_skip_ai_check("/static/main.css"));
        assert!(should_skip_ai_check("/admin/ai/status"));
        assert!(should_skip_ai_check("/.well-known/openid-configuration"));
        assert!(!should_skip_ai_check("/auth/login"));
        assert!(!should_skip_ai_check("/api/v1/users"));
    }
}
