//! Observability - Logging, Tracing, and Metrics
//!
//! Provides:
//! - Structured JSON logging
//! - Request/response logging
//! - Performance metrics tracking

use axum::{body::Body, extract::Request, middleware::Next, response::Response};
use std::time::Instant;
use tracing::{info_span, Instrument};
use tracing_subscriber::Layer;

/// Initialize observability (logging)
pub fn init(config: &crate::config::ObservabilityConfig) {
    init_tracing(config);
}

/// Initialize structured logging
fn init_tracing(config: &crate::config::ObservabilityConfig) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    // JSON format for production, pretty for development
    let json_format = !cfg!(debug_assertions);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true);

    let fmt_layer = if json_format {
        fmt_layer.json().flatten_event(true).boxed()
    } else {
        fmt_layer.pretty().boxed()
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.otel_service_name));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

/// Shutdown observability
pub fn shutdown() {
    // Flush any pending logs
    tracing::info!("Shutting down observability");
}

/// Request tracing middleware
pub async fn trace_request(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let request_id = generate_request_id();

    // Extract relevant headers for tracing
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    let client_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Create span for request
    let span = info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        uri = %uri.path(),
        client_ip = %client_ip,
        user_agent = %user_agent,
    );

    // Process request within span
    let response = next.run(request).instrument(span.clone()).await;

    // Calculate duration
    let duration = start.elapsed();
    let status = response.status().as_u16();

    // Log completion
    if status >= 500 {
        tracing::error!(parent: &span, status = status, duration_ms = duration.as_millis() as u64, "request_complete");
    } else if status >= 400 {
        tracing::warn!(parent: &span, status = status, duration_ms = duration.as_millis() as u64, "request_complete");
    } else {
        tracing::info!(parent: &span, status = status, duration_ms = duration.as_millis() as u64, "request_complete");
    }

    // Add request ID to response
    let mut response = response;
    response
        .headers_mut()
        .insert("x-request-id", request_id.parse().unwrap());

    response
}

/// Generate unique request ID
fn generate_request_id() -> String {
    use uuid::Uuid;
    Uuid::new_v4().to_string()
}

/// Log authentication events
pub fn log_auth_event(event: AuthEvent) {
    match event {
        AuthEvent::LoginSuccess {
            user_id,
            email,
            ip,
            method,
        } => {
            tracing::info!(
                event = "login_success",
                user_id = %user_id,
                email = %email,
                ip = %ip,
                method = %method,
                "User logged in successfully"
            );
        }
        AuthEvent::LoginFailed { email, ip, reason } => {
            tracing::warn!(
                event = "login_failed",
                email = %email,
                ip = %ip,
                reason = %reason,
                "Login attempt failed"
            );
        }
        AuthEvent::Logout {
            user_id,
            session_id,
        } => {
            tracing::info!(
                event = "logout",
                user_id = %user_id,
                session_id = %session_id,
                "User logged out"
            );
        }
        AuthEvent::TokenRefresh {
            user_id,
            session_id,
        } => {
            tracing::debug!(
                event = "token_refresh",
                user_id = %user_id,
                session_id = %session_id,
                "Token refreshed"
            );
        }
        AuthEvent::PasswordChanged { user_id } => {
            tracing::info!(
                event = "password_changed",
                user_id = %user_id,
                "User changed password"
            );
        }
        AuthEvent::MfaEnabled { user_id, method } => {
            tracing::info!(
                event = "mfa_enabled",
                user_id = %user_id,
                method = %method,
                "MFA enabled for user"
            );
        }
        AuthEvent::SuspiciousActivity {
            user_id,
            activity,
            ip,
        } => {
            tracing::warn!(
                event = "suspicious_activity",
                user_id = %user_id,
                activity = %activity,
                ip = %ip,
                "Suspicious activity detected"
            );
        }
    }
}

/// Authentication events for audit logging
#[derive(Debug)]
pub enum AuthEvent {
    LoginSuccess {
        user_id: String,
        email: String,
        ip: String,
        method: String,
    },
    LoginFailed {
        email: String,
        ip: String,
        reason: String,
    },
    Logout {
        user_id: String,
        session_id: String,
    },
    TokenRefresh {
        user_id: String,
        session_id: String,
    },
    PasswordChanged {
        user_id: String,
    },
    MfaEnabled {
        user_id: String,
        method: String,
    },
    SuspiciousActivity {
        user_id: String,
        activity: String,
        ip: String,
    },
}

/// Performance metrics tracking
pub struct Metrics;

impl Metrics {
    /// Record database query duration
    pub fn record_db_query(operation: &str, table: &str, duration: std::time::Duration) {
        tracing::debug!(
            metric = "db_query_duration",
            operation = %operation,
            table = %table,
            duration_ms = duration.as_millis() as u64,
        );
    }

    /// Record cache operation
    pub fn record_cache_hit(key: &str) {
        tracing::debug!(
            metric = "cache_hit",
            key_prefix = %key.split(':').next().unwrap_or("unknown"),
        );
    }

    pub fn record_cache_miss(key: &str) {
        tracing::debug!(
            metric = "cache_miss",
            key_prefix = %key.split(':').next().unwrap_or("unknown"),
        );
    }

    /// Record rate limit event
    pub fn record_rate_limit(key: &str, limit: u32) {
        tracing::warn!(
            metric = "rate_limit_exceeded",
            key = %key,
            limit = limit,
            "Rate limit exceeded"
        );
    }

    /// Record email sent
    pub fn record_email_sent(template: &str, recipient: &str) {
        tracing::info!(
            metric = "email_sent",
            template = %template,
            recipient_domain = %recipient.split('@').nth(1).unwrap_or("unknown"),
        );
    }

    /// Record failed email
    pub fn record_email_failed(template: &str, error: &str) {
        tracing::error!(
            metric = "email_failed",
            template = %template,
            error = %error,
            "Failed to send email"
        );
    }
}
