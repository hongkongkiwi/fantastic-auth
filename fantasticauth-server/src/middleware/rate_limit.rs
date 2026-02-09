//! Rate limiting middleware

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;

use crate::state::AppState;
use crate::state::{CurrentUser, TenantContext};

/// Rate limit key type
#[derive(Debug, Clone, Copy)]
pub enum RateLimitKey {
    /// IP address
    Ip,
    /// User ID (if authenticated)
    User,
    /// Custom key
    Custom(&'static str),
}

/// Rate limiting middleware builder
#[derive(Clone)]
pub struct RateLimit {
    /// Requests allowed per window
    pub requests: u32,
    /// Window size in seconds
    pub window_secs: u64,
    /// Key type for rate limiting
    pub key_type: RateLimitKey,
}

impl RateLimit {
    /// Create new rate limit configuration
    pub fn new(requests: u32, window_secs: u64) -> Self {
        Self {
            requests,
            window_secs,
            key_type: RateLimitKey::Ip,
        }
    }

    /// Use user ID as key
    pub fn per_user(mut self) -> Self {
        self.key_type = RateLimitKey::User;
        self
    }

    /// Use IP address as key
    pub fn per_ip(mut self) -> Self {
        self.key_type = RateLimitKey::Ip;
        self
    }

    /// Use custom key
    pub fn custom(mut self, key: &'static str) -> Self {
        self.key_type = RateLimitKey::Custom(key);
        self
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get rate limit config from request extensions
    let rate_limit = request
        .extensions()
        .get::<RateLimit>()
        .cloned()
        .unwrap_or_else(|| {
            // Default rate limit
            RateLimit::new(
                state.config.rate_limit.api_per_minute,
                state.config.rate_limit.window_seconds,
            )
        });

    // Build rate limit key
    let tenant_prefix = if let Some(user) = request.extensions().get::<CurrentUser>() {
        Some(user.tenant_id.clone())
    } else if let Some(tenant) = request.extensions().get::<TenantContext>() {
        Some(tenant.tenant_id.clone())
    } else {
        None
    };

    let raw_key = match rate_limit.key_type {
        RateLimitKey::Ip => format!("ip:{}", addr.ip()),
        RateLimitKey::User => {
            // Try to get user ID from extensions
            if let Some(user) = request.extensions().get::<crate::state::CurrentUser>() {
                format!("user:{}", user.user_id)
            } else {
                // Fall back to IP if no user
                format!("ip:{}", addr.ip())
            }
        }
        RateLimitKey::Custom(k) => format!("custom:{}:{}", k, addr.ip()),
    };

    let key = if let Some(tenant_id) = tenant_prefix {
        format!("tenant:{}:{}", tenant_id, raw_key)
    } else {
        raw_key
    };

    // Check rate limit
    let allowed = state
        .rate_limiter
        .is_allowed(&key, rate_limit.requests, rate_limit.window_secs)
        .await;

    if !allowed {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

/// Rate limiting middleware for auth endpoints (stricter)
pub async fn auth_rate_limit_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let tenant_prefix = if let Some(user) = request.extensions().get::<CurrentUser>() {
        Some(user.tenant_id.clone())
    } else if let Some(tenant) = request.extensions().get::<TenantContext>() {
        Some(tenant.tenant_id.clone())
    } else {
        None
    };

    let raw_key = format!("auth:ip:{}", addr.ip());
    let key = if let Some(tenant_id) = tenant_prefix {
        format!("tenant:{}:{}", tenant_id, raw_key)
    } else {
        raw_key
    };

    let allowed = state
        .rate_limiter
        .is_allowed(
            &key,
            state.config.rate_limit.auth_per_minute,
            state.config.rate_limit.window_seconds,
        )
        .await;

    if !allowed {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_builder() {
        let rl = RateLimit::new(10, 60).per_user();
        assert_eq!(rl.requests, 10);
        assert_eq!(rl.window_secs, 60);
        matches!(rl.key_type, RateLimitKey::User);
    }
}
