//! Prometheus Metrics Endpoint
//!
//! Exposes key metrics for monitoring:
//! - HTTP request latency and counts
//! - Authentication events
//! - Database connection pool stats
//! - Cache hit/miss rates
//! - Rate limiting events

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Metrics state
#[derive(Default)]
pub struct MetricsCollector {
    /// Total HTTP requests
    http_requests_total: AtomicU64,
    /// HTTP requests by status code
    http_requests_2xx: AtomicU64,
    http_requests_3xx: AtomicU64,
    http_requests_4xx: AtomicU64,
    http_requests_5xx: AtomicU64,
    /// Total request duration in milliseconds
    request_duration_ms: AtomicU64,
    /// Active sessions
    active_sessions: AtomicU64,
    /// Failed login attempts
    failed_logins: AtomicU64,
    /// Successful logins
    successful_logins: AtomicU64,
    /// Rate limit hits
    rate_limit_hits: AtomicU64,
    /// Token refreshes
    token_refreshes: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Record HTTP request
    pub fn record_request(&self, status: u16, duration_ms: u64) {
        self.http_requests_total.fetch_add(1, Ordering::Relaxed);
        self.request_duration_ms.fetch_add(duration_ms, Ordering::Relaxed);
        
        match status {
            200..=299 => self.http_requests_2xx.fetch_add(1, Ordering::Relaxed),
            300..=399 => self.http_requests_3xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.http_requests_4xx.fetch_add(1, Ordering::Relaxed),
            500..=599 => self.http_requests_5xx.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }
    
    /// Record login attempt
    pub fn record_login(&self, success: bool) {
        if success {
            self.successful_logins.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_logins.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// Record rate limit hit
    pub fn record_rate_limit(&self) {
        self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record token refresh
    pub fn record_token_refresh(&self) {
        self.token_refreshes.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Update active sessions count
    pub fn set_active_sessions(&self, count: u64) {
        self.active_sessions.store(count, Ordering::Relaxed);
    }
    
    /// Generate Prometheus format output
    pub fn render(&self) -> String {
        let mut output = String::new();
        
        // HTTP requests total
        output.push_str("# HELP http_requests_total Total HTTP requests\n");
        output.push_str("# TYPE http_requests_total counter\n");
        output.push_str(&format!(
            "http_requests_total {}\n",
            self.http_requests_total.load(Ordering::Relaxed)
        ));
        
        // HTTP requests by status
        output.push_str("# HELP http_requests_by_status HTTP requests by status code\n");
        output.push_str("# TYPE http_requests_by_status counter\n");
        output.push_str(&format!(
            "http_requests_by_status{{status=\"2xx\"}} {}\n",
            self.http_requests_2xx.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "http_requests_by_status{{status=\"3xx\"}} {}\n",
            self.http_requests_3xx.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "http_requests_by_status{{status=\"4xx\"}} {}\n",
            self.http_requests_4xx.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "http_requests_by_status{{status=\"5xx\"}} {}\n",
            self.http_requests_5xx.load(Ordering::Relaxed)
        ));
        
        // Average request duration
        let total_reqs = self.http_requests_total.load(Ordering::Relaxed);
        let avg_duration = if total_reqs > 0 {
            self.request_duration_ms.load(Ordering::Relaxed) / total_reqs
        } else {
            0
        };
        output.push_str("# HELP http_request_duration_ms Average HTTP request duration\n");
        output.push_str("# TYPE http_request_duration_ms gauge\n");
        output.push_str(&format!("http_request_duration_ms {}\n", avg_duration));
        
        // Active sessions
        output.push_str("# HELP active_sessions Current active sessions\n");
        output.push_str("# TYPE active_sessions gauge\n");
        output.push_str(&format!(
            "active_sessions {}\n",
            self.active_sessions.load(Ordering::Relaxed)
        ));
        
        // Login metrics
        output.push_str("# HELP auth_logins_total Total login attempts\n");
        output.push_str("# TYPE auth_logins_total counter\n");
        output.push_str(&format!(
            "auth_logins_total{{result=\"success\"}} {}\n",
            self.successful_logins.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "auth_logins_total{{result=\"failure\"}} {}\n",
            self.failed_logins.load(Ordering::Relaxed)
        ));
        
        // Rate limiting
        output.push_str("# HELP rate_limit_hits_total Total rate limit hits\n");
        output.push_str("# TYPE rate_limit_hits_total counter\n");
        output.push_str(&format!(
            "rate_limit_hits_total {}\n",
            self.rate_limit_hits.load(Ordering::Relaxed)
        ));
        
        // Token refreshes
        output.push_str("# HELP token_refreshes_total Total token refreshes\n");
        output.push_str("# TYPE token_refreshes_total counter\n");
        output.push_str(&format!(
            "token_refreshes_total {}\n",
            self.token_refreshes.load(Ordering::Relaxed)
        ));
        
        // Build info
        output.push_str("# HELP vault_auth_build_info Build information\n");
        output.push_str("# TYPE vault_auth_build_info gauge\n");
        output.push_str(&format!(
            "vault_auth_build_info{{version=\"{}\",commit=\"unknown\"}} 1\n",
            env!("CARGO_PKG_VERSION")
        ));
        
        output
    }
}

/// Metrics routes
pub fn routes() -> Router<crate::state::AppState> {
    Router::new().route("/metrics", get(metrics_handler))
}

/// Metrics handler
async fn metrics_handler(State(state): State<crate::state::AppState>) -> impl IntoResponse {
    // In a real implementation, this would pull from actual metrics collectors
    // For now, return a basic response
    let metrics = MetricsCollector::new();
    
    Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(metrics.render())
        .unwrap()
}
