//! Vault Server - User Management API
//!
//! A secure, quantum-resistant user authentication and management server.

use axum::{middleware as axum_middleware, routing::get, Router};
use std::net::SocketAddr;
use std::time::Duration;
use tower_http::{compression::CompressionLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing::info;

mod audit;
mod auth;
mod background;
mod billing;
mod bulk;
mod config;
mod consent;
mod db;
mod domains;
mod i18n;
mod ldap;
mod metrics_internal;
mod middleware;
mod monitoring;
mod observability;
mod routes;
mod scim;
mod security;
mod state;
mod validation;
mod webhooks;

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config = Config::from_env()?;

    // Initialize observability (logging + tracing)
    observability::init(&config.observability);

    info!(
        version = vault_core::VERSION,
        host = %config.host,
        port = config.port,
        "Starting Vault Server"
    );

    // Create application state
    let state = AppState::new(config.clone()).await?;

    // Start background jobs
    background::start(&config, &state.db, &state);

    // Build application
    let app = create_app(state, &config);

    // Create socket address
    let addr: SocketAddr = config.socket_addr();

    info!(address = %addr, "Server listening");

    // Start server with graceful shutdown
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    // Cleanup
    observability::shutdown();
    info!("Server shutdown complete");

    Ok(())
}

/// Handle shutdown signals
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, shutting down..."),
        _ = terminate => info!("Received SIGTERM, shutting down..."),
    }
}

/// Create the Axum application
fn create_app(state: AppState, config: &Config) -> Router {
    // Build router with layers applied in reverse order (bottom to top)
    Router::new()
        // Health and metrics routes (no auth required)
        .merge(routes::health::routes())
        // Legacy health endpoint for backwards compatibility
        .route("/health", get(routes::health::simple_health_check))
        // API routes
        .nest("/api/v1", routes::api_routes())
        // SCIM 2.0 routes (separate from main API)
        .nest("/scim/v2", routes::scim_routes())
        // 404 handler
        .fallback(routes::not_found)
        // Add state first (innermost layer) - clone for i18n middleware
        .with_state(state.clone())
        // i18n middleware for language detection
        .layer(axum_middleware::from_fn_with_state(
            state,
            middleware::i18n::i18n_middleware,
        ))
        // Request validation
        .layer(axum_middleware::from_fn(
            middleware::security::validate_request,
        ))
        // Security headers
        .layer(axum_middleware::from_fn(
            middleware::security::security_headers,
        ))
        // Tracing
        .layer(
            TraceLayer::new_for_http().make_span_with(
                tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO),
            ),
        )
        // Body size limit (10MB)
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        // Compression
        .layer(CompressionLayer::new())
        // CORS (outermost)
        .layer(middleware::security::cors_layer(
            config.cors_origins.clone(),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        // Test the health check function directly
        let response = routes::health::simple_health_check().await;
        assert_eq!(response.0.status, "healthy");
    }
}
