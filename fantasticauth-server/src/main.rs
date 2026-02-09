//! Vault Server - User Management API
//!
//! A secure, quantum-resistant user authentication and management server.

use std::net::SocketAddr;
use tracing::info;

use vault_server::{background, create_app, observability, routes, AppState, Config};

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
