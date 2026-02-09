//! Shared library surface for server modules and test integration.

use axum::{middleware as axum_middleware, routing::get, Router};
use std::time::Duration;
use tower_http::{compression::CompressionLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};

pub mod ai;
pub mod analytics;
pub mod actions;
pub mod audit;
pub mod auth;
pub mod background;
pub mod billing;
pub mod bulk;
pub mod communications;
pub mod config;
pub mod consent;
pub mod db;
pub mod domains;
pub mod federation;
pub mod i18n;
pub mod impersonation;
pub mod ldap;
pub mod m2m;
pub mod migration;
pub mod mfa;
pub mod metrics_internal;
pub mod middleware;
pub mod monitoring;
pub mod observability;
pub mod oidc;
pub mod permissions;
pub mod routes;
pub mod saml;
pub mod scim;
pub mod security;
pub mod settings;
pub mod state;
pub mod validation;
pub mod webhooks;

pub use config::Config;
pub use state::AppState;

/// Create the Axum application.
pub fn create_app(state: AppState, config: &Config) -> Router {
    Router::new()
        .merge(routes::health::routes())
        .route("/health", get(routes::health::simple_health_check))
        .nest("/api/v1", routes::api_routes())
        .merge(routes::oidc::routes())
        .nest("/hosted/api", routes::hosted::hosted_routes())
        .nest("/scim/v2", routes::scim_routes())
        .merge(saml::handlers::routes())
        .merge(ai::router())
        .fallback(routes::not_found)
        .with_state(state.clone())
        .layer(axum_middleware::from_fn_with_state(
            state,
            middleware::i18n::i18n_middleware,
        ))
        .layer(axum_middleware::from_fn(
            middleware::security::validate_request,
        ))
        .layer(axum_middleware::from_fn(
            middleware::security::security_headers,
        ))
        .layer(
            TraceLayer::new_for_http().make_span_with(
                tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO),
            ),
        )
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(CompressionLayer::new())
        .layer(middleware::security::cors_layer(
            config.cors_origins.clone(),
        ))
}
