//! Common test utilities for integration tests
//!
//! Provides test fixtures, database setup, and helper functions for integration tests.

use axum::{body::Body, http::Request, Router};
use serde_json::json;
use std::net::SocketAddr;
use tower::ServiceExt;
use vault_server::config::Config;
use vault_server::state::AppState;

/// Default test database URL
pub const TEST_DATABASE_URL: &str = "postgres://vault:vault@localhost:5432/vault_test";

/// Test server handle with utilities for making requests
pub struct TestServer {
    pub app: Router,
    pub state: AppState,
    pub base_url: String,
}

impl TestServer {
    /// Create a new test server with test database
    pub async fn new() -> anyhow::Result<Self> {
        let config = test_config();
        let state = AppState::new(config).await?;

        // Create the app with test state
        let app = create_test_app(state.clone()).await;

        Ok(Self {
            app,
            state,
            base_url: "http://localhost:3000".to_string(),
        })
    }

    /// Make a GET request
    pub async fn get(&self, path: &str) -> axum::response::Response<Body> {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();

        self.app.clone().oneshot(request).await.unwrap()
    }

    /// Make a POST request with JSON body
    pub async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> axum::response::Response<Body> {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        self.app.clone().oneshot(request).await.unwrap()
    }

    /// Make a POST request with authorization header
    pub async fn post_with_auth(
        &self,
        path: &str,
        body: serde_json::Value,
        token: &str,
    ) -> axum::response::Response<Body> {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::from(body.to_string()))
            .unwrap();

        self.app.clone().oneshot(request).await.unwrap()
    }

    /// Make a GET request with authorization header
    pub async fn get_with_auth(&self, path: &str, token: &str) -> axum::response::Response<Body> {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        self.app.clone().oneshot(request).await.unwrap()
    }

    /// Make a PATCH request with authorization header
    pub async fn patch_with_auth(
        &self,
        path: &str,
        body: serde_json::Value,
        token: &str,
    ) -> axum::response::Response<Body> {
        let request = Request::builder()
            .method("PATCH")
            .uri(path)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::from(body.to_string()))
            .unwrap();

        self.app.clone().oneshot(request).await.unwrap()
    }

    /// Make a DELETE request with authorization header
    pub async fn delete_with_auth(
        &self,
        path: &str,
        token: &str,
    ) -> axum::response::Response<Body> {
        let request = Request::builder()
            .method("DELETE")
            .uri(path)
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        self.app.clone().oneshot(request).await.unwrap()
    }
}

/// Create test application
async fn create_test_app(state: AppState) -> Router {
    use axum::routing::get;
    use tower_http::cors::CorsLayer;
    use vault_server::routes;

    // Build test router
    axum::Router::new()
        .route("/health", get(routes::health_check))
        .route("/metrics", get(routes::metrics_handler))
        .nest("/api/v1", routes::api_routes())
        .fallback(routes::not_found)
        .with_state(state)
        .layer(CorsLayer::permissive())
}

/// Create test configuration
fn test_config() -> Config {
    Config {
        host: "127.0.0.1".to_string(),
        port: 0,
        base_url: "http://localhost:3000".to_string(),
        database_url: std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| TEST_DATABASE_URL.to_string()),
        redis_url: None, // Use in-memory token store for tests
        jwt: Default::default(),
        cors_origins: vec!["http://localhost:3000".to_string()],
        rate_limit: Default::default(),
        smtp: None,
        oauth: Default::default(),
        log_level: "warn".to_string(),
        db_pool: Default::default(),
        security: Default::default(),
        webhook: Default::default(),
        features: test_feature_flags(),
        observability: Default::default(),
        background_jobs: Default::default(),
        tls: Default::default(),
    }
}

/// Test feature flags - enable features useful for testing
fn test_feature_flags() -> vault_server::config::FeatureFlags {
    vault_server::config::FeatureFlags {
        enable_email_verification: true,
        enable_mfa_default: true,
        enable_oauth_signup: true,
        dev_skip_email: true,        // Skip sending actual emails in tests
        dev_auto_verify_email: true, // Auto-verify emails in tests
    }
}

/// Test user credentials
pub struct TestUser {
    pub email: String,
    pub password: String,
    pub name: String,
}

impl TestUser {
    pub fn new() -> Self {
        use rand::Rng;
        let random: u32 = rand::thread_rng().gen();
        Self {
            email: format!("test{}@example.com", random),
            password: "TestPassword123!".to_string(),
            name: "Test User".to_string(),
        }
    }

    /// Create JSON for registration request
    pub fn register_json(&self) -> serde_json::Value {
        json!({
            "email": self.email,
            "password": self.password,
            "name": self.name,
        })
    }

    /// Create JSON for login request
    pub fn login_json(&self) -> serde_json::Value {
        json!({
            "email": self.email,
            "password": self.password,
        })
    }
}

impl Default for TestUser {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate unique test email
pub fn unique_email() -> String {
    use rand::Rng;
    let random: u32 = rand::thread_rng().gen();
    format!("test{}@example.com", random)
}

/// Generate unique test email with prefix
pub fn unique_email_with_prefix(prefix: &str) -> String {
    use rand::Rng;
    let random: u32 = rand::thread_rng().gen();
    format!("{}-test{}@example.com", prefix, random)
}

/// Setup tracing for tests
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();
}

/// Helper to extract response body as JSON
pub async fn response_json(response: axum::response::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(null))
}

/// Helper to extract response body as string
pub async fn response_text(response: axum::response::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

/// Assert response has expected status code
pub fn assert_status(response: &axum::response::Response<Body>, expected: axum::http::StatusCode) {
    assert_eq!(
        response.status(),
        expected,
        "Expected status {:?}, got {:?}",
        expected,
        response.status()
    );
}

/// Setup test database - runs migrations and cleans up test data
pub async fn setup_test_db() -> anyhow::Result<Database> {
    let db = Database::new(TEST_DATABASE_URL).await?;

    // Clean up any existing test data
    cleanup_test_data(&db).await?;

    Ok(db)
}

/// Cleanup test data from database
async fn cleanup_test_data(db: &Database) -> anyhow::Result<()> {
    // Delete test users (those with test emails)
    sqlx::query("DELETE FROM users WHERE email LIKE 'test%@example.com'")
        .execute(db.pool())
        .await?;

    Ok(())
}

use vault_server::db::Database;

/// Integration test context - holds server and helper state
pub struct TestContext {
    pub server: TestServer,
}

impl TestContext {
    /// Create new test context
    pub async fn new() -> anyhow::Result<Self> {
        init_tracing();
        let server = TestServer::new().await?;
        Ok(Self { server })
    }

    /// Register and login a new user, returning tokens
    pub async fn create_user_and_login(&self) -> anyhow::Result<(TestUser, String, String)> {
        let user = TestUser::new();

        // Register
        let response = self
            .server
            .post("/api/v1/register", user.register_json())
            .await;
        assert_status(&response, axum::http::StatusCode::OK);

        let body = response_json(response).await;
        let access_token = body["accessToken"].as_str().unwrap().to_string();
        let refresh_token = body["refreshToken"].as_str().unwrap().to_string();

        Ok((user, access_token, refresh_token))
    }

    /// Create an admin user
    pub async fn create_admin_user(&self) -> anyhow::Result<(TestUser, String)> {
        let (user, token, _) = self.create_user_and_login().await?;

        // Note: In a real test, you'd need to promote this user to admin
        // This depends on your admin promotion mechanism

        Ok((user, token))
    }
}

/// Skip test if database is not available
#[macro_export]
macro_rules! skip_if_no_db {
    () => {
        if std::env::var("TEST_DATABASE_URL").is_err()
            && !vault_server::tests::common::test_db_available().await
        {
            eprintln!("Skipping test: database not available");
            return;
        }
    };
}

/// Check if test database is available
pub async fn test_db_available() -> bool {
    match Database::new(TEST_DATABASE_URL).await {
        Ok(db) => db.ping().await.is_ok(),
        Err(_) => false,
    }
}

/// WireMock helpers for external service mocking
pub mod wiremock_helpers {
    use wiremock::matchers::{body_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Create a mock OAuth provider server
    pub async fn mock_oauth_provider() -> MockServer {
        MockServer::start().await
    }

    /// Mock OAuth token endpoint
    pub async fn mock_oauth_token(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
            })))
            .mount(server)
            .await;
    }

    /// Mock OAuth userinfo endpoint
    pub async fn mock_oauth_userinfo(server: &MockServer, email: &str) {
        Mock::given(method("GET"))
            .and(path("/oauth/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "12345",
                "email": email,
                "email_verified": true,
                "name": "Test User",
            })))
            .mount(server)
            .await;
    }

    /// Mock email service endpoint
    pub async fn mock_email_service(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/send"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message_id": "mock-message-id",
                "status": "sent",
            })))
            .mount(server)
            .await;
    }
}
