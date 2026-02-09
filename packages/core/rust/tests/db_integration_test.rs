//! Database repository integration tests
//!
//! Tests require a running PostgreSQL database.
//! Run with: cargo test --test db_integration_test -- --nocapture
//! Database URL: postgres://vault:vault@localhost:5432/vault

use sqlx::PgPool;
use fantasticauth_core::db::{users::CreateUserRequest, DbContext};
use fantasticauth_core::models::user::UserStatus;

fn should_run() -> bool {
    std::env::var("RUN_DB_INTEGRATION_TESTS").ok().as_deref() == Some("1")
}

/// Setup test database connection
async fn setup_db() -> DbContext {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://vault:vault@localhost:5432/vault".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    DbContext::new(pool)
}

/// Generate unique test email
fn test_email() -> String {
    format!("test-{}@example.com", uuid::Uuid::new_v4())
}

/// Test user creation
#[tokio::test]
async fn test_user_create() {
    if !should_run() {
        return;
    }

    let db = setup_db().await;

    // Set tenant context
    db.set_tenant_context("test-tenant", None, None)
        .await
        .unwrap();

    let email = test_email();
    let req = CreateUserRequest {
        tenant_id: "test-tenant".to_string(),
        email: email.clone(),
        password_hash: Some("hashed_password".to_string()),
        email_verified: false,
        profile: None,
        metadata: None,
    };

    let user = db.users().create(req).await.unwrap();

    assert!(!user.id.is_empty());
    assert_eq!(user.email, email);
    assert_eq!(user.status, UserStatus::Pending);
    assert!(!user.email_verified);
}

/// Test finding user by email
#[tokio::test]
async fn test_user_find_by_email() {
    if !should_run() {
        return;
    }

    let db = setup_db().await;

    db.set_tenant_context("test-tenant", None, None)
        .await
        .unwrap();

    let email = test_email();
    let req = CreateUserRequest {
        tenant_id: "test-tenant".to_string(),
        email: email.clone(),
        password_hash: Some("hashed_password".to_string()),
        email_verified: true,
        profile: None,
        metadata: None,
    };

    let created = db.users().create(req).await.unwrap();

    let found = db
        .users()
        .find_by_email("test-tenant", &email)
        .await
        .unwrap();

    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.id, created.id);
    assert_eq!(found.email, email);
}

/// Test finding non-existent user
#[tokio::test]
async fn test_user_find_not_found() {
    if !should_run() {
        return;
    }

    let db = setup_db().await;

    db.set_tenant_context("test-tenant", None, None)
        .await
        .unwrap();

    let found = db
        .users()
        .find_by_email("test-tenant", "nonexistent@example.com")
        .await
        .unwrap();

    assert!(found.is_none());
}

/// Test email exists check
#[tokio::test]
async fn test_user_email_exists() {
    if !should_run() {
        return;
    }

    let db = setup_db().await;

    db.set_tenant_context("test-tenant", None, None)
        .await
        .unwrap();

    let email = test_email();
    let req = CreateUserRequest {
        tenant_id: "test-tenant".to_string(),
        email: email.clone(),
        password_hash: Some("hashed_password".to_string()),
        email_verified: false,
        profile: None,
        metadata: None,
    };

    db.users().create(req).await.unwrap();

    let exists = db
        .users()
        .email_exists("test-tenant", &email)
        .await
        .unwrap();

    assert!(exists);

    let not_exists = db
        .users()
        .email_exists("test-tenant", "nonexistent@example.com")
        .await
        .unwrap();

    assert!(!not_exists);
}
