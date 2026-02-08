//! Test utilities for integration tests

use serde_json::json;

/// Generate a unique test email
pub fn test_email() -> String {
    format!("test-{}@test.example", uuid::Uuid::new_v4())
}

/// Generate a test password
pub fn test_password() -> String {
    "SecureTestPass123!".to_string()
}

/// Test user credentials
pub struct TestUser {
    pub email: String,
    pub password: String,
    pub name: String,
}

impl Default for TestUser {
    fn default() -> Self {
        Self {
            email: test_email(),
            password: test_password(),
            name: "Test User".to_string(),
        }
    }
}

impl TestUser {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "email": self.email,
            "password": self.password,
            "name": self.name,
        })
    }
}
