//! Error types for Vault

use thiserror::Error;

/// Main error type for Vault operations
#[derive(Error, Debug)]
pub enum VaultError {
    /// Authentication errors
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Authorization errors
    #[error("Authorization failed: {0}")]
    Authorization(String),

    /// Validation errors
    #[error("Validation failed: {0}")]
    Validation(String),

    /// Database errors
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Crypto errors
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Base64 encoding errors
    #[error("Base64 encoding error: {0}")]
    Base64(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Not found errors
    #[error("{resource} not found: {id}")]
    NotFound { resource: String, id: String },

    /// Conflict errors
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Rate limit errors
    #[error("Rate limit exceeded. Try again in {retry_after} seconds")]
    RateLimit { retry_after: u64 },

    /// External service errors
    #[error("External service error ({service}): {message}")]
    ExternalService { service: String, message: String },

    /// Internal errors
    #[error("Internal error: {0}")]
    Internal(String),
}

impl VaultError {
    /// Create a not found error
    pub fn not_found(resource: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            resource: resource.into(),
            id: id.into(),
        }
    }

    /// Create an authentication error
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Authentication(message.into())
    }

    /// Create an authentication error (alias)
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication(message.into())
    }

    /// Create an authorization error
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Authorization(message.into())
    }

    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    /// Create a crypto error
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }

    /// Create an internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// Create a conflict error
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    /// Create a rate limit error
    pub fn rate_limit(retry_after: u64) -> Self {
        Self::RateLimit { retry_after }
    }

    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            VaultError::Authentication(_) => 401,
            VaultError::Authorization(_) => 403,
            VaultError::Validation(_) => 422,
            VaultError::Database(_) => 500,
            VaultError::Crypto(_) => 500,
            VaultError::Serialization(_) => 500,
            VaultError::Base64(_) => 500,
            VaultError::Config(_) => 500,
            VaultError::NotFound { .. } => 404,
            VaultError::Conflict(_) => 409,
            VaultError::RateLimit { .. } => 429,
            VaultError::ExternalService { .. } => 502,
            VaultError::Internal(_) => 500,
        }
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, VaultError>;

/// Error response for API
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl From<&VaultError> for ErrorResponse {
    fn from(err: &VaultError) -> Self {
        let code = match err {
            VaultError::Authentication(_) => "AUTHENTICATION_ERROR",
            VaultError::Authorization(_) => "AUTHORIZATION_ERROR",
            VaultError::Validation(_) => "VALIDATION_ERROR",
            VaultError::Database(_) => "DATABASE_ERROR",
            VaultError::Crypto(_) => "CRYPTO_ERROR",
            VaultError::Serialization(_) => "SERIALIZATION_ERROR",
            VaultError::Config(_) => "CONFIG_ERROR",
            VaultError::NotFound { .. } => "NOT_FOUND",
            VaultError::Conflict(_) => "CONFLICT",
            VaultError::RateLimit { .. } => "RATE_LIMIT_EXCEEDED",
            VaultError::ExternalService { .. } => "EXTERNAL_SERVICE_ERROR",
            VaultError::Base64(_) => "BASE64_ERROR",
            VaultError::Internal(_) => "INTERNAL_ERROR",
        };

        Self {
            error: ErrorDetail {
                code: code.to_string(),
                message: err.to_string(),
                details: None,
            },
        }
    }
}
