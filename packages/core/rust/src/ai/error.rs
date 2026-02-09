//! Error types for the AI security system

use thiserror::Error;

/// Result type for AI operations
pub type AiResult<T> = Result<T, AiError>;

/// Errors that can occur in the AI security system
#[derive(Error, Debug)]
pub enum AiError {
    /// Model loading or inference error
    #[error("Model error: {0}")]
    ModelError(String),

    /// Feature extraction error
    #[error("Feature extraction error: {0}")]
    FeatureError(String),

    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    /// Invalid input data
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Model not found
    #[error("Model not found: {0}")]
    ModelNotFound(String),

    /// Inference timeout
    #[error("Inference timeout after {0}ms")]
    InferenceTimeout(u64),

    /// Not enough data for analysis
    #[error("Insufficient data: {0}")]
    InsufficientData(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// External service error (e.g., threat intel API)
    #[error("External service error: {0}")]
    ExternalServiceError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl AiError {
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            AiError::InferenceTimeout(_)
                | AiError::ExternalServiceError(_)
                | AiError::DatabaseError(_)
        )
    }

    /// Get error category for metrics
    pub fn category(&self) -> &'static str {
        match self {
            AiError::ModelError(_) => "model",
            AiError::FeatureError(_) => "feature",
            AiError::DatabaseError(_) => "database",
            AiError::InvalidInput(_) => "input",
            AiError::ConfigError(_) => "config",
            AiError::ModelNotFound(_) => "model_not_found",
            AiError::InferenceTimeout(_) => "timeout",
            AiError::InsufficientData(_) => "insufficient_data",
            AiError::SerializationError(_) => "serialization",
            AiError::ExternalServiceError(_) => "external",
            AiError::InternalError(_) => "internal",
        }
    }
}

/// Error context for better debugging
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// Operation being performed
    pub operation: String,
    /// User ID if available
    pub user_id: Option<String>,
    /// Request ID for tracing
    pub request_id: String,
    /// Additional context
    pub details: Option<serde_json::Value>,
}

impl ErrorContext {
    /// Create new error context
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            user_id: None,
            request_id: uuid::Uuid::new_v4().to_string(),
            details: None,
        }
    }

    /// Add user ID
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Add request ID
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = request_id.into();
        self
    }

    /// Add details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}
