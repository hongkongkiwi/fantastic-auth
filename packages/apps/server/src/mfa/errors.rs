//! MFA Error Types
//!
//! Standardized error handling for all MFA operations.

use axum::http::StatusCode;
use thiserror::Error;

/// MFA-specific error types
#[derive(Debug, Error)]
pub enum MfaError {
    #[error("MFA method not enabled: {0}")]
    MethodNotEnabled(String),

    #[error("Invalid MFA method: {0}")]
    InvalidMethod(String),

    #[error("Invalid verification code")]
    InvalidCode,

    #[error("Code expired or not found")]
    CodeExpired,

    #[error("Rate limit exceeded. Please try again later")]
    RateLimitExceeded,

    #[error("Phone number not configured")]
    PhoneNotConfigured,

    #[error("Invalid phone number: {0}")]
    InvalidPhoneNumber(String),

    #[error("SMS service not available")]
    SmsServiceUnavailable,

    #[error("WhatsApp service not available")]
    WhatsappServiceUnavailable,

    #[error("Email service not available")]
    EmailServiceUnavailable,

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for MFA operations
pub type MfaResult<T> = Result<T, MfaError>;

impl MfaError {
    /// Convert to HTTP status code
    pub fn status_code(&self) -> StatusCode {
        match self {
            MfaError::MethodNotEnabled(_) => StatusCode::BAD_REQUEST,
            MfaError::InvalidMethod(_) => StatusCode::BAD_REQUEST,
            MfaError::InvalidCode => StatusCode::UNAUTHORIZED,
            MfaError::CodeExpired => StatusCode::UNAUTHORIZED,
            MfaError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            MfaError::PhoneNotConfigured => StatusCode::BAD_REQUEST,
            MfaError::InvalidPhoneNumber(_) => StatusCode::BAD_REQUEST,
            MfaError::SmsServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            MfaError::WhatsappServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            MfaError::EmailServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            MfaError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            MfaError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get user-facing error message
    pub fn user_message(&self) -> String {
        match self {
            MfaError::MethodNotEnabled(method) => {
                format!("{} MFA is not enabled for your account", method)
            }
            MfaError::InvalidMethod(method) => format!("Invalid MFA method: {}", method),
            MfaError::InvalidCode => "Invalid verification code".to_string(),
            MfaError::CodeExpired => "Code has expired. Please request a new one".to_string(),
            MfaError::RateLimitExceeded => {
                "Too many attempts. Please wait before trying again".to_string()
            }
            MfaError::PhoneNotConfigured => {
                "No phone number configured. Please set up first".to_string()
            }
            MfaError::InvalidPhoneNumber(msg) => format!("Invalid phone number: {}", msg),
            MfaError::SmsServiceUnavailable => {
                "SMS service is temporarily unavailable".to_string()
            }
            MfaError::WhatsappServiceUnavailable => {
                "WhatsApp service is temporarily unavailable".to_string()
            }
            MfaError::EmailServiceUnavailable => {
                "Email service is temporarily unavailable".to_string()
            }
            MfaError::Database(_) | MfaError::Internal(_) => {
                "An unexpected error occurred".to_string()
            }
        }
    }
}

/// Convert MFA error to API error response
impl From<MfaError> for crate::routes::ApiError {
    fn from(err: MfaError) -> Self {
        match &err {
            MfaError::InvalidCode | MfaError::CodeExpired => crate::routes::ApiError::Unauthorized,
            MfaError::RateLimitExceeded => {
                crate::routes::ApiError::TooManyRequests(err.user_message())
            }
            MfaError::MethodNotEnabled(msg)
            | MfaError::InvalidMethod(msg)
            | MfaError::InvalidPhoneNumber(msg) => {
                crate::routes::ApiError::BadRequest(msg.clone())
            }
            MfaError::SmsServiceUnavailable
            | MfaError::WhatsappServiceUnavailable
            | MfaError::EmailServiceUnavailable => crate::routes::ApiError::internal(),
            _ => crate::routes::ApiError::internal(),
        }
    }
}
