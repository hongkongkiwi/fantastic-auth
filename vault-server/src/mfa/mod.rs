//! MFA (Multi-Factor Authentication) Module
//!
//! Provides a unified interface for all MFA methods:
//! - TOTP (Time-based One-Time Password)
//! - SMS (SMS-based OTP)
//! - WhatsApp (WhatsApp-based OTP)
//! - Email (Email-based OTP)
//! - WebAuthn (FIDO2/Passkeys)
//! - Backup Codes
//!
//! This module provides:
//! - Common verification handlers with rate limiting
//! - Unified error handling
//! - Method-agnostic traits for extensibility

pub mod common;
pub mod email;
pub mod errors;
pub mod push;
pub mod sms;
pub mod totp;
pub mod whatsapp;

pub use common::MfaVerificationHandler;
pub use errors::{MfaError, MfaResult};

use crate::state::AppState;

/// Sync user MFA methods to user record
/// This updates the user's mfa_methods field based on enabled MFA methods
pub async fn sync_user_mfa_methods(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
) -> Result<(), crate::mfa::errors::MfaError> {
    let methods = state
        .db
        .mfa()
        .get_enabled_methods(tenant_id, user_id)
        .await
        .map_err(crate::mfa::errors::MfaError::Database)?;

    let mut method_names: Vec<String> = methods
        .iter()
        .filter_map(|m| {
            match m.method_type {
                vault_core::db::mfa::MfaMethodType::Totp => Some("totp".to_string()),
                vault_core::db::mfa::MfaMethodType::Email => Some("email".to_string()),
                vault_core::db::mfa::MfaMethodType::Sms => Some("sms".to_string()),
                vault_core::db::mfa::MfaMethodType::Webauthn => Some("webauthn".to_string()),
                vault_core::db::mfa::MfaMethodType::Whatsapp => Some("whatsapp".to_string()),
            }
        })
        .collect();

    let backup_codes = state
        .db
        .mfa()
        .get_backup_codes(tenant_id, user_id)
        .await
        .map_err(crate::mfa::errors::MfaError::Database)?;

    if !backup_codes.is_empty() {
        method_names.push("backup_codes".to_string());
    }

    method_names.sort();
    method_names.dedup();

    state
        .db
        .users()
        .set_mfa_methods(tenant_id, user_id, &method_names)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update user MFA methods: {}", e);
            crate::mfa::errors::MfaError::Internal("Failed to sync MFA methods".to_string())
        })?;

    Ok(())
}

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;

use crate::state::AppState;

/// Rate limiting middleware for MFA verification endpoints
///
/// SECURITY: Enforces strict rate limiting on MFA verification endpoints to prevent brute force attacks.
/// - 5 attempts per 5 minutes per IP address for verification endpoints
/// - Applies to all code verification endpoints (TOTP, SMS, Email, WhatsApp, Backup codes)
pub async fn mfa_verification_rate_limit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Only apply rate limiting to POST requests (verification attempts)
    if request.method() != axum::http::Method::POST {
        return Ok(next.run(request).await);
    }

    // Create rate limit key based on IP address
    let key = format!("mfa_verify:{}", addr.ip());

    // Check rate limit: 5 attempts per 5 minutes (300 seconds)
    // This is stricter than general rate limiting due to security sensitivity
    const MAX_ATTEMPTS: u32 = 5;
    const WINDOW_SECS: u64 = 300; // 5 minutes

    if !state
        .rate_limiter
        .is_allowed(&key, MAX_ATTEMPTS, WINDOW_SECS)
        .await
    {
        tracing::warn!("MFA verification rate limit exceeded for IP: {}", addr.ip());
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

/// MFA method types supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaMethod {
    Totp,
    Sms,
    Whatsapp,
    Email,
    Webauthn,
    BackupCode,
}

impl MfaMethod {
    /// Get the string identifier for this method
    pub fn as_str(&self) -> &'static str {
        match self {
            MfaMethod::Totp => "totp",
            MfaMethod::Sms => "sms",
            MfaMethod::Whatsapp => "whatsapp",
            MfaMethod::Email => "email",
            MfaMethod::Webauthn => "webauthn",
            MfaMethod::BackupCode => "backup_code",
        }
    }

    /// Get the display name for this method
    pub fn display_name(&self) -> &'static str {
        match self {
            MfaMethod::Totp => "Authenticator App",
            MfaMethod::Sms => "SMS",
            MfaMethod::Whatsapp => "WhatsApp",
            MfaMethod::Email => "Email",
            MfaMethod::Webauthn => "Security Key",
            MfaMethod::BackupCode => "Backup Code",
        }
    }
}

impl std::str::FromStr for MfaMethod {
    type Err = MfaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "totp" | "authenticator" => Ok(MfaMethod::Totp),
            "sms" => Ok(MfaMethod::Sms),
            "whatsapp" => Ok(MfaMethod::Whatsapp),
            "email" => Ok(MfaMethod::Email),
            "webauthn" | "security_key" => Ok(MfaMethod::Webauthn),
            "backup_code" | "backup" => Ok(MfaMethod::BackupCode),
            _ => Err(MfaError::InvalidMethod(s.to_string())),
        }
    }
}
