//! Step-up Authentication Middleware
//!
//! This middleware checks if the current request has sufficient
//! step-up authentication for sensitive operations.
//!
//! # Usage
//!
//! ```rust,ignore
//! // Apply to specific routes
//! Router::new()
//!     .route("/change-password", post(change_password))
//!     .layer(require_step_up(StepUpLevel::Elevated, 10))
//! ```

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::auth::{SensitiveOperation, StepUpChallenge, StepUpChallengeResponse, StepUpPolicy};
use crate::state::{AppState, CurrentUser};
use vault_core::crypto::StepUpLevel;

/// Extension trait to add step-up methods to CurrentUser
pub trait StepUpUserExt {
    /// Check if the user has valid step-up for the required level
    fn has_step_up(&self, required_level: &StepUpLevel) -> bool;

    /// Get the current step-up level from claims
    fn step_up_level(&self) -> StepUpLevel;

    /// Check if step-up is expired
    fn is_step_up_expired(&self) -> bool;
}

impl StepUpUserExt for CurrentUser {
    fn has_step_up(&self, required_level: &StepUpLevel) -> bool {
        self.claims.has_step_up_level(required_level)
    }

    fn step_up_level(&self) -> StepUpLevel {
        self.claims.step_up_level()
    }

    fn is_step_up_expired(&self) -> bool {
        !self.claims.is_step_up_valid()
    }
}

/// Require step-up authentication middleware
///
/// Must be used after auth_middleware (which sets CurrentUser in extensions).
///
/// # Arguments
/// * `level` - Minimum step-up level required
/// * `max_age_minutes` - Maximum age of step-up authentication
///
/// # Errors
/// Returns 403 Forbidden with step-up challenge if step-up is required but not present
pub async fn require_step_up(
    level: StepUpLevel,
    max_age_minutes: u32,
) -> impl Fn(Request, Next) -> futures::future::BoxFuture<'static, Result<Response, StatusCode>> + Clone
{
    move |request: Request, next: Next| {
        let level = level.clone();
        Box::pin(async move {
            // Get current user from extensions
            let user = request
                .extensions()
                .get::<CurrentUser>()
                .ok_or(StatusCode::UNAUTHORIZED)?;

            // Check if user has sufficient step-up
            if !user.has_step_up(&level) {
                // Determine available challenge methods
                let methods = if user.mfa_authenticated {
                    vec![StepUpChallenge::Password, StepUpChallenge::Mfa]
                } else {
                    vec![StepUpChallenge::Password]
                };

                let challenge = StepUpChallengeResponse::new(level, methods, max_age_minutes)
                    .with_message(format!(
                        "This operation requires {} authentication. Please re-authenticate.",
                        format!("{:?}", level).to_lowercase()
                    ));

                return Ok((StatusCode::FORBIDDEN, Json(challenge)).into_response());
            }

            // Check if step-up has expired
            if user.is_step_up_expired() {
                let methods = if user.mfa_authenticated {
                    vec![StepUpChallenge::Password, StepUpChallenge::Mfa]
                } else {
                    vec![StepUpChallenge::Password]
                };

                let challenge = StepUpChallengeResponse::new(level, methods, max_age_minutes)
                    .with_message("Your elevated session has expired. Please re-authenticate.");

                return Ok((StatusCode::FORBIDDEN, Json(challenge)).into_response());
            }

            Ok(next.run(request).await)
        })
    }
}

/// Require step-up authentication with policy lookup
///
/// Uses the tenant's step-up policy to determine requirements.
/// Must be used after auth_middleware.
///
/// # Arguments
/// * `operation` - The sensitive operation being performed
pub async fn require_step_up_for_operation(
    State(state): State<AppState>,
    request: Request,
    next: Next,
    operation: SensitiveOperation,
) -> Result<Response, StatusCode> {
    // Get current user from extensions
    let user = request
        .extensions()
        .get::<CurrentUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Get policy for tenant
    let policy = &state.step_up_policy;
    let requirement = policy.get_requirement(&operation);

    // If standard level is sufficient, no step-up needed
    if requirement.level == StepUpLevel::Standard {
        return Ok(next.run(request).await);
    }

    // Check if user has sufficient step-up
    if !user.has_step_up(&requirement.level) {
        let methods = if user.mfa_authenticated || requirement.require_mfa {
            vec![StepUpChallenge::Password, StepUpChallenge::Mfa]
        } else {
            vec![StepUpChallenge::Password]
        };

        let challenge = StepUpChallengeResponse::new(
            requirement.level.clone(),
            methods,
            state.step_up_max_age_minutes,
        )
        .with_message(format!(
            "This operation requires {} authentication.",
            format!("{:?}", requirement.level).to_lowercase()
        ));

        return Ok((StatusCode::FORBIDDEN, Json(challenge)).into_response());
    }

    // Check if step-up has expired
    if user.is_step_up_expired() {
        let methods = if user.mfa_authenticated || requirement.require_mfa {
            vec![StepUpChallenge::Password, StepUpChallenge::Mfa]
        } else {
            vec![StepUpChallenge::Password]
        };

        let challenge = StepUpChallengeResponse::new(
            requirement.level.clone(),
            methods,
            state.step_up_max_age_minutes,
        )
        .with_message("Your elevated session has expired. Please re-authenticate.");

        return Ok((StatusCode::FORBIDDEN, Json(challenge)).into_response());
    }

    Ok(next.run(request).await)
}

/// Simple step-up middleware that checks for elevated access
///
/// This is a convenience middleware that requires Elevated level
/// with the default max age from configuration.
pub async fn require_elevated(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    require_step_up_for_operation(
        State(state),
        request,
        next,
        SensitiveOperation::ViewSensitiveData,
    )
    .await
}

/// Check if step-up is required for an operation
///
/// This function can be used in handlers to check step-up status
/// before performing an operation.
pub fn check_step_up_required(
    user: &CurrentUser,
    operation: &SensitiveOperation,
    policy: &StepUpPolicy,
) -> Option<StepUpChallengeResponse> {
    let requirement = policy.get_requirement(operation);

    // Standard level requires no step-up
    if requirement.level == StepUpLevel::Standard {
        return None;
    }

    // Check if user has sufficient step-up
    if !user.has_step_up(&requirement.level) {
        let methods = if user.mfa_authenticated || requirement.require_mfa {
            vec![StepUpChallenge::Password, StepUpChallenge::Mfa]
        } else {
            vec![StepUpChallenge::Password]
        };

        return Some(StepUpChallengeResponse::new(
            requirement.level.clone(),
            methods,
            requirement.max_age_minutes,
        ));
    }

    // Check if step-up has expired
    if user.is_step_up_expired() {
        let methods = if user.mfa_authenticated || requirement.require_mfa {
            vec![StepUpChallenge::Password, StepUpChallenge::Mfa]
        } else {
            vec![StepUpChallenge::Password]
        };

        return Some(
            StepUpChallengeResponse::new(
                requirement.level.clone(),
                methods,
                requirement.max_age_minutes,
            )
            .with_message("Your elevated session has expired."),
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vault_core::crypto::{AuthMethod, Claims, TokenType};

    fn create_test_user_with_step_up(level: StepUpLevel, expired: bool) -> CurrentUser {
        let exp_timestamp = if expired {
            (Utc::now() - chrono::Duration::minutes(1)).timestamp()
        } else {
            (Utc::now() + chrono::Duration::minutes(10)).timestamp()
        };

        let claims = Claims::new(
            "user_123",
            "tenant_456",
            TokenType::Access,
            "vault",
            "myapp",
        )
        .with_step_up_level(level)
        .with_step_up_expiry(chrono::DateTime::from_timestamp(exp_timestamp, 0).unwrap());

        CurrentUser {
            user_id: "user_123".to_string(),
            tenant_id: "tenant_456".to_string(),
            session_id: Some("session_789".to_string()),
            email: "test@example.com".to_string(),
            email_verified: true,
            mfa_authenticated: true,
            claims,
            impersonator_id: None,
            is_impersonation: false,
        }
    }

    #[test]
    fn test_step_up_user_ext_has_step_up() {
        let user = create_test_user_with_step_up(StepUpLevel::Elevated, false);

        assert!(user.has_step_up(&StepUpLevel::Standard));
        assert!(user.has_step_up(&StepUpLevel::Elevated));
        assert!(!user.has_step_up(&StepUpLevel::HighAssurance));
    }

    #[test]
    fn test_step_up_user_ext_expired() {
        let expired_user = create_test_user_with_step_up(StepUpLevel::Elevated, true);
        assert!(expired_user.is_step_up_expired());
        assert!(!expired_user.has_step_up(&StepUpLevel::Standard));

        let valid_user = create_test_user_with_step_up(StepUpLevel::Elevated, false);
        assert!(!valid_user.is_step_up_expired());
    }

    #[test]
    fn test_check_step_up_required() {
        let policy = StepUpPolicy::new();

        // User without step-up
        let user = create_test_user_with_step_up(StepUpLevel::Standard, false);

        // Change password requires elevated
        let result = check_step_up_required(&user, &SensitiveOperation::ChangePassword, &policy);
        assert!(result.is_some());

        // Delete account requires high assurance
        let result = check_step_up_required(&user, &SensitiveOperation::DeleteAccount, &policy);
        assert!(result.is_some());

        // User with elevated step-up
        let user = create_test_user_with_step_up(StepUpLevel::Elevated, false);

        // Change password should pass
        let result = check_step_up_required(&user, &SensitiveOperation::ChangePassword, &policy);
        assert!(result.is_none());

        // Delete account still requires high assurance
        let result = check_step_up_required(&user, &SensitiveOperation::DeleteAccount, &policy);
        assert!(result.is_some());
    }
}
