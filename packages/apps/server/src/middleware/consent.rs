//! Consent Middleware
//!
//! Middleware for enforcing consent requirements on operations.
//! Blocks operations if required consent is not granted.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{
    consent::{ConsentManager, ConsentRequirement, ConsentType},
    state::{AppState, CurrentUser},
};

/// Consent check error response
#[derive(Debug, Serialize)]
struct ConsentRequiredError {
    error: ConsentErrorDetail,
}

#[derive(Debug, Serialize)]
struct ConsentErrorDetail {
    code: String,
    message: String,
    #[serde(rename = "consentType")]
    consent_type: String,
    #[serde(rename = "consentUrl")]
    consent_url: Option<String>,
}

/// Middleware that requires specific consent to be granted
///
/// Usage:
/// ```rust
/// Router::new()
///     .route("/analytics", get(track_analytics))
///     .layer(middleware::from_fn(require_consent(ConsentType::Analytics)))
/// ```
pub fn require_consent(
    consent_type: ConsentType,
) -> impl Fn(State<AppState>, Request, Next) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Response> + Send>,
> + Clone {
    move |State(state): State<AppState>, request: Request, next: Next| {
        let consent_type = consent_type;
        Box::pin(async move {
            // Get current user from extensions
            let user = match request.extensions().get::<CurrentUser>() {
                Some(u) => u.clone(),
                None => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({
                            "error": {
                                "code": "UNAUTHORIZED",
                                "message": "Authentication required"
                            }
                        })),
                    )
                        .into_response();
                }
            };

            // Create consent manager
            let repository =
                crate::consent::ConsentRepository::new(state.db.pool().clone());
            let config = crate::consent::ConsentConfig::default();
            let manager = ConsentManager::new(repository, config);

            // Check consent
            let requirement = ConsentRequirement::new(consent_type)
                .error_message(format!("{} consent required", consent_type.display_name()));

            match manager.check_consent(&user.user_id, &requirement).await {
                Ok(()) => {
                    // Consent granted, proceed
                    next.run(request).await
                }
                Err(e) => {
                    tracing::warn!(
                        "Consent required but not granted for user {}: {}",
                        user.user_id,
                        e
                    );

                    // Get current consent URL for the user
                    let consent_url = get_consent_url(&state, &user.tenant_id, consent_type).await;

                    let error_response = ConsentRequiredError {
                        error: ConsentErrorDetail {
                            code: "CONSENT_REQUIRED".to_string(),
                            message: format!(
                                "You must consent to {} before performing this action",
                                consent_type.display_name()
                            ),
                            consent_type: format!("{:?}", consent_type).to_lowercase(),
                            consent_url,
                        },
                    };

                    (StatusCode::FORBIDDEN, Json(error_response)).into_response()
                }
            }
        })
    }
}

/// Middleware that requires analytics consent
pub async fn require_analytics_consent(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    require_consent(ConsentType::Analytics)(State(state), request, next).await
}

/// Middleware that requires marketing consent
pub async fn require_marketing_consent(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    require_consent(ConsentType::Marketing)(State(state), request, next).await
}

/// Middleware that requires cookies consent
pub async fn require_cookies_consent(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    require_consent(ConsentType::Cookies)(State(state), request, next).await
}

/// Middleware that checks if user has all required consents
/// Returns 403 with list of pending required consents if not
pub async fn require_all_required_consents(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Get current user from extensions
    let user = match request.extensions().get::<CurrentUser>() {
        Some(u) => u.clone(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": {
                        "code": "UNAUTHORIZED",
                        "message": "Authentication required"
                    }
                })),
            )
                .into_response();
        }
    };

    // Create consent manager
    let repository = crate::consent::ConsentRepository::new(state.db.pool().clone());
    let config = crate::consent::ConsentConfig::default();
    let manager = ConsentManager::new(repository, config);

    // Get pending required consents
    match manager.get_pending_consents(&user.user_id).await {
        Ok(pending) => {
            let required_pending: Vec<_> = pending
                .into_iter()
                .filter(|p| p.required)
                .map(|p| serde_json::json!({
                    "type": p.consent_type,
                    "title": p.version.title,
                    "url": p.version.url,
                }))
                .collect();

            if required_pending.is_empty() {
                // All required consents granted, proceed
                next.run(request).await
            } else {
                tracing::warn!(
                    "User {} has pending required consents: {:?}",
                    user.user_id,
                    required_pending
                );

                let error_response = serde_json::json!({
                    "error": {
                        "code": "REQUIRED_CONSENTS_PENDING",
                        "message": "You must accept all required consents before proceeding",
                        "pendingConsents": required_pending,
                        "consentUrl": format!("/{}/consents", user.tenant_id)
                    }
                });

                (StatusCode::FORBIDDEN, Json(error_response)).into_response()
            }
        }
        Err(e) => {
            tracing::error!("Failed to check pending consents: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "Failed to check consent status"
                    }
                })),
            )
                .into_response()
        }
    }
}

/// Middleware that injects consent status into request extensions
/// This allows handlers to check consent status without querying again
pub async fn inject_consent_status(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Get current user from extensions
    if let Some(user) = request.extensions().get::<CurrentUser>().cloned() {
        // Create consent manager
        let repository = crate::consent::ConsentRepository::new(state.db.pool().clone());
        let config = crate::consent::ConsentConfig::default();
        let manager = ConsentManager::new(repository, config);

        // Get user consent status
        if let Ok(statuses) = manager.get_user_consent_status(&user.user_id).await {
            let consent_status = UserConsentStatus {
                has_analytics: statuses
                    .iter()
                    .any(|s| s.consent_type == ConsentType::Analytics && s.has_consented),
                has_marketing: statuses
                    .iter()
                    .any(|s| s.consent_type == ConsentType::Marketing && s.has_consented),
                has_cookies: statuses
                    .iter()
                    .any(|s| s.consent_type == ConsentType::Cookies && s.has_consented),
                all_required_granted: statuses
                    .iter()
                    .filter(|s| s.required)
                    .all(|s| s.has_consented),
            };

            request.extensions_mut().insert(consent_status);
        }
    }

    next.run(request).await
}

/// User consent status extracted from request extensions
#[derive(Debug, Clone)]
pub struct UserConsentStatus {
    pub has_analytics: bool,
    pub has_marketing: bool,
    pub has_cookies: bool,
    pub all_required_granted: bool,
}

/// Extension trait to extract consent status from request
pub trait ConsentStatusExt {
    fn consent_status(&self) -> Option<&UserConsentStatus>;
    fn has_consent(&self, consent_type: ConsentType) -> bool;
}

impl ConsentStatusExt for axum::extract::Request {
    fn consent_status(&self) -> Option<&UserConsentStatus> {
        self.extensions().get::<UserConsentStatus>()
    }

    fn has_consent(&self, consent_type: ConsentType) -> bool {
        self.extensions()
            .get::<UserConsentStatus>()
            .map(|s| match consent_type {
                ConsentType::Analytics => s.has_analytics,
                ConsentType::Marketing => s.has_marketing,
                ConsentType::Cookies => s.has_cookies,
                _ => s.all_required_granted,
            })
            .unwrap_or(false)
    }
}

/// Helper to get consent URL for a tenant
async fn get_consent_url(
    _state: &AppState,
    _tenant_id: &str,
    _consent_type: ConsentType,
) -> Option<String> {
    // In production, this would look up the tenant-specific URL
    // For now, return a default
    Some("/consents".to_string())
}

/// Conditional middleware that only applies if consent is required
/// 
/// This allows you to wrap routes that only need consent checks
/// under certain conditions
pub fn conditional_consent_middleware<F>(
    condition: F,
    consent_type: ConsentType,
) -> impl Fn(State<AppState>, Request, Next) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Response> + Send>,
> + Clone
where
    F: Fn(&Request) -> bool + Clone + Send + Sync + 'static,
{
    move |state: State<AppState>, request: Request, next: Next| {
        let condition = condition.clone();
        let consent_type = consent_type;

        Box::pin(async move {
            if condition(&request) {
                // Apply consent check
                require_consent(consent_type)(state, request, next).await
            } else {
                // Skip consent check
                next.run(request).await
            }
        })
    }
}

/// Builder for consent middleware with custom configuration
#[derive(Clone)]
pub struct ConsentMiddlewareBuilder {
    consent_type: ConsentType,
    min_version: Option<String>,
    custom_error_message: Option<String>,
    allow_override: bool,
}

impl ConsentMiddlewareBuilder {
    /// Create a new builder
    pub fn new(consent_type: ConsentType) -> Self {
        Self {
            consent_type,
            min_version: None,
            custom_error_message: None,
            allow_override: false,
        }
    }

    /// Set minimum version required
    pub fn min_version(mut self, version: impl Into<String>) -> Self {
        self.min_version = Some(version.into());
        self
    }

    /// Set custom error message
    pub fn error_message(mut self, message: impl Into<String>) -> Self {
        self.custom_error_message = Some(message.into());
        self
    }

    /// Allow admin override
    pub fn allow_admin_override(mut self) -> Self {
        self.allow_override = true;
        self
    }

    /// Build the middleware
    pub fn build(
        self,
    ) -> impl Fn(State<AppState>, Request, Next) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Response> + Send>,
    > + Clone {
        move |State(state): State<AppState>, request: Request, next: Next| {
            let builder = self.clone();

            Box::pin(async move {
                // Get current user from extensions
                let user = match request.extensions().get::<CurrentUser>() {
                    Some(u) => u.clone(),
                    None => {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(serde_json::json!({
                                "error": {
                                    "code": "UNAUTHORIZED",
                                    "message": "Authentication required"
                                }
                            })),
                        )
                            .into_response();
                    }
                };

                // Check for admin override
                if builder.allow_override {
                    let is_admin = user
                        .claims
                        .roles
                        .as_ref()
                        .map(|r| r.iter().any(|role| role == "admin" || role == "superadmin"))
                        .unwrap_or(false);

                    if is_admin {
                        return next.run(request).await;
                    }
                }

                // Create consent manager
                let repository = crate::consent::ConsentRepository::new(state.db.pool().clone());
                let config = crate::consent::ConsentConfig::default();
                let manager = ConsentManager::new(repository, config);

                // Build requirement
                let mut requirement = ConsentRequirement::new(builder.consent_type);

                if let Some(ref version) = builder.min_version {
                    requirement = requirement.min_version(version.clone());
                }

                if let Some(ref message) = builder.custom_error_message {
                    requirement = requirement.error_message(message.clone());
                }

                // Check consent
                match manager.check_consent(&user.user_id, &requirement).await {
                    Ok(()) => next.run(request).await,
                    Err(e) => {
                        tracing::warn!("Consent check failed: {}", e);

                        let error_response = ConsentRequiredError {
                            error: ConsentErrorDetail {
                                code: "CONSENT_REQUIRED".to_string(),
                                message: builder
                                    .custom_error_message
                                    .clone()
                                    .unwrap_or_else(|| {
                                        format!(
                                            "{} consent required",
                                            builder.consent_type.display_name()
                                        )
                                    }),
                                consent_type: format!("{:?}", builder.consent_type).to_lowercase(),
                                consent_url: Some("/consents".to_string()),
                            },
                        };

                        (StatusCode::FORBIDDEN, Json(error_response)).into_response()
                    }
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consent_middleware_builder() {
        let builder = ConsentMiddlewareBuilder::new(ConsentType::Analytics)
            .min_version("2.0")
            .error_message("Please accept analytics to continue")
            .allow_admin_override();

        assert_eq!(builder.min_version, Some("2.0".to_string()));
        assert!(builder.allow_override);
    }
}
