//! HTTP middleware

pub mod anonymous;
pub mod audit;
pub mod auth;
pub mod admin_roles;
pub mod bot_protection;
pub mod consent;
pub mod geo;
pub mod i18n;
pub mod m2m_auth;
pub mod permission;
pub mod rate_limit;
pub mod security;
pub mod step_up;
pub mod tenant;

pub use anonymous::{
    is_anonymous_user, reject_anonymous_users, require_anonymous_user,
    anonymous_path_restrictions, is_anonymous_restricted_path,
    AnonymousLimits, get_anonymous_limits,
};
pub use audit::{audit_middleware, log_action, log_admin_event, log_auth_event};
pub use auth::auth_middleware;
pub use bot_protection::{
    bot_protection_middleware, conditional_bot_protection_middleware,
    is_captcha_required_for_login, record_failed_login, reset_failed_login, CaptchaSiteKeyResponse,
};
pub use geo::{
    extract_client_ip, geo_logging_middleware, geo_restriction_middleware, GeoInfo, GeoInfoExt,
};
pub use i18n::{i18n_middleware, language_detection_layer, extract_language};
pub use step_up::{
    check_step_up_required, require_elevated, require_step_up, require_step_up_for_operation,
    StepUpUserExt,
};
