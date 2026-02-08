//! Authentication module
//!
//! Contains authentication-related components including:
//! - Anonymous/guest authentication
//! - Step-up authentication (sudo mode)
//! - Step-up policies
//! - Account linking
//! - Web3 authentication (SIWE)

pub mod account_linking;
pub mod anonymous;
pub mod policies;
pub mod step_up;
pub mod web3;

pub use account_linking::{
    AccountLinkingError, AccountLinkingService, AuthProvider, LinkAccountRequest, LinkedAccount,
};
pub use anonymous::{
    create_anonymous_session, convert_to_full_account, cleanup_expired_anonymous_sessions,
    extend_anonymous_session, validate_anonymous_claims, AnonymousSession,
    AnonymousSessionResponse, AnonymousConversionResponse, ConvertAnonymousRequest,
    CreateAnonymousSessionRequest, AnonymousConversionUser, anonymous_rate_limit_key,
};
pub use policies::{
    SensitiveOperation, StepUpPolicy, StepUpPolicyService, StepUpRequirement,
    DEFAULT_HIGH_ASSURANCE_MAX_AGE_MINUTES, DEFAULT_STEP_UP_MAX_AGE_MINUTES,
};
pub use step_up::{
    is_step_up_valid, methods_to_amr, StepUpAuthMethod, StepUpChallenge, StepUpChallengeResponse,
    StepUpCredentials, StepUpFailureReason, StepUpRequest, StepUpResult, StepUpService,
    StepUpSession, StepUpTokenResponse,
};
