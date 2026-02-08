//! Authentication module
//!
//! Contains authentication-related components including:
//! - Step-up authentication (sudo mode)
//! - Step-up policies
//! - Account linking
//! - Web3 authentication (SIWE)

pub mod account_linking;
pub mod policies;
pub mod step_up;
pub mod web3;

pub use account_linking::{
    AccountLinkingError, AccountLinkingService, AuthProvider, LinkAccountRequest, LinkedAccount,
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
