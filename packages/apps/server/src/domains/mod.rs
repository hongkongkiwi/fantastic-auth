//! Domain verification module
//!
//! Handles domain verification for organizations, enabling B2B auto-enrollment.
//! Supports multiple verification methods: DNS TXT, HTML meta tag, and file upload.
//!
//! Also includes custom domain (white-label) support for tenant-specific authentication domains.

pub mod custom;
pub mod custom_repository;
pub mod custom_service;
pub mod models;
pub mod repository;
pub mod service;
pub mod verification;

pub use custom::*;
pub use custom_repository::SqlxCustomDomainRepository;
pub use custom_service::CustomDomainService;
pub use models::*;
pub use repository::DomainRepository;
pub use service::DomainService;
pub use verification::DnsVerifier;
