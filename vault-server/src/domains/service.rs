//! Domain service
//!
//! High-level service for domain verification and auto-enrollment.
//! Coordinates between repository, verification, and webhook notifications.

use crate::domains::models::{
    AutoEnrollmentResult, CreateDomainRequest, DomainResponse, DomainStatus, OrganizationDomain,
    UpdateDomainRequest, VerificationMethod,
};
use crate::domains::repository::DomainRepository;
use crate::domains::verification::{DnsVerifier, VerificationResult};
use crate::webhooks::events as webhook_events;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Domain service for managing organization domains
#[derive(Clone)]
pub struct DomainService {
    repository: DomainRepository,
    verifier: DnsVerifier,
    pool: Arc<PgPool>,
}

impl DomainService {
    /// Create a new domain service
    pub async fn new(pool: Arc<PgPool>) -> anyhow::Result<Self> {
        let repository = DomainRepository::new(pool.clone());
        let verifier = DnsVerifier::new().await?;

        Ok(Self {
            repository,
            verifier,
            pool,
        })
    }

    /// Create a new domain for an organization
    pub async fn create_domain(
        &self,
        tenant_id: &str,
        organization_id: &str,
        request: CreateDomainRequest,
    ) -> anyhow::Result<DomainResponse> {
        // Validate domain format
        let domain = request.domain.to_lowercase().trim().to_string();

        if !Self::is_valid_domain(&domain) {
            anyhow::bail!("Invalid domain format: {}", domain);
        }

        // Check if domain already exists for this organization
        if self
            .repository
            .exists(tenant_id, organization_id, &domain)
            .await?
        {
            anyhow::bail!(
                "Domain '{}' is already registered for this organization",
                domain
            );
        }

        // Generate verification token
        let token = DnsVerifier::generate_token();

        // Create domain
        let mut domain_record =
            OrganizationDomain::new(tenant_id, organization_id, &domain, &token);

        // Apply optional settings
        if let Some(auto_enroll) = request.auto_enroll_enabled {
            domain_record.set_auto_enroll(auto_enroll);
        }
        if let Some(default_role) = request.default_role {
            domain_record.set_default_role(default_role);
        }

        // Save to database
        let domain_record = self.repository.create(&domain_record).await?;

        info!(
            "Created domain '{}' for organization {} in tenant {}",
            domain, organization_id, tenant_id
        );

        Ok(domain_record.into())
    }

    /// List all domains for an organization
    pub async fn list_domains(
        &self,
        tenant_id: &str,
        organization_id: &str,
    ) -> anyhow::Result<Vec<DomainResponse>> {
        let domains = self
            .repository
            .list_for_organization(tenant_id, organization_id)
            .await?;
        Ok(domains.into_iter().map(Into::into).collect())
    }

    /// Get a single domain by ID
    pub async fn get_domain(
        &self,
        tenant_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<Option<DomainResponse>> {
        let domain = self.repository.get_by_id(tenant_id, domain_id).await?;
        Ok(domain.map(Into::into))
    }

    /// Delete a domain
    pub async fn delete_domain(
        &self,
        tenant_id: &str,
        organization_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<()> {
        // Verify the domain belongs to the organization
        if let Some(domain) = self.repository.get_by_id(tenant_id, domain_id).await? {
            if domain.organization_id != organization_id {
                anyhow::bail!("Domain does not belong to this organization");
            }
        }

        self.repository.delete(tenant_id, domain_id).await?;

        info!(
            "Deleted domain {} for organization {} in tenant {}",
            domain_id, organization_id, tenant_id
        );

        Ok(())
    }

    /// Update domain settings
    pub async fn update_domain(
        &self,
        tenant_id: &str,
        organization_id: &str,
        domain_id: &str,
        request: UpdateDomainRequest,
    ) -> anyhow::Result<DomainResponse> {
        // Verify the domain belongs to the organization
        if let Some(domain) = self.repository.get_by_id(tenant_id, domain_id).await? {
            if domain.organization_id != organization_id {
                anyhow::bail!("Domain does not belong to this organization");
            }
        }

        let domain = self
            .repository
            .update_settings(
                tenant_id,
                domain_id,
                request.auto_enroll_enabled,
                request.default_role,
            )
            .await?;

        info!(
            "Updated domain {} for organization {} in tenant {}",
            domain_id, organization_id, tenant_id
        );

        Ok(domain.into())
    }

    /// Verify a domain using DNS
    pub async fn verify_domain_dns(
        &self,
        tenant_id: &str,
        organization_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<VerificationResult> {
        let domain = self.repository.get_by_id(tenant_id, domain_id).await?;

        let domain = match domain {
            Some(d) => d,
            None => anyhow::bail!("Domain not found"),
        };

        if domain.organization_id != organization_id {
            anyhow::bail!("Domain does not belong to this organization");
        }

        if domain.status == DomainStatus::Verified {
            return Ok(VerificationResult {
                success: true,
                method: VerificationMethod::Dns,
                message: "Domain is already verified".to_string(),
                records_found: None,
            });
        }

        // Perform DNS verification
        let result = self
            .verifier
            .verify_dns(&domain.domain, &domain.verification_token)
            .await?;

        // Update domain status based on result
        if result.success {
            self.repository
                .update_status(
                    tenant_id,
                    domain_id,
                    DomainStatus::Verified,
                    Some(VerificationMethod::Dns),
                )
                .await?;

            info!(
                "Successfully verified domain '{}' for organization {} via DNS",
                domain.domain, organization_id
            );
        } else {
            // Mark as failed if not already pending
            self.repository
                .update_status(tenant_id, domain_id, DomainStatus::Failed, None)
                .await?;

            warn!(
                "Failed to verify domain '{}' for organization {}: {}",
                domain.domain, organization_id, result.message
            );
        }

        Ok(result)
    }

    /// Verify a domain using HTML meta tag
    pub async fn verify_domain_html(
        &self,
        tenant_id: &str,
        organization_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<VerificationResult> {
        let domain = self.repository.get_by_id(tenant_id, domain_id).await?;

        let domain = match domain {
            Some(d) => d,
            None => anyhow::bail!("Domain not found"),
        };

        if domain.organization_id != organization_id {
            anyhow::bail!("Domain does not belong to this organization");
        }

        if domain.status == DomainStatus::Verified {
            return Ok(VerificationResult {
                success: true,
                method: VerificationMethod::HtmlMeta,
                message: "Domain is already verified".to_string(),
                records_found: None,
            });
        }

        // Perform HTML meta verification
        let result = self
            .verifier
            .verify_html_meta(&domain.domain, &domain.verification_token)
            .await?;

        // Update domain status based on result
        if result.success {
            self.repository
                .update_status(
                    tenant_id,
                    domain_id,
                    DomainStatus::Verified,
                    Some(VerificationMethod::HtmlMeta),
                )
                .await?;

            info!(
                "Successfully verified domain '{}' for organization {} via HTML meta tag",
                domain.domain, organization_id
            );
        } else {
            self.repository
                .update_status(tenant_id, domain_id, DomainStatus::Failed, None)
                .await?;
        }

        Ok(result)
    }

    /// Verify a domain using file upload
    pub async fn verify_domain_file(
        &self,
        tenant_id: &str,
        organization_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<VerificationResult> {
        let domain = self.repository.get_by_id(tenant_id, domain_id).await?;

        let domain = match domain {
            Some(d) => d,
            None => anyhow::bail!("Domain not found"),
        };

        if domain.organization_id != organization_id {
            anyhow::bail!("Domain does not belong to this organization");
        }

        if domain.status == DomainStatus::Verified {
            return Ok(VerificationResult {
                success: true,
                method: VerificationMethod::File,
                message: "Domain is already verified".to_string(),
                records_found: None,
            });
        }

        // Perform file verification
        let result = self
            .verifier
            .verify_file(&domain.domain, &domain.verification_token)
            .await?;

        // Update domain status based on result
        if result.success {
            self.repository
                .update_status(
                    tenant_id,
                    domain_id,
                    DomainStatus::Verified,
                    Some(VerificationMethod::File),
                )
                .await?;

            info!(
                "Successfully verified domain '{}' for organization {} via file upload",
                domain.domain, organization_id
            );
        } else {
            self.repository
                .update_status(tenant_id, domain_id, DomainStatus::Failed, None)
                .await?;
        }

        Ok(result)
    }

    /// Verify domain with any available method
    pub async fn verify_domain_any(
        &self,
        tenant_id: &str,
        organization_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<VerificationResult> {
        let domain = self.repository.get_by_id(tenant_id, domain_id).await?;

        let domain = match domain {
            Some(d) => d,
            None => anyhow::bail!("Domain not found"),
        };

        if domain.organization_id != organization_id {
            anyhow::bail!("Domain does not belong to this organization");
        }

        if domain.status == DomainStatus::Verified {
            return Ok(VerificationResult {
                success: true,
                method: VerificationMethod::Dns,
                message: "Domain is already verified".to_string(),
                records_found: None,
            });
        }

        // Try any verification method
        let result = self
            .verifier
            .verify_any(&domain.domain, &domain.verification_token)
            .await?;

        // Update domain status based on result
        if result.success {
            self.repository
                .update_status(
                    tenant_id,
                    domain_id,
                    DomainStatus::Verified,
                    Some(result.method),
                )
                .await?;

            info!(
                "Successfully verified domain '{}' for organization {} via {:?}",
                domain.domain, organization_id, result.method
            );
        }

        Ok(result)
    }

    /// Check if a user should be auto-enrolled in an organization based on email domain
    pub async fn check_auto_enrollment(&self, email: &str) -> anyhow::Result<AutoEnrollmentResult> {
        // Extract domain from email
        let domain = match email.split('@').nth(1) {
            Some(d) => d.to_lowercase(),
            None => {
                return Ok(AutoEnrollmentResult {
                    enrolled: false,
                    organization_id: None,
                    role: None,
                })
            }
        };

        // Look up verified domain
        let org_domain = self.repository.get_verified_by_domain(&domain).await?;

        match org_domain {
            Some(d) if d.is_verified() && d.auto_enroll_enabled => Ok(AutoEnrollmentResult {
                enrolled: true,
                organization_id: Some(d.organization_id),
                role: Some(d.default_role),
            }),
            _ => Ok(AutoEnrollmentResult {
                enrolled: false,
                organization_id: None,
                role: None,
            }),
        }
    }

    /// Auto-enroll a user in an organization
    pub async fn auto_enroll_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        email: &str,
    ) -> anyhow::Result<AutoEnrollmentResult> {
        let result = self.check_auto_enrollment(email).await?;

        if !result.enrolled {
            return Ok(result);
        }

        let organization_id = result.organization_id.as_ref().unwrap();
        let role = result.role.as_ref().unwrap();

        // Check if user is already a member
        let org_repo = vault_core::db::OrganizationRepository::new(self.pool.clone());
        let existing = org_repo
            .get_member(tenant_id, organization_id, user_id)
            .await?;

        if existing.is_some() {
            info!(
                "User {} is already a member of organization {}, skipping auto-enrollment",
                user_id, organization_id
            );
            return Ok(AutoEnrollmentResult {
                enrolled: false,
                organization_id: Some(organization_id.clone()),
                role: Some(role.clone()),
            });
        }

        // Parse the role
        let role_enum = role
            .parse::<vault_core::models::organization::OrganizationRole>()
            .unwrap_or(vault_core::models::organization::OrganizationRole::Member);

        // Create membership
        let member = vault_core::models::organization::OrganizationMember::new(
            tenant_id,
            organization_id,
            user_id,
            role_enum,
        );

        // Set status to active (auto-enrolled users are immediately active)
        let mut member = member;
        member.accept();

        org_repo.add_member(tenant_id, &member).await?;

        info!(
            "Auto-enrolled user {} in organization {} with role {} (via domain {})",
            user_id,
            organization_id,
            role,
            email.split('@').nth(1).unwrap_or("")
        );

        Ok(result)
    }

    /// Validate domain format
    fn is_valid_domain(domain: &str) -> bool {
        // Basic domain validation
        // Must not be empty
        if domain.is_empty() || domain.len() > 253 {
            return false;
        }

        // Must not contain spaces or special characters
        if domain.contains(' ') || domain.contains('\t') {
            return false;
        }

        // Must contain at least one dot (e.g., example.com)
        if !domain.contains('.') {
            return false;
        }

        // Must not start or end with a dot
        if domain.starts_with('.') || domain.ends_with('.') {
            return false;
        }

        // Must not have consecutive dots
        if domain.contains("..") {
            return false;
        }

        // Each label must be valid
        for label in domain.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }

            // Labels must start and end with alphanumeric
            let first_char = label.chars().next().unwrap();
            let last_char = label.chars().last().unwrap();

            if !first_char.is_alphanumeric() || !last_char.is_alphanumeric() {
                return false;
            }

            // Labels can only contain alphanumeric and hyphens
            for c in label.chars() {
                if !c.is_alphanumeric() && c != '-' {
                    return false;
                }
            }
        }

        true
    }

    /// Get repository reference
    pub fn repository(&self) -> &DomainRepository {
        &self.repository
    }
}

/// Auto-enrollment service helper
pub struct AutoEnrollmentService {
    domain_service: DomainService,
}

impl AutoEnrollmentService {
    /// Create a new auto-enrollment service
    pub async fn new(pool: Arc<PgPool>) -> anyhow::Result<Self> {
        let domain_service = DomainService::new(pool).await?;
        Ok(Self { domain_service })
    }

    /// Process auto-enrollment for a newly registered user
    pub async fn process_user_registration(
        &self,
        tenant_id: &str,
        user_id: &str,
        email: &str,
        state: &crate::state::AppState,
    ) -> anyhow::Result<AutoEnrollmentResult> {
        // Check and perform auto-enrollment
        let result = self
            .domain_service
            .auto_enroll_user(tenant_id, user_id, email)
            .await?;

        if result.enrolled {
            if let Some(org_id) = &result.organization_id {
                // Trigger webhook for user joined organization
                webhook_events::trigger_user_joined_organization(
                    state,
                    tenant_id,
                    user_id,
                    email,
                    org_id,
                    result.role.as_deref(),
                    true, // auto_enrolled
                )
                .await;

                // TODO: Send notification to org admins
                // This would typically be handled by a notification service
                info!(
                    "User {} auto-enrolled in organization {}. Admins should be notified.",
                    user_id, org_id
                );
            }
        }

        Ok(result)
    }
}

/// Webhook event extensions for domain-related events
pub mod webhook_events_ext {
    use crate::state::AppState;
    use serde_json::json;

    /// Trigger a user.joined_organization webhook event
    pub async fn trigger_user_joined_organization(
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        email: &str,
        organization_id: &str,
        role: Option<&str>,
        auto_enrolled: bool,
    ) {
        let payload = json!({
            "user_id": user_id,
            "email": email,
            "organization_id": organization_id,
            "role": role,
            "auto_enrolled": auto_enrolled,
            "joined_at": chrono::Utc::now().to_rfc3339(),
        });

        trigger_event(state, tenant_id, "user.joined_organization", payload).await;
    }

    /// Trigger a domain.verified webhook event
    pub async fn trigger_domain_verified(
        state: &AppState,
        tenant_id: &str,
        domain_id: &str,
        domain: &str,
        organization_id: &str,
        method: &str,
    ) {
        let payload = json!({
            "domain_id": domain_id,
            "domain": domain,
            "organization_id": organization_id,
            "verification_method": method,
            "verified_at": chrono::Utc::now().to_rfc3339(),
        });

        trigger_event(state, tenant_id, "domain.verified", payload).await;
    }

    /// Generic helper to trigger any webhook event
    async fn trigger_event(
        state: &AppState,
        tenant_id: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) {
        use tracing::{debug, error};

        if !state.config.webhook.enabled {
            debug!(
                "Webhook processing is disabled, skipping event: {}",
                event_type
            );
            return;
        }

        match state
            .webhook_service
            .trigger_event(tenant_id, event_type, payload)
            .await
        {
            Ok(deliveries) => {
                debug!(
                    event_type = event_type,
                    delivery_count = deliveries.len(),
                    "Webhook event triggered"
                );
            }
            Err(e) => {
                error!(
                    event_type = event_type,
                    error = %e,
                    "Failed to trigger webhook event"
                );
            }
        }
    }
}
