//! SAML 2.0 Validation
//!
//! This module provides comprehensive validation for SAML assertions and responses:
//! - Signature validation
//! - Time validation (NotBefore, NotOnOrAfter)
//! - Audience restriction validation
//! - Subject confirmation validation
//! - Replay attack prevention

use chrono::{DateTime, Duration, Utc};
use std::collections::HashSet;

use super::{
    crypto::{parse_xml_signature, SamlCrypto, XmlSignature},
    ns, AuthnContext, AuthnStatement, SamlAssertion, SamlConditions, SamlError, SamlResponse,
    SamlResult, ServiceProviderConfig, StatusCode, SubjectConfirmation, SubjectConfirmationData,
};

/// SAML validator
#[derive(Debug, Clone)]
pub struct SamlValidator {
    /// Clock skew allowance in seconds
    clock_skew_seconds: i64,
    /// IdP certificate for verification
    idp_certificate: Option<super::crypto::X509Certificate>,
    /// Valid audience values
    valid_audiences: HashSet<String>,
    /// Valid destinations
    valid_destinations: HashSet<String>,
    /// Replay cache
    seen_ids: HashSet<String>,
}

impl SamlValidator {
    /// Create new validator with default clock skew (60 seconds)
    pub fn new(clock_skew_seconds: i64) -> Self {
        Self {
            clock_skew_seconds,
            idp_certificate: None,
            valid_audiences: HashSet::new(),
            valid_destinations: HashSet::new(),
            seen_ids: HashSet::new(),
        }
    }
    
    /// Create validator with IdP configuration
    pub fn with_idp(idp: &super::IdentityProviderConfig) -> Self {
        let mut validator = Self::new(idp.clock_skew_seconds);
        validator.idp_certificate = Some(idp.certificate.clone());
        validator
    }
    
    /// Add valid audience
    pub fn add_audience(&mut self, audience: impl Into<String>) {
        self.valid_audiences.insert(audience.into());
    }
    
    /// Add valid destination
    pub fn add_destination(&mut self, destination: impl Into<String>) {
        self.valid_destinations.insert(destination.into());
    }
    
    /// Validate a SAML Response
    pub fn validate_response(
        &self,
        response: &SamlResponse,
        sp_config: &ServiceProviderConfig,
    ) -> SamlResult<()> {
        // Check for replay
        self.check_replay(&response.id)?;
        
        // Validate status
        self.validate_status(response)?;
        
        // Validate destination if present
        if let Some(ref destination) = response.destination {
            self.validate_destination(destination, sp_config)?;
        }
        
        // Validate issue instant
        self.validate_issue_instant(response.issue_instant)?;
        
        // Validate each assertion
        for assertion in &response.assertions {
            self.validate_assertion(assertion, sp_config, response.in_response_to.as_deref())?;
        }
        
        Ok(())
    }
    
    /// Validate SAML status code
    fn validate_status(&self, response: &SamlResponse) -> SamlResult<()> {
        match response.status {
            StatusCode::Success => Ok(()),
            status => {
                let message = response.status_message.clone()
                    .unwrap_or_else(|| format!("SAML error: {:?}", status));
                Err(SamlError::InvalidResponse(message))
            }
        }
    }
    
    /// Validate a SAML Assertion
    pub fn validate_assertion(
        &self,
        assertion: &SamlAssertion,
        sp_config: &ServiceProviderConfig,
        in_response_to: Option<&str>,
    ) -> SamlResult<()> {
        // Check for replay
        self.check_replay(&assertion.id)?;
        
        // Validate issue instant
        self.validate_issue_instant(assertion.issue_instant)?;
        
        // Validate conditions
        self.validate_conditions(&assertion.conditions, sp_config)?;
        
        // Validate subject
        if let Some(ref confirmation) = assertion.subject.subject_confirmation {
            self.validate_subject_confirmation(
                confirmation,
                sp_config,
                in_response_to,
            )?;
        }
        
        // Validate authentication statement
        if let Some(ref authn) = assertion.authn_statement {
            self.validate_authn_statement(authn)?;
        }
        
        // Validate signature if required
        if sp_config.want_assertions_signed {
            self.validate_assertion_signature(assertion)?;
        }
        
        Ok(())
    }
    
    /// Validate assertion conditions
    fn validate_conditions(
        &self,
        conditions: &SamlConditions,
        sp_config: &ServiceProviderConfig,
    ) -> SamlResult<()> {
        let now = Utc::now();
        let skew = Duration::seconds(self.clock_skew_seconds);
        
        // Validate NotBefore
        let not_before = conditions.not_before - skew;
        if now < not_before {
            return Err(SamlError::TimeError(format!(
                "Assertion not yet valid. NotBefore: {}, Current time: {}",
                conditions.not_before, now
            )));
        }
        
        // Validate NotOnOrAfter
        let not_on_or_after = conditions.not_on_or_after + skew;
        if now >= not_on_or_after {
            return Err(SamlError::AssertionExpired);
        }
        
        // Validate audience restrictions
        if !conditions.audience_restrictions.is_empty() {
            let mut found_valid_audience = false;
            
            for audience in &conditions.audience_restrictions {
                if audience == &sp_config.entity_id {
                    found_valid_audience = true;
                    break;
                }
            }
            
            if !found_valid_audience {
                return Err(SamlError::AudienceMismatch {
                    expected: sp_config.entity_id.clone(),
                    actual: conditions.audience_restrictions.join(", "),
                });
            }
        }
        
        Ok(())
    }
    
    /// Validate subject confirmation
    fn validate_subject_confirmation(
        &self,
        confirmation: &SubjectConfirmation,
        sp_config: &ServiceProviderConfig,
        in_response_to: Option<&str>,
    ) -> SamlResult<()> {
        // Check method
        if confirmation.method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
            // Only bearer confirmation is supported
            return Err(SamlError::ValidationError(format!(
                "Unsupported subject confirmation method: {}",
                confirmation.method
            )));
        }
        
        // Validate subject confirmation data
        if let Some(ref data) = confirmation.data {
            self.validate_subject_confirmation_data(data, sp_config, in_response_to)?;
        }
        
        Ok(())
    }
    
    /// Validate subject confirmation data
    fn validate_subject_confirmation_data(
        &self,
        data: &SubjectConfirmationData,
        sp_config: &ServiceProviderConfig,
        in_response_to: Option<&str>,
    ) -> SamlResult<()> {
        let now = Utc::now();
        let skew = Duration::seconds(self.clock_skew_seconds);
        
        // Validate NotOnOrAfter
        let not_on_or_after = data.not_on_or_after + skew;
        if now >= not_on_or_after {
            return Err(SamlError::TimeError(
                "Subject confirmation data has expired".to_string()
            ));
        }
        
        // Validate NotBefore if present
        if let Some(not_before) = data.not_before {
            let not_before = not_before - skew;
            if now < not_before {
                return Err(SamlError::TimeError(
                    "Subject confirmation data not yet valid".to_string()
                ));
            }
        }
        
        // Validate recipient (should be ACS URL)
        if let Some(ref recipient) = data.recipient {
            if recipient != &sp_config.acs_url {
                return Err(SamlError::DestinationMismatch {
                    expected: sp_config.acs_url.clone(),
                    actual: recipient.clone(),
                });
            }
        }
        
        // Validate InResponseTo
        if let Some(ref response_to) = data.in_response_to {
            if let Some(expected) = in_response_to {
                if response_to != expected {
                    return Err(SamlError::ValidationError(format!(
                        "InResponseTo mismatch: expected {}, got {}",
                        expected, response_to
                    )));
                }
            }
        }
        
        Ok(())
    }
    
    /// Validate authentication statement
    fn validate_authn_statement(&self, authn: &AuthnStatement) -> SamlResult<()> {
        // Validate authentication instant
        let now = Utc::now();
        let skew = Duration::seconds(self.clock_skew_seconds);
        
        // AuthnInstant should not be in the future
        if authn.authn_instant > now + skew {
            return Err(SamlError::TimeError(
                "AuthnInstant is in the future".to_string()
            ));
        }
        
        // Validate authentication context
        self.validate_authn_context(&authn.authn_context)?;
        
        Ok(())
    }
    
    /// Validate authentication context
    fn validate_authn_context(&self, context: &AuthnContext) -> SamlResult<()> {
        // Check that the authentication context class reference is valid
        let valid_contexts = [
            "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
            "urn:federation:authentication:windows",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
        ];
        
        if !valid_contexts.contains(&context.class_ref.as_str()) {
            // Not a fatal error, but log a warning
            tracing::warn!("Unrecognized authentication context: {}", context.class_ref);
        }
        
        Ok(())
    }
    
    /// Validate assertion signature
    fn validate_assertion_signature(&self, assertion: &SamlAssertion) -> SamlResult<()> {
        if let Some(ref raw_xml) = assertion.raw_xml {
            return self.validate_xml_signature(raw_xml);
        }
        
        Err(SamlError::InvalidSignature(
            "No signature found on assertion".to_string()
        ))
    }
    
    /// Validate XML signature
    fn validate_xml_signature(&self, xml: &str) -> SamlResult<()> {
        // Parse the XML signature
        let signature = parse_xml_signature(xml)?;
        
        let signature = match signature {
            Some(sig) => sig,
            None => {
                return Err(SamlError::InvalidSignature(
                    "No XML signature found".to_string()
                ));
            }
        };
        
        // Get IdP certificate
        let idp_cert = self.idp_certificate.as_ref()
            .ok_or_else(|| SamlError::ConfigurationError(
                "No IdP certificate configured for signature validation".to_string()
            ))?;
        
        // Create crypto instance with IdP certificate
        let crypto = SamlCrypto::new(None, None)?
            .with_idp_certificate(idp_cert.clone());
        
        // Validate signature
        let valid = crypto.verify_xml_signature(xml, &signature)?;
        
        if !valid {
            return Err(SamlError::InvalidSignature(
                "XML signature validation failed".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Validate issue instant
    fn validate_issue_instant(&self, issue_instant: DateTime<Utc>) -> SamlResult<()> {
        let now = Utc::now();
        let skew = Duration::seconds(self.clock_skew_seconds);
        
        // IssueInstant should not be in the future
        if issue_instant > now + skew {
            return Err(SamlError::TimeError(format!(
                "IssueInstant is in the future: {}",
                issue_instant
            )));
        }
        
        // IssueInstant should not be too old (e.g., more than 5 minutes)
        let max_age = Duration::minutes(5);
        if issue_instant < now - max_age - skew {
            return Err(SamlError::TimeError(format!(
                "IssueInstant is too old: {}",
                issue_instant
            )));
        }
        
        Ok(())
    }
    
    /// Validate destination
    fn validate_destination(
        &self,
        destination: &str,
        sp_config: &ServiceProviderConfig,
    ) -> SamlResult<()> {
        let valid_destinations = vec![
            &sp_config.acs_url,
            sp_config.slo_url.as_deref().unwrap_or(""),
        ];
        
        if !valid_destinations.iter().any(|d| *d == destination) {
            return Err(SamlError::DestinationMismatch {
                expected: sp_config.acs_url.clone(),
                actual: destination.to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Check for replay attack
    fn check_replay(&self, id: &str) -> SamlResult<()> {
        // In a production implementation, this should check against a persistent store
        // (e.g., Redis or database) to prevent replays across server restarts
        
        if self.seen_ids.contains(id) {
            return Err(SamlError::ReplayDetected);
        }
        
        // Note: In production, add to seen_ids and set TTL
        Ok(())
    }
}

/// Validate a NameID format string
pub fn validate_name_id_format(format: &str) -> SamlResult<()> {
    let valid_formats = [
        ns::NAMEID_EMAIL,
        ns::NAMEID_TRANSIENT,
        ns::NAMEID_PERSISTENT,
        ns::NAMEID_UNSPECIFIED,
        "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
    ];
    
    if !valid_formats.contains(&format) {
        return Err(SamlError::UnsupportedNameIdFormat(format.to_string()));
    }
    
    Ok(())
}

/// Validate a SAML binding
pub fn validate_binding(binding: &str) -> SamlResult<()> {
    let valid_bindings = [
        ns::BINDING_HTTP_REDIRECT,
        ns::BINDING_HTTP_POST,
        ns::BINDING_HTTP_ARTIFACT,
        ns::BINDING_SOAP,
        "urn:oasis:names:tc:SAML:2.0:bindings:PAOS",
        "urn:oasis:names:tc:SAML:2.0:bindings:Discovery",
        "urn:oasis:names:tc:SAML:2.0:profiles:holder-of-key:SSO:browser",
    ];
    
    if !valid_bindings.contains(&binding) {
        return Err(SamlError::UnsupportedBinding(binding.to_string()));
    }
    
    Ok(())
}

/// Validate SAML version
pub fn validate_version(version: &str) -> SamlResult<()> {
    if version != "2.0" {
        return Err(SamlError::ValidationError(format!(
            "Unsupported SAML version: {}. Only 2.0 is supported.",
            version
        )));
    }
    
    Ok(())
}

/// Validate and normalize a SAML attribute
pub fn validate_attribute(
    name: &str,
    values: &[String],
    name_format: Option<&str>,
) -> SamlResult<()> {
    // Check that name is not empty
    if name.is_empty() {
        return Err(SamlError::ValidationError(
            "Attribute name cannot be empty".to_string()
        ));
    }
    
    // Validate name format if provided
    if let Some(format) = name_format {
        let valid_formats = [
            "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
            "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        ];
        
        if !valid_formats.contains(&format) {
            tracing::warn!("Unrecognized attribute name format: {}", format);
        }
    }
    
    // Validate values
    for value in values {
        if value.len() > 1024 * 1024 { // 1MB limit per value
            return Err(SamlError::ValidationError(format!(
                "Attribute value too long for attribute: {}",
                name
            )));
        }
    }
    
    Ok(())
}

/// Replay cache using Redis
pub struct ReplayCache {
    redis: redis::aio::ConnectionManager,
    ttl_seconds: u64,
}

impl ReplayCache {
    /// Create new replay cache
    pub fn new(redis: redis::aio::ConnectionManager, ttl_seconds: u64) -> Self {
        Self { redis, ttl_seconds }
    }
    
    /// Check if ID has been seen before
    pub async fn check(&mut self, id: &str) -> SamlResult<bool> {
        let key = format!("saml:replay:{}", id);
        
        let exists: bool = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut self.redis)
            .await
            .map_err(|e| SamlError::InternalError(format!("Redis error: {}", e)))?;
        
        if exists {
            return Ok(true);
        }
        
        // Add to cache with TTL
        let _: () = redis::cmd("SETEX")
            .arg(&key)
            .arg(self.ttl_seconds)
            .arg("1")
            .query_async(&mut self.redis)
            .await
            .map_err(|e| SamlError::InternalError(format!("Redis error: {}", e)))?;
        
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{NameIdFormat, SamlSubject};
    
    fn create_test_sp_config() -> ServiceProviderConfig {
        ServiceProviderConfig {
            entity_id: "https://sp.example.com".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            slo_url: Some("https://sp.example.com/slo".to_string()),
            metadata_url: "https://sp.example.com/metadata".to_string(),
            certificate: None,
            private_key: None,
            want_authn_requests_signed: false,
            want_assertions_signed: false,
            want_assertions_encrypted: false,
            name_id_format: NameIdFormat::EmailAddress,
            organization: None,
            contacts: Vec::new(),
        }
    }
    
    fn create_test_assertion() -> SamlAssertion {
        SamlAssertion {
            id: "_assertion1".to_string(),
            issuer: "https://idp.example.com".to_string(),
            issue_instant: Utc::now(),
            subject: SamlSubject {
                name_id: "user@example.com".to_string(),
                name_id_format: NameIdFormat::EmailAddress,
                subject_confirmation: Some(SubjectConfirmation {
                    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string(),
                    data: Some(SubjectConfirmationData {
                        not_before: None,
                        not_on_or_after: Utc::now() + Duration::hours(1),
                        recipient: Some("https://sp.example.com/acs".to_string()),
                        in_response_to: Some("_request1".to_string()),
                        address: None,
                    }),
                }),
            },
            conditions: SamlConditions {
                not_before: Utc::now() - Duration::minutes(5),
                not_on_or_after: Utc::now() + Duration::hours(1),
                audience_restrictions: vec!["https://sp.example.com".to_string()],
            },
            authn_statement: Some(AuthnStatement {
                authn_instant: Utc::now() - Duration::minutes(1),
                session_index: Some("session123".to_string()),
                authn_context: AuthnContext {
                    class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".to_string(),
                    authenticating_authorities: vec![],
                },
            }),
            attribute_statements: vec![],
            raw_xml: None,
        }
    }
    
    #[test]
    fn test_validate_conditions_valid() {
        let validator = SamlValidator::new(60);
        let sp_config = create_test_sp_config();
        let assertion = create_test_assertion();
        
        assert!(validator.validate_conditions(&assertion.conditions, &sp_config).is_ok());
    }
    
    #[test]
    fn test_validate_conditions_expired() {
        let validator = SamlValidator::new(60);
        let sp_config = create_test_sp_config();
        let mut assertion = create_test_assertion();
        
        // Set NotOnOrAfter to the past
        assertion.conditions.not_on_or_after = Utc::now() - Duration::hours(1);
        
        let result = validator.validate_conditions(&assertion.conditions, &sp_config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SamlError::AssertionExpired));
    }
    
    #[test]
    fn test_validate_conditions_not_yet_valid() {
        let validator = SamlValidator::new(60);
        let sp_config = create_test_sp_config();
        let mut assertion = create_test_assertion();
        
        // Set NotBefore to the future
        assertion.conditions.not_before = Utc::now() + Duration::hours(1);
        
        let result = validator.validate_conditions(&assertion.conditions, &sp_config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SamlError::TimeError(_)));
    }
    
    #[test]
    fn test_validate_conditions_wrong_audience() {
        let validator = SamlValidator::new(60);
        let sp_config = create_test_sp_config();
        let mut assertion = create_test_assertion();
        
        // Set wrong audience
        assertion.conditions.audience_restrictions = vec!["https://wrong-sp.example.com".to_string()];
        
        let result = validator.validate_conditions(&assertion.conditions, &sp_config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SamlError::AudienceMismatch { .. }));
    }
    
    #[test]
    fn test_validate_subject_confirmation_valid() {
        let validator = SamlValidator::new(60);
        let sp_config = create_test_sp_config();
        let assertion = create_test_assertion();
        
        if let Some(ref confirmation) = assertion.subject.subject_confirmation {
            assert!(validator.validate_subject_confirmation(
                confirmation,
                &sp_config,
                Some("_request1")
            ).is_ok());
        }
    }
    
    #[test]
    fn test_validate_subject_confirmation_wrong_recipient() {
        let validator = SamlValidator::new(60);
        let sp_config = create_test_sp_config();
        let mut assertion = create_test_assertion();
        
        // Modify recipient
        if let Some(ref mut confirmation) = assertion.subject.subject_confirmation {
            if let Some(ref mut data) = confirmation.data {
                data.recipient = Some("https://wrong.example.com/acs".to_string());
            }
        }
        
        if let Some(ref confirmation) = assertion.subject.subject_confirmation {
            let result = validator.validate_subject_confirmation(confirmation, &sp_config, None);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), SamlError::DestinationMismatch { .. }));
        }
    }
    
    #[test]
    fn test_validate_version() {
        assert!(validate_version("2.0").is_ok());
        assert!(validate_version("1.1").is_err());
        assert!(validate_version("3.0").is_err());
    }
    
    #[test]
    fn test_validate_binding() {
        assert!(validate_binding(ns::BINDING_HTTP_REDIRECT).is_ok());
        assert!(validate_binding(ns::BINDING_HTTP_POST).is_ok());
        assert!(validate_binding("invalid-binding").is_err());
    }
    
    #[test]
    fn test_validate_name_id_format() {
        assert!(validate_name_id_format(ns::NAMEID_EMAIL).is_ok());
        assert!(validate_name_id_format(ns::NAMEID_TRANSIENT).is_ok());
        assert!(validate_name_id_format("invalid-format").is_err());
    }
}
