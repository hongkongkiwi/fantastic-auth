//! SAML Federation Provider
//!
//! Implements SAML 2.0 federation support for Vault.

use base64::Engine;
use std::collections::HashMap;

use crate::saml::{SamlRequest, SamlResponse, SamlService, ServiceProviderConfig, IdentityProviderConfig};
use crate::saml::{NameIdFormat, SamlBinding};
use crate::saml::crypto::X509Certificate;

use super::{SamlProviderConfig, TokenResponse};

/// SAML Federation Provider implementation
#[derive(Debug, Clone)]
pub struct SamlFederationProvider {
    config: SamlProviderConfig,
}

/// SAML AuthN request wrapper
#[derive(Debug, Clone)]
pub struct SamlAuthnRequest {
    pub id: String,
    pub xml: String,
    pub relay_state: Option<String>,
}

impl SamlFederationProvider {
    /// Create a new SAML federation provider
    pub fn new(config: SamlProviderConfig) -> Self {
        Self { config }
    }

    /// Build SAML authentication request
    pub fn build_authn_request(&self, relay_state: Option<String>) -> anyhow::Result<SamlAuthnRequest> {
        let id = format!("_{}", uuid::Uuid::new_v4());
        
        let name_id_format = NameIdFormat::from_str(&self.config.name_id_format)
            .unwrap_or(NameIdFormat::EmailAddress);

        let request = SamlRequest::new(
            &self.config.entity_id,
            &self.config.sso_url,
            &self.config.entity_id, // ACS URL same as entity ID for IdP-initiated
        )
        .with_name_id_format(name_id_format);

        let xml = request.to_xml()
            .map_err(|e| anyhow::anyhow!("Failed to generate AuthnRequest: {}", e))?;

        Ok(SamlAuthnRequest {
            id,
            xml,
            relay_state,
        })
    }

    /// Build redirect URL with encoded SAML request
    pub fn build_redirect_url(&self, relay_state: Option<String>) -> anyhow::Result<String> {
        let sp_config = ServiceProviderConfig {
            entity_id: self.config.entity_id.clone(),
            acs_url: format!("{}/acs", self.config.entity_id),
            slo_url: self.config.slo_url.clone(),
            metadata_url: format!("{}/metadata", self.config.entity_id),
            certificate: None,
            private_key: self.config.sp_private_key.clone(),
            want_authn_requests_signed: false,
            want_assertions_signed: self.config.want_assertions_signed,
            want_assertions_encrypted: self.config.want_assertions_encrypted,
            name_id_format: NameIdFormat::from_str(&self.config.name_id_format)
                .unwrap_or(NameIdFormat::EmailAddress),
            organization: None,
            contacts: vec![],
        };

        let idp_config = IdentityProviderConfig {
            entity_id: self.config.entity_id.clone(),
            sso_url: self.config.sso_url.clone(),
            slo_url: self.config.slo_url.clone(),
            certificate: X509Certificate::from_pem(&self.config.certificate)
                .map_err(|e| anyhow::anyhow!("Invalid certificate: {}", e))?,
            bindings: vec![SamlBinding::HttpRedirect, SamlBinding::HttpPost],
            name_id_format: NameIdFormat::from_str(&self.config.name_id_format)
                .unwrap_or(NameIdFormat::EmailAddress),
            attribute_mappings: self.config.attribute_mappings.clone(),
            clock_skew_seconds: 300,
        };

        let saml_service = SamlService::new(sp_config)
            .map_err(|e| anyhow::anyhow!("Failed to create SAML service: {}", e))?
            .with_identity_provider(idp_config);

        let request = saml_service.create_authn_request(relay_state.clone())
            .map_err(|e| anyhow::anyhow!("Failed to create AuthnRequest: {}", e))?;

        let url = saml_service.build_redirect_url(&request)
            .map_err(|e| anyhow::anyhow!("Failed to build redirect URL: {}", e))?;

        Ok(url)
    }

    /// Process SAML Response (ACS callback)
    pub async fn process_saml_response(
        &self,
        saml_response: &str,
        relay_state: Option<&str>,
    ) -> anyhow::Result<SamlProcessResult> {
        let sp_config = ServiceProviderConfig {
            entity_id: self.config.entity_id.clone(),
            acs_url: format!("{}/acs", self.config.entity_id),
            slo_url: self.config.slo_url.clone(),
            metadata_url: format!("{}/metadata", self.config.entity_id),
            certificate: None,
            private_key: self.config.sp_private_key.clone(),
            want_authn_requests_signed: false,
            want_assertions_signed: self.config.want_assertions_signed,
            want_assertions_encrypted: self.config.want_assertions_encrypted,
            name_id_format: NameIdFormat::from_str(&self.config.name_id_format)
                .unwrap_or(NameIdFormat::EmailAddress),
            organization: None,
            contacts: vec![],
        };

        let idp_config = IdentityProviderConfig {
            entity_id: self.config.entity_id.clone(),
            sso_url: self.config.sso_url.clone(),
            slo_url: self.config.slo_url.clone(),
            certificate: X509Certificate::from_pem(&self.config.certificate)
                .map_err(|e| anyhow::anyhow!("Invalid certificate: {}", e))?,
            bindings: vec![SamlBinding::HttpPost],
            name_id_format: NameIdFormat::from_str(&self.config.name_id_format)
                .unwrap_or(NameIdFormat::EmailAddress),
            attribute_mappings: self.config.attribute_mappings.clone(),
            clock_skew_seconds: 300,
        };

        let saml_service = SamlService::new(sp_config)
            .map_err(|e| anyhow::anyhow!("Failed to create SAML service: {}", e))?
            .with_identity_provider(idp_config);

        let response = saml_service.parse_response(saml_response, relay_state).await
            .map_err(|e| anyhow::anyhow!("Failed to parse SAML response: {}", e))?;

        // Extract user information from assertions
        let mut result = SamlProcessResult {
            name_id: String::new(),
            name_id_format: String::new(),
            session_index: None,
            attributes: HashMap::new(),
        };

        if let Some(assertion) = response.assertions.first() {
            result.name_id = assertion.subject.name_id.clone();
            result.name_id_format = format!("{:?}", assertion.subject.name_id_format);
            
            if let Some(ref authn) = assertion.authn_statement {
                result.session_index = authn.session_index.clone();
            }

            // Extract attributes
            for stmt in &assertion.attribute_statements {
                for attr in &stmt.attributes {
                    let key = attr.name.clone();
                    let value = attr.values.join(",");
                    result.attributes.insert(key, value);
                }
            }
        }

        Ok(result)
    }

    /// Generate SP metadata XML
    pub fn generate_metadata(&self) -> anyhow::Result<String> {
        let acs_url = format!("{}/acs", self.config.entity_id);
        let slo_url = self.config.slo_url.as_ref()
            .map(|_| format!("{}/slo", self.config.entity_id));

        let cert_xml = if let Some(ref cert_pem) = self.config.sp_certificate {
            let cert = X509Certificate::from_pem(cert_pem)
                .map_err(|e| anyhow::anyhow!("Invalid certificate: {}", e))?;
            let cert_der_b64 = base64::engine::general_purpose::STANDARD.encode(&cert.der);
            format!(
                r#"<KeyDescriptor use="signing">
                <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data>
                        <X509Certificate>{}</X509Certificate>
                    </X509Data>
                </KeyInfo>
            </KeyDescriptor>"#,
                cert_der_b64
            )
        } else {
            String::new()
        };

        let slo_xml = if let Some(ref slo) = slo_url {
            format!(
                r#"<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{}"/>"#,
                slo
            )
        } else {
            String::new()
        };

        let metadata = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}">
    <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="{}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        {}
        {}
        <NameIDFormat>{}</NameIDFormat>
        <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{}" index="0" isDefault="true"/>
    </SPSSODescriptor>
</EntityDescriptor>"#,
            self.config.entity_id,
            self.config.want_assertions_signed,
            cert_xml,
            slo_xml,
            self.config.name_id_format,
            acs_url
        );

        Ok(metadata)
    }

    /// Create a logout request
    pub fn create_logout_request(&self, name_id: &str, session_index: Option<&str>) -> anyhow::Result<String> {
        use crate::saml::LogoutRequest;

        let slo_url = self.config.slo_url.as_ref()
            .ok_or_else(|| anyhow::anyhow!("SLO URL not configured"))?;

        let name_id_format = NameIdFormat::from_str(&self.config.name_id_format)
            .unwrap_or(NameIdFormat::EmailAddress);

        let mut request = LogoutRequest::new(
            &self.config.entity_id,
            slo_url,
            name_id,
        );
        request.name_id_format = name_id_format;
        request.session_index = session_index.map(|s| s.to_string());

        let xml = request.to_xml()
            .map_err(|e| anyhow::anyhow!("Failed to create logout request: {}", e))?;

        Ok(xml)
    }
}

/// Result of processing a SAML response
#[derive(Debug, Clone)]
pub struct SamlProcessResult {
    pub name_id: String,
    pub name_id_format: String,
    pub session_index: Option<String>,
    pub attributes: HashMap<String, String>,
}

impl SamlProcessResult {
    /// Convert to claims HashMap for further processing
    pub fn to_claims(&self) -> HashMap<String, String> {
        let mut claims = self.attributes.clone();
        claims.insert("sub".to_string(), self.name_id.clone());
        claims.insert("name_id".to_string(), self.name_id.clone());
        claims.insert("name_id_format".to_string(), self.name_id_format.clone());
        if let Some(ref session) = self.session_index {
            claims.insert("session_index".to_string(), session.clone());
        }
        claims
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SamlProviderConfig {
        // Generate a test certificate
        let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4nEHXqzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDH
-----END CERTIFICATE-----"#.to_string();

        SamlProviderConfig {
            entity_id: "https://sp.example.com".to_string(),
            sso_url: "https://idp.example.com/sso".to_string(),
            slo_url: Some("https://idp.example.com/slo".to_string()),
            certificate: cert_pem,
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            attribute_mappings: [
                ("email".to_string(), "email".to_string()),
                ("name".to_string(), "name".to_string()),
            ].into_iter().collect(),
            want_assertions_signed: true,
            want_assertions_encrypted: false,
            sp_private_key: None,
            sp_certificate: None,
        }
    }

    #[test]
    fn test_build_authn_request() {
        let config = test_config();
        let provider = SamlFederationProvider::new(config);
        
        let request = provider.build_authn_request(Some("relay-state-123")).unwrap();
        
        assert!(request.id.starts_with('_'));
        assert!(request.xml.contains("AuthnRequest"));
        assert!(request.xml.contains("https://sp.example.com"));
    }

    #[test]
    fn test_generate_metadata() {
        let config = test_config();
        let provider = SamlFederationProvider::new(config);
        
        let metadata = provider.generate_metadata().unwrap();
        
        assert!(metadata.contains("EntityDescriptor"));
        assert!(metadata.contains("SPSSODescriptor"));
        assert!(metadata.contains("https://sp.example.com"));
        assert!(metadata.contains("AssertionConsumerService"));
    }
}
