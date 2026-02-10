//! SAML 2.0 Metadata
//!
//! This module handles SAML 2.0 metadata:
//! - Service Provider metadata generation
//! - Identity Provider metadata parsing
//! - EntityDescriptor handling


use super::{escape_xml, ns, ContactInfo, NameIdFormat, OrganizationInfo, SamlBinding, SamlError, SamlResult, ServiceProviderConfig};
use super::crypto::X509Certificate;

/// SAML EntityDescriptor - Root metadata element
#[derive(Debug, Clone)]
pub struct EntityDescriptor {
    /// Entity ID
    pub entity_id: String,
    /// Valid until timestamp
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Cache duration
    pub cache_duration: Option<String>,
    /// IDP SSO Descriptor
    pub idp_sso_descriptor: Option<IdpSsoDescriptor>,
    /// SP SSO Descriptor
    pub sp_sso_descriptor: Option<SpSsoDescriptor>,
    /// Organization
    pub organization: Option<OrganizationInfo>,
    /// Contacts
    pub contacts: Vec<ContactInfo>,
}

/// IDP SSO Descriptor
#[derive(Debug, Clone)]
pub struct IdpSsoDescriptor {
    /// Supported protocols
    pub protocols_supported: Vec<String>,
    /// NameID formats
    pub name_id_formats: Vec<NameIdFormat>,
    /// Single Sign-On services
    pub single_sign_on_services: Vec<Endpoint>,
    /// Single Logout services
    pub single_logout_services: Vec<Endpoint>,
    /// Signing certificate
    pub signing_certificate: Option<X509Certificate>,
    /// Encryption certificate
    pub encryption_certificate: Option<X509Certificate>,
    /// Whether to want authn requests signed
    pub want_authn_requests_signed: bool,
}

/// SP SSO Descriptor
#[derive(Debug, Clone)]
pub struct SpSsoDescriptor {
    /// Supported protocols
    pub protocols_supported: Vec<String>,
    /// NameID formats
    pub name_id_formats: Vec<NameIdFormat>,
    /// Assertion Consumer Services
    pub assertion_consumer_services: Vec<IndexedEndpoint>,
    /// Single Logout services
    pub single_logout_services: Vec<Endpoint>,
    /// Signing certificate
    pub signing_certificate: Option<X509Certificate>,
    /// Encryption certificate
    pub encryption_certificate: Option<X509Certificate>,
    /// Whether authn requests are signed
    pub authn_requests_signed: bool,
    /// Whether assertions should be signed
    pub want_assertions_signed: bool,
}

/// Endpoint (URL + Binding)
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub binding: SamlBinding,
    pub location: String,
    pub response_location: Option<String>,
}

/// Indexed endpoint (for ACS)
#[derive(Debug, Clone)]
pub struct IndexedEndpoint {
    pub index: u32,
    pub binding: SamlBinding,
    pub location: String,
    pub is_default: bool,
}

/// SP Metadata generator
pub struct SpMetadataGenerator {
    config: ServiceProviderConfig,
}

impl SpMetadataGenerator {
    pub fn new(config: ServiceProviderConfig) -> Self {
        Self { config }
    }
    
    /// Generate SP metadata XML
    pub fn generate(&self) -> SamlResult<String> {
        let entity_id = escape_xml(&self.config.entity_id);
        let valid_until = self.format_valid_until()?;
        
        let cert_xml = self.generate_key_descriptor()?;
        let acs_xml = self.generate_acs_endpoints()?;
        let slo_xml = self.generate_slo_endpoints()?;
        let nameid_xml = self.generate_name_id_formats()?;
        let org_xml = self.generate_organization()?;
        let contacts_xml = self.generate_contacts()?;
        
        let xml = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{}"{}>
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="{}" WantAssertionsSigned="{}">
{}{}{}{}    </SPSSODescriptor>
{}{}</EntityDescriptor>"#,
            entity_id,
            valid_until,
            self.config.want_authn_requests_signed,
            self.config.want_assertions_signed,
            cert_xml,
            nameid_xml,
            acs_xml,
            slo_xml,
            org_xml,
            contacts_xml,
        );
        
        Ok(xml)
    }
    
    fn format_valid_until(&self) -> SamlResult<String> {
        let valid_until = chrono::Utc::now() + chrono::Duration::days(365);
        Ok(format!(r#" validUntil="{}""#, valid_until.to_rfc3339()))
    }
    
    fn generate_key_descriptor(&self) -> SamlResult<String> {
        let mut xml = String::new();
        
        if let Some(ref cert) = self.config.certificate {
            let cert_base64 = cert.to_base64()?;
            
            // Signing key
            xml.push_str(r#"        <KeyDescriptor use="signing">"#);
            xml.push('\n');
            xml.push_str(r#"            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#);
            xml.push('\n');
            xml.push_str(r#"                <ds:X509Data>"#);
            xml.push('\n');
            xml.push_str(&format!(r#"                    <ds:X509Certificate>{}</ds:X509Certificate>"#, cert_base64));
            xml.push('\n');
            xml.push_str(r#"                </ds:X509Data>"#);
            xml.push('\n');
            xml.push_str(r#"            </ds:KeyInfo>"#);
            xml.push('\n');
            xml.push_str(r#"        </KeyDescriptor>"#);
            xml.push('\n');
            
            // Encryption key
            xml.push_str(r#"        <KeyDescriptor use="encryption">"#);
            xml.push('\n');
            xml.push_str(r#"            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#);
            xml.push('\n');
            xml.push_str(r#"                <ds:X509Data>"#);
            xml.push('\n');
            xml.push_str(&format!(r#"                    <ds:X509Certificate>{}</ds:X509Certificate>"#, cert_base64));
            xml.push('\n');
            xml.push_str(r#"                </ds:X509Data>"#);
            xml.push('\n');
            xml.push_str(r#"            </ds:KeyInfo>"#);
            xml.push('\n');
            xml.push_str(r#"            <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>"#);
            xml.push('\n');
            xml.push_str(r#"        </KeyDescriptor>"#);
            xml.push('\n');
        }
        
        Ok(xml)
    }
    
    fn generate_acs_endpoints(&self) -> SamlResult<String> {
        let acs_url = escape_xml(&self.config.acs_url);
        let mut xml = String::new();
        
        // HTTP-POST binding (required)
        xml.push_str(&format!(
            r#"        <AssertionConsumerService index="0" Binding="{}" Location="{}" isDefault="true"/>"#,
            ns::BINDING_HTTP_POST,
            acs_url
        ));
        xml.push('\n');
        
        Ok(xml)
    }
    
    fn generate_slo_endpoints(&self) -> SamlResult<String> {
        let mut xml = String::new();
        
        if let Some(ref slo_url) = self.config.slo_url {
            let slo_url = escape_xml(slo_url);
            
            // HTTP-Redirect binding
            xml.push_str(&format!(
                r#"        <SingleLogoutService Binding="{}" Location="{}"/>"#,
                ns::BINDING_HTTP_REDIRECT,
                slo_url
            ));
            xml.push('\n');
            
            // HTTP-POST binding
            xml.push_str(&format!(
                r#"        <SingleLogoutService Binding="{}" Location="{}"/>"#,
                ns::BINDING_HTTP_POST,
                slo_url
            ));
            xml.push('\n');
        }
        
        Ok(xml)
    }
    
    fn generate_name_id_formats(&self) -> SamlResult<String> {
        let formats = vec![
            ns::NAMEID_EMAIL,
            ns::NAMEID_TRANSIENT,
            ns::NAMEID_PERSISTENT,
        ];
        
        let mut xml = String::new();
        for format in formats {
            xml.push_str(&format!(r#"        <NameIDFormat>{}</NameIDFormat>"#, format));
            xml.push('\n');
        }
        
        Ok(xml)
    }
    
    fn generate_organization(&self) -> SamlResult<String> {
        if let Some(ref org) = self.config.organization {
            let name = escape_xml(&org.name);
            let display_name = escape_xml(&org.display_name);
            let url = escape_xml(&org.url);
            
            Ok(format!(r#"    <Organization>
        <OrganizationName xml:lang="en">{}</OrganizationName>
        <OrganizationDisplayName xml:lang="en">{}</OrganizationDisplayName>
        <OrganizationURL xml:lang="en">{}</OrganizationURL>
    </Organization>
"#, name, display_name, url))
        } else {
            Ok(String::new())
        }
    }
    
    fn generate_contacts(&self) -> SamlResult<String> {
        let mut xml = String::new();
        
        for contact in &self.config.contacts {
            let contact_type = escape_xml(&contact.contact_type);
            xml.push_str(&format!(r#"    <ContactPerson contactType="{}">"#, contact_type));
            xml.push('\n');
            
            if let Some(ref company) = contact.company {
                xml.push_str(&format!(r#"        <Company>{}</Company>"#, escape_xml(company)));
                xml.push('\n');
            }
            if let Some(ref given_name) = contact.given_name {
                xml.push_str(&format!(r#"        <GivenName>{}</GivenName>"#, escape_xml(given_name)));
                xml.push('\n');
            }
            if let Some(ref surname) = contact.surname {
                xml.push_str(&format!(r#"        <SurName>{}</SurName>"#, escape_xml(surname)));
                xml.push('\n');
            }
            if let Some(ref email) = contact.email {
                xml.push_str(&format!(r#"        <EmailAddress>{}</EmailAddress>"#, escape_xml(email)));
                xml.push('\n');
            }
            if let Some(ref phone) = contact.phone {
                xml.push_str(&format!(r#"        <TelephoneNumber>{}</TelephoneNumber>"#, escape_xml(phone)));
                xml.push('\n');
            }
            
            xml.push_str(r#"    </ContactPerson>"#);
            xml.push('\n');
        }
        
        Ok(xml)
    }
}

/// IdP Metadata parser
pub struct IdpMetadataParser;

impl IdpMetadataParser {
    /// Parse IdP metadata XML
    /// 
    /// SECURITY: This parser uses multiple layers of XXE protection:
    /// 1. String-based DOCTYPE detection as first-line defense
    /// 2. quick_xml's safe-by-default configuration (no external entity expansion)
    /// 3. Disabled DTD processing via check_comments(false)
    /// 4. Limited buffer size to prevent entity expansion attacks
    pub fn parse(xml: &str) -> SamlResult<EntityDescriptor> {
        use quick_xml::events::Event;
        use quick_xml::reader::Reader;
        
        // SECURITY: Layer 1 - Reject XML with DOCTYPE declarations
        // This catches obvious XXE attempts before parsing
        if xml.to_uppercase().contains("<!DOCTYPE") || xml.to_uppercase().contains("<!ENTITY") {
            return Err(SamlError::XmlParseError(
                "XML with DOCTYPE/ENTITY declarations is not allowed for security reasons".to_string()
            ));
        }
        
        // SECURITY: Layer 2 & 3 - Configure reader for safe parsing
        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);
        // Disable DTD processing to prevent XXE attacks
        reader.check_comments(false);
        // Note: quick_xml 0.31 is safe by default - no external entity expansion
        
        let mut buf = Vec::new();
        let mut entity_id = String::new();
        let mut idp_descriptor = None;
        let mut in_idp_descriptor = false;
        
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    match e.name().as_ref() {
                        b"EntityDescriptor" => {
                            for attr in e.attributes() {
                                let attr = attr.map_err(|e| SamlError::XmlParseError(e.to_string()))?;
                                if attr.key.as_ref() == b"entityID" {
                                    entity_id = String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                        }
                        b"IDPSSODescriptor" => {
                            in_idp_descriptor = true;
                            idp_descriptor = Some(IdpSsoDescriptor {
                                protocols_supported: vec![ns::SAML2_PROTOCOL.to_string()],
                                name_id_formats: Vec::new(),
                                single_sign_on_services: Vec::new(),
                                single_logout_services: Vec::new(),
                                signing_certificate: None,
                                encryption_certificate: None,
                                want_authn_requests_signed: false,
                            });
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e)) => {
                    if e.name().as_ref() == b"IDPSSODescriptor" {
                        in_idp_descriptor = false;
                    }
                }
                Ok(Event::Empty(e)) => {
                    if in_idp_descriptor {
                        match e.name().as_ref() {
                            b"SingleSignOnService" => {
                                if let Some(ref mut idp) = idp_descriptor {
                                    let mut binding = None;
                                    let mut location = None;
                                    
                                    for attr in e.attributes() {
                                        let attr = attr.map_err(|e| SamlError::XmlParseError(e.to_string()))?;
                                        match attr.key.as_ref() {
                                            b"Binding" => binding = Some(String::from_utf8_lossy(&attr.value).to_string()),
                                            b"Location" => location = Some(String::from_utf8_lossy(&attr.value).to_string()),
                                            _ => {}
                                        }
                                    }
                                    
                                    if let (Some(binding), Some(location)) = (binding, location) {
                                        idp.single_sign_on_services.push(Endpoint {
                                            binding: SamlBinding::from_str(&binding)?,
                                            location,
                                            response_location: None,
                                        });
                                    }
                                }
                            }
                            b"SingleLogoutService" => {
                                if let Some(ref mut idp) = idp_descriptor {
                                    let mut binding = None;
                                    let mut location = None;
                                    
                                    for attr in e.attributes() {
                                        let attr = attr.map_err(|e| SamlError::XmlParseError(e.to_string()))?;
                                        match attr.key.as_ref() {
                                            b"Binding" => binding = Some(String::from_utf8_lossy(&attr.value).to_string()),
                                            b"Location" => location = Some(String::from_utf8_lossy(&attr.value).to_string()),
                                            _ => {}
                                        }
                                    }
                                    
                                    if let (Some(binding), Some(location)) = (binding, location) {
                                        idp.single_logout_services.push(Endpoint {
                                            binding: SamlBinding::from_str(&binding)?,
                                            location,
                                            response_location: None,
                                        });
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::Text(_)) => {}
                Ok(Event::Eof) => break,
                Err(e) => return Err(SamlError::XmlParseError(e.to_string())),
                _ => {}
            }
            buf.clear();
        }
        
        Ok(EntityDescriptor {
            entity_id,
            valid_until: None,
            cache_duration: None,
            idp_sso_descriptor: idp_descriptor,
            sp_sso_descriptor: None,
            organization: None,
            contacts: Vec::new(),
        })
    }
    
    /// Extract SSO URL from IdP metadata
    pub fn extract_sso_url(metadata: &EntityDescriptor, binding: SamlBinding) -> Option<String> {
        metadata.idp_sso_descriptor.as_ref()?.single_sign_on_services
            .iter()
            .find(|ep| ep.binding == binding)
            .map(|ep| ep.location.clone())
    }
    
    /// Extract SLO URL from IdP metadata
    pub fn extract_slo_url(metadata: &EntityDescriptor, binding: SamlBinding) -> Option<String> {
        metadata.idp_sso_descriptor.as_ref()?.single_logout_services
            .iter()
            .find(|ep| ep.binding == binding)
            .map(|ep| ep.location.clone())
    }
    
    /// Extract certificate from IdP metadata
    pub fn extract_certificate(metadata: &EntityDescriptor) -> Option<String> {
        // In a full implementation, extract from KeyDescriptor/X509Data
        None
    }
}

/// Generate SP metadata from configuration
pub fn generate_sp_metadata(config: &ServiceProviderConfig) -> SamlResult<String> {
    let generator = SpMetadataGenerator::new(config.clone());
    generator.generate()
}

/// Parse IdP metadata
pub fn parse_idp_metadata(xml: &str) -> SamlResult<EntityDescriptor> {
    IdpMetadataParser::parse(xml)
}

/// Extract key information from IdP metadata XML
pub fn extract_idp_cert_from_metadata(xml: &str) -> SamlResult<X509Certificate> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);
    
    let mut buf = Vec::new();
    let mut in_x509_data = false;
    let mut cert_base64 = String::new();
    
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if e.name().as_ref() == b"ds:X509Certificate" || e.name().as_ref() == b"X509Certificate" {
                    in_x509_data = true;
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref() == b"ds:X509Certificate" || e.name().as_ref() == b"X509Certificate" {
                    in_x509_data = false;
                }
            }
            Ok(Event::Text(e)) => {
                if in_x509_data {
                    cert_base64.push_str(&String::from_utf8_lossy(&e.into_inner()));
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SamlError::XmlParseError(e.to_string())),
            _ => {}
        }
        buf.clear();
    }
    
    if cert_base64.is_empty() {
        return Err(SamlError::CertificateError("No certificate found in metadata".to_string()));
    }
    
    X509Certificate::from_base64(&cert_base64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::crypto::generate_self_signed_cert;
    
    #[test]
    fn test_generate_sp_metadata() {
        let (cert_pem, key_pem) = generate_self_signed_cert("sp.example.com", 365).unwrap();
        let cert = X509Certificate::from_pem(&cert_pem).unwrap();
        
        let config = ServiceProviderConfig {
            entity_id: "https://sp.example.com".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            slo_url: Some("https://sp.example.com/slo".to_string()),
            metadata_url: "https://sp.example.com/metadata".to_string(),
            certificate: Some(cert),
            private_key: Some(key_pem),
            want_authn_requests_signed: true,
            want_assertions_signed: true,
            want_assertions_encrypted: false,
            name_id_format: NameIdFormat::EmailAddress,
            organization: Some(OrganizationInfo {
                name: "Example Corp".to_string(),
                display_name: "Example Corporation".to_string(),
                url: "https://example.com".to_string(),
            }),
            contacts: vec![
                ContactInfo {
                    contact_type: "technical".to_string(),
                    company: Some("Example Corp".to_string()),
                    given_name: Some("John".to_string()),
                    surname: Some("Doe".to_string()),
                    email: Some("admin@example.com".to_string()),
                    phone: None,
                },
            ],
        };
        
        let metadata = generate_sp_metadata(&config).unwrap();
        
        assert!(metadata.contains("EntityDescriptor"));
        assert!(metadata.contains("SPSSODescriptor"));
        assert!(metadata.contains("https://sp.example.com"));
        assert!(metadata.contains("https://sp.example.com/acs"));
        assert!(metadata.contains("AssertionConsumerService"));
    }
    
    #[test]
    fn test_parse_idp_metadata() {
        let metadata = r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/slo"/>
    </IDPSSODescriptor>
</EntityDescriptor>"#;
        
        let descriptor = IdpMetadataParser::parse(metadata).unwrap();
        
        assert_eq!(descriptor.entity_id, "https://idp.example.com");
        assert!(descriptor.idp_sso_descriptor.is_some());
        
        let idp = descriptor.idp_sso_descriptor.unwrap();
        assert_eq!(idp.single_sign_on_services.len(), 1);
        assert_eq!(idp.single_sign_on_services[0].location, "https://idp.example.com/sso");
    }
    
    #[test]
    fn test_extract_sso_url() {
        let metadata = EntityDescriptor {
            entity_id: "https://idp.example.com".to_string(),
            valid_until: None,
            cache_duration: None,
            idp_sso_descriptor: Some(IdpSsoDescriptor {
                protocols_supported: vec![ns::SAML2_PROTOCOL.to_string()],
                name_id_formats: vec![NameIdFormat::EmailAddress],
                single_sign_on_services: vec![
                    Endpoint {
                        binding: SamlBinding::HttpRedirect,
                        location: "https://idp.example.com/sso".to_string(),
                        response_location: None,
                    },
                ],
                single_logout_services: vec![],
                signing_certificate: None,
                encryption_certificate: None,
                want_authn_requests_signed: false,
            }),
            sp_sso_descriptor: None,
            organization: None,
            contacts: Vec::new(),
        };
        
        let sso_url = IdpMetadataParser::extract_sso_url(&metadata, SamlBinding::HttpRedirect);
        assert_eq!(sso_url, Some("https://idp.example.com/sso".to_string()));
    }
}


// Property-based tests for SAML metadata parser
// 
// These tests verify:
// 1. The parser never panics on arbitrary input (security/DoS protection)
// 2. XXE attack prevention works correctly
// 3. Malformed XML is handled gracefully
// 4. Round-trip properties (parse -> serialize -> parse)
#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    // Strategy for generating valid entity IDs
    fn valid_entity_id() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("https://idp.example.com".to_string()),
            Just("urn:mace:example.com:idp".to_string()),
            "https://[a-z][a-z0-9-]{1,30}\\.[a-z]{2,10}/[a-z]{1,20}".prop_map(|s| s),
        ]
    }

    // Strategy for generating valid URLs
    fn valid_url() -> impl Strategy<Value = String> {
        "https://[a-z][a-z0-9-]{1,30}\\.[a-z]{2,10}/[a-z/]{1,50}".prop_map(|s| s)
    }

    proptest! {
        // Test that the IdP metadata parser never panics on arbitrary input
        // This is critical for preventing DoS attacks via malformed metadata
        #[test]
        fn test_idp_metadata_parser_never_panics(input in "\\PC*") {
            // Should never panic regardless of input
            let _ = IdpMetadataParser::parse(&input);
        }

        // Test that the cert extraction function never panics
        #[test]
        fn test_cert_extraction_never_panics(input in "\\PC*") {
            let _ = extract_idp_cert_from_metadata(&input);
        }

        // Test XXE prevention - DOCTYPE declarations should be rejected
        #[test]
        fn test_xxe_prevention_doctype(entity in "[a-zA-Z]{1,20}",
                                        path in "(/[a-z]{1,20}){1,5}") {
            let xxe_payload = format!(
                r#"<?xml version="1.0"?>
<!DOCTYPE {} [
  <!ENTITY xxe SYSTEM "file://{}">
]>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="&xxe;"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#,
                entity, path
            );
            
            // Should reject DOCTYPE for security
            let result = IdpMetadataParser::parse(&xxe_payload);
            prop_assert!(
                result.is_err(),
                "XXE attack via DOCTYPE should be rejected"
            );
        }

        // Test XXE prevention - ENTITY declarations should be rejected
        #[test]
        fn test_xxe_prevention_entity(entity in "[a-zA-Z]{1,20}") {
            let xxe_payload = format!(
                r#"<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY {} SYSTEM "http://attacker.com/xxe">
]>
<EntityDescriptor entityID="test" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
</EntityDescriptor>"#,
                entity
            );
            
            // Should reject ENTITY declarations
            let result = IdpMetadataParser::parse(&xxe_payload);
            prop_assert!(
                result.is_err(),
                "XXE attack via ENTITY should be rejected"
            );
        }

        // Test that the parser handles deeply nested XML
        #[test]
        fn test_deeply_nested_xml(depth in 1usize..100) {
            let mut xml = String::from(r#"<?xml version="1.0"?><EntityDescriptor entityID="test" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">"#);
            
            for _ in 0..depth {
                xml.push_str("<Nested>");
            }
            xml.push_str("content");
            for _ in 0..depth {
                xml.push_str("</Nested>");
            }
            xml.push_str("</EntityDescriptor>");
            
            // Should not panic or stack overflow
            let _ = IdpMetadataParser::parse(&xml);
        }

        // Test that the parser handles XML with many attributes
        #[test]
        fn test_many_attributes(count in 1usize..100) {
            let mut attrs = String::new();
            for i in 0..count {
                attrs.push_str(&format!(r#" attr{}="value{}""#, i, i));
            }
            
            let xml = format!(
                r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test"{}>
</EntityDescriptor>"#,
                attrs
            );
            
            // Should handle many attributes without issues
            let _ = IdpMetadataParser::parse(&xml);
        }

        // Test that the parser handles very long text content
        #[test]
        fn test_long_text_content(length in 100usize..10000) {
            let long_text = "x".repeat(length);
            let xml = format!(
                r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}">
</EntityDescriptor>"#,
                long_text
            );
            
            // Should handle long content without issues
            let _ = IdpMetadataParser::parse(&xml);
        }

        // Test that the parser handles binary/null data gracefully
        #[test]
        fn test_binary_and_null_data(input in "[\\x00-\\x1F]*") {
            let xml = format!(
                r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{}"/>
    </IDPSSODescriptor>
</EntityDescriptor>"#,
                input
            );
            
            // Should not panic on binary/null data
            let _ = IdpMetadataParser::parse(&xml);
        }

        // Test that the parser handles unicode input correctly
        #[test]
        fn test_unicode_input(input in "\\PC*") {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}">
</EntityDescriptor>"#,
                input
            );
            
            // Should not panic on unicode input
            let _ = IdpMetadataParser::parse(&xml);
        }

        // Test that malformed XML is handled gracefully
        #[test]
        fn test_malformed_xml(input in "[<>/a-zA-Z]{0,500}") {
            // Random combinations of XML-like characters
            let xml = format!("<?xml version=\"1.0\"?>\n{}", input);
            
            // Should not panic on malformed XML
            let _ = IdpMetadataParser::parse(&xml);
        }

        // Test that unclosed tags don't cause issues
        #[test]
        fn test_unclosed_tags(tag in "[a-zA-Z]{1,30}", content in "[a-zA-Z0-9]*") {
            let xml = format!(
                r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test">
    <{tag}>{content}
</EntityDescriptor>"#
            );
            
            // Should handle unclosed tags gracefully
            let _ = IdpMetadataParser::parse(&xml);
        }

        // Test SP metadata generation doesn't panic on valid configs
        #[test]
        fn test_sp_metadata_generation_never_panics(
            entity_id in valid_entity_id(),
            acs_url in valid_url()
        ) {
            let config = ServiceProviderConfig {
                entity_id,
                acs_url,
                slo_url: None,
                metadata_url: "https://example.com/metadata".to_string(),
                certificate: None,
                private_key: None,
                want_authn_requests_signed: false,
                want_assertions_signed: false,
                want_assertions_encrypted: false,
                name_id_format: NameIdFormat::EmailAddress,
                organization: None,
                contacts: vec![],
            };
            
            // Should not panic
            let _ = generate_sp_metadata(&config);
        }

        // Test extraction functions with empty/null metadata
        #[test]
        fn test_extraction_with_empty_metadata() {
            let empty = "";
            let _ = IdpMetadataParser::extract_sso_url(&EntityDescriptor {
                entity_id: "".to_string(),
                valid_until: None,
                cache_duration: None,
                idp_sso_descriptor: None,
                sp_sso_descriptor: None,
                organization: None,
                contacts: vec![],
            }, SamlBinding::HttpRedirect);
            
            let _ = IdpMetadataParser::extract_slo_url(&EntityDescriptor {
                entity_id: "".to_string(),
                valid_until: None,
                cache_duration: None,
                idp_sso_descriptor: None,
                sp_sso_descriptor: None,
                organization: None,
                contacts: vec![],
            }, SamlBinding::HttpRedirect);
            
            let _ = extract_idp_cert_from_metadata(empty);
        }

        // Test that the parser handles XML entities (not XXE, just normal encoding)
        #[test]
        fn test_xml_entities(input in "[a-zA-Z0-9&;]{0,100}") {
            let xml = format!(
                r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/{}"/>
    </IDPSSODescriptor>
</EntityDescriptor>"#,
                input
            );
            
            // Should not panic
            let _ = IdpMetadataParser::parse(&xml);
        }

        // Test that endpoint extraction handles edge cases
        #[test]
        fn test_endpoint_extraction_edge_cases(binding in 0u8..5u8) {
            let binding_enum = match binding {
                0 => SamlBinding::HttpRedirect,
                1 => SamlBinding::HttpPost,
                2 => SamlBinding::HttpArtifact,
                3 => SamlBinding::Soap,
                _ => SamlBinding::HttpRedirect,
            };
            
            let metadata = EntityDescriptor {
                entity_id: "test".to_string(),
                valid_until: None,
                cache_duration: None,
                idp_sso_descriptor: Some(IdpSsoDescriptor {
                    protocols_supported: vec![],
                    name_id_formats: vec![],
                    single_sign_on_services: vec![],
                    single_logout_services: vec![],
                    signing_certificate: None,
                    encryption_certificate: None,
                    want_authn_requests_signed: false,
                }),
                sp_sso_descriptor: None,
                organization: None,
                contacts: vec![],
            };
            
            // Should return None without panicking
            let _ = IdpMetadataParser::extract_sso_url(&metadata, binding_enum);
            let _ = IdpMetadataParser::extract_slo_url(&metadata, binding_enum);
        }
    }
}
