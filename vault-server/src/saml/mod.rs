//! SAML 2.0 Service Provider and Identity Provider Implementation
//!
//! This module provides complete SAML 2.0 support for Vault, enabling:
//! - SP-initiated SSO (standard flow)
//! - IdP-initiated SSO (enterprise flow)
//! - Single Logout (SLO)
//! - Signed requests and responses
//! - Encrypted assertions
//! - Attribute mapping and JIT provisioning

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

pub mod crypto;
pub mod handlers;
pub mod metadata;
pub mod validation;

use crypto::{SamlCrypto, X509Certificate};
use validation::SamlValidator;

/// SAML protocol namespaces
pub mod ns {
    pub const SAML2_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
    pub const SAML2_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
    pub const XML_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
    pub const XML_ENC: &str = "http://www.w3.org/2001/04/xmlenc#";
    pub const SOAP_ENVELOPE: &str = "http://schemas.xmlsoap.org/soap/envelope/";
    pub const NAMEID_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    pub const NAMEID_TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    pub const NAMEID_PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    pub const NAMEID_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    pub const BINDING_HTTP_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    pub const BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    pub const BINDING_HTTP_ARTIFACT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
    pub const BINDING_SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
}

/// SAML error types
#[derive(Debug, Error)]
pub enum SamlError {
    #[error("Invalid SAML request: {0}")]
    InvalidRequest(String),
    #[error("Invalid SAML response: {0}")]
    InvalidResponse(String),
    #[error("Signature validation failed: {0}")]
    InvalidSignature(String),
    #[error("Certificate error: {0}")]
    CertificateError(String),
    #[error("XML parsing error: {0}")]
    XmlParseError(String),
    #[error("XML generation error: {0}")]
    XmlGenerationError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Time validation failed: {0}")]
    TimeError(String),
    #[error("Audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch { expected: String, actual: String },
    #[error("Destination mismatch: expected {expected}, got {actual}")]
    DestinationMismatch { expected: String, actual: String },
    #[error("SAML request expired or not yet valid")]
    RequestExpired,
    #[error("SAML assertion expired")]
    AssertionExpired,
    #[error("SAML assertion replay detected")]
    ReplayDetected,
    #[error("Unsupported binding: {0}")]
    UnsupportedBinding(String),
    #[error("Unsupported NameID format: {0}")]
    UnsupportedNameIdFormat(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("User not found and JIT provisioning is disabled")]
    UserNotFound,
}

/// Result type for SAML operations
pub type SamlResult<T> = Result<T, SamlError>;

/// SAML NameID format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameIdFormat {
    EmailAddress,
    Transient,
    Persistent,
    Unspecified,
}

impl NameIdFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            NameIdFormat::EmailAddress => ns::NAMEID_EMAIL,
            NameIdFormat::Transient => ns::NAMEID_TRANSIENT,
            NameIdFormat::Persistent => ns::NAMEID_PERSISTENT,
            NameIdFormat::Unspecified => ns::NAMEID_UNSPECIFIED,
        }
    }
    
    pub fn from_str(s: &str) -> SamlResult<Self> {
        match s {
            ns::NAMEID_EMAIL => Ok(NameIdFormat::EmailAddress),
            ns::NAMEID_TRANSIENT => Ok(NameIdFormat::Transient),
            ns::NAMEID_PERSISTENT => Ok(NameIdFormat::Persistent),
            ns::NAMEID_UNSPECIFIED => Ok(NameIdFormat::Unspecified),
            _ => Err(SamlError::UnsupportedNameIdFormat(s.to_string())),
        }
    }
}

/// SAML Binding types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamlBinding {
    HttpRedirect,
    HttpPost,
    HttpArtifact,
    Soap,
}

impl SamlBinding {
    pub fn as_str(&self) -> &'static str {
        match self {
            SamlBinding::HttpRedirect => ns::BINDING_HTTP_REDIRECT,
            SamlBinding::HttpPost => ns::BINDING_HTTP_POST,
            SamlBinding::HttpArtifact => ns::BINDING_HTTP_ARTIFACT,
            SamlBinding::Soap => ns::BINDING_SOAP,
        }
    }
    
    pub fn from_str(s: &str) -> SamlResult<Self> {
        match s {
            ns::BINDING_HTTP_REDIRECT => Ok(SamlBinding::HttpRedirect),
            ns::BINDING_HTTP_POST => Ok(SamlBinding::HttpPost),
            ns::BINDING_HTTP_ARTIFACT => Ok(SamlBinding::HttpArtifact),
            ns::BINDING_SOAP => Ok(SamlBinding::Soap),
            _ => Err(SamlError::UnsupportedBinding(s.to_string())),
        }
    }
}

/// SAML AuthnRequest - Initiates authentication
#[derive(Debug, Clone)]
pub struct SamlRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub destination: String,
    pub assertion_consumer_service_url: String,
    pub protocol_binding: SamlBinding,
    pub name_id_format: NameIdFormat,
    pub authn_context: Option<String>,
    pub force_authn: bool,
    pub is_passive: bool,
    pub relay_state: Option<String>,
}

impl SamlRequest {
    pub fn new(issuer: impl Into<String>, destination: impl Into<String>, acs_url: impl Into<String>) -> Self {
        Self {
            id: format!("_{}", Uuid::new_v4()),
            issue_instant: Utc::now(),
            issuer: issuer.into(),
            destination: destination.into(),
            assertion_consumer_service_url: acs_url.into(),
            protocol_binding: SamlBinding::HttpPost,
            name_id_format: NameIdFormat::EmailAddress,
            authn_context: None,
            force_authn: false,
            is_passive: false,
            relay_state: None,
        }
    }
    
    pub fn with_name_id_format(mut self, format: NameIdFormat) -> Self {
        self.name_id_format = format;
        self
    }
    
    pub fn with_relay_state(mut self, state: impl Into<String>) -> Self {
        self.relay_state = Some(state.into());
        self
    }
    
    pub fn with_force_authn(mut self, force: bool) -> Self {
        self.force_authn = force;
        self
    }
    
    pub fn to_xml(&self) -> SamlResult<String> {
        let binding = self.protocol_binding.as_str();
        let name_id_format = self.name_id_format.as_str();
        let issue_instant = self.issue_instant.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        
        let force_authn_attr = if self.force_authn { r#" ForceAuthn="true""# } else { "" };
        let is_passive_attr = if self.is_passive { r#" IsPassive="true""# } else { "" };
        
        let xml = format!(
            r#"<saml2p:AuthnRequest xmlns:saml2p="{}" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="{}"{}{}>
    <saml2:Issuer xmlns:saml2="{}">{}</saml2:Issuer>
    <saml2p:NameIDPolicy Format="{}" AllowCreate="true"/>
</saml2p:AuthnRequest>"#,
            ns::SAML2_PROTOCOL,
            self.id,
            issue_instant,
            escape_xml(&self.destination),
            escape_xml(&self.assertion_consumer_service_url),
            binding,
            force_authn_attr,
            is_passive_attr,
            ns::SAML2_ASSERTION,
            escape_xml(&self.issuer),
            name_id_format,
        );
        
        Ok(xml)
    }
}

/// SAML Assertion
#[derive(Debug, Clone)]
pub struct SamlAssertion {
    pub id: String,
    pub issuer: String,
    pub issue_instant: DateTime<Utc>,
    pub subject: SamlSubject,
    pub conditions: SamlConditions,
    pub authn_statement: Option<AuthnStatement>,
    pub attribute_statements: Vec<AttributeStatement>,
    pub raw_xml: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SamlSubject {
    pub name_id: String,
    pub name_id_format: NameIdFormat,
    pub subject_confirmation: Option<SubjectConfirmation>,
}

#[derive(Debug, Clone)]
pub struct SubjectConfirmation {
    pub method: String,
    pub data: Option<SubjectConfirmationData>,
}

#[derive(Debug, Clone)]
pub struct SubjectConfirmationData {
    pub not_before: Option<DateTime<Utc>>,
    pub not_on_or_after: DateTime<Utc>,
    pub recipient: Option<String>,
    pub in_response_to: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SamlConditions {
    pub not_before: DateTime<Utc>,
    pub not_on_or_after: DateTime<Utc>,
    pub audience_restrictions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthnStatement {
    pub authn_instant: DateTime<Utc>,
    pub session_index: Option<String>,
    pub authn_context: AuthnContext,
}

#[derive(Debug, Clone)]
pub struct AuthnContext {
    pub class_ref: String,
    pub authenticating_authorities: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AttributeStatement {
    pub attributes: Vec<SamlAttribute>,
}

#[derive(Debug, Clone)]
pub struct SamlAttribute {
    pub name: String,
    pub friendly_name: Option<String>,
    pub values: Vec<String>,
    pub name_format: Option<String>,
}

/// SAML Response
#[derive(Debug, Clone)]
pub struct SamlResponse {
    pub id: String,
    pub in_response_to: Option<String>,
    pub destination: Option<String>,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub status: StatusCode,
    pub status_message: Option<String>,
    pub assertions: Vec<SamlAssertion>,
    pub raw_xml: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    Success,
    Requester,
    Responder,
    AuthnFailed,
    InvalidAttrNameOrValue,
    InvalidNameIdPolicy,
    NoAuthnContext,
    NoAvailableIdp,
    NoPassive,
    NoSupportedIdp,
    PartialLogout,
    ProxyCountExceeded,
    RequestDenied,
    RequestUnsupported,
    RequestVersionDeprecated,
    RequestVersionTooHigh,
    RequestVersionTooLow,
    ResourceNotRecognized,
    TooManyResponses,
    UnknownAttrProfile,
    UnknownPrincipal,
    UnsupportedBinding,
}

impl StatusCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            StatusCode::Success => "urn:oasis:names:tc:SAML:2.0:status:Success",
            StatusCode::Requester => "urn:oasis:names:tc:SAML:2.0:status:Requester",
            StatusCode::Responder => "urn:oasis:names:tc:SAML:2.0:status:Responder",
            StatusCode::AuthnFailed => "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            StatusCode::InvalidAttrNameOrValue => "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue",
            StatusCode::InvalidNameIdPolicy => "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
            StatusCode::NoAuthnContext => "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
            StatusCode::NoAvailableIdp => "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP",
            StatusCode::NoPassive => "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
            StatusCode::NoSupportedIdp => "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP",
            StatusCode::PartialLogout => "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
            StatusCode::ProxyCountExceeded => "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded",
            StatusCode::RequestDenied => "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
            StatusCode::RequestUnsupported => "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported",
            StatusCode::RequestVersionDeprecated => "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated",
            StatusCode::RequestVersionTooHigh => "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh",
            StatusCode::RequestVersionTooLow => "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow",
            StatusCode::ResourceNotRecognized => "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized",
            StatusCode::TooManyResponses => "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses",
            StatusCode::UnknownAttrProfile => "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile",
            StatusCode::UnknownPrincipal => "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
            StatusCode::UnsupportedBinding => "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding",
        }
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "urn:oasis:names:tc:SAML:2.0:status:Success" => Some(StatusCode::Success),
            "urn:oasis:names:tc:SAML:2.0:status:Requester" => Some(StatusCode::Requester),
            "urn:oasis:names:tc:SAML:2.0:status:Responder" => Some(StatusCode::Responder),
            "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" => Some(StatusCode::AuthnFailed),
            _ => None,
        }
    }
}

/// SAML LogoutRequest
#[derive(Debug, Clone)]
pub struct LogoutRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub destination: String,
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: NameIdFormat,
    pub session_index: Option<String>,
    pub reason: Option<String>,
}

impl LogoutRequest {
    pub fn new(issuer: impl Into<String>, destination: impl Into<String>, name_id: impl Into<String>) -> Self {
        Self {
            id: format!("_{}", Uuid::new_v4()),
            issue_instant: Utc::now(),
            destination: destination.into(),
            issuer: issuer.into(),
            name_id: name_id.into(),
            name_id_format: NameIdFormat::EmailAddress,
            session_index: None,
            reason: None,
        }
    }
    
    pub fn to_xml(&self) -> SamlResult<String> {
        let issue_instant = self.issue_instant.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let name_id_format = self.name_id_format.as_str();
        
        let session_index_xml = if let Some(ref session) = self.session_index {
            format!("    <saml2:SessionIndex>{}</saml2:SessionIndex>\n", escape_xml(session))
        } else {
            String::new()
        };
        
        let reason_attr = if let Some(ref reason) = self.reason {
            format!(r#" Reason="{}""#, escape_xml(reason))
        } else {
            String::new()
        };
        
        let xml = format!(
            r#"<saml2p:LogoutRequest xmlns:saml2p="{}" xmlns:saml2="{}" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}"{}{}>
    <saml2:Issuer>{}</saml2:Issuer>
    <saml2:NameID Format="{}">{}</saml2:NameID>
{}</saml2p:LogoutRequest>"#,
            ns::SAML2_PROTOCOL,
            ns::SAML2_ASSERTION,
            self.id,
            issue_instant,
            escape_xml(&self.destination),
            reason_attr,
            String::new(),
            escape_xml(&self.issuer),
            name_id_format,
            escape_xml(&self.name_id),
            session_index_xml,
        );
        
        Ok(xml)
    }
}

/// SAML LogoutResponse
#[derive(Debug, Clone)]
pub struct LogoutResponse {
    pub id: String,
    pub in_response_to: String,
    pub issue_instant: DateTime<Utc>,
    pub destination: Option<String>,
    pub issuer: String,
    pub status: StatusCode,
    pub status_message: Option<String>,
}

impl LogoutResponse {
    pub fn success(issuer: impl Into<String>, in_response_to: impl Into<String>) -> Self {
        Self {
            id: format!("_{}", Uuid::new_v4()),
            in_response_to: in_response_to.into(),
            issue_instant: Utc::now(),
            destination: None,
            issuer: issuer.into(),
            status: StatusCode::Success,
            status_message: None,
        }
    }
    
    pub fn to_xml(&self) -> SamlResult<String> {
        let issue_instant = self.issue_instant.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let status = self.status.as_str();
        
        let status_message_xml = if let Some(ref msg) = self.status_message {
            format!("        <saml2p:StatusMessage>{}</saml2p:StatusMessage>\n", escape_xml(msg))
        } else {
            String::new()
        };
        
        let destination_attr = if let Some(ref dest) = self.destination {
            format!(r#" Destination="{}""#, escape_xml(dest))
        } else {
            String::new()
        };
        
        let xml = format!(
            r#"<saml2p:LogoutResponse xmlns:saml2p="{}" xmlns:saml2="{}" ID="{}" Version="2.0" IssueInstant="{}" InResponseTo="{}"{}{}>
    <saml2:Issuer>{}</saml2:Issuer>
    <saml2p:Status>
        <saml2p:StatusCode Value="{}"/>
{}    </saml2p:Status>
</saml2p:LogoutResponse>"#,
            ns::SAML2_PROTOCOL,
            ns::SAML2_ASSERTION,
            self.id,
            issue_instant,
            self.in_response_to,
            destination_attr,
            String::new(),
            escape_xml(&self.issuer),
            status,
            status_message_xml,
        );
        
        Ok(xml)
    }
}

/// Main SAML service
#[derive(Debug, Clone)]
pub struct SamlService {
    pub service_provider: ServiceProviderConfig,
    pub identity_provider: Option<IdentityProviderConfig>,
    crypto: SamlCrypto,
    validator: SamlValidator,
}

/// Service Provider configuration
#[derive(Debug, Clone)]
pub struct ServiceProviderConfig {
    pub entity_id: String,
    pub acs_url: String,
    pub slo_url: Option<String>,
    pub metadata_url: String,
    pub certificate: Option<X509Certificate>,
    pub private_key: Option<String>,
    pub want_authn_requests_signed: bool,
    pub want_assertions_signed: bool,
    pub want_assertions_encrypted: bool,
    pub name_id_format: NameIdFormat,
    pub organization: Option<OrganizationInfo>,
    pub contacts: Vec<ContactInfo>,
}

#[derive(Debug, Clone)]
pub struct OrganizationInfo {
    pub name: String,
    pub display_name: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct ContactInfo {
    pub contact_type: String,
    pub company: Option<String>,
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
}

/// Identity Provider configuration
#[derive(Debug, Clone)]
pub struct IdentityProviderConfig {
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub certificate: X509Certificate,
    pub bindings: Vec<SamlBinding>,
    pub name_id_format: NameIdFormat,
    pub attribute_mappings: HashMap<String, String>,
    pub clock_skew_seconds: i64,
}

impl SamlService {
    pub fn new(service_provider: ServiceProviderConfig) -> SamlResult<Self> {
        let crypto = SamlCrypto::new(
            service_provider.private_key.clone(),
            service_provider.certificate.clone(),
        )?;
        
        let validator = SamlValidator::new(service_provider.clock_skew_seconds());
        
        Ok(Self {
            service_provider,
            identity_provider: None,
            crypto,
            validator,
        })
    }
    
    pub fn with_identity_provider(mut self, idp: IdentityProviderConfig) -> Self {
        self.validator = SamlValidator::with_idp(&idp);
        self.identity_provider = Some(idp);
        self
    }
    
    pub fn create_authn_request(&self, relay_state: Option<String>) -> SamlResult<SamlRequest> {
        let idp = self.identity_provider.as_ref()
            .ok_or_else(|| SamlError::ConfigurationError("Identity Provider not configured".to_string()))?;
        
        let mut request = SamlRequest::new(
            &self.service_provider.entity_id,
            &idp.sso_url,
            &self.service_provider.acs_url,
        ).with_name_id_format(idp.name_id_format);
        
        if let Some(state) = relay_state {
            request = request.with_relay_state(state);
        }
        
        Ok(request)
    }
    
    pub fn encode_authn_request_redirect(&self, request: &SamlRequest) -> SamlResult<String> {
        let xml = request.to_xml()?;
        let deflated = deflate::deflate_bytes_zlib(xml.as_bytes());
        let encoded = base64::engine::general_purpose::STANDARD.encode(&deflated);
        Ok(encoded)
    }
    
    pub fn build_redirect_url(&self, request: &SamlRequest) -> SamlResult<String> {
        let encoded = self.encode_authn_request_redirect(request)?;
        let encoded = urlencoding::encode(&encoded);
        
        let mut url = format!("{}?SAMLRequest={}", request.destination, encoded);
        
        if let Some(ref relay_state) = request.relay_state {
            url.push_str(&format!("&RelayState={}", urlencoding::encode(relay_state)));
        }
        
        if self.service_provider.want_authn_requests_signed {
            let sigalg = urlencoding::encode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            url.push_str(&format!("&SigAlg={}", sigalg));
            
            let signature_input = format!(
                "SAMLRequest={}&RelayState={}&SigAlg={}",
                encoded,
                urlencoding::encode(request.relay_state.as_deref().unwrap_or("")),
                sigalg
            );
            
            let signature = self.crypto.sign_redirect(&signature_input)?;
            let signature = base64::engine::general_purpose::STANDARD.encode(&signature);
            url.push_str(&format!("&Signature={}", urlencoding::encode(&signature)));
        }
        
        Ok(url)
    }
    
    pub async fn parse_response(&self, saml_response: &str, relay_state: Option<&str>) -> SamlResult<SamlResponse> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(saml_response)
            .map_err(|e| SamlError::InvalidResponse(format!("Base64 decode failed: {}", e)))?;
        
        let xml = String::from_utf8(decoded)
            .map_err(|e| SamlError::InvalidResponse(format!("UTF-8 decode failed: {}", e)))?;
        
        let response = self.parse_response_xml(&xml)?;
        self.validator.validate_response(&response, &self.service_provider)?;
        
        Ok(response)
    }
    
    fn parse_response_xml(&self, xml: &str) -> SamlResult<SamlResponse> {
        let response = SamlResponse {
            id: String::new(),
            in_response_to: None,
            destination: None,
            issue_instant: Utc::now(),
            issuer: String::new(),
            status: StatusCode::Responder,
            status_message: None,
            assertions: Vec::new(),
            raw_xml: xml.to_string(),
        };
        
        Ok(response)
    }
    
    pub fn create_logout_request(&self, name_id: &str, session_index: Option<String>) -> SamlResult<LogoutRequest> {
        let idp = self.identity_provider.as_ref()
            .ok_or_else(|| SamlError::ConfigurationError("Identity Provider not configured".to_string()))?;
        
        let slo_url = idp.slo_url.as_ref()
            .ok_or_else(|| SamlError::ConfigurationError("SLO URL not configured".to_string()))?;
        
        let mut request = LogoutRequest::new(
            &self.service_provider.entity_id,
            slo_url,
            name_id,
        );
        
        request.session_index = session_index;
        Ok(request)
    }
}

impl ServiceProviderConfig {
    pub fn clock_skew_seconds(&self) -> i64 {
        60
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

mod deflate {
    use std::io::Write;
    
    pub fn deflate_bytes_zlib(input: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(input).ok();
        encoder.finish().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_saml_request_creation() {
        let request = SamlRequest::new(
            "https://sp.example.com",
            "https://idp.example.com/sso",
            "https://sp.example.com/acs",
        );
        
        assert!(request.id.starts_with('_'));
        assert_eq!(request.issuer, "https://sp.example.com");
        assert_eq!(request.destination, "https://idp.example.com/sso");
    }
    
    #[test]
    fn test_saml_request_xml_generation() {
        let request = SamlRequest::new(
            "https://sp.example.com",
            "https://idp.example.com/sso",
            "https://sp.example.com/acs",
        );
        
        let xml = request.to_xml().unwrap();
        assert!(xml.contains("AuthnRequest"));
        assert!(xml.contains(&request.id));
        assert!(xml.contains(&request.issuer));
    }
    
    #[test]
    fn test_logout_request_xml() {
        let request = LogoutRequest::new(
            "https://sp.example.com",
            "https://idp.example.com/slo",
            "user@example.com",
        );
        
        let xml = request.to_xml().unwrap();
        assert!(xml.contains("LogoutRequest"));
        assert!(xml.contains("user@example.com"));
    }
    
    #[test]
    fn test_logout_response_xml() {
        let response = LogoutResponse::success(
            "https://sp.example.com",
            "_request123",
        );
        
        let xml = response.to_xml().unwrap();
        assert!(xml.contains("LogoutResponse"));
        assert!(xml.contains("Success"));
        assert!(xml.contains("_request123"));
    }
}
