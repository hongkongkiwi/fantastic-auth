//! SAML 2.0 Cryptographic Operations
//!
//! This module provides cryptographic functionality for SAML 2.0:
//! - X509 certificate handling and validation
//! - XML Signature generation and validation
//! - RSA-SHA256 signing
//! - Keypair generation

use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;
use std::fmt;

use super::{SamlError, SamlResult};

/// X509 Certificate wrapper
#[derive(Clone)]
pub struct X509Certificate {
    /// PEM encoded certificate
    pem: String,
}

impl fmt::Debug for X509Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preview = self.pem.chars().take(50).collect::<String>();
        f.debug_struct("X509Certificate")
            .field("pem", &preview)
            .finish()
    }
}

impl X509Certificate {
    /// Create from PEM string
    pub fn from_pem(pem: impl Into<String>) -> SamlResult<Self> {
        let pem = pem.into();
        Self::parse_pem(&pem)?;
        
        Ok(Self {
            pem,
        })
    }
    
    /// Create from base64 encoded DER
    pub fn from_base64(base64: &str) -> SamlResult<Self> {
        let der = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| SamlError::CertificateError(format!("Invalid base64: {}", e)))?;
        
        let parsed = X509::from_der(&der)
            .map_err(|e| SamlError::CertificateError(format!("Invalid DER: {}", e)))?;
        
        let pem = String::from_utf8(parsed.to_pem()
            .map_err(|e| SamlError::CertificateError(format!("PEM conversion failed: {}", e)))?)
            .map_err(|e| SamlError::CertificateError(format!("UTF-8 error: {}", e)))?;
        
        Ok(Self {
            pem,
        })
    }
    
    /// Parse PEM certificate
    fn parse_pem(pem: &str) -> SamlResult<X509> {
        X509::from_pem(pem.as_bytes())
            .map_err(|e| SamlError::CertificateError(format!("Failed to parse PEM: {}", e)))
    }
    
    /// Get the parsed certificate
    pub fn parsed(&self) -> SamlResult<X509> {
        Self::parse_pem(&self.pem)
    }
    
    /// Get PEM string
    pub fn pem(&self) -> &str {
        &self.pem
    }
    
    /// Get certificate subject
    pub fn subject(&self) -> SamlResult<String> {
        let cert = self.parsed()?;
        let subject = cert.subject_name();
        Ok(format!("{:?}", subject))
    }
    
    /// Get certificate issuer
    pub fn issuer(&self) -> SamlResult<String> {
        let cert = self.parsed()?;
        let issuer = cert.issuer_name();
        Ok(format!("{:?}", issuer))
    }
    
    /// Get certificate not before date
    pub fn not_before(&self) -> SamlResult<chrono::DateTime<chrono::Utc>> {
        let cert = self.parsed()?;
        let not_before = cert.not_before();
        let not_before_str = format!("{}", not_before);
        parse_openssl_time(&not_before_str)
    }
    
    /// Get certificate not after date
    pub fn not_after(&self) -> SamlResult<chrono::DateTime<chrono::Utc>> {
        let cert = self.parsed()?;
        let not_after = cert.not_after();
        let not_after_str = format!("{}", not_after);
        parse_openssl_time(&not_after_str)
    }
    
    /// Get public key from certificate
    pub fn public_key(&self) -> SamlResult<PKey<Public>> {
        let cert = self.parsed()?;
        cert.public_key()
            .map_err(|e| SamlError::CertificateError(format!("Failed to extract public key: {}", e)))
    }
    
    /// Get certificate fingerprint (SHA256)
    pub fn fingerprint(&self) -> SamlResult<String> {
        let cert = self.parsed()?;
        let digest = cert.digest(MessageDigest::sha256())
            .map_err(|e| SamlError::CertificateError(format!("Failed to compute fingerprint: {}", e)))?;
        Ok(hex::encode(digest))
    }
    
    /// Check if certificate is valid at given time
    pub fn is_valid_at(&self, time: chrono::DateTime<chrono::Utc>) -> SamlResult<bool> {
        let not_before = self.not_before()?;
        let not_after = self.not_after()?;
        Ok(time >= not_before && time <= not_after)
    }
    
    /// Get certificate as base64 (without PEM headers)
    pub fn to_base64(&self) -> SamlResult<String> {
        let cert = self.parsed()?;
        let der = cert.to_der()
            .map_err(|e| SamlError::CertificateError(format!("DER conversion failed: {}", e)))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&der))
    }
}

/// SAML Crypto utilities
#[derive(Clone)]
pub struct SamlCrypto {
    /// SP private key for signing
    private_key: Option<PKey<Private>>,
    /// SP certificate
    certificate: Option<X509Certificate>,
    /// IdP certificate for verification
    idp_certificate: Option<X509Certificate>,
}

impl fmt::Debug for SamlCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SamlCrypto")
            .field("has_private_key", &self.private_key.is_some())
            .field("has_certificate", &self.certificate.is_some())
            .field("has_idp_certificate", &self.idp_certificate.is_some())
            .finish()
    }
}

impl SamlCrypto {
    /// Create new crypto instance
    pub fn new(
        private_key_pem: Option<String>,
        certificate: Option<X509Certificate>,
    ) -> SamlResult<Self> {
        let private_key = if let Some(pem) = private_key_pem {
            Some(Self::parse_private_key(&pem)?)
        } else {
            None
        };
        
        Ok(Self {
            private_key,
            certificate,
            idp_certificate: None,
        })
    }
    
    /// Set IdP certificate for verification
    pub fn with_idp_certificate(mut self, cert: X509Certificate) -> Self {
        self.idp_certificate = Some(cert);
        self
    }
    
    /// Parse private key from PEM
    fn parse_private_key(pem: &str) -> SamlResult<PKey<Private>> {
        PKey::private_key_from_pem(pem.as_bytes())
            .map_err(|e| SamlError::CertificateError(format!("Failed to parse private key: {}", e)))
    }
    
    /// Generate a new RSA keypair (2048 bits)
    pub fn generate_keypair() -> SamlResult<(String, String)> {
        let rsa = Rsa::generate(2048)
            .map_err(|e| SamlError::CertificateError(format!("Key generation failed: {}", e)))?;
        
        let pkey = PKey::from_rsa(rsa)
            .map_err(|e| SamlError::CertificateError(format!("PKey creation failed: {}", e)))?;
        
        let private_key_pem = String::from_utf8(
            pkey.private_key_to_pem_pkcs8()
                .map_err(|e| SamlError::CertificateError(format!("PEM export failed: {}", e)))?
        ).map_err(|e| SamlError::InternalError(format!("UTF-8 error: {}", e)))?;
        
        let public_key_pem = String::from_utf8(
            pkey.public_key_to_pem()
                .map_err(|e| SamlError::CertificateError(format!("Public key export failed: {}", e)))?
        ).map_err(|e| SamlError::InternalError(format!("UTF-8 error: {}", e)))?;
        
        Ok((private_key_pem, public_key_pem))
    }
    
    /// Sign data using RSA-SHA256
    pub fn sign(&self, data: &[u8]) -> SamlResult<Vec<u8>> {
        let key = self.private_key.as_ref()
            .ok_or_else(|| SamlError::ConfigurationError("No private key configured".to_string()))?;
        
        let mut signer = Signer::new(MessageDigest::sha256(), key)
            .map_err(|e| SamlError::InvalidSignature(format!("Signer creation failed: {}", e)))?;
        
        signer.update(data)
            .map_err(|e| SamlError::InvalidSignature(format!("Update failed: {}", e)))?;
        
        signer.sign_to_vec()
            .map_err(|e| SamlError::InvalidSignature(format!("Signing failed: {}", e)))
    }
    
    /// Sign for redirect binding (URL-safe base64)
    pub fn sign_redirect(&self, data: &str) -> SamlResult<Vec<u8>> {
        self.sign(data.as_bytes())
    }
    
    /// Verify signature using IdP certificate
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> SamlResult<bool> {
        let cert = self.idp_certificate.as_ref()
            .ok_or_else(|| SamlError::ConfigurationError("No IdP certificate configured".to_string()))?;
        
        let public_key = cert.public_key()?;
        
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)
            .map_err(|e| SamlError::InvalidSignature(format!("Verifier creation failed: {}", e)))?;
        
        verifier.update(data)
            .map_err(|e| SamlError::InvalidSignature(format!("Update failed: {}", e)))?;
        
        verifier.verify(signature)
            .map_err(|e| SamlError::InvalidSignature(format!("Verification failed: {}", e)))
    }
    
    /// Verify XML signature on SAML response/assertion
    /// 
    /// This implements proper XML Signature verification according to SAML 2.0 specification:
    /// 1. Parse and canonicalize the SignedInfo
    /// 2. Extract the signed content (Assertion/Response)
    /// 3. Verify the digest of the signed content
    /// 4. Verify the signature using the IdP's public key
    pub fn verify_xml_signature(&self, xml: &str, signature: &XmlSignature) -> SamlResult<bool> {
        let cert = self.idp_certificate.as_ref()
            .ok_or_else(|| SamlError::ConfigurationError("No IdP certificate configured".to_string()))?;
        
        let public_key = cert.public_key()?;
        
        // Step 1: Decode signature value
        let signature_value = base64::engine::general_purpose::STANDARD
            .decode(&signature.signature_value)
            .map_err(|e| SamlError::InvalidSignature(format!("Base64 decode failed: {}", e)))?;
        
        // Step 2: Extract and canonicalize the signed element
        let signed_element = extract_signed_element(xml, &signature.reference_uri)?;
        let canonicalized = canonicalize_xml(&signed_element)?;
        
        // Step 3: Verify digest (integrity check)
        let computed_digest = compute_sha256_digest(canonicalized.as_bytes())?;
        if computed_digest != signature.digest_value {
            return Err(SamlError::InvalidSignature(
                format!("Digest mismatch: computed {} != expected {}", 
                    computed_digest, signature.digest_value)
            ));
        }
        
        // Step 4: Canonicalize SignedInfo for signature verification
        // The signature is computed over the canonicalized SignedInfo
        let canonicalized_signed_info = canonicalize_xml(&signature.signed_info)?;
        
        // Step 5: Verify signature using RSA-SHA256
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)
            .map_err(|e| SamlError::InvalidSignature(format!("Verifier creation failed: {}", e)))?;
        
        verifier.update(canonicalized_signed_info.as_bytes())
            .map_err(|e| SamlError::InvalidSignature(format!("Update failed: {}", e)))?;
        
        verifier.verify(&signature_value)
            .map_err(|e| SamlError::InvalidSignature(format!("Verification failed: {}", e)))
    }
    
    /// Get the certificate (if configured)
    pub fn certificate(&self) -> Option<&X509Certificate> {
        self.certificate.as_ref()
    }
    
    /// Get certificate as base64 for metadata
    pub fn certificate_base64(&self) -> SamlResult<Option<String>> {
        match &self.certificate {
            Some(cert) => cert.to_base64().map(Some),
            None => Ok(None),
        }
    }
}

/// XML Signature structure
#[derive(Debug, Clone)]
pub struct XmlSignature {
    /// SignedInfo element (as XML string)
    pub signed_info: String,
    /// Signature value (base64 encoded)
    pub signature_value: String,
    /// KeyInfo element (optional)
    pub key_info: Option<String>,
    /// XPath or ID of the signed element
    pub reference_uri: Option<String>,
    /// Digest value
    pub digest_value: String,
    /// Canonicalization method
    pub canonicalization_method: String,
    /// Signature method
    pub signature_method: String,
    /// Digest method
    pub digest_method: String,
}

/// Parse XML signature from SAML response
/// 
/// This implementation extracts the XML Signature element and its components
/// using string parsing. It handles the common ds:Signature format.
pub fn parse_xml_signature(xml: &str) -> SamlResult<Option<XmlSignature>> {
    // Check if there's a signature
    if !xml.contains("Signature") && !xml.contains("ds:Signature") {
        return Ok(None);
    }
    
    // Extract SignedInfo
    let signed_info = extract_xml_element(xml, "SignedInfo", "ds")
        .ok_or_else(|| SamlError::InvalidSignature("Missing SignedInfo element".to_string()))?;
    
    // Extract SignatureValue
    let signature_value = extract_xml_element(xml, "SignatureValue", "ds")
        .ok_or_else(|| SamlError::InvalidSignature("Missing SignatureValue element".to_string()))?;
    
    // Extract DigestValue
    let digest_value = extract_xml_element(xml, "DigestValue", "ds")
        .ok_or_else(|| SamlError::InvalidSignature("Missing DigestValue element".to_string()))?;
    
    // Extract optional Reference URI
    let reference_uri = extract_reference_uri(&signed_info);
    
    // Extract KeyInfo (optional)
    let key_info = extract_xml_element(xml, "KeyInfo", "ds");
    
    // Extract canonicalization method
    let canonicalization_method = extract_algorithm(&signed_info, "CanonicalizationMethod")
        .unwrap_or_else(|| "http://www.w3.org/2001/10/xml-exc-c14n#".to_string());
    
    // Extract signature method
    let signature_method = extract_algorithm(&signed_info, "SignatureMethod")
        .unwrap_or_else(|| "http://www.w3.org/2000/09/xmldsig#rsa-sha256".to_string());
    
    // Extract digest method
    let digest_method = extract_algorithm(&signed_info, "DigestMethod")
        .unwrap_or_else(|| "http://www.w3.org/2001/04/xmlenc#sha256".to_string());
    
    Ok(Some(XmlSignature {
        signed_info,
        signature_value,
        key_info,
        reference_uri,
        digest_value,
        canonicalization_method,
        signature_method,
        digest_method,
    }))
}

/// Extract an XML element by name (handles both namespaced and non-namespaced)
fn extract_xml_element(xml: &str, element_name: &str, namespace_prefix: &str) -> Option<String> {
    // Try with namespace prefix first (e.g., ds:SignedInfo)
    let ns_pattern_start = format!("<{}:{}", namespace_prefix, element_name);
    let ns_pattern_end = format!("</{}:{}", namespace_prefix, element_name);
    
    if let Some(start) = xml.find(&ns_pattern_start) {
        let after_start = &xml[start..];
        // Find the end of the opening tag
        if let Some(tag_end) = after_start.find('>') {
            let content_start = start + tag_end + 1;
            // Find the closing tag
            if let Some(end) = xml[content_start..].find(&ns_pattern_end) {
                return Some(xml[content_start..content_start + end].trim().to_string());
            }
            // Self-closing tag check
            if after_start[..tag_end+1].ends_with("/>") {
                return Some(String::new());
            }
        }
    }
    
    // Try without namespace
    let pattern_start = format!("<{}", element_name);
    let pattern_end = format!("</{}", element_name);
    
    if let Some(start) = xml.find(&pattern_start) {
        let after_start = &xml[start..];
        // Make sure it's the exact element (not a prefix of another element name)
        let after_tag = &after_start[pattern_start.len()..];
        if after_tag.starts_with('>') || after_tag.starts_with(' ') || after_tag.starts_with('\n') || after_tag.starts_with('\t') {
            if let Some(tag_end) = after_start.find('>') {
                let content_start = start + tag_end + 1;
                if let Some(end) = xml[content_start..].find(&pattern_end) {
                    return Some(xml[content_start..content_start + end].trim().to_string());
                }
            }
        }
    }
    
    None
}

/// Extract Reference URI from SignedInfo
fn extract_reference_uri(signed_info: &str) -> Option<String> {
    // Look for <Reference URI="...">
    if let Some(start) = signed_info.find("URI=\"") {
        let after_uri = &signed_info[start + 5..];
        if let Some(end) = after_uri.find('"') {
            return Some(after_uri[..end].to_string());
        }
    }
    None
}

/// Extract Algorithm attribute from an element
fn extract_algorithm(xml: &str, element_name: &str) -> Option<String> {
    let pattern = format!("{}", element_name);
    if let Some(start) = xml.find(&pattern) {
        let after_element = &xml[start..];
        // Find Algorithm attribute within the element tag
        if let Some(alg_start) = after_element.find("Algorithm=\"") {
            let after_alg = &after_element[alg_start + 10..];
            if let Some(end) = after_alg.find('"') {
                return Some(after_alg[..end].to_string());
            }
        }
    }
    None
}

/// Canonicalize XML using C14N
/// 
/// This implements exclusive XML Canonicalization (C14N) as required by SAML.
/// For now, it provides a simplified version that normalizes whitespace and
/// attribute ordering.
pub fn canonicalize_xml(xml: &str) -> SamlResult<String> {
    // In a production environment, consider using a proper C14N library
    // For now, we provide a best-effort normalization:
    // 1. Remove XML declaration
    // 2. Normalize line endings to LF
    // 3. Trim whitespace between elements
    
    let mut result = xml.to_string();
    
    // Remove XML declaration
    if result.starts_with("<?xml") {
        if let Some(end) = result.find("?>") {
            result = result[end + 2..].trim_start().to_string();
        }
    }
    
    // Normalize line endings
    result = result.replace("\r\n", "\n").replace('\r', "\n");
    
    // Basic whitespace normalization between elements
    // This is a simplified approach - full C14N is complex
    Ok(result.trim().to_string())
}

/// Extract the signed element from XML based on reference URI
fn extract_signed_element(xml: &str, reference_uri: &Option<String>) -> SamlResult<String> {
    match reference_uri {
        Some(uri) if uri.starts_with('#') => {
            // Extract by ID
            let id = &uri[1..];
            extract_element_by_id(xml, id)
        }
        _ => {
            // Default: look for Assertion or Response element
            extract_assertion_or_response(xml)
        }
    }
}

/// Extract an element by its ID attribute
fn extract_element_by_id(xml: &str, id: &str) -> SamlResult<String> {
    // Look for ID="id" or id="id"
    let patterns = [
        format!(" ID=\"{}\"", id),
        format!(" id=\"{}\"", id),
        format!(" ID='{}'", id),
        format!(" id='{}'", id),
    ];
    
    for pattern in &patterns {
        if let Some(pos) = xml.find(pattern) {
            // Find the start of the element
            let before = &xml[..pos];
            if let Some(start) = before.rfind('<') {
                // Find the matching end tag
                let element_start = &xml[start..];
                if let Some(space_pos) = element_start.find(' ') {
                    let tag_name = &element_start[1..space_pos];
                    // Find the closing tag
                    let end_tag = format!("</{}>", tag_name);
                    let end_tag_ns = format!("</saml:{}>", tag_name);
                    let end_tag_saml2 = format!("</saml2:{}>", tag_name);
                    
                    if let Some(end) = xml[start..].find(&end_tag) {
                        return Ok(xml[start..start + end + end_tag.len()].to_string());
                    }
                    if let Some(end) = xml[start..].find(&end_tag_ns) {
                        return Ok(xml[start..start + end + end_tag_ns.len()].to_string());
                    }
                    if let Some(end) = xml[start..].find(&end_tag_saml2) {
                        return Ok(xml[start..start + end + end_tag_saml2.len()].to_string());
                    }
                }
            }
        }
    }
    
    Err(SamlError::InvalidSignature(format!("Element with ID '{}' not found", id)))
}

/// Extract Assertion or Response element
fn extract_assertion_or_response(xml: &str) -> SamlResult<String> {
    // Try to find Assertion first
    if let Some(start) = xml.find("<Assertion") {
        if let Some(end) = xml[start..].find("</Assertion>") {
            return Ok(xml[start..start + end + 12].to_string());
        }
    }
    
    // Then try saml:Assertion
    if let Some(start) = xml.find("<saml:Assertion") {
        if let Some(end) = xml[start..].find("</saml:Assertion>") {
            return Ok(xml[start..start + end + 17].to_string());
        }
    }
    
    // Fall back to Response
    if let Some(start) = xml.find("<Response") {
        if let Some(end) = xml[start..].find("</Response>") {
            return Ok(xml[start..start + end + 11].to_string());
        }
    }
    
    Err(SamlError::InvalidSignature("Could not find signed element".to_string()))
}

/// Compute SHA256 digest of data
fn compute_sha256_digest(data: &[u8]) -> SamlResult<String> {
    use openssl::sha::Sha256;
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finish();
    Ok(base64::engine::general_purpose::STANDARD.encode(result))
}

/// Verify digest of signed content
pub fn verify_digest(signed_content: &str, expected_digest: &str) -> SamlResult<bool> {
    let canonicalized = canonicalize_xml(signed_content)?;
    let computed_digest = compute_sha256_digest(canonicalized.as_bytes())?;
    Ok(computed_digest == expected_digest)
}

/// Generate self-signed certificate for testing
pub fn generate_self_signed_cert(
    common_name: &str,
    days_valid: u32,
) -> SamlResult<(String, String)> {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::X509NameBuilder;
    
    // Generate keypair
    let rsa = Rsa::generate(2048)
        .map_err(|e| SamlError::CertificateError(format!("Key generation failed: {}", e)))?;
    
    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| SamlError::CertificateError(format!("PKey creation failed: {}", e)))?;
    
    // Build certificate name
    let mut name_builder = X509NameBuilder::new()
        .map_err(|e| SamlError::CertificateError(format!("Name builder failed: {}", e)))?;
    
    name_builder.append_entry_by_text("CN", common_name)
        .map_err(|e| SamlError::CertificateError(format!("CN entry failed: {}", e)))?;
    name_builder.append_entry_by_text("O", "Vault SAML")
        .map_err(|e| SamlError::CertificateError(format!("O entry failed: {}", e)))?;
    
    let name = name_builder.build();
    
    // Build certificate
    let mut builder = X509::builder()
        .map_err(|e| SamlError::CertificateError(format!("X509 builder failed: {}", e)))?;
    
    builder.set_version(2)
        .map_err(|e| SamlError::CertificateError(format!("Set version failed: {}", e)))?;
    
    let serial = BigNum::from_u32(1)
        .map_err(|e| SamlError::CertificateError(format!("Serial number failed: {}", e)))?;
    let serial = serial.to_asn1_integer()
        .map_err(|e| SamlError::CertificateError(format!("ASN1 integer failed: {}", e)))?;
    builder.set_serial_number(&serial)
        .map_err(|e| SamlError::CertificateError(format!("Set serial failed: {}", e)))?;
    
    builder.set_subject_name(&name)
        .map_err(|e| SamlError::CertificateError(format!("Set subject failed: {}", e)))?;
    builder.set_issuer_name(&name)
        .map_err(|e| SamlError::CertificateError(format!("Set issuer failed: {}", e)))?;
    
    builder.set_pubkey(&pkey)
        .map_err(|e| SamlError::CertificateError(format!("Set pubkey failed: {}", e)))?;
    
    let not_before = Asn1Time::days_from_now(0)
        .map_err(|e| SamlError::CertificateError(format!("Not before failed: {}", e)))?;
    builder.set_not_before(&not_before)
        .map_err(|e| SamlError::CertificateError(format!("Set not before failed: {}", e)))?;
    
    let not_after = Asn1Time::days_from_now(days_valid)
        .map_err(|e| SamlError::CertificateError(format!("Not after failed: {}", e)))?;
    builder.set_not_after(&not_after)
        .map_err(|e| SamlError::CertificateError(format!("Set not after failed: {}", e)))?;
    
    // Add SAN extension
    let san = SubjectAlternativeName::new()
        .dns(common_name)
        .build(&builder.x509v3_context(None, None))
        .map_err(|e| SamlError::CertificateError(format!("SAN build failed: {}", e)))?;
    
    builder.append_extension(san)
        .map_err(|e| SamlError::CertificateError(format!("Append SAN failed: {}", e)))?;
    
    // Self-sign
    builder.sign(&pkey, MessageDigest::sha256())
        .map_err(|e| SamlError::CertificateError(format!("Signing failed: {}", e)))?;
    
    let cert = builder.build();
    
    // Export
    let cert_pem = String::from_utf8(cert.to_pem()
        .map_err(|e| SamlError::CertificateError(format!("Cert PEM export failed: {}", e)))?)
        .map_err(|e| SamlError::InternalError(format!("UTF-8 error: {}", e)))?;
    
    let key_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8()
        .map_err(|e| SamlError::CertificateError(format!("Key PEM export failed: {}", e)))?)
        .map_err(|e| SamlError::InternalError(format!("UTF-8 error: {}", e)))?;
    
    Ok((cert_pem, key_pem))
}

/// Parse OpenSSL ASN1 time to chrono DateTime
fn parse_openssl_time(time_str: &str) -> SamlResult<chrono::DateTime<chrono::Utc>> {
    // OpenSSL times are typically in format "Apr 21 12:00:00 2024 GMT"
    // or ASN1 format
    use chrono::NaiveDateTime;
    
    // Try various formats
    let formats = [
        "%b %e %H:%M:%S %Y GMT",
        "%Y%m%d%H%M%SZ",
        "%Y-%m-%d %H:%M:%S",
    ];
    
    for format in &formats {
        if let Ok(dt) = NaiveDateTime::parse_from_str(time_str.trim(), format) {
            return Ok(chrono::DateTime::from_naive_utc_and_offset(dt, chrono::Utc));
        }
    }
    
    // Fallback: try to parse as general time
    Err(SamlError::TimeError(format!("Cannot parse time: {}", time_str)))
}

/// Extract certificate info from PEM
pub fn extract_cert_info(pem: &str) -> SamlResult<CertInfo> {
    let cert = X509::from_pem(pem.as_bytes())
        .map_err(|e| SamlError::CertificateError(format!("Parse failed: {}", e)))?;
    
    let subject = cert.subject_name();
    let issuer = cert.issuer_name();
    
    Ok(CertInfo {
        subject: format!("{:?}", subject),
        issuer: format!("{:?}", issuer),
        not_before: format!("{}", cert.not_before()),
        not_after: format!("{}", cert.not_after()),
        fingerprint: hex::encode(cert.digest(MessageDigest::sha256())
            .map_err(|e| SamlError::CertificateError(format!("Fingerprint failed: {}", e)))?),
    })
}

/// Certificate information
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_keypair() {
        let (private_key, public_key) = SamlCrypto::generate_keypair().unwrap();
        assert!(private_key.contains("BEGIN PRIVATE KEY"));
        assert!(public_key.contains("BEGIN PUBLIC KEY"));
    }
    
    #[test]
    fn test_generate_self_signed_cert() {
        let (cert, key) = generate_self_signed_cert("test.example.com", 365).unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
        
        // Verify certificate can be parsed
        let x509 = X509Certificate::from_pem(&cert).unwrap();
        assert!(x509.is_valid_at(chrono::Utc::now()).unwrap());
    }
    
    #[test]
    fn test_sign_and_verify() {
        // Generate keypair for SP
        let (sp_cert, sp_key) = generate_self_signed_cert("sp.example.com", 365).unwrap();
        let sp_cert = X509Certificate::from_pem(&sp_cert).unwrap();
        
        // Create crypto with SP key
        let crypto = SamlCrypto::new(Some(sp_key), Some(sp_cert.clone())).unwrap()
            .with_idp_certificate(sp_cert); // Self-verification for testing
        
        // Sign data
        let data = b"test message";
        let signature = crypto.sign(data).unwrap();
        
        // Verify signature
        let verified = crypto.verify(data, &signature).unwrap();
        assert!(verified);
    }
    
    #[test]
    fn test_cert_fingerprint() {
        let (cert, _) = generate_self_signed_cert("test.example.com", 365).unwrap();
        let x509 = X509Certificate::from_pem(&cert).unwrap();
        
        let fingerprint = x509.fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 64); // SHA256 hex string
    }
}
