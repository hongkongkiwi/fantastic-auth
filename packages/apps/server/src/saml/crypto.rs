//! SAML 2.0 Cryptographic Operations
//!
//! This module provides cryptographic functionality for SAML 2.0:
//! - X509 certificate handling and validation
//! - XML Signature generation and validation
//! - RSA-SHA256 signing
//! - Keypair generation

use base64::Engine;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::x509::{X509Ref, X509};
use std::fmt;

use super::{SamlError, SamlResult};

/// X509 Certificate wrapper
#[derive(Clone)]
pub struct X509Certificate {
    /// PEM encoded certificate
    pem: String,
    /// Parsed X509 certificate (not serializable, loaded on demand)
    #[allow(dead_code)]
    parsed: Option<X509>,
}

impl fmt::Debug for X509Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preview = self.pem.chars().take(50).collect::<String>();
        f.debug_struct("X509Certificate")
            .field("pem", &preview)
            .field("has_parsed", &self.parsed.is_some())
            .finish()
    }
}

impl X509Certificate {
    /// Create from PEM string
    pub fn from_pem(pem: impl Into<String>) -> SamlResult<Self> {
        let pem = pem.into();
        let parsed = Self::parse_pem(&pem)?;
        
        Ok(Self {
            pem,
            parsed: Some(parsed),
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
            parsed: Some(parsed),
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
    pub fn verify_xml_signature(&self, xml: &str, signature: &XmlSignature) -> SamlResult<bool> {
        // In a full implementation, this would:
        // 1. Parse the XML signature
        // 2. Canonicalize the signed content
        // 3. Verify using the appropriate algorithm
        // For now, we provide the structure
        
        let cert = self.idp_certificate.as_ref()
            .ok_or_else(|| SamlError::ConfigurationError("No IdP certificate configured".to_string()))?;
        
        let public_key = cert.public_key()?;
        
        // Decode signature value
        let signature_value = base64::engine::general_purpose::STANDARD
            .decode(&signature.signature_value)
            .map_err(|e| SamlError::InvalidSignature(format!("Base64 decode failed: {}", e)))?;
        
        // Create verifier
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)
            .map_err(|e| SamlError::InvalidSignature(format!("Verifier creation failed: {}", e)))?;
        
        // In a real implementation, we would canonicalize and hash the signed info
        // For now, this is a placeholder
        verifier.update(signature.signed_info.as_bytes())
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
}

/// Parse XML signature from SAML response
pub fn parse_xml_signature(xml: &str) -> SamlResult<Option<XmlSignature>> {
    // Simplified implementation - in production, use a proper XML signature library
    // This would parse the <ds:Signature> element and extract:
    // - SignedInfo
    // - SignatureValue
    // - KeyInfo
    // - DigestValue
    
    if !xml.contains("Signature") {
        return Ok(None);
    }
    
    // Placeholder implementation
    Ok(Some(XmlSignature {
        signed_info: String::new(),
        signature_value: String::new(),
        key_info: None,
        reference_uri: None,
        digest_value: String::new(),
    }))
}

/// Canonicalize XML using C14N
pub fn canonicalize_xml(xml: &str) -> SamlResult<String> {
    // In a full implementation, use an XML canonicalization library
    // For now, provide a simplified version
    Ok(xml.to_string())
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
    use openssl::x509::{X509NameBuilder, X509ReqBuilder};
    
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
