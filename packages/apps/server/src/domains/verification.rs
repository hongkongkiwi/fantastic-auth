//! Domain verification service
//!
//! Handles DNS TXT record lookups, HTML meta tag verification, and file verification.
//! Uses trust-dns-resolver for DNS lookups with caching and retry logic.

use crate::domains::models::VerificationMethod;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// DNS TXT record verifier
#[derive(Clone)]
pub struct DnsVerifier {
    /// DNS resolver
    resolver: trust_dns_resolver::TokioAsyncResolver,
    /// Timeout for DNS lookups
    lookup_timeout: Duration,
}

/// Verification result
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub success: bool,
    pub method: VerificationMethod,
    pub message: String,
    pub records_found: Option<Vec<String>>,
}

impl DnsVerifier {
    /// Create a new DNS verifier with default configuration
    pub async fn new() -> anyhow::Result<Self> {
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf()?;

        Ok(Self {
            resolver,
            lookup_timeout: Duration::from_secs(30),
        })
    }

    /// Create a new DNS verifier with custom timeout
    pub async fn with_timeout(timeout_secs: u64) -> anyhow::Result<Self> {
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf()?;

        Ok(Self {
            resolver,
            lookup_timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Verify domain via DNS TXT record
    ///
    /// Looks for a TXT record at `_vault.<domain>` containing `vault-verify=<token>`
    pub async fn verify_dns(
        &self,
        domain: &str,
        expected_token: &str,
    ) -> anyhow::Result<VerificationResult> {
        let hostname = format!("_vault.{}", domain);
        let expected_record = format!("vault-verify={}", expected_token);

        info!(
            "Checking DNS TXT record for {}: expecting '{}'",
            hostname, expected_record
        );

        // Perform DNS lookup with timeout
        let lookup_result = timeout(self.lookup_timeout, self.resolver.txt_lookup(&hostname)).await;

        match lookup_result {
            Ok(Ok(txt_lookup)) => {
                let mut records_found = Vec::new();
                let mut found_match = false;

                for record in txt_lookup.iter() {
                    let txt_data: Vec<String> = record
                        .iter()
                        .map(|b| String::from_utf8_lossy(b).to_string())
                        .collect();
                    let full_record = txt_data.join("");
                    records_found.push(full_record.clone());

                    debug!("Found TXT record for {}: '{}'", hostname, full_record);

                    // Check if record matches expected value
                    if full_record.trim() == expected_record {
                        found_match = true;
                        info!(
                            "DNS verification successful for {}: record matched",
                            hostname
                        );
                    }
                }

                if found_match {
                    Ok(VerificationResult {
                        success: true,
                        method: VerificationMethod::Dns,
                        message: "DNS TXT record verified successfully".to_string(),
                        records_found: Some(records_found),
                    })
                } else {
                    warn!(
                        "DNS verification failed for {}: no matching record found. Expected '{}', found {:?}",
                        hostname, expected_record, records_found
                    );
                    Ok(VerificationResult {
                        success: false,
                        method: VerificationMethod::Dns,
                        message: format!(
                            "No matching TXT record found. Expected '{}' at {}",
                            expected_record, hostname
                        ),
                        records_found: Some(records_found),
                    })
                }
            }
            Ok(Err(e)) => {
                warn!("DNS lookup failed for {}: {}", hostname, e);
                Ok(VerificationResult {
                    success: false,
                    method: VerificationMethod::Dns,
                    message: format!("DNS lookup failed: {}", e),
                    records_found: None,
                })
            }
            Err(_) => {
                warn!("DNS lookup timed out for {}", hostname);
                Ok(VerificationResult {
                    success: false,
                    method: VerificationMethod::Dns,
                    message: "DNS lookup timed out".to_string(),
                    records_found: None,
                })
            }
        }
    }

    /// Verify domain via HTML meta tag
    ///
    /// Fetches the website at `https://<domain>` and looks for
    /// `<meta name="vault-verification" content="<token>" />`
    pub async fn verify_html_meta(
        &self,
        domain: &str,
        expected_token: &str,
    ) -> anyhow::Result<VerificationResult> {
        let url = format!("https://{}", domain);
        info!(
            "Checking HTML meta tag for {}: expecting '{}'",
            url, expected_token
        );

        // Create HTTP client with timeout
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;

        match client.get(&url).send().await {
            Ok(response) => {
                if !response.status().is_success() {
                    return Ok(VerificationResult {
                        success: false,
                        method: VerificationMethod::HtmlMeta,
                        message: format!("Website returned status: {}", response.status()),
                        records_found: None,
                    });
                }

                match response.text().await {
                    Ok(html) => {
                        let meta_tag = format!(
                            r#"<meta name="vault-verification" content="{}""#,
                            expected_token
                        );

                        if html.contains(&meta_tag) {
                            info!("HTML meta verification successful for {}", domain);
                            Ok(VerificationResult {
                                success: true,
                                method: VerificationMethod::HtmlMeta,
                                message: "HTML meta tag verified successfully".to_string(),
                                records_found: None,
                            })
                        } else {
                            // Also check for alternative formats
                            let alt_pattern = format!(r#"name=["']vault-verification["']"#);
                            let found_meta = html.contains(&alt_pattern);

                            warn!(
                                "HTML meta verification failed for {}: expected tag not found. Found similar meta: {}",
                                domain, found_meta
                            );

                            Ok(VerificationResult {
                                success: false,
                                method: VerificationMethod::HtmlMeta,
                                message: format!("HTML meta tag not found. Expected: {}", meta_tag),
                                records_found: None,
                            })
                        }
                    }
                    Err(e) => {
                        error!("Failed to read HTML from {}: {}", url, e);
                        Ok(VerificationResult {
                            success: false,
                            method: VerificationMethod::HtmlMeta,
                            message: format!("Failed to read website content: {}", e),
                            records_found: None,
                        })
                    }
                }
            }
            Err(e) => {
                error!("Failed to fetch {}: {}", url, e);
                Ok(VerificationResult {
                    success: false,
                    method: VerificationMethod::HtmlMeta,
                    message: format!("Failed to fetch website: {}", e),
                    records_found: None,
                })
            }
        }
    }

    /// Verify domain via file upload
    ///
    /// Fetches the file at `https://<domain>/.well-known/vault-verify-<token>`
    /// and checks if it contains the expected token
    pub async fn verify_file(
        &self,
        domain: &str,
        token: &str,
    ) -> anyhow::Result<VerificationResult> {
        let file_path = format!("/.well-known/vault-verify-{}", &token[..16]);
        let url = format!("https://{}{}", domain, file_path);
        info!("Checking file verification for {}", url);

        // Create HTTP client with timeout
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;

        match client.get(&url).send().await {
            Ok(response) => {
                if response.status() == 404 {
                    return Ok(VerificationResult {
                        success: false,
                        method: VerificationMethod::File,
                        message: format!("Verification file not found at {}", file_path),
                        records_found: None,
                    });
                }

                if !response.status().is_success() {
                    return Ok(VerificationResult {
                        success: false,
                        method: VerificationMethod::File,
                        message: format!("Server returned status: {}", response.status()),
                        records_found: None,
                    });
                }

                match response.text().await {
                    Ok(content) => {
                        let content = content.trim();

                        if content == token {
                            info!("File verification successful for {}", domain);
                            Ok(VerificationResult {
                                success: true,
                                method: VerificationMethod::File,
                                message: "File verification successful".to_string(),
                                records_found: Some(vec![content.to_string()]),
                            })
                        } else {
                            warn!(
                                "File verification failed for {}: content mismatch. Expected '{}', found '{}'",
                                domain, token, content
                            );
                            Ok(VerificationResult {
                                success: false,
                                method: VerificationMethod::File,
                                message: "File content does not match expected token".to_string(),
                                records_found: Some(vec![content.to_string()]),
                            })
                        }
                    }
                    Err(e) => {
                        error!("Failed to read file from {}: {}", url, e);
                        Ok(VerificationResult {
                            success: false,
                            method: VerificationMethod::File,
                            message: format!("Failed to read file content: {}", e),
                            records_found: None,
                        })
                    }
                }
            }
            Err(e) => {
                error!("Failed to fetch {}: {}", url, e);
                Ok(VerificationResult {
                    success: false,
                    method: VerificationMethod::File,
                    message: format!("Failed to fetch verification file: {}", e),
                    records_found: None,
                })
            }
        }
    }

    /// Verify with any available method
    ///
    /// Tries DNS first, then HTML meta, then file
    pub async fn verify_any(
        &self,
        domain: &str,
        token: &str,
    ) -> anyhow::Result<VerificationResult> {
        // Try DNS first
        let dns_result = self.verify_dns(domain, token).await?;
        if dns_result.success {
            return Ok(dns_result);
        }

        // Try HTML meta tag
        let html_result = self.verify_html_meta(domain, token).await?;
        if html_result.success {
            return Ok(html_result);
        }

        // Try file verification
        let file_result = self.verify_file(domain, token).await?;
        if file_result.success {
            return Ok(file_result);
        }

        // Return the most informative error
        Ok(VerificationResult {
            success: false,
            method: VerificationMethod::Dns,
            message: format!(
                "All verification methods failed. DNS: {}. HTML: {}. File: {}",
                dns_result.message, html_result.message, file_result.message
            ),
            records_found: dns_result.records_found,
        })
    }

    /// Generate a verification token
    /// 
    /// SECURITY: Uses OsRng (operating system's CSPRNG) for cryptographically secure
    /// token generation. DNS verification tokens prove domain ownership and must be
    /// unpredictable to prevent attackers from verifying domains they don't control.
    pub fn generate_token() -> String {
        use rand::Rng;
        use rand_core::OsRng;
        
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const TOKEN_LEN: usize = 32;

        // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
        let mut rng = OsRng;
        let token: String = (0..TOKEN_LEN)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        token
    }
}

impl Default for DnsVerifier {
    fn default() -> Self {
        // This is a blocking call for Default, but in practice
        // the verifier should be created at startup using `new()`
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(
            trust_dns_resolver::config::ResolverConfig::default(),
            trust_dns_resolver::config::ResolverOpts::default(),
        );

        Self {
            resolver,
            lookup_timeout: Duration::from_secs(30),
        }
    }
}

/// Background verification poller
pub struct VerificationPoller {
    verifier: DnsVerifier,
    poll_interval: Duration,
    max_attempts: u32,
}

impl VerificationPoller {
    /// Create a new verification poller
    pub async fn new() -> anyhow::Result<Self> {
        let verifier = DnsVerifier::new().await?;

        Ok(Self {
            verifier,
            poll_interval: Duration::from_secs(60), // Check every minute
            max_attempts: 60,                       // Try for up to 1 hour
        })
    }

    /// Set poll interval
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Set max attempts
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Poll for verification completion
    ///
    /// Returns true if verified, false if max attempts reached without success
    pub async fn poll_verification(
        &self,
        domain: &str,
        token: &str,
    ) -> anyhow::Result<VerificationResult> {
        for attempt in 0..self.max_attempts {
            info!(
                "Polling for domain verification (attempt {}/{}): {}",
                attempt + 1,
                self.max_attempts,
                domain
            );

            let result = self.verifier.verify_dns(domain, token).await?;

            if result.success {
                return Ok(result);
            }

            // Wait before next attempt
            if attempt < self.max_attempts - 1 {
                tokio::time::sleep(self.poll_interval).await;
            }
        }

        Ok(VerificationResult {
            success: false,
            method: VerificationMethod::Dns,
            message: format!(
                "Verification not completed after {} attempts",
                self.max_attempts
            ),
            records_found: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let token1 = DnsVerifier::generate_token();
        let token2 = DnsVerifier::generate_token();

        assert_eq!(token1.len(), 32);
        assert_eq!(token2.len(), 32);
        assert_ne!(token1, token2); // Should be unique
    }

    #[test]
    fn test_verification_result() {
        let result = VerificationResult {
            success: true,
            method: VerificationMethod::Dns,
            message: "Success".to_string(),
            records_found: Some(vec!["vault-verify=abc123".to_string()]),
        };

        assert!(result.success);
        assert_eq!(result.method.as_str(), "dns");
    }
}
