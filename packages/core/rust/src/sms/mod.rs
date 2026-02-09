//! SMS service for sending OTP codes and notifications
//!
//! Supports multiple providers:
//! - Twilio
//! - AWS SNS
//! - WhatsApp Business API
//! - Mock provider for testing

use crate::error::VaultError;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod twilio;
pub mod whatsapp;

pub use twilio::TwilioProvider;
pub use whatsapp::{WhatsAppConfig, WhatsAppProvider};

/// OTP channel type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OtpChannel {
    /// SMS text message
    #[default]
    Sms,
    /// WhatsApp message
    WhatsApp,
    /// Voice call
    Voice,
}

impl OtpChannel {
    /// Get channel name
    pub fn as_str(&self) -> &'static str {
        match self {
            OtpChannel::Sms => "sms",
            OtpChannel::WhatsApp => "whatsapp",
            OtpChannel::Voice => "voice",
        }
    }
}

impl std::str::FromStr for OtpChannel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sms" | "text" => Ok(OtpChannel::Sms),
            "whatsapp" | "wa" => Ok(OtpChannel::WhatsApp),
            "voice" | "call" => Ok(OtpChannel::Voice),
            _ => Err(format!("Unknown OTP channel: {}", s)),
        }
    }
}

/// SMS error types
#[derive(Debug, thiserror::Error)]
pub enum SmsError {
    #[error("Invalid phone number: {0}")]
    InvalidPhoneNumber(String),
    #[error("Rate limit exceeded for phone: {0}")]
    RateLimitExceeded(String),
    #[error("Provider error: {0}")]
    ProviderError(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Code not found or expired")]
    CodeNotFound,
    #[error("Invalid verification code")]
    InvalidCode,
    #[error("SMS service not configured")]
    NotConfigured,
    #[error("WhatsApp not available for this phone number")]
    WhatsAppNotAvailable,
}

impl From<SmsError> for VaultError {
    fn from(err: SmsError) -> Self {
        match err {
            SmsError::InvalidPhoneNumber(msg) => {
                VaultError::validation(format!("Invalid phone number: {}", msg))
            }
            SmsError::RateLimitExceeded(phone) => VaultError::RateLimit { retry_after: 600 },
            SmsError::ProviderError(msg) => VaultError::ExternalService {
                service: "sms".to_string(),
                message: msg,
            },
            SmsError::Configuration(msg) => VaultError::Config(msg),
            SmsError::CodeNotFound => {
                VaultError::authentication("Verification code not found or expired")
            }
            SmsError::InvalidCode => VaultError::authentication("Invalid verification code"),
            SmsError::NotConfigured => VaultError::Config("SMS service not configured".to_string()),
            SmsError::WhatsAppNotAvailable => VaultError::ExternalService {
                service: "whatsapp".to_string(),
                message: "WhatsApp not available for this phone number".to_string(),
            },
        }
    }
}

/// SMS provider trait
#[async_trait]
pub trait SmsProvider: Send + Sync {
    /// Send an SMS message
    async fn send_sms(&self, to: &str, message: &str) -> Result<(), SmsError>;

    /// Get provider name
    fn name(&self) -> &'static str;

    /// Health check
    async fn health_check(&self) -> Result<(), SmsError> {
        Ok(())
    }

    /// Send a template message (optional support)
    async fn send_template(
        &self,
        _to: &str,
        _template_name: &str,
        _params: &[String],
    ) -> Result<(), SmsError> {
        Err(SmsError::ProviderError(
            "Template messaging not supported".to_string(),
        ))
    }
}

/// OTP code store trait for persisting verification codes
#[async_trait]
pub trait OtpCodeStore: Send + Sync {
    /// Store a code with expiration
    async fn store_code(
        &self,
        phone: &str,
        code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), SmsError>;

    /// Retrieve and remove a code (single use)
    async fn retrieve_code(&self, phone: &str)
        -> Result<Option<(String, DateTime<Utc>)>, SmsError>;

    /// Check rate limit for phone number
    async fn check_rate_limit(
        &self,
        phone: &str,
        max_attempts: u32,
        window_secs: u64,
    ) -> Result<bool, SmsError>;

    /// Record SMS send attempt
    async fn record_attempt(&self, phone: &str, window_secs: u64) -> Result<u32, SmsError>;
}

/// In-memory OTP code store (for development/testing)
pub struct InMemoryOtpCodeStore {
    codes: Arc<Mutex<HashMap<String, (String, DateTime<Utc>)>>>,
    attempts: Arc<Mutex<HashMap<String, Vec<DateTime<Utc>>>>>,
}

impl InMemoryOtpCodeStore {
    /// Create new in-memory store
    pub fn new() -> Self {
        Self {
            codes: Arc::new(Mutex::new(HashMap::new())),
            attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Clean up expired entries
    async fn cleanup_expired(&self) {
        let now = Utc::now();
        let mut codes = self.codes.lock().await;
        codes.retain(|_, (_, expires_at)| *expires_at > now);

        let mut attempts = self.attempts.lock().await;
        let window = Duration::minutes(10);
        for (_, timestamps) in attempts.iter_mut() {
            timestamps.retain(|t| now - *t < window);
        }
    }
}

impl Default for InMemoryOtpCodeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OtpCodeStore for InMemoryOtpCodeStore {
    async fn store_code(
        &self,
        phone: &str,
        code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), SmsError> {
        self.cleanup_expired().await;
        let mut codes = self.codes.lock().await;
        codes.insert(phone.to_string(), (code.to_string(), expires_at));
        Ok(())
    }

    async fn retrieve_code(
        &self,
        phone: &str,
    ) -> Result<Option<(String, DateTime<Utc>)>, SmsError> {
        self.cleanup_expired().await;
        let mut codes = self.codes.lock().await;
        Ok(codes.remove(phone))
    }

    async fn check_rate_limit(
        &self,
        phone: &str,
        max_attempts: u32,
        window_secs: u64,
    ) -> Result<bool, SmsError> {
        self.cleanup_expired().await;
        let attempts = self.attempts.lock().await;
        let now = Utc::now();
        let window = Duration::seconds(window_secs as i64);

        if let Some(timestamps) = attempts.get(phone) {
            let recent_count = timestamps.iter().filter(|t| now - **t < window).count() as u32;
            Ok(recent_count < max_attempts)
        } else {
            Ok(true)
        }
    }

    async fn record_attempt(&self, phone: &str, window_secs: u64) -> Result<u32, SmsError> {
        self.cleanup_expired().await;
        let mut attempts = self.attempts.lock().await;
        let now = Utc::now();
        let window = Duration::seconds(window_secs as i64);

        let timestamps = attempts.entry(phone.to_string()).or_default();
        timestamps.retain(|t| now - *t < window);
        timestamps.push(now);

        Ok(timestamps.len() as u32)
    }
}

/// Redis-backed OTP code store
pub struct RedisOtpCodeStore {
    redis: redis::aio::ConnectionManager,
    code_ttl_secs: u64,
}

impl RedisOtpCodeStore {
    /// Create new Redis-backed store
    pub fn new(redis: redis::aio::ConnectionManager) -> Self {
        Self {
            redis,
            code_ttl_secs: 600, // 10 minutes
        }
    }

    /// Create with custom TTL
    pub fn with_ttl(redis: redis::aio::ConnectionManager, code_ttl_secs: u64) -> Self {
        Self {
            redis,
            code_ttl_secs,
        }
    }

    fn code_key(&self, phone: &str) -> String {
        format!("sms:otp:{}", phone)
    }

    fn rate_limit_key(&self, phone: &str) -> String {
        format!("sms:ratelimit:{}", phone)
    }
}

#[async_trait]
impl OtpCodeStore for RedisOtpCodeStore {
    async fn store_code(
        &self,
        phone: &str,
        code: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<(), SmsError> {
        let mut conn = self.redis.clone();
        let key = self.code_key(phone);

        redis::cmd("SETEX")
            .arg(&key)
            .arg(self.code_ttl_secs)
            .arg(code)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| SmsError::ProviderError(format!("Redis error: {}", e)))?;

        Ok(())
    }

    async fn retrieve_code(
        &self,
        phone: &str,
    ) -> Result<Option<(String, DateTime<Utc>)>, SmsError> {
        let mut conn = self.redis.clone();
        let key = self.code_key(phone);

        // Use GETDEL to retrieve and delete atomically
        let code: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| SmsError::ProviderError(format!("Redis error: {}", e)))?;

        Ok(code.map(|c| (c, Utc::now() + Duration::seconds(self.code_ttl_secs as i64))))
    }

    async fn check_rate_limit(
        &self,
        phone: &str,
        max_attempts: u32,
        window_secs: u64,
    ) -> Result<bool, SmsError> {
        let mut conn = self.redis.clone();
        let key = self.rate_limit_key(phone);

        let count: u32 = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap_or(Some(0))
            .unwrap_or(0);

        Ok(count < max_attempts)
    }

    async fn record_attempt(&self, phone: &str, window_secs: u64) -> Result<u32, SmsError> {
        let mut conn = self.redis.clone();
        let key = self.rate_limit_key(phone);

        let count: u32 = match redis::cmd("INCR")
            .arg(&key)
            .query_async::<_, u32>(&mut conn)
            .await
        {
            Ok(c) => c,
            Err(e) => return Err(SmsError::ProviderError(format!("Redis error: {}", e))),
        };

        // Set expiry on first request
        if count == 1 {
            let _: Result<(), _> = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(window_secs)
                .query_async(&mut conn)
                .await;
        }

        Ok(count)
    }
}

/// SMS service for sending OTP codes via multiple channels (SMS, WhatsApp)
pub struct SmsService {
    sms_provider: Option<Box<dyn SmsProvider>>,
    whatsapp_provider: Option<Box<dyn SmsProvider>>,
    code_store: Box<dyn OtpCodeStore>,
    config: SmsConfig,
}

/// SMS configuration
#[derive(Debug, Clone)]
pub struct SmsConfig {
    /// Maximum SMS sends per phone number per window
    pub max_sends_per_phone: u32,
    /// Rate limit window in seconds
    pub rate_limit_window_secs: u64,
    /// OTP code expiry in minutes
    pub code_expiry_minutes: i64,
    /// OTP code length
    pub code_length: usize,
    /// Fallback to SMS if primary channel fails
    pub fallback_to_sms: bool,
}

impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            max_sends_per_phone: 3,
            rate_limit_window_secs: 600, // 10 minutes
            code_expiry_minutes: 10,
            code_length: 6,
            fallback_to_sms: true,
        }
    }
}

impl SmsService {
    /// Create new SMS service with provider and code store
    #[deprecated(since = "0.2.0", note = "Use `new_multi_channel` instead")]
    pub fn new(
        provider: Option<Box<dyn SmsProvider>>,
        code_store: Box<dyn OtpCodeStore>,
        config: SmsConfig,
    ) -> Self {
        Self {
            sms_provider: provider,
            whatsapp_provider: None,
            code_store,
            config,
        }
    }

    /// Create new SMS service with multiple channel support
    pub fn new_multi_channel(
        sms_provider: Option<Box<dyn SmsProvider>>,
        whatsapp_provider: Option<Box<dyn SmsProvider>>,
        code_store: Box<dyn OtpCodeStore>,
        config: SmsConfig,
    ) -> Self {
        Self {
            sms_provider,
            whatsapp_provider,
            code_store,
            config,
        }
    }

    /// Create service without provider (for testing/development)
    pub fn new_without_provider(code_store: Box<dyn OtpCodeStore>) -> Self {
        Self {
            sms_provider: None,
            whatsapp_provider: None,
            code_store,
            config: SmsConfig::default(),
        }
    }

    /// Set the SMS provider
    pub fn with_provider(mut self, provider: Box<dyn SmsProvider>) -> Self {
        self.sms_provider = Some(provider);
        self
    }

    /// Set the WhatsApp provider
    pub fn with_whatsapp_provider(mut self, provider: Box<dyn SmsProvider>) -> Self {
        self.whatsapp_provider = Some(provider);
        self
    }

    /// Validate phone number format (E.164)
    pub fn validate_phone_number(phone: &str) -> Result<String, SmsError> {
        // Basic E.164 validation
        // Format: +[country code][national number]
        // Country code: 1-3 digits
        // National number: up to 12 digits
        // Total max length: 15 digits (plus +)

        if !phone.starts_with('+') {
            return Err(SmsError::InvalidPhoneNumber(
                "Phone number must start with + and include country code".to_string(),
            ));
        }

        let digits_only: String = phone
            .chars()
            .skip(1)
            .filter(|c| c.is_ascii_digit())
            .collect();

        if digits_only.len() < 7 || digits_only.len() > 15 {
            return Err(SmsError::InvalidPhoneNumber(
                "Phone number must be between 7 and 15 digits".to_string(),
            ));
        }

        // Check for invalid characters
        let valid_chars: String = phone
            .chars()
            .filter(|c| {
                c.is_ascii_digit() || *c == '+' || *c == ' ' || *c == '-' || *c == '(' || *c == ')'
            })
            .collect();

        if valid_chars.len() != phone.len() {
            return Err(SmsError::InvalidPhoneNumber(
                "Phone number contains invalid characters".to_string(),
            ));
        }

        // Normalize to E.164 format
        Ok(format!("+{}", digits_only))
    }

    /// Generate a cryptographically secure random OTP code
    ///
    /// SECURITY: Uses OsRng (operating system's CSPRNG) for cryptographically secure
    /// random digit generation. SMS OTP codes are sensitive credentials that must be
    /// unpredictable to prevent unauthorized access.
    fn generate_code(&self) -> String {
        use rand::Rng;
        use rand_core::OsRng;

        // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
        let mut rng = OsRng;
        let code: String = (0..self.config.code_length)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect();
        code
    }

    /// Send OTP code to phone number via SMS (legacy method)
    pub async fn send_code(&self, phone: &str) -> Result<(), SmsError> {
        self.send_code_with_channel(phone, OtpChannel::Sms).await
    }

    /// Send OTP code to phone number via specific channel
    pub async fn send_code_with_channel(
        &self,
        phone: &str,
        channel: OtpChannel,
    ) -> Result<(), SmsError> {
        // Validate phone number
        let normalized_phone = Self::validate_phone_number(phone)?;

        // Check rate limit
        let allowed = self
            .code_store
            .check_rate_limit(
                &normalized_phone,
                self.config.max_sends_per_phone,
                self.config.rate_limit_window_secs,
            )
            .await?;

        if !allowed {
            return Err(SmsError::RateLimitExceeded(normalized_phone));
        }

        // Generate code
        let code = self.generate_code();

        // Store code with expiration
        let expires_at = Utc::now() + Duration::minutes(self.config.code_expiry_minutes);
        self.code_store
            .store_code(&normalized_phone, &code, expires_at)
            .await?;

        // Record attempt
        self.code_store
            .record_attempt(&normalized_phone, self.config.rate_limit_window_secs)
            .await?;

        // Send via appropriate channel
        match channel {
            OtpChannel::WhatsApp => {
                if let Some(provider) = &self.whatsapp_provider {
                    let message = format!(
                        "Your verification code is: {}. This code will expire in {} minutes.",
                        code, self.config.code_expiry_minutes
                    );

                    match provider.send_sms(&normalized_phone, &message).await {
                        Ok(()) => {
                            tracing::info!("WhatsApp OTP sent to {}", normalized_phone);
                        }
                        Err(e) => {
                            tracing::warn!("WhatsApp send failed: {}, attempting fallback", e);
                            if self.config.fallback_to_sms {
                                self.send_sms_fallback(&normalized_phone, &code).await?;
                            } else {
                                return Err(e);
                            }
                        }
                    }
                } else if self.config.fallback_to_sms {
                    tracing::warn!("WhatsApp provider not configured, falling back to SMS");
                    self.send_sms_fallback(&normalized_phone, &code).await?;
                } else {
                    return Err(SmsError::NotConfigured);
                }
            }
            OtpChannel::Sms | OtpChannel::Voice => {
                self.send_sms_fallback(&normalized_phone, &code).await?;
            }
        }

        Ok(())
    }

    /// Send OTP via SMS (internal helper)
    async fn send_sms_fallback(&self, phone: &str, code: &str) -> Result<(), SmsError> {
        let provider = self.sms_provider.as_ref().ok_or(SmsError::NotConfigured)?;

        let message = format!(
            "Your verification code is: {}. This code will expire in {} minutes.",
            code, self.config.code_expiry_minutes
        );

        provider.send_sms(phone, &message).await?;

        tracing::info!("SMS OTP sent to {} (fallback)", phone);

        Ok(())
    }

    /// Verify OTP code
    /// Uses constant-time comparison to prevent timing attacks
    pub async fn verify_code(&self, phone: &str, code: &str) -> Result<bool, SmsError> {
        // Validate phone number
        let normalized_phone = Self::validate_phone_number(phone)?;

        // Retrieve stored code (this also deletes it)
        let stored = self.code_store.retrieve_code(&normalized_phone).await?;

        let (stored_code, expires_at) = match stored {
            Some(data) => data,
            None => return Err(SmsError::CodeNotFound),
        };

        // Check expiration
        if Utc::now() > expires_at {
            return Err(SmsError::CodeNotFound);
        }

        // Constant-time comparison
        let valid = crate::crypto::secure_compare(code.as_bytes(), stored_code.as_bytes());

        if valid {
            tracing::info!("SMS OTP verified successfully for {}", normalized_phone);
            Ok(true)
        } else {
            tracing::warn!("Invalid SMS OTP attempt for {}", normalized_phone);
            Err(SmsError::InvalidCode)
        }
    }

    /// Get remaining attempts for a phone number
    pub async fn get_remaining_attempts(&self, phone: &str) -> Result<u32, SmsError> {
        let normalized_phone = Self::validate_phone_number(phone)?;
        let current = self
            .code_store
            .record_attempt(&normalized_phone, self.config.rate_limit_window_secs)
            .await?;
        // Decrement since record_attempt increments
        let actual_current = current.saturating_sub(1);
        Ok(self
            .config
            .max_sends_per_phone
            .saturating_sub(actual_current))
    }

    /// Check if SMS service is configured
    pub fn is_configured(&self) -> bool {
        self.sms_provider.is_some()
    }

    /// Send a notification message (non-OTP)
    pub async fn send_message(
        &self,
        phone: &str,
        message: &str,
        channel: OtpChannel,
    ) -> Result<(), SmsError> {
        let normalized_phone = Self::validate_phone_number(phone)?;

        match channel {
            OtpChannel::Sms | OtpChannel::Voice => {
                let provider = self.sms_provider.as_ref().ok_or(SmsError::NotConfigured)?;
                provider.send_sms(&normalized_phone, message).await?;
            }
            OtpChannel::WhatsApp => {
                if let Some(provider) = &self.whatsapp_provider {
                    provider.send_sms(&normalized_phone, message).await?;
                } else if self.config.fallback_to_sms {
                    let provider = self.sms_provider.as_ref().ok_or(SmsError::NotConfigured)?;
                    provider.send_sms(&normalized_phone, message).await?;
                } else {
                    return Err(SmsError::NotConfigured);
                }
            }
        }

        Ok(())
    }

    /// Send a WhatsApp template message (requires WhatsApp provider)
    pub async fn send_template_message(
        &self,
        phone: &str,
        template_name: &str,
        params: &[String],
    ) -> Result<(), SmsError> {
        let normalized_phone = Self::validate_phone_number(phone)?;
        let provider = self
            .whatsapp_provider
            .as_ref()
            .ok_or(SmsError::NotConfigured)?;
        provider
            .send_template(&normalized_phone, template_name, params)
            .await
    }

    /// Get SMS provider name
    pub fn provider_name(&self) -> Option<&'static str> {
        self.sms_provider.as_ref().map(|p| p.name())
    }

    /// Check if WhatsApp service is configured
    pub fn is_whatsapp_configured(&self) -> bool {
        self.whatsapp_provider.is_some()
    }

    /// Get WhatsApp provider name
    pub fn whatsapp_provider_name(&self) -> Option<&'static str> {
        self.whatsapp_provider.as_ref().map(|p| p.name())
    }

    /// Check if a specific channel is available
    pub fn is_channel_available(&self, channel: OtpChannel) -> bool {
        match channel {
            OtpChannel::Sms => self.sms_provider.is_some(),
            OtpChannel::WhatsApp => self.whatsapp_provider.is_some(),
            OtpChannel::Voice => false, // Voice not yet implemented
        }
    }

    /// Get available channels
    pub fn available_channels(&self) -> Vec<OtpChannel> {
        let mut channels = Vec::new();
        if self.sms_provider.is_some() {
            channels.push(OtpChannel::Sms);
        }
        if self.whatsapp_provider.is_some() {
            channels.push(OtpChannel::WhatsApp);
        }
        channels
    }
}

/// Mock SMS provider for testing
#[derive(Clone)]
pub struct MockSmsProvider {
    sent_messages: Arc<Mutex<Vec<(String, String)>>>,
}

impl MockSmsProvider {
    /// Create new mock provider
    pub fn new() -> Self {
        Self {
            sent_messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get sent messages
    pub async fn get_sent_messages(&self) -> Vec<(String, String)> {
        self.sent_messages.lock().await.clone()
    }

    /// Clear sent messages
    pub async fn clear(&self) {
        self.sent_messages.lock().await.clear();
    }

    /// Get last sent code for a phone number
    pub async fn get_last_code(&self, phone: &str) -> Option<String> {
        let messages = self.sent_messages.lock().await;
        messages
            .iter()
            .rev()
            .find(|(to, _)| to == phone)
            .map(|(_, msg)| {
                // Extract code from message like "Your verification code is: 123456..."
                msg.split("Your verification code is: ")
                    .nth(1)
                    .and_then(|s| s.split('.').next())
                    .map(|s| s.to_string())
            })
            .flatten()
    }
}

impl Default for MockSmsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SmsProvider for MockSmsProvider {
    async fn send_sms(&self, to: &str, message: &str) -> Result<(), SmsError> {
        self.sent_messages
            .lock()
            .await
            .push((to.to_string(), message.to_string()));
        tracing::info!("[MOCK SMS] To: {}, Message: {}", to, message);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_phone_number() {
        // Valid numbers
        assert!(SmsService::validate_phone_number("+12345678901").is_ok());
        assert!(SmsService::validate_phone_number("+44 20 7946 0958").is_ok());
        assert!(SmsService::validate_phone_number("+1-800-555-0199").is_ok());

        // Invalid - no country code
        assert!(SmsService::validate_phone_number("1234567890").is_err());

        // Invalid - too short
        assert!(SmsService::validate_phone_number("+123").is_err());

        // Invalid - too long
        assert!(SmsService::validate_phone_number("+1234567890123456").is_err());

        // Invalid characters
        assert!(SmsService::validate_phone_number("+123abc").is_err());
    }

    #[tokio::test]
    async fn test_sms_service_send_and_verify() {
        let mock_provider = MockSmsProvider::new();
        let code_store = Box::new(InMemoryOtpCodeStore::new());

        let service = SmsService::new(
            Some(Box::new(mock_provider.clone())),
            code_store,
            SmsConfig::default(),
        );

        // Send code
        service.send_code("+12345678901").await.unwrap();

        // Get the sent code from mock
        let code = mock_provider.get_last_code("+12345678901").await.unwrap();
        assert_eq!(code.len(), 6);

        // Verify with correct code
        let valid = service.verify_code("+12345678901", &code).await.unwrap();
        assert!(valid);

        // Verify code is consumed (can't use again)
        let result = service.verify_code("+12345678901", &code).await;
        assert!(matches!(result, Err(SmsError::CodeNotFound)));
    }

    #[tokio::test]
    async fn test_sms_service_invalid_code() {
        let mock_provider = MockSmsProvider::new();
        let code_store = Box::new(InMemoryOtpCodeStore::new());

        let service = SmsService::new(
            Some(Box::new(mock_provider.clone())),
            code_store,
            SmsConfig::default(),
        );

        // Send code
        service.send_code("+12345678901").await.unwrap();

        // Verify with wrong code
        let result = service.verify_code("+12345678901", "000000").await;
        assert!(matches!(result, Err(SmsError::InvalidCode)));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let mock_provider = MockSmsProvider::new();
        let code_store = Box::new(InMemoryOtpCodeStore::new());

        let config = SmsConfig {
            max_sends_per_phone: 2,
            rate_limit_window_secs: 600,
            code_expiry_minutes: 10,
            code_length: 6,
            fallback_to_sms: true,
        };

        let service = SmsService::new(Some(Box::new(mock_provider.clone())), code_store, config);

        // First two sends should succeed
        service.send_code("+12345678901").await.unwrap();
        service.send_code("+12345678901").await.unwrap();

        // Third send should fail due to rate limit
        let result = service.send_code("+12345678901").await;
        assert!(matches!(result, Err(SmsError::RateLimitExceeded(_))));
    }

    #[test]
    fn test_generate_code() {
        let service = SmsService::new_without_provider(Box::new(InMemoryOtpCodeStore::new()));

        // Generate multiple codes and verify format
        for _ in 0..100 {
            let code = service.generate_code();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[tokio::test]
    async fn test_phone_normalization() {
        let mock_provider = MockSmsProvider::new();
        let code_store = Box::new(InMemoryOtpCodeStore::new());

        let service = SmsService::new(
            Some(Box::new(mock_provider.clone())),
            code_store,
            SmsConfig::default(),
        );

        // Send with different formats
        service.send_code("+1 (234) 567-8901").await.unwrap();

        // Get the code using normalized format
        let code = mock_provider.get_last_code("+12345678901").await.unwrap();

        // Verify with different format should work due to normalization
        let valid = service.verify_code("+1-234-567-8901", &code).await.unwrap();
        assert!(valid);
    }
}
