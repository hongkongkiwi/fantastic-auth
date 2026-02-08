//! Attack Pattern Detection System
//!
//! This module provides real-time detection of various attack patterns:
//! - Distributed brute force attacks
//! - Credential stuffing campaigns
//! - Account enumeration attempts
//! - Session hijacking attempts
//! - Bot traffic patterns

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::error::{AiError, AiResult};
use super::ml_models::ModelManager;
use crate::db::DbContext;

/// Types of attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    /// Distributed brute force
    DistributedBruteForce,
    /// Credential stuffing
    CredentialStuffing,
    /// Account enumeration
    AccountEnumeration,
    /// Session hijacking
    SessionHijacking,
    /// Bot traffic
    BotTraffic,
    /// Rate limit evasion
    RateLimitEvasion,
    /// Password spraying
    PasswordSpraying,
    /// MFA bypass attempt
    MfaBypass,
    /// Account takeover
    AccountTakeover,
    /// Impossible travel campaign
    ImpossibleTravelCampaign,
}

impl AttackType {
    /// Get severity level
    pub fn severity(&self) -> AttackSeverity {
        match self {
            AttackType::DistributedBruteForce => AttackSeverity::High,
            AttackType::CredentialStuffing => AttackSeverity::Critical,
            AttackType::AccountEnumeration => AttackSeverity::Medium,
            AttackType::SessionHijacking => AttackSeverity::Critical,
            AttackType::BotTraffic => AttackSeverity::Medium,
            AttackType::RateLimitEvasion => AttackSeverity::High,
            AttackType::PasswordSpraying => AttackSeverity::High,
            AttackType::MfaBypass => AttackSeverity::Critical,
            AttackType::AccountTakeover => AttackSeverity::Critical,
            AttackType::ImpossibleTravelCampaign => AttackSeverity::High,
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            AttackType::DistributedBruteForce => {
                "Coordinated brute force attack from multiple sources"
            }
            AttackType::CredentialStuffing => "Automated credential stuffing campaign",
            AttackType::AccountEnumeration => "Systematic username enumeration attempt",
            AttackType::SessionHijacking => "Active session hijacking attempt",
            AttackType::BotTraffic => "Automated bot traffic detected",
            AttackType::RateLimitEvasion => "Attempt to evade rate limiting",
            AttackType::PasswordSpraying => "Password spraying attack",
            AttackType::MfaBypass => "Attempt to bypass MFA",
            AttackType::AccountTakeover => "Active account takeover campaign",
            AttackType::ImpossibleTravelCampaign => {
                "Coordinated attack using stolen credentials from multiple locations"
            }
        }
    }
}

/// Attack severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AttackSeverity {
    /// Get numeric value
    pub fn value(&self) -> u8 {
        match self {
            AttackSeverity::Low => 1,
            AttackSeverity::Medium => 2,
            AttackSeverity::High => 3,
            AttackSeverity::Critical => 4,
        }
    }
}

/// Detected attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attack {
    /// Unique attack ID
    pub id: String,
    /// Attack type
    pub attack_type: AttackType,
    /// Severity
    pub severity: AttackSeverity,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// End time (if resolved)
    pub ended_at: Option<DateTime<Utc>>,
    /// Source IPs involved
    pub source_ips: Vec<String>,
    /// Target accounts
    pub target_accounts: Vec<String>,
    /// Number of attempts
    pub attempt_count: u64,
    /// Success rate (0-1)
    pub success_rate: f64,
    /// Confidence score (0-1)
    pub confidence: f64,
    /// Attack pattern details
    pub details: AttackDetails,
    /// Recommended actions
    pub recommendations: Vec<String>,
    /// Is active
    pub is_active: bool,
}

impl Attack {
    /// Create new attack detection
    pub fn new(
        attack_type: AttackType,
        severity: AttackSeverity,
        confidence: f64,
        details: AttackDetails,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            attack_type,
            severity,
            started_at: Utc::now(),
            ended_at: None,
            source_ips: Vec::new(),
            target_accounts: Vec::new(),
            attempt_count: 0,
            success_rate: 0.0,
            confidence: confidence.clamp(0.0, 1.0),
            details,
            recommendations: Self::default_recommendations(&attack_type),
            is_active: true,
        }
    }

    /// Add source IP
    pub fn add_source_ip(&mut self, ip: impl Into<String>) {
        let ip = ip.into();
        if !self.source_ips.contains(&ip) {
            self.source_ips.push(ip);
        }
    }

    /// Add target account
    pub fn add_target(&mut self, account: impl Into<String>) {
        let account = account.into();
        if !self.target_accounts.contains(&account) {
            self.target_accounts.push(account);
        }
    }

    /// Mark as resolved
    pub fn resolve(&mut self) {
        self.ended_at = Some(Utc::now());
        self.is_active = false;
    }

    /// Get duration
    pub fn duration(&self) -> Duration {
        let end = self.ended_at.unwrap_or_else(Utc::now);
        end - self.started_at
    }

    /// Default recommendations for attack type
    fn default_recommendations(attack_type: &AttackType) -> Vec<String> {
        match attack_type {
            AttackType::DistributedBruteForce => vec![
                "Enable IP-based blocking".to_string(),
                "Consider enabling CAPTCHA".to_string(),
                "Alert affected users".to_string(),
            ],
            AttackType::CredentialStuffing => vec![
                "Block source IPs immediately".to_string(),
                "Force password reset for affected accounts".to_string(),
                "Enable additional MFA checks".to_string(),
            ],
            AttackType::AccountEnumeration => vec![
                "Rate limit authentication endpoints".to_string(),
                "Add random delays to responses".to_string(),
            ],
            AttackType::SessionHijacking => vec![
                "Invalidate affected sessions".to_string(),
                "Force re-authentication".to_string(),
                "Review session binding settings".to_string(),
            ],
            AttackType::BotTraffic => vec![
                "Enable bot protection".to_string(),
                "Consider implementing proof-of-work".to_string(),
            ],
            _ => vec!["Review security logs".to_string()],
        }
    }
}

/// Attack details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackDetails {
    /// Pattern description
    pub pattern: String,
    /// Average request rate (per minute)
    pub avg_request_rate: f64,
    /// Geographic distribution
    pub geo_distribution: Vec<String>,
    /// User agent patterns
    pub user_agents: Vec<String>,
    /// Time distribution
    pub time_distribution: TimeDistribution,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Time distribution of attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeDistribution {
    /// Peak hour
    pub peak_hour: u8,
    /// Is distributed over time
    pub is_distributed: bool,
    /// Burst pattern detected
    pub has_burst_pattern: bool,
}

/// Time window for analysis
#[derive(Debug, Clone, Copy)]
pub struct TimeWindow {
    /// Start time
    pub start: DateTime<Utc>,
    /// End time
    pub end: DateTime<Utc>,
}

impl TimeWindow {
    /// Create new time window
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self { start, end }
    }

    /// Create window from duration
    pub fn from_duration(duration: Duration) -> Self {
        let end = Utc::now();
        let start = end - duration;
        Self::new(start, end)
    }

    /// Create window for last N minutes
    pub fn last_minutes(minutes: i64) -> Self {
        Self::from_duration(Duration::minutes(minutes))
    }

    /// Create window for last N hours
    pub fn last_hours(hours: i64) -> Self {
        Self::from_duration(Duration::hours(hours))
    }

    /// Get duration
    pub fn duration(&self) -> Duration {
        self.end - self.start
    }
}

/// Attack signature for pattern matching
#[derive(Debug, Clone)]
pub struct AttackSignature {
    /// Signature name
    pub name: String,
    /// Attack type
    pub attack_type: AttackType,
    /// Pattern rules
    pub rules: Vec<SignatureRule>,
    /// Threshold for triggering
    pub threshold: u32,
    /// Time window for counting
    pub window_seconds: u64,
}

/// Signature rule
#[derive(Debug, Clone)]
pub enum SignatureRule {
    /// Match on user agent pattern
    UserAgentPattern(String),
    /// Match on request rate
    RequestRate { min: u32, per_seconds: u64 },
    /// Match on failed login ratio
    FailedLoginRatio { min: f64 },
    /// Match on IP diversity
    IpDiversity { min_ips: u32 },
    /// Match on account diversity
    AccountDiversity { min_accounts: u32 },
    /// Match on geographic spread
    GeoSpread { min_countries: u32 },
}

/// Threat intelligence feed
#[derive(Debug, Clone)]
pub struct ThreatIntelligence {
    /// Known bad IPs
    pub known_bad_ips: Arc<RwLock<HashSet<String>>>,
    /// Known bad user agents
    pub known_bad_ua: Arc<RwLock<Vec<String>>>,
    /// TOR exit nodes
    pub tor_exit_nodes: Arc<RwLock<HashSet<String>>>,
    /// VPN/proxy ranges
    pub proxy_ranges: Arc<RwLock<Vec<String>>>,
    /// Last update time
    pub last_update: Arc<RwLock<DateTime<Utc>>>,
}

impl ThreatIntelligence {
    /// Create new threat intelligence
    pub fn new() -> Self {
        Self {
            known_bad_ips: Arc::new(RwLock::new(HashSet::new())),
            known_bad_ua: Arc::new(RwLock::new(Vec::new())),
            tor_exit_nodes: Arc::new(RwLock::new(HashSet::new())),
            proxy_ranges: Arc::new(RwLock::new(Vec::new())),
            last_update: Arc::new(RwLock::new(Utc::now())),
        }
    }

    /// Check if IP is known bad
    pub async fn is_known_bad(&self, ip: &str) -> bool {
        let bad_ips = self.known_bad_ips.read().await;
        bad_ips.contains(ip)
    }

    /// Check if user agent is suspicious
    pub async fn is_suspicious_ua(&self, ua: &str) -> bool {
        let bad_ua = self.known_bad_ua.read().await;
        bad_ua.iter().any(|pattern| ua.contains(pattern))
    }

    /// Update threat data (would fetch from external sources)
    pub async fn update(&self) -> AiResult<()> {
        // In production, this would fetch from threat intel APIs
        // For now, just update timestamp
        let mut last_update = self.last_update.write().await;
        *last_update = Utc::now();
        Ok(())
    }
}

impl Default for ThreatIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

/// Main threat detector
pub struct ThreatDetector {
    /// Detection window size in seconds
    window_seconds: u64,
    /// Database connection
    db: DbContext,
    /// Model manager
    model_manager: Arc<ModelManager>,
    /// Threat intelligence
    threat_intel: Arc<ThreatIntelligence>,
    /// Active attacks
    active_attacks: Arc<RwLock<HashMap<String, Attack>>>,
    /// Attack signatures
    signatures: Vec<AttackSignature>,
    /// Event buffer for analysis
    event_buffer: Arc<RwLock<Vec<AuthEvent>>>,
    /// Total blocked counter
    blocked_count: Arc<RwLock<u64>>,
}

/// Authentication event for analysis
#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<IpAddr>,
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub success: bool,
    pub user_agent: Option<String>,
    pub country_code: Option<String>,
}

/// Attack pattern for detection
#[derive(Clone)]
pub struct AttackPattern {
    /// Pattern name
    pub name: String,
    /// Associated attack type
    pub attack_type: AttackType,
    /// Detection function
    pub detector: Arc<dyn Fn(&[AuthEvent]) -> Option<Attack> + Send + Sync>,
}

impl ThreatDetector {
    /// Create new threat detector
    pub async fn new(
        window_seconds: u64,
        db: DbContext,
        model_manager: Arc<ModelManager>,
    ) -> AiResult<Self> {
        let threat_intel = Arc::new(ThreatIntelligence::new());

        // Initialize attack signatures
        let signatures = Self::initialize_signatures();

        Ok(Self {
            window_seconds,
            db,
            model_manager,
            threat_intel,
            active_attacks: Arc::new(RwLock::new(HashMap::new())),
            signatures,
            event_buffer: Arc::new(RwLock::new(Vec::new())),
            blocked_count: Arc::new(RwLock::new(0)),
        })
    }

    /// Initialize default attack signatures
    fn initialize_signatures() -> Vec<AttackSignature> {
        vec![
            // Distributed brute force
            AttackSignature {
                name: "Distributed Brute Force".to_string(),
                attack_type: AttackType::DistributedBruteForce,
                rules: vec![
                    SignatureRule::FailedLoginRatio { min: 0.8 },
                    SignatureRule::IpDiversity { min_ips: 5 },
                    SignatureRule::RequestRate {
                        min: 10,
                        per_seconds: 60,
                    },
                ],
                threshold: 50,
                window_seconds: 300,
            },
            // Credential stuffing
            AttackSignature {
                name: "Credential Stuffing".to_string(),
                attack_type: AttackType::CredentialStuffing,
                rules: vec![
                    SignatureRule::AccountDiversity { min_accounts: 10 },
                    SignatureRule::RequestRate {
                        min: 30,
                        per_seconds: 60,
                    },
                    SignatureRule::UserAgentPattern("python-requests".to_string()),
                ],
                threshold: 100,
                window_seconds: 60,
            },
            // Account enumeration
            AttackSignature {
                name: "Account Enumeration".to_string(),
                attack_type: AttackType::AccountEnumeration,
                rules: vec![
                    SignatureRule::AccountDiversity { min_accounts: 20 },
                    SignatureRule::FailedLoginRatio { min: 1.0 },
                    SignatureRule::RequestRate {
                        min: 20,
                        per_seconds: 60,
                    },
                ],
                threshold: 30,
                window_seconds: 120,
            },
        ]
    }

    /// Detect attacks in time window
    pub async fn detect_attacks(&self, window: TimeWindow) -> AiResult<Vec<Attack>> {
        let mut attacks = Vec::new();

        // Get recent events
        let events = self.get_events_in_window(window).await?;

        // Check for distributed brute force
        if let Some(attack) = self.detect_distributed_brute_force(&events).await? {
            attacks.push(attack);
        }

        // Check for credential stuffing
        if let Some(attack) = self.detect_credential_stuffing(&events).await? {
            attacks.push(attack);
        }

        // Check for account enumeration
        if let Some(attack) = self.detect_account_enumeration(&events).await? {
            attacks.push(attack);
        }

        // Check for session hijacking patterns
        if let Some(attack) = self.detect_session_hijacking(&events).await? {
            attacks.push(attack);
        }

        // Check for bot traffic
        if let Some(attack) = self.detect_bot_traffic(&events).await? {
            attacks.push(attack);
        }

        // Update active attacks
        let mut active = self.active_attacks.write().await;
        for attack in &attacks {
            active.insert(attack.id.clone(), attack.clone());
        }

        Ok(attacks)
    }

    /// Get events in time window
    async fn get_events_in_window(&self, window: TimeWindow) -> AiResult<Vec<AuthEvent>> {
        // In production, this would query the database
        // For now, return from buffer
        let buffer = self.event_buffer.read().await;
        let events: Vec<AuthEvent> = buffer
            .iter()
            .filter(|e| e.timestamp >= window.start && e.timestamp <= window.end)
            .cloned()
            .collect();
        Ok(events)
    }

    /// Detect distributed brute force
    async fn detect_distributed_brute_force(
        &self,
        events: &[AuthEvent],
    ) -> AiResult<Option<Attack>> {
        let failed_events: Vec<_> = events.iter().filter(|e| !e.success).collect();

        if failed_events.len() < 50 {
            return Ok(None);
        }

        // Count unique IPs
        let unique_ips: HashSet<_> = failed_events
            .iter()
            .filter_map(|e| e.ip_address.map(|ip| ip.to_string()))
            .collect();

        // Count unique targets
        let unique_targets: HashSet<_> = failed_events
            .iter()
            .filter_map(|e| e.email.clone())
            .collect();

        // Distributed brute force: many IPs, few targets, high failure rate
        if unique_ips.len() >= 5 && unique_targets.len() <= 10 {
            let success_rate =
                events.iter().filter(|e| e.success).count() as f64 / events.len() as f64;

            let mut attack = Attack::new(
                AttackType::DistributedBruteForce,
                AttackSeverity::High,
                0.85,
                AttackDetails {
                    pattern: "Multiple IPs targeting few accounts with high failure rate"
                        .to_string(),
                    avg_request_rate: events.len() as f64 / 5.0, // per minute
                    geo_distribution: vec![],
                    user_agents: vec![],
                    time_distribution: TimeDistribution {
                        peak_hour: Utc::now().hour() as u8,
                        is_distributed: true,
                        has_burst_pattern: false,
                    },
                    metadata: Some(serde_json::json!({
                        "unique_ips": unique_ips.len(),
                        "unique_targets": unique_targets.len(),
                        "success_rate": success_rate,
                    })),
                },
            );

            for ip in unique_ips {
                attack.add_source_ip(ip);
            }
            for target in unique_targets {
                attack.add_target(target);
            }
            attack.attempt_count = failed_events.len() as u64;
            attack.success_rate = success_rate;

            return Ok(Some(attack));
        }

        Ok(None)
    }

    /// Detect credential stuffing
    async fn detect_credential_stuffing(&self, events: &[AuthEvent]) -> AiResult<Option<Attack>> {
        // Credential stuffing: many accounts, distributed IPs, often with same password patterns
        let unique_accounts: HashSet<_> = events.iter().filter_map(|e| e.email.clone()).collect();

        if unique_accounts.len() < 20 {
            return Ok(None);
        }

        let unique_ips: HashSet<_> = events
            .iter()
            .filter_map(|e| e.ip_address.map(|ip| ip.to_string()))
            .collect();

        // High account diversity with distributed sources
        if unique_accounts.len() > unique_ips.len() * 2 {
            let success_count = events.iter().filter(|e| e.success).count();
            let success_rate = success_count as f64 / events.len() as f64;

            // Low success rate is typical for credential stuffing
            if success_rate < 0.1 {
                let mut attack = Attack::new(
                    AttackType::CredentialStuffing,
                    AttackSeverity::Critical,
                    0.9,
                    AttackDetails {
                        pattern: "Automated login attempts with many different credentials"
                            .to_string(),
                        avg_request_rate: events.len() as f64 / 5.0,
                        geo_distribution: vec![],
                        user_agents: vec![],
                        time_distribution: TimeDistribution {
                            peak_hour: Utc::now().hour() as u8,
                            is_distributed: true,
                            has_burst_pattern: true,
                        },
                        metadata: Some(serde_json::json!({
                            "unique_accounts": unique_accounts.len(),
                            "unique_ips": unique_ips.len(),
                            "success_rate": success_rate,
                        })),
                    },
                );

                for ip in unique_ips {
                    attack.add_source_ip(ip);
                }
                for account in unique_accounts {
                    attack.add_target(account);
                }
                attack.attempt_count = events.len() as u64;
                attack.success_rate = success_rate;

                return Ok(Some(attack));
            }
        }

        Ok(None)
    }

    /// Detect account enumeration
    async fn detect_account_enumeration(&self, events: &[AuthEvent]) -> AiResult<Option<Attack>> {
        // Account enumeration: systematic checking of usernames, typically all failing
        let unique_accounts: HashSet<_> = events.iter().filter_map(|e| e.email.clone()).collect();

        let failed_count = events.iter().filter(|e| !e.success).count();
        let failure_rate = failed_count as f64 / events.len().max(1) as f64;

        // Many accounts checked, nearly all fail (probing for valid usernames)
        if unique_accounts.len() >= 20 && failure_rate > 0.95 {
            let unique_ips: HashSet<_> = events
                .iter()
                .filter_map(|e| e.ip_address.map(|ip| ip.to_string()))
                .collect();

            let mut attack = Attack::new(
                AttackType::AccountEnumeration,
                AttackSeverity::Medium,
                0.75,
                AttackDetails {
                    pattern: "Systematic username enumeration".to_string(),
                    avg_request_rate: events.len() as f64 / 5.0,
                    geo_distribution: vec![],
                    user_agents: vec![],
                    time_distribution: TimeDistribution {
                        peak_hour: Utc::now().hour() as u8,
                        is_distributed: false,
                        has_burst_pattern: true,
                    },
                    metadata: Some(serde_json::json!({
                        "unique_accounts": unique_accounts.len(),
                        "failure_rate": failure_rate,
                    })),
                },
            );

            for ip in unique_ips {
                attack.add_source_ip(ip);
            }
            attack.attempt_count = events.len() as u64;
            attack.success_rate = 1.0 - failure_rate;

            return Ok(Some(attack));
        }

        Ok(None)
    }

    /// Detect session hijacking patterns
    async fn detect_session_hijacking(&self, _events: &[AuthEvent]) -> AiResult<Option<Attack>> {
        // Session hijacking detection would require session data
        // This is a placeholder for the implementation
        Ok(None)
    }

    /// Detect bot traffic
    async fn detect_bot_traffic(&self, events: &[AuthEvent]) -> AiResult<Option<Attack>> {
        // Check for bot-like patterns
        let suspicious_ua_count = events
            .iter()
            .filter(|e| {
                e.user_agent.as_ref().map_or(false, |ua| {
                    ua.contains("bot") || ua.contains("crawler") || ua.contains("scraper")
                })
            })
            .count();

        if suspicious_ua_count > events.len() / 2 && events.len() > 20 {
            let unique_ips: HashSet<_> = events
                .iter()
                .filter_map(|e| e.ip_address.map(|ip| ip.to_string()))
                .collect();

            let mut attack = Attack::new(
                AttackType::BotTraffic,
                AttackSeverity::Medium,
                0.7,
                AttackDetails {
                    pattern: "Automated bot traffic detected".to_string(),
                    avg_request_rate: events.len() as f64 / 5.0,
                    geo_distribution: vec![],
                    user_agents: events.iter().filter_map(|e| e.user_agent.clone()).collect(),
                    time_distribution: TimeDistribution {
                        peak_hour: Utc::now().hour() as u8,
                        is_distributed: true,
                        has_burst_pattern: false,
                    },
                    metadata: None,
                },
            );

            for ip in unique_ips {
                attack.add_source_ip(ip);
            }
            attack.attempt_count = events.len() as u64;

            return Ok(Some(attack));
        }

        Ok(None)
    }

    /// Record an authentication event
    pub async fn record_event(&self, event: AuthEvent) -> AiResult<()> {
        let mut buffer = self.event_buffer.write().await;
        buffer.push(event);

        // Keep buffer size manageable (keep last 10000 events)
        if buffer.len() > 10000 {
            buffer.drain(0..1000);
        }

        Ok(())
    }

    /// Get active attacks
    pub async fn get_active_attacks(&self) -> Vec<Attack> {
        let active = self.active_attacks.read().await;
        active.values().filter(|a| a.is_active).cloned().collect()
    }

    /// Get attack by ID
    pub async fn get_attack(&self, attack_id: &str) -> Option<Attack> {
        let active = self.active_attacks.read().await;
        active.get(attack_id).cloned()
    }

    /// Resolve an attack
    pub async fn resolve_attack(&self, attack_id: &str) -> AiResult<()> {
        let mut active = self.active_attacks.write().await;
        if let Some(attack) = active.get_mut(attack_id) {
            attack.resolve();
        }
        Ok(())
    }

    /// Get total blocked count
    pub fn total_blocked(&self) -> u64 {
        0 // Would return actual count in production
    }
}

/// Brute force detector for individual accounts
pub struct BruteForceDetector {
    /// Max attempts before triggering
    max_attempts: u32,
    /// Time window in seconds
    window_seconds: u64,
    /// Attempt tracking
    attempts: Arc<RwLock<HashMap<String, Vec<DateTime<Utc>>>>>,
}

impl BruteForceDetector {
    /// Create new detector
    pub fn new(max_attempts: u32, window_seconds: u64) -> Self {
        Self {
            max_attempts,
            window_seconds,
            attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a failed attempt
    pub async fn record_failure(&self, identifier: &str) -> bool {
        let mut attempts = self.attempts.write().await;
        let now = Utc::now();

        let entry = attempts
            .entry(identifier.to_string())
            .or_insert_with(Vec::new);
        entry.push(now);

        // Clean old attempts
        let cutoff = now - Duration::seconds(self.window_seconds as i64);
        entry.retain(|t| *t > cutoff);

        // Check if threshold exceeded
        entry.len() as u32 >= self.max_attempts
    }

    /// Reset attempts for identifier
    pub async fn reset(&self, identifier: &str) {
        let mut attempts = self.attempts.write().await;
        attempts.remove(identifier);
    }

    /// Get current attempt count
    pub async fn get_attempt_count(&self, identifier: &str) -> u32 {
        let attempts = self.attempts.read().await;
        attempts
            .get(identifier)
            .map(|v| v.len() as u32)
            .unwrap_or(0)
    }
}

/// Credential stuffing detector
pub struct CredentialStuffingDetector {
    /// Min unique accounts for detection
    min_accounts: u32,
    /// Min attempts per minute
    min_rate: u32,
    /// Attempt tracking per IP
    ip_attempts: Arc<RwLock<HashMap<String, Vec<AccountAttempt>>>>,
}

/// Account attempt record
#[derive(Debug, Clone)]
struct AccountAttempt {
    account: String,
    timestamp: DateTime<Utc>,
}

impl CredentialStuffingDetector {
    /// Create new detector
    pub fn new(min_accounts: u32, min_rate: u32) -> Self {
        Self {
            min_accounts,
            min_rate,
            ip_attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record an attempt
    pub async fn record_attempt(&self, ip: &str, account: &str) -> bool {
        let mut attempts = self.ip_attempts.write().await;
        let now = Utc::now();

        let entry = attempts.entry(ip.to_string()).or_insert_with(Vec::new);
        entry.push(AccountAttempt {
            account: account.to_string(),
            timestamp: now,
        });

        // Clean old attempts (older than 1 minute)
        let cutoff = now - Duration::minutes(1);
        entry.retain(|a| a.timestamp > cutoff);

        // Check for credential stuffing pattern
        let unique_accounts: HashSet<_> = entry.iter().map(|a| &a.account).collect();
        let rate = entry.len() as u32;

        unique_accounts.len() as u32 >= self.min_accounts && rate >= self.min_rate
    }

    /// Reset tracking for IP
    pub async fn reset(&self, ip: &str) {
        let mut attempts = self.ip_attempts.write().await;
        attempts.remove(ip);
    }
}

/// Session hijacking detector
pub struct SessionHijackingDetector {
    /// Session tracking
    sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
    /// Max location changes before alert
    max_location_changes: u32,
}

/// Session information
#[derive(Debug, Clone)]
struct SessionInfo {
    user_id: String,
    ip_address: String,
    user_agent: String,
    location_changes: u32,
    created_at: DateTime<Utc>,
}

impl SessionHijackingDetector {
    /// Create new detector
    pub fn new(max_location_changes: u32) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_location_changes,
        }
    }

    /// Check session for hijacking indicators
    pub async fn check_session(
        &self,
        session_id: &str,
        user_id: &str,
        ip: &str,
        user_agent: &str,
    ) -> bool {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(session_id) {
            // Check for changes
            if session.ip_address != ip || session.user_agent != user_agent {
                session.location_changes += 1;

                if session.location_changes >= self.max_location_changes {
                    return true; // Potential hijacking
                }
            }
        } else {
            // New session
            sessions.insert(
                session_id.to_string(),
                SessionInfo {
                    user_id: user_id.to_string(),
                    ip_address: ip.to_string(),
                    user_agent: user_agent.to_string(),
                    location_changes: 0,
                    created_at: Utc::now(),
                },
            );
        }

        false
    }

    /// End session tracking
    pub async fn end_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_type_severity() {
        assert_eq!(
            AttackType::CredentialStuffing.severity(),
            AttackSeverity::Critical
        );
        assert_eq!(
            AttackType::DistributedBruteForce.severity(),
            AttackSeverity::High
        );
        assert_eq!(
            AttackType::AccountEnumeration.severity(),
            AttackSeverity::Medium
        );
    }

    #[test]
    fn test_attack_creation() {
        let details = AttackDetails {
            pattern: "Test pattern".to_string(),
            avg_request_rate: 10.0,
            geo_distribution: vec![],
            user_agents: vec![],
            time_distribution: TimeDistribution {
                peak_hour: 12,
                is_distributed: false,
                has_burst_pattern: true,
            },
            metadata: None,
        };

        let mut attack = Attack::new(
            AttackType::BotTraffic,
            AttackSeverity::Medium,
            0.75,
            details,
        );

        attack.add_source_ip("192.168.1.1");
        attack.add_source_ip("192.168.1.1"); // Duplicate should be ignored
        attack.add_target("user@example.com");

        assert_eq!(attack.source_ips.len(), 1);
        assert_eq!(attack.target_accounts.len(), 1);
        assert!(attack.is_active);
    }

    #[test]
    fn test_time_window() {
        let window = TimeWindow::last_minutes(5);
        assert!(window.duration().num_seconds() <= 300);
        assert!(window.duration().num_seconds() > 295);
    }

    #[test]
    fn test_brute_force_detector() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let detector = BruteForceDetector::new(3, 60);

            assert!(!detector.record_failure("user1").await);
            assert!(!detector.record_failure("user1").await);
            assert!(detector.record_failure("user1").await); // Third attempt triggers

            assert_eq!(detector.get_attempt_count("user1").await, 3);

            detector.reset("user1").await;
            assert_eq!(detector.get_attempt_count("user1").await, 0);
        });
    }
}
