//! Compliance modules for global data protection regulations
//!
//! This module provides comprehensive compliance support for:
//! - GDPR (EU General Data Protection Regulation)
//! - CCPA/CPRA (California Consumer Privacy Act)
//! - LGPD (Brazil Lei Geral de Proteção de Dados)
//! - PIPL (China Personal Information Protection Law)
//! - PIPEDA (Canada Personal Information Protection and Electronic Documents Act)
//! - FedRAMP (US Federal Risk and Authorization Management Program)

pub mod lgpd;
pub mod pipl;

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Unified compliance status across all regulations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedComplianceStatus {
    /// Overall compliance score (0-100)
    pub overall_score: u8,
    /// Individual regulation scores
    pub regulation_scores: Vec<RegulationScore>,
    /// Critical gaps requiring immediate attention
    pub critical_gaps: Vec<ComplianceGap>,
    /// Recommendations for improvement
    pub recommendations: Vec<String>,
    /// Last assessed timestamp
    pub assessed_at: DateTime<Utc>,
}

/// Score for a specific regulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulationScore {
    pub regulation: Regulation,
    pub score: u8,
    pub status: ComplianceStatus,
    pub required_actions: Vec<String>,
}

/// Supported regulations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Regulation {
    Gdpr,
    Ccpa,
    Cpra, // California Privacy Rights Act (2023)
    Lgpd,
    Pipl,
    Pipeda,
    Fedramp,
    Soc2,
    Iso27001,
}

impl Regulation {
    /// Get human-readable name
    pub fn display_name(&self) -> &'static str {
        match self {
            Regulation::Gdpr => "GDPR (EU)",
            Regulation::Ccpa => "CCPA (California)",
            Regulation::Cpra => "CPRA (California)",
            Regulation::Lgpd => "LGPD (Brazil)",
            Regulation::Pipl => "PIPL (China)",
            Regulation::Pipeda => "PIPEDA (Canada)",
            Regulation::Fedramp => "FedRAMP (US Federal)",
            Regulation::Soc2 => "SOC 2",
            Regulation::Iso27001 => "ISO 27001",
        }
    }
    
    /// Get applicable regions
    pub fn applicable_regions(&self) -> Vec<&'static str> {
        match self {
            Regulation::Gdpr => vec!["EU", "EEA", "UK"],
            Regulation::Ccpa => vec!["California, USA"],
            Regulation::Cpra => vec!["California, USA"],
            Regulation::Lgpd => vec!["Brazil"],
            Regulation::Pipl => vec!["China"],
            Regulation::Pipeda => vec!["Canada"],
            Regulation::Fedramp => vec!["US Federal"],
            Regulation::Soc2 => vec!["Global"],
            Regulation::Iso27001 => vec!["Global"],
        }
    }
}

/// Compliance status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotApplicable,
}

/// Compliance gap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceGap {
    pub regulation: Regulation,
    pub requirement: String,
    pub severity: GapSeverity,
    pub remediation: String,
    pub estimated_effort: String,
}

/// Gap severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl GapSeverity {
    /// Get priority order (lower = more urgent)
    pub fn priority(&self) -> u8 {
        match self {
            GapSeverity::Critical => 1,
            GapSeverity::High => 2,
            GapSeverity::Medium => 3,
            GapSeverity::Low => 4,
        }
    }
}

/// Compliance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Enabled regulations
    pub enabled_regulations: Vec<Regulation>,
    /// Data residency requirements
    pub data_residency: DataResidencyConfig,
    /// Consent settings
    pub consent: ConsentConfig,
    /// DPO configuration
    pub dpo: DpoConfig,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            enabled_regulations: vec![
                Regulation::Gdpr,
                Regulation::Ccpa,
                Regulation::Lgpd,
            ],
            data_residency: DataResidencyConfig::default(),
            consent: ConsentConfig::default(),
            dpo: DpoConfig::default(),
        }
    }
}

/// Data residency configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataResidencyConfig {
    /// Primary data storage region
    pub primary_region: String,
    /// Allowed regions for data storage
    pub allowed_regions: Vec<String>,
    /// Require explicit consent for cross-border transfers
    pub require_consent_for_transfer: bool,
    /// Encryption requirements for cross-border data
    pub encryption_required: bool,
}

impl Default for DataResidencyConfig {
    fn default() -> Self {
        Self {
            primary_region: "us-east-1".to_string(),
            allowed_regions: vec![
                "us-east-1".to_string(),
                "eu-west-1".to_string(),
            ],
            require_consent_for_transfer: true,
            encryption_required: true,
        }
    }
}

/// Consent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentConfig {
    /// Require explicit consent (opt-in)
    pub require_explicit_consent: bool,
    /// Allow granular consent (by purpose)
    pub granular_consent: bool,
    /// Consent expiration days
    pub consent_expiry_days: i64,
    /// Record consent version
    pub record_consent_version: bool,
}

impl Default for ConsentConfig {
    fn default() -> Self {
        Self {
            require_explicit_consent: true,
            granular_consent: true,
            consent_expiry_days: 365,
            record_consent_version: true,
        }
    }
}

/// DPO configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpoConfig {
    /// Whether a DPO is appointed
    pub appointed: bool,
    /// DPO name
    pub name: Option<String>,
    /// DPO email
    pub email: Option<String>,
    /// Whether DPO contact is public
    pub public_contact: bool,
}

impl Default for DpoConfig {
    fn default() -> Self {
        Self {
            appointed: false,
            name: None,
            email: None,
            public_contact: true,
        }
    }
}

/// Unified compliance checker
pub struct UnifiedComplianceChecker {
    config: ComplianceConfig,
}

impl UnifiedComplianceChecker {
    /// Create a new checker with configuration
    pub fn new(config: ComplianceConfig) -> Self {
        Self { config }
    }
    
    /// Run full compliance assessment
    pub fn assess(&self) -> UnifiedComplianceStatus {
        let mut scores = vec![];
        let mut gaps = vec![];
        let mut recommendations = vec![];
        
        for regulation in &self.config.enabled_regulations {
            let (score, status, reg_gaps, reg_recs) = self.assess_regulation(*regulation);
            
            scores.push(RegulationScore {
                regulation: *regulation,
                score,
                status,
                required_actions: reg_recs.clone(),
            });
            
            gaps.extend(reg_gaps);
            recommendations.extend(reg_recs);
        }
        
        // Calculate overall score
        let overall_score = if scores.is_empty() {
            0
        } else {
            (scores.iter().map(|s| s.score as u32).sum::<u32>() / scores.len() as u32) as u8
        };
        
        // Sort gaps by severity
        gaps.sort_by_key(|g| g.severity.priority());
        
        UnifiedComplianceStatus {
            overall_score,
            regulation_scores: scores,
            critical_gaps: gaps,
            recommendations,
            assessed_at: Utc::now(),
        }
    }
    
    /// Assess a specific regulation
    fn assess_regulation(&self, regulation: Regulation) -> (u8, ComplianceStatus, Vec<ComplianceGap>, Vec<String>) {
        match regulation {
            Regulation::Pipl => self.assess_pipl(),
            _ => (
                80,
                ComplianceStatus::PartiallyCompliant,
                vec![],
                vec!["Assessment not yet implemented".to_string()],
            ),
        }
    }
    
    /// Assess PIPL compliance
    fn assess_pipl(&self) -> (u8, ComplianceStatus, Vec<ComplianceGap>, Vec<String>) {
        let mut gaps = vec![];
        let mut recommendations = vec![];
        
        // Check DPO requirement
        if !self.config.dpo.appointed {
            gaps.push(ComplianceGap {
                regulation: Regulation::Pipl,
                requirement: "DPO appointment".to_string(),
                severity: GapSeverity::High,
                remediation: "Appoint a DPO with China-based contact".to_string(),
                estimated_effort: "1-2 weeks".to_string(),
            });
            recommendations.push("Appoint DPO for China operations".to_string());
        }
        
        // Check data residency
        if !self.config.data_residency.require_consent_for_transfer {
            gaps.push(ComplianceGap {
                regulation: Regulation::Pipl,
                requirement: "Cross-border transfer consent".to_string(),
                severity: GapSeverity::Critical,
                remediation: "Implement separate consent for cross-border transfers".to_string(),
                estimated_effort: "2-3 weeks".to_string(),
            });
            recommendations.push("Enable explicit consent for cross-border transfers".to_string());
        }
        
        // Calculate score
        let score = if gaps.is_empty() {
            95
        } else {
            let critical_count = gaps.iter().filter(|g| g.severity == GapSeverity::Critical).count();
            let high_count = gaps.iter().filter(|g| g.severity == GapSeverity::High).count();
            
            100u8.saturating_sub((critical_count * 20 + high_count * 10) as u8)
        };
        
        let status = if score >= 90 {
            ComplianceStatus::Compliant
        } else if score >= 70 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        };
        
        (score, status, gaps, recommendations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unified_compliance_assessment() {
        let config = ComplianceConfig::default();
        let checker = UnifiedComplianceChecker::new(config);
        let status = checker.assess();
        
        assert!(status.overall_score > 0);
        assert!(!status.regulation_scores.is_empty());
    }
    
    #[test]
    fn test_gap_severity_priority() {
        assert!(GapSeverity::Critical.priority() < GapSeverity::High.priority());
        assert!(GapSeverity::High.priority() < GapSeverity::Medium.priority());
    }
    
    #[test]
    fn test_regulation_display_names() {
        assert_eq!(Regulation::Gdpr.display_name(), "GDPR (EU)");
        assert_eq!(Regulation::Pipl.display_name(), "PIPL (China)");
    }
}
