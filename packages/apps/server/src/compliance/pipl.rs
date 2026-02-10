//! China PIPL (Personal Information Protection Law) Compliance Module
//!
//! PIPL is China's comprehensive data protection law effective November 1, 2021.
//! It has extraterritorial reach and strict requirements for cross-border data transfers.
//!
//! # Key Requirements
//!
//! 1. **Legal Basis** - Must have clear legal basis for processing (consent, contract, legal obligation, etc.)
//! 2. **Data Localization** - Sensitive personal information should be stored in China
//! 3. **Cross-Border Transfers** - Require security assessment or certification
//! 4. **Consent** - Must be informed, voluntary, and explicit
//! 5. **Data Subject Rights** - Access, correction, deletion, portability
//! 6. **PIA** - Personal Information Protection Impact Assessment for sensitive processing

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PIPL consent record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiplConsent {
    pub id: String,
    pub user_id: String,
    pub purpose: String,
    pub purpose_category: PiplPurposeCategory,
    pub sensitive: bool,
    pub granted: bool,
    pub granted_at: Option<DateTime<Utc>>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub version: String,
    pub language: String, // Must be Chinese for PIPL
    pub cross_border: bool,
    pub third_parties: Vec<String>,
}

/// PIPL purpose categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiplPurposeCategory {
    /// Necessary for contract performance
    ContractPerformance,
    /// Necessary for legal compliance
    LegalCompliance,
    /// Vital interests (emergency)
    VitalInterests,
    /// Public interest
    PublicInterest,
    /// Legitimate interests
    LegitimateInterests,
    /// Consent (default for most processing)
    Consent,
}

impl PiplPurposeCategory {
    /// Get the legal basis description in Chinese
    pub fn chinese_description(&self) -> &'static str {
        match self {
            PiplPurposeCategory::ContractPerformance => "订立、履行合同所必需",
            PiplPurposeCategory::LegalCompliance => "履行法定职责或义务",
            PiplPurposeCategory::VitalInterests => "应对突发公共卫生事件或紧急情况下保护生命健康",
            PiplPurposeCategory::PublicInterest => "公共利益实施新闻报道、舆论监督",
            PiplPurposeCategory::LegitimateInterests => "在合理范围内处理已公开的个人信息",
            PiplPurposeCategory::Consent => "取得个人同意",
        }
    }
    
    /// Check if this legal basis requires consent
    pub fn requires_consent(&self) -> bool {
        matches!(self, PiplPurposeCategory::Consent)
    }
    
    /// Check if this basis allows cross-border transfer
    pub fn allows_cross_border(&self) -> bool {
        // All bases can allow cross-border with proper measures
        true
    }
}

/// Cross-border data transfer assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossBorderAssessment {
    pub id: String,
    pub organization_name: String,
    pub data_types: Vec<String>,
    pub data_volume: String, // "<100k", "100k-1M", ">1M"
    pub recipient_country: String,
    pub recipient_name: String,
    pub transfer_purpose: String,
    pub security_measures: Vec<String>,
    pub assessment_status: AssessmentStatus,
    pub assessment_date: Option<DateTime<Utc>>,
    pub approval_number: Option<String>, // CAC approval number
}

/// Assessment status for cross-border transfers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatus {
    /// Standard contract (for <100k individuals)
    StandardContract,
    /// Professional institution certification
    ProfessionalCertification,
    /// Security assessment by CAC (for critical info infrastructure operators or >1M individuals)
    SecurityAssessment,
    /// Pending assessment
    Pending,
    /// Approved
    Approved,
    /// Rejected
    Rejected,
}

/// Personal Information Protection Impact Assessment (PIA)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiplPia {
    pub id: String,
    pub processing_activity: String,
    pub purpose: String,
    pub data_types: Vec<String>,
    pub sensitive_data: bool,
    pub automated_decision_making: bool,
    pub third_country_transfer: bool,
    pub data_subjects_count: u64,
    pub risk_assessment: RiskAssessment,
    pub safeguards: Vec<String>,
    pub conducted_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub retention_period_days: i32,
}

/// Risk assessment for PIA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub likelihood: RiskLevel,
    pub impact: RiskLevel,
    pub overall_risk: RiskLevel,
    pub justification: String,
}

/// Risk levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Get Chinese description
    pub fn chinese_description(&self) -> &'static str {
        match self {
            RiskLevel::Low => "低",
            RiskLevel::Medium => "中",
            RiskLevel::High => "高",
            RiskLevel::Critical => "严重",
        }
    }
}

/// DPO (Data Protection Officer) record for PIPL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiplDpo {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub contact_email: String,
    pub contact_phone: String,
    pub address: String, // Must be in China
    pub appointed_at: DateTime<Utc>,
    pub responsibilities: Vec<String>,
    pub is_public: bool, // Contact info must be publicly disclosed
}

/// Data subject rights request (PIPL)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiplRightsRequest {
    pub id: String,
    pub user_id: String,
    pub request_type: RightsType,
    pub status: RequestStatus,
    pub requested_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>, // PIPL requires 15 days response
    pub responded_at: Option<DateTime<Utc>>,
    pub response: Option<String>,
    pub rejection_reason: Option<String>,
}

/// Types of rights under PIPL
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RightsType {
    /// Right to know (知情权)
    RightToKnow,
    /// Right to decide (决定权)
    RightToDecide,
    /// Right to access/consult (查阅、复制权)
    RightToAccess,
    /// Right to correct (更正、补充权)
    RightToCorrect,
    /// Right to deletion (删除权)
    RightToDeletion,
    /// Right to portability (可携带权)
    RightToPortability,
    /// Right to explanation (解释权)
    RightToExplanation,
}

impl RightsType {
    /// Get Chinese name
    pub fn chinese_name(&self) -> &'static str {
        match self {
            RightsType::RightToKnow => "知情权",
            RightsType::RightToDecide => "决定权",
            RightsType::RightToAccess => "查阅复制权",
            RightsType::RightToCorrect => "更正补充权",
            RightsType::RightToDeletion => "删除权",
            RightsType::RightToPortability => "可携带权",
            RightsType::RightToExplanation => "解释权",
        }
    }
    
    /// Get response deadline in days (PIPL requirement)
    pub fn deadline_days(&self) -> i64 {
        match self {
            // Most rights require response within 15 days
            _ => 15,
        }
    }
}

/// Request status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    InReview,
    Approved,
    PartiallyApproved,
    Rejected,
    Escalated,
}

/// PIPL compliance checker
pub struct PiplComplianceChecker {
    /// Whether this is a critical information infrastructure operator (CIIO)
    pub is_ciio: bool,
    /// Estimated data subjects in China
    pub data_subjects_count: u64,
    /// Data is stored in China
    pub data_localized: bool,
    /// Cross-border transfer mechanism
    pub cross_border_mechanism: Option<CrossBorderMechanism>,
}

/// Cross-border data transfer mechanisms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossBorderMechanism {
    /// Standard contract (standard contract clauses)
    StandardContract,
    /// Security assessment by CAC
    SecurityAssessment,
    /// Professional institution certification
    ProfessionalCertification,
}

impl PiplComplianceChecker {
    /// Create a new compliance checker
    pub fn new(is_ciio: bool, data_subjects_count: u64, data_localized: bool) -> Self {
        Self {
            is_ciio,
            data_subjects_count,
            data_localized,
            cross_border_mechanism: None,
        }
    }
    
    /// Set cross-border mechanism
    pub fn with_cross_border_mechanism(mut self, mechanism: CrossBorderMechanism) -> Self {
        self.cross_border_mechanism = Some(mechanism);
        self
    }
    
    /// Check if cross-border transfer is allowed
    pub fn can_transfer_cross_border(&self) -> bool {
        if self.data_localized && self.data_subjects_count > 100_000 {
            // Must have explicit mechanism for large datasets
            self.cross_border_mechanism.is_some()
        } else if self.is_ciio {
            // CIIO must have security assessment
            matches!(self.cross_border_mechanism, Some(CrossBorderMechanism::SecurityAssessment))
        } else {
            // Smaller datasets or non-CIIO can use standard contract
            matches!(
                self.cross_border_mechanism,
                Some(CrossBorderMechanism::StandardContract) |
                Some(CrossBorderMechanism::SecurityAssessment) |
                Some(CrossBorderMechanism::ProfessionalCertification)
            )
        }
    }
    
    /// Check if PIA is required
    pub fn is_pia_required(&self, processing: &PiplPia) -> bool {
        // PIA required for:
        // 1. Processing sensitive personal info
        // 2. Automated decision making with significant impact
        // 3. Cross-border transfers
        // 4. Processing by CIIO
        // 5. Large-scale processing
        
        processing.sensitive_data
            || processing.automated_decision_making
            || processing.third_country_transfer
            || self.is_ciio
            || processing.data_subjects_count > 100_000
    }
    
    /// Check if DPO is required
    pub fn is_dpo_required(&self) -> bool {
        // DPO required for CIIO or large-scale processing
        self.is_ciio || self.data_subjects_count > 1_000_000
    }
    
    /// Get compliance requirements checklist
    pub fn get_requirements(&self) -> Vec<ComplianceRequirement> {
        let mut requirements = vec![];
        
        // Always required
        requirements.push(ComplianceRequirement {
            item: "Obtain valid consent for processing".to_string(),
            required: true,
            applicable: true,
        });
        requirements.push(ComplianceRequirement {
            item: "Provide privacy notice in Chinese".to_string(),
            required: true,
            applicable: true,
        });
        requirements.push(ComplianceRequirement {
            item: "Implement data subject rights procedures".to_string(),
            required: true,
            applicable: true,
        });
        requirements.push(ComplianceRequirement {
            item: "Ensure data security measures".to_string(),
            required: true,
            applicable: true,
        });
        
        // CIIO specific
        if self.is_ciio {
            requirements.push(ComplianceRequirement {
                item: "Conduct CAC security assessment for cross-border transfers".to_string(),
                required: true,
                applicable: true,
            });
            requirements.push(ComplianceRequirement {
                item: "Appoint DPO and report to authorities".to_string(),
                required: true,
                applicable: true,
            });
            requirements.push(ComplianceRequirement {
                item: "Localize critical personal information within China".to_string(),
                required: true,
                applicable: true,
            });
        }
        
        // Large-scale processing
        if self.data_subjects_count > 1_000_000 {
            requirements.push(ComplianceRequirement {
                item: "Appoint DPO".to_string(),
                required: true,
                applicable: true,
            });
        }
        
        // Cross-border transfers
        if self.cross_border_mechanism.is_some() {
            requirements.push(ComplianceRequirement {
                item: "Conduct PIA for cross-border transfer".to_string(),
                required: true,
                applicable: true,
            });
            requirements.push(ComplianceRequirement {
                item: "Obtain separate consent for cross-border transfer".to_string(),
                required: true,
                applicable: true,
            });
        }
        
        requirements
    }
    
    /// Validate consent for PIPL
    pub fn validate_consent(&self, consent: &PiplConsent) -> Vec<String> {
        let mut issues = vec![];
        
        // Must be in Chinese
        if consent.language != "zh-CN" && consent.language != "zh" {
            issues.push("Consent must be in Chinese (Simplified) for PIPL".to_string());
        }
        
        // Must specify purpose clearly
        if consent.purpose.is_empty() {
            issues.push("Purpose must be specified".to_string());
        }
        
        // Cross-border requires explicit consent
        if consent.cross_border && !consent.purpose.contains("跨境") && !consent.purpose.contains("cross-border") {
            issues.push("Cross-border transfer must be explicitly mentioned in consent".to_string());
        }
        
        // Third parties must be disclosed
        if !consent.third_parties.is_empty() {
            let has_disclosure = consent.purpose.contains("第三方") || 
                                 consent.purpose.contains("接收方");
            if !has_disclosure {
                issues.push("Third party recipients must be disclosed".to_string());
            }
        }
        
        // Sensitive data requires separate consent
        if consent.sensitive && !consent.granted {
            issues.push("Sensitive personal information requires explicit consent".to_string());
        }
        
        issues
    }
}

/// Compliance requirement item
#[derive(Debug, Clone)]
pub struct ComplianceRequirement {
    pub item: String,
    pub required: bool,
    pub applicable: bool,
}

/// PIPL privacy notice template (Chinese)
pub const PIPL_PRIVACY_NOTICE_TEMPLATE: &str = r#"
隐私政策

生效日期：{effective_date}

一、引言

{company_name}（"我们"或"我们的"）非常重视您的个人信息保护。本隐私政策说明我们如何收集、使用、存储和保护您的个人信息。

二、个人信息处理者信息

名称：{company_name}
地址：{company_address}
联系方式：{contact_email}
个人信息保护负责人：{dpo_contact}

三、我们收集的个人信息

我们可能会收集以下类型的个人信息：

1. 基本信息：姓名、电子邮件地址、电话号码
2. 账户信息：用户名、密码（加密存储）
3. 设备信息：IP地址、设备标识符、浏览器类型
4. 使用信息：访问时间、浏览记录、操作日志

四、处理目的和法律依据

我们基于以下目的处理您的个人信息：

1. 提供和维护服务（合同履行必需）
2. 验证身份和账户安全（合同履行必需）
3. 改进服务质量（征得同意）
4. 发送重要通知（合同履行必需）

五、个人信息的共享和转让

{sharing_statement}

六、跨境数据传输

{cross_border_statement}

七、您的权利

根据《个人信息保护法》，您享有以下权利：

1. 知情权 - 了解我们如何处理您的个人信息
2. 决定权 - 限制或拒绝他人对您个人信息的处理
3. 查阅复制权 - 查阅、复制您的个人信息
4. 更正补充权 - 更正、补充不准确的个人信息
5. 删除权 - 在法定情形下删除您的个人信息
6. 可携带权 - 要求将个人信息转移至其他处理者
7. 解释权 - 要求对个人信息的处理规则进行解释说明

八、敏感个人信息

{sensitive_data_statement}

九、未成年人保护

我们特别重视未成年人个人信息的保护。如果您是未成年人，请在监护人指导下使用我们的服务。

十、联系我们

如果您对本隐私政策有任何疑问，或希望行使您的权利，请通过以下方式联系我们：

电子邮件：{contact_email}
电话：{contact_phone}
地址：{company_address}

我们将在15个工作日内回复您的请求。
"#;

/// Generate PIPL-compliant privacy notice
pub fn generate_pipl_privacy_notice(
    company_name: &str,
    company_address: &str,
    contact_email: &str,
    contact_phone: &str,
    dpo_contact: &str,
    cross_border: bool,
    processes_sensitive: bool,
) -> String {
    let effective_date = Utc::now().format("%Y年%m月%d日").to_string();
    
    let sharing_statement = "我们不会向第三方共享您的个人信息，除非获得您的单独同意或法律另有规定。";
    
    let cross_border_statement = if cross_border {
        "我们可能将您的个人信息传输至中国境外。传输前，我们将获得您的单独同意，并采取必要的安全保障措施。"
    } else {
        "您的个人信息将存储在中国境内，不会传输至境外。"
    };
    
    let sensitive_data_statement = if processes_sensitive {
        "我们可能处理您的敏感个人信息（如身份证件号码）。处理前，我们将获得您的单独同意，并采取严格的保护措施。"
    } else {
        "我们不处理敏感个人信息。"
    };
    
    PIPL_PRIVACY_NOTICE_TEMPLATE
        .replace("{effective_date}", &effective_date)
        .replace("{company_name}", company_name)
        .replace("{company_address}", company_address)
        .replace("{contact_email}", contact_email)
        .replace("{contact_phone}", contact_phone)
        .replace("{dpo_contact}", dpo_contact)
        .replace("{sharing_statement}", sharing_statement)
        .replace("{cross_border_statement}", cross_border_statement)
        .replace("{sensitive_data_statement}", sensitive_data_statement)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pipl_compliance_checker() {
        let checker = PiplComplianceChecker::new(false, 50_000, true);
        assert!(!checker.is_dpo_required());
        assert!(checker.can_transfer_cross_border());
        
        let checker = PiplComplianceChecker::new(true, 1_000, false);
        assert!(checker.is_dpo_required());
        assert!(!checker.can_transfer_cross_border());
    }
    
    #[test]
    fn test_pipl_consent_validation() {
        let checker = PiplComplianceChecker::new(false, 0, true);
        
        let consent = PiplConsent {
            id: "test".to_string(),
            user_id: "user".to_string(),
            purpose: "提供服务".to_string(),
            purpose_category: PiplPurposeCategory::Consent,
            sensitive: false,
            granted: true,
            granted_at: Some(Utc::now()),
            withdrawn_at: None,
            expires_at: None,
            version: "1.0".to_string(),
            language: "zh-CN".to_string(),
            cross_border: false,
            third_parties: vec![],
        };
        
        let issues = checker.validate_consent(&consent);
        assert!(issues.is_empty());
    }
    
    #[test]
    fn test_privacy_notice_generation() {
        let notice = generate_pipl_privacy_notice(
            "测试公司",
            "中国北京市",
            "privacy@test.com",
            "+86 10 12345678",
            "dpo@test.com",
            true,
            true,
        );
        
        assert!(notice.contains("测试公司"));
        assert!(notice.contains("跨境"));
        assert!(notice.contains("敏感个人信息"));
    }
    
    #[test]
    fn test_purpose_category() {
        assert!(PiplPurposeCategory::Consent.requires_consent());
        assert!(!PiplPurposeCategory::ContractPerformance.requires_consent());
        assert_eq!(PiplPurposeCategory::LegalCompliance.chinese_description(), "履行法定职责或义务");
    }
    
    #[test]
    fn test_rights_type() {
        assert_eq!(RightsType::RightToAccess.chinese_name(), "查阅复制权");
        assert_eq!(RightsType::RightToDeletion.deadline_days(), 15);
    }
}
