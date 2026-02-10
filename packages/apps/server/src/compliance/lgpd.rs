//! Brazil LGPD (Lei Geral de Proteção de Dados) Compliance Module
//!
//! LGPD is Brazil's comprehensive data protection law effective August 2020.
//! It's heavily influenced by GDPR but has unique Brazilian requirements.
//!
//! # Key Requirements
//!
//! 1. **Legal Basis** - Similar to GDPR but with Brazilian-specific bases
//! 2. **Consent** - Must be informed, free, and specific
//! 3. **Data Subject Rights** - 9 rights including portability and explanation
//! 4. **DPO** - Required for most organizations
//! 5. **ANPD** - National Data Protection Authority oversight
//! 6. **International Transfers** - Adequacy decisions or safeguards required
//! 7. **PIA** - Risk assessment for high-risk processing

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// LGPD legal bases for processing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LgpdLegalBasis {
    /// Consent (Consentimento)
    Consent,
    /// Contract performance (Cumprimento de contrato)
    ContractPerformance,
    /// Legal obligation (Cumprimento de obrigação legal)
    LegalObligation,
    /// Regular exercise of rights (Exercício regular de direitos)
    RegularRights,
    /// Protection of life (Proteção da vida)
    ProtectionOfLife,
    /// Health protection (Proteção da saúde)
    HealthProtection,
    /// Public interest (Interesse público)
    PublicInterest,
    /// Legitimate interest (Legítimo interesse)
    LegitimateInterest,
    /// Credit protection (Proteção do crédito)
    CreditProtection,
    /// Research (Pesquisa)
    Research,
}

impl LgpdLegalBasis {
    /// Get Portuguese name
    pub fn portuguese_name(&self) -> &'static str {
        match self {
            LgpdLegalBasis::Consent => "Consentimento",
            LgpdLegalBasis::ContractPerformance => "Cumprimento de contrato",
            LgpdLegalBasis::LegalObligation => "Cumprimento de obrigação legal",
            LgpdLegalBasis::RegularRights => "Exercício regular de direitos",
            LgpdLegalBasis::ProtectionOfLife => "Proteção da vida",
            LgpdLegalBasis::HealthProtection => "Proteção da saúde",
            LgpdLegalBasis::PublicInterest => "Interesse público",
            LgpdLegalBasis::LegitimateInterest => "Legítimo interesse",
            LgpdLegalBasis::CreditProtection => "Proteção do crédito",
            LgpdLegalBasis::Research => "Pesquisa",
        }
    }
    
    /// Check if this basis requires consent
    pub fn requires_consent(&self) -> bool {
        matches!(self, LgpdLegalBasis::Consent)
    }
    
    /// Check if this basis requires balancing test (legitimate interest)
    pub fn requires_balancing_test(&self) -> bool {
        matches!(self, LgpdLegalBasis::LegitimateInterest)
    }
}

/// LGPD consent record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LgpdConsent {
    pub id: String,
    pub user_id: String,
    pub purpose: String,
    pub legal_basis: LgpdLegalBasis,
    pub granted: bool,
    pub granted_at: Option<DateTime<Utc>>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub version: String,
    pub language: String,
    pub explicit: bool, // LGPD requires explicit consent for sensitive data
    pub proof_of_consent: Option<String>, // Record of how consent was obtained
}

/// LGPD data subject rights (9 rights)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LgpdRight {
    /// Confirmation (Confirmação)
    Confirmation,
    /// Access (Acesso)
    Access,
    /// Correction (Correção)
    Correction,
    /// Anonymization (Anonimização)
    Anonymization,
    /// Portability (Portabilidade)
    Portability,
    /// Deletion (Eliminação)
    Deletion,
    /// Information about sharing (Informação sobre compartilhamento)
    InformationSharing,
    /// Information about consequences (Informação sobre consequências)
    InformationConsequences,
    /// Revocation (Revogação)
    Revocation,
}

impl LgpdRight {
    /// Get Portuguese name
    pub fn portuguese_name(&self) -> &'static str {
        match self {
            LgpdRight::Confirmation => "Confirmação",
            LgpdRight::Access => "Acesso",
            LgpdRight::Correction => "Correção",
            LgpdRight::Anonymization => "Anonimização",
            LgpdRight::Portability => "Portabilidade",
            LgpdRight::Deletion => "Eliminação",
            LgpdRight::InformationSharing => "Informação sobre compartilhamento",
            LgpdRight::InformationConsequences => "Informação sobre consequências",
            LgpdRight::Revocation => "Revogação",
        }
    }
    
    /// Response deadline in days (ANPD guidelines)
    pub fn deadline_days(&self) -> i64 {
        match self {
            // Most requests: 15 days
            _ => 15,
        }
    }
}

/// LGPD rights request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LgpdRightsRequest {
    pub id: String,
    pub user_id: String,
    pub right: LgpdRight,
    pub status: LgpdRequestStatus,
    pub requested_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>,
    pub responded_at: Option<DateTime<Utc>>,
    pub response: Option<String>,
    pub anpd_notified: bool,
}

/// Request status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LgpdRequestStatus {
    Pending,
    InReview,
    Approved,
    PartiallyApproved,
    Rejected,
    EscalatedToAnpd,
}

/// LGPD DPO (Encarregado)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LgpdDpo {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub email: String,
    pub phone: Option<String>,
    pub appointed_at: DateTime<Utc>,
    pub is_public: bool, // Must be publicly disclosed
    pub anpd_registered: bool,
}

/// LGPD compliance report for ANPD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LgpdComplianceReport {
    pub id: String,
    pub organization_id: String,
    pub report_period_start: DateTime<Utc>,
    pub report_period_end: DateTime<Utc>,
    pub total_data_subjects: u64,
    pub rights_requests_received: u32,
    pub rights_requests_fulfilled: u32,
    pub data_breaches: u32,
    pub data_breaches_notified: u32,
    pub consent_withdrawals: u32,
    pub international_transfers: u32,
    pub generated_at: DateTime<Utc>,
}

/// LGPD PIA (RIPD - Relatório de Impacto à Proteção de Dados Pessoais)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ripd {
    pub id: String,
    pub processing_activity: String,
    pub purpose: String,
    pub data_types: Vec<String>,
    pub sensitive_data: bool,
    pub data_subjects: Vec<String>, // Categories
    pub data_volume: String,
    pub retention_period: String,
    pub security_measures: Vec<String>,
    pub risks_identified: Vec<RiskIdentified>,
    pub mitigation_measures: Vec<String>,
    pub dpo_approved: bool,
    pub created_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
}

/// Risk identified in RIPD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskIdentified {
    pub description: String,
    pub likelihood: RiskLevel,
    pub impact: RiskLevel,
    pub residual_risk: RiskLevel,
}

/// Risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// LGPD compliance checker
pub struct LgpdComplianceChecker {
    pub data_subjects_count: u64,
    pub processes_sensitive_data: bool,
    pub does_profiling: bool,
    pub has_dpo: bool,
}

impl LgpdComplianceChecker {
    /// Create new checker
    pub fn new(
        data_subjects_count: u64,
        processes_sensitive_data: bool,
        does_profiling: bool,
        has_dpo: bool,
    ) -> Self {
        Self {
            data_subjects_count,
            processes_sensitive_data,
            does_profiling,
            has_dpo,
        }
    }
    
    /// Check if DPO is required
    /// 
    /// LGPD requires DPO for:
    /// - Public legal entities
    /// - Companies with large-scale data processing
    /// - Companies processing sensitive data
    /// - Data processing for profiling/commercial purposes
    pub fn is_dpo_required(&self) -> bool {
        self.processes_sensitive_data
            || self.does_profiling
            || self.data_subjects_count > 100_000
    }
    
    /// Check if RIPD (PIA) is required
    ///
    /// Required for:
    /// - Sensitive data processing
    /// - Profiling with significant effects
    /// - Large-scale processing
    pub fn is_ripd_required(&self) -> bool {
        self.processes_sensitive_data
            || self.does_profiling
            || self.data_subjects_count > 500_000
    }
    
    /// Validate consent
    pub fn validate_consent(&self, consent: &LgpdConsent) -> Vec<String> {
        let mut issues = vec![];
        
        // Must have proof of consent
        if consent.proof_of_consent.is_none() {
            issues.push("Proof of consent required under LGPD".to_string());
        }
        
        // Sensitive data requires explicit consent
        if self.processes_sensitive_data && !consent.explicit {
            issues.push("Sensitive data requires explicit consent".to_string());
        }
        
        // Must have version
        if consent.version.is_empty() {
            issues.push("Consent version required".to_string());
        }
        
        issues
    }
    
    /// Get compliance requirements checklist
    pub fn get_requirements(&self) -> Vec<LgpdRequirement> {
        let mut requirements = vec![];
        
        // Always required
        requirements.push(LgpdRequirement {
            item: "Privacy notice in Portuguese".to_string(),
            required: true,
            applicable: true,
        });
        requirements.push(LgpdRequirement {
            item: "Implement 9 data subject rights".to_string(),
            required: true,
            applicable: true,
        });
        requirements.push(LgpdRequirement {
            item: "Data security measures".to_string(),
            required: true,
            applicable: true,
        });
        requirements.push(LgpdRequirement {
            item: "Data breach notification (ANPD and data subjects)".to_string(),
            required: true,
            applicable: true,
        });
        
        // DPO required
        if self.is_dpo_required() {
            requirements.push(LgpdRequirement {
                item: "Appoint DPO (Encarregado)".to_string(),
                required: true,
                applicable: true,
            });
            requirements.push(LgpdRequirement {
                item: "Publish DPO contact information".to_string(),
                required: true,
                applicable: true,
            });
        }
        
        // RIPD required
        if self.is_ripd_required() {
            requirements.push(LgpdRequirement {
                item: "Conduct RIPD (Privacy Impact Assessment)".to_string(),
                required: true,
                applicable: true,
            });
        }
        
        // International transfers
        requirements.push(LgpdRequirement {
            item: "Implement safeguards for international transfers".to_string(),
            required: true,
            applicable: true,
        });
        
        requirements
    }
    
    /// Check international transfer compliance
    pub fn check_international_transfer(&self, destination_country: &str, has_adequacy: bool) -> TransferCompliance {
        if has_adequacy {
            TransferCompliance::Compliant
        } else {
            // Need to check other mechanisms
            TransferCompliance::RequiresSafeguards(vec![
                "Standard contractual clauses".to_string(),
                "Binding corporate rules".to_string(),
                "ANPD authorization".to_string(),
            ])
        }
    }
}

/// Transfer compliance status
#[derive(Debug, Clone)]
pub enum TransferCompliance {
    Compliant,
    RequiresSafeguards(Vec<String>),
    NonCompliant(String),
}

/// LGPD requirement item
#[derive(Debug, Clone)]
pub struct LgpdRequirement {
    pub item: String,
    pub required: bool,
    pub applicable: bool,
}

/// LGPD privacy notice template (Portuguese)
pub const LGPD_PRIVACY_NOTICE_TEMPLATE: &str = r#"
Política de Privacidade

Data de vigência: {effective_date}

1. Introdução

{company_name} ("nós", "nosso") valoriza a privacidade dos seus dados pessoais. Esta política descreve como coletamos, usamos, armazenamos e protegemos seus dados pessoais, em conformidade com a Lei Geral de Proteção de Dados Pessoais (LGPD).

2. Controlador de Dados

Razão social: {company_name}
Endereço: {company_address}
E-mail: {contact_email}
Encarregado (DPO): {dpo_contact}

3. Dados Pessoais Coletados

Podemos coletar os seguintes dados pessoais:

• Dados de identificação: nome, e-mail, telefone
• Dados de acesso: endereço IP, cookies, informações do dispositivo
• Dados de uso: histórico de acesso, preferências

4. Base Legal e Finalidades

Processamos seus dados pessoais com base nas seguintes hipóteses legais da LGPD:

• Consentimento: quando você autoriza expressamente
• Contrato: para execução de contrato ou procedimentos preliminares
• Obrigação legal: para cumprimento de obrigações legais
• Legítimo interesse: quando permitido pela legislação

5. Compartilhamento de Dados

{sharing_statement}

6. Transferência Internacional

{international_transfer_statement}

7. Seus Direitos (LGPD)

De acordo com a LGPD, você tem os seguintes direitos:

• Confirmação: confirmar a existência de tratamento de dados
• Acesso: acessar seus dados pessoais
• Correção: corrigir dados incompletos ou desatualizados
• Anonimização: anonimização de dados desnecessários
• Portabilidade: portar dados para outro serviço
• Eliminação: eliminar dados pessoais (exceto quando houver obrigação legal)
• Informação: saber com quem compartilhamos seus dados
• Revogação: revogar o consentimento a qualquer momento

8. Medidas de Segurança

Implementamos medidas técnicas e administrativas para proteger seus dados pessoais contra acessos não autorizados, destruição, perda ou vazamento.

9. Retenção de Dados

Mantemos seus dados pessoais apenas pelo tempo necessário para cumprir as finalidades descritas nesta política, ou conforme exigido por lei.

10. Alterações nesta Política

Podemos atualizar esta política periodicamente. Notificaremos você sobre alterações significativas.

11. Contato

Para exercer seus direitos ou esclarecer dúvidas, entre em contato:

E-mail: {contact_email}
Telefone: {contact_phone}
Encarregado: {dpo_contact}

Responderemos em até 15 dias úteis.

12. Autoridade de Proteção de Dados

Você pode registrar reclamações junto à Autoridade Nacional de Proteção de Dados (ANPD):

Site: www.gov.br/anpd
"#;

/// Generate LGPD-compliant privacy notice
pub fn generate_lgpd_privacy_notice(
    company_name: &str,
    company_address: &str,
    contact_email: &str,
    contact_phone: &str,
    dpo_contact: &str,
    shares_data: bool,
    international_transfer: bool,
) -> String {
    let effective_date = Utc::now().format("%d/%m/%Y").to_string();
    
    let sharing_statement = if shares_data {
        "Podemos compartilhar seus dados com parceiros de confiança, sempre em conformidade com a LGPD e para as finalidades descritas nesta política."
    } else {
        "Não compartilhamos seus dados pessoais com terceiros, exceto quando necessário para cumprimento de obrigação legal ou com seu consentimento."
    };
    
    let international_transfer_statement = if international_transfer {
        "Seus dados podem ser transferidos para fora do Brasil. Garantimos que tais transferências cumpram os requisitos da LGPD, utilizando cláusulas contratuais padrão ou outras garantias adequadas."
    } else {
        "Seus dados são armazenados e processados no Brasil, sem transferência internacional."
    };
    
    LGPD_PRIVACY_NOTICE_TEMPLATE
        .replace("{effective_date}", &effective_date)
        .replace("{company_name}", company_name)
        .replace("{company_address}", company_address)
        .replace("{contact_email}", contact_email)
        .replace("{contact_phone}", contact_phone)
        .replace("{dpo_contact}", dpo_contact)
        .replace("{sharing_statement}", sharing_statement)
        .replace("{international_transfer_statement}", international_transfer_statement)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lgpd_legal_basis() {
        assert!(LgpdLegalBasis::Consent.requires_consent());
        assert!(!LgpdLegalBasis::ContractPerformance.requires_consent());
        assert!(LgpdLegalBasis::LegitimateInterest.requires_balancing_test());
        assert_eq!(LgpdLegalBasis::Consent.portuguese_name(), "Consentimento");
    }
    
    #[test]
    fn test_lgpd_rights() {
        assert_eq!(LgpdRight::Access.portuguese_name(), "Acesso");
        assert_eq!(LgpdRight::Deletion.deadline_days(), 15);
    }
    
    #[test]
    fn test_dpo_requirement() {
        let checker_small = LgpdComplianceChecker::new(1_000, false, false, false);
        assert!(!checker_small.is_dpo_required());
        
        let checker_large = LgpdComplianceChecker::new(1_000_000, false, false, false);
        assert!(checker_large.is_dpo_required());
        
        let checker_sensitive = LgpdComplianceChecker::new(1_000, true, false, false);
        assert!(checker_sensitive.is_dpo_required());
        
        let checker_profiling = LgpdComplianceChecker::new(1_000, false, true, false);
        assert!(checker_profiling.is_dpo_required());
    }
    
    #[test]
    fn test_ripd_requirement() {
        let checker = LgpdComplianceChecker::new(1_000_000, true, true, false);
        assert!(checker.is_ripd_required());
    }
    
    #[test]
    fn test_consent_validation() {
        let checker = LgpdComplianceChecker::new(1_000, true, false, false);
        
        let consent = LgpdConsent {
            id: "test".to_string(),
            user_id: "user".to_string(),
            purpose: "Test".to_string(),
            legal_basis: LgpdLegalBasis::Consent,
            granted: true,
            granted_at: Some(Utc::now()),
            withdrawn_at: None,
            version: "1.0".to_string(),
            language: "pt-BR".to_string(),
            explicit: false,
            proof_of_consent: None,
        };
        
        let issues = checker.validate_consent(&consent);
        assert!(issues.len() >= 2); // Proof of consent and explicit consent issues
    }
    
    #[test]
    fn test_privacy_notice_generation() {
        let notice = generate_lgpd_privacy_notice(
            "Empresa Teste",
            "São Paulo, Brasil",
            "privacidade@empresa.com",
            "+55 11 1234-5678",
            "encarregado@empresa.com",
            true,
            true,
        );
        
        assert!(notice.contains("Empresa Teste"));
        assert!(notice.contains("LGPD"));
        assert!(notice.contains("Encarregado"));
        assert!(notice.contains("ANPD"));
    }
}
