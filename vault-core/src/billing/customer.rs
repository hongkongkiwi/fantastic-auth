//! Customer management for billing
//!
//! This module provides types and utilities for managing billing customers.

use serde::{Deserialize, Serialize};

use super::{Address, Customer};

/// Customer creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCustomerRequest {
    pub email: String,
    pub name: Option<String>,
    pub phone: Option<String>,
    pub address: Option<Address>,
    pub metadata: Option<serde_json::Value>,
}

/// Customer update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCustomerRequest {
    pub email: Option<String>,
    pub name: Option<String>,
    pub phone: Option<String>,
    pub address: Option<Address>,
    pub metadata: Option<serde_json::Value>,
}

/// Customer billing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingInfo {
    pub customer: Customer,
    pub payment_methods: Vec<PaymentMethodInfo>,
    pub default_payment_method: Option<String>,
}

/// Payment method information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethodInfo {
    pub id: String,
    pub type_: String,
    pub is_default: bool,
    pub card: Option<CardInfo>,
    pub billing_details: BillingDetails,
}

/// Card information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardInfo {
    pub brand: String,
    pub last4: String,
    pub exp_month: i32,
    pub exp_year: i32,
    pub country: Option<String>,
    pub funding: Option<String>, // credit, debit, prepaid, unknown
}

/// Billing details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingDetails {
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<Address>,
}

/// Tax information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxInfo {
    pub tax_id: Option<String>,
    pub tax_id_type: Option<TaxIdType>,
    pub vat_number: Option<String>,
    pub business_name: Option<String>,
}

/// Tax ID types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaxIdType {
    EuVat,
    GbVat,
    UsEin,
    CaBn,
    AuAbn,
    InGst,
    #[serde(other)]
    Other,
}

impl std::fmt::Display for TaxIdType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaxIdType::EuVat => write!(f, "eu_vat"),
            TaxIdType::GbVat => write!(f, "gb_vat"),
            TaxIdType::UsEin => write!(f, "us_ein"),
            TaxIdType::CaBn => write!(f, "ca_bn"),
            TaxIdType::AuAbn => write!(f, "au_abn"),
            TaxIdType::InGst => write!(f, "in_gst"),
            TaxIdType::Other => write!(f, "other"),
        }
    }
}

/// Customer portal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalConfiguration {
    pub return_url: String,
    pub flow_data: Option<PortalFlowData>,
}

/// Portal flow data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalFlowData {
    pub type_: String,
    pub after_completion: Option<AfterCompletion>,
}

/// After completion behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AfterCompletion {
    pub type_: String,
    pub redirect: Option<RedirectAfterCompletion>,
}

/// Redirect after completion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectAfterCompletion {
    pub return_url: String,
}

/// Customer validation
pub mod validation {
    use super::*;

    /// Validate email format
    pub fn is_valid_email(email: &str) -> bool {
        let email_regex = regex::Regex::new(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        ).unwrap();
        email_regex.is_match(email)
    }

    /// Validate phone number (basic validation)
    pub fn is_valid_phone(phone: &str) -> bool {
        // Basic phone validation - at least 10 digits
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        digits.len() >= 10
    }

    /// Validate address
    pub fn is_valid_address(address: &Address) -> bool {
        address.line1.is_some() && 
        !address.line1.as_ref().unwrap().is_empty() &&
        address.city.is_some() &&
        address.country.is_some()
    }

    /// Sanitize customer name
    pub fn sanitize_name(name: &str) -> String {
        name.trim().to_string()
    }

    /// Format phone number to E.164
    pub fn format_phone_e164(phone: &str, country_code: &str) -> String {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        
        if digits.starts_with('+') {
            digits
        } else if digits.starts_with('0') {
            // Assume local format, add country code
            format!("+{}{}", country_code.trim_start_matches('+'), &digits[1..])
        } else {
            format!("+{}{}", country_code.trim_start_matches('+'), digits)
        }
    }
}

/// Customer builder
pub struct CustomerBuilder {
    tenant_id: String,
    email: String,
    name: Option<String>,
    phone: Option<String>,
    address: Option<Address>,
    metadata: serde_json::Value,
}

impl CustomerBuilder {
    /// Create a new customer builder
    pub fn new(tenant_id: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            email: email.into(),
            name: None,
            phone: None,
            address: None,
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Set customer name
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set customer phone
    pub fn phone(mut self, phone: impl Into<String>) -> Self {
        self.phone = Some(phone.into());
        self
    }

    /// Set customer address
    pub fn address(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        if let serde_json::Value::Object(ref mut map) = self.metadata {
            map.insert(key.into(), value.into());
        }
        self
    }

    /// Build the customer (this would normally call the API)
    pub fn build(self) -> CreateCustomerRequest {
        CreateCustomerRequest {
            email: self.email,
            name: self.name,
            phone: self.phone,
            address: self.address,
            metadata: Some(self.metadata),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        assert!(validation::is_valid_email("test@example.com"));
        assert!(validation::is_valid_email("user+tag@example.co.uk"));
        assert!(!validation::is_valid_email("invalid"));
        assert!(!validation::is_valid_email("@example.com"));
        assert!(!validation::is_valid_email("test@"));
    }

    #[test]
    fn test_phone_validation() {
        assert!(validation::is_valid_phone("+1 555-123-4567"));
        assert!(validation::is_valid_phone("5551234567"));
        assert!(!validation::is_valid_phone("123"));
    }

    #[test]
    fn test_customer_builder() {
        let request = CustomerBuilder::new("tenant_123", "test@example.com")
            .name("Test User")
            .phone("+1 555-123-4567")
            .with_metadata("source", "web")
            .build();

        assert_eq!(request.email, "test@example.com");
        assert_eq!(request.name, Some("Test User".to_string()));
        assert_eq!(request.phone, Some("+1 555-123-4567".to_string()));
    }
}
