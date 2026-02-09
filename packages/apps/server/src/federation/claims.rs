//! Claims Transformation
//!
//! Transforms external claims from various IdPs into Vault's standard format.
//! Supports flexible mapping rules and claim transformations.

use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Claims transformer for converting external claims to Vault format
#[derive(Debug, Clone)]
pub struct ClaimsTransformer {
    mappings: Vec<ClaimMapping>,
}

/// Individual claim mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimMapping {
    pub source_claim: String,
    pub vault_claim: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<TransformFunction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// Claim transformation functions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "config")]
pub enum TransformFunction {
    /// Copy as-is (no transformation)
    #[serde(rename = "direct")]
    Direct,
    /// Convert to uppercase
    #[serde(rename = "uppercase")]
    Uppercase,
    /// Convert to lowercase
    #[serde(rename = "lowercase")]
    Lowercase,
    /// Split by separator and take index
    #[serde(rename = "split")]
    Split { separator: String, index: usize },
    /// Replace using regex
    #[serde(rename = "regex")]
    Regex { pattern: String, replacement: String },
    /// Concatenate multiple values
    #[serde(rename = "concat")]
    Concat { values: Vec<String>, separator: Option<String> },
    /// Map values to other values
    #[serde(rename = "map")]
    Map { mappings: HashMap<String, String> },
    /// Extract domain from email
    #[serde(rename = "domain")]
    Domain,
    /// Extract local part from email
    #[serde(rename = "local_part")]
    LocalPart,
    /// Custom JavaScript/Expression transformation (placeholder)
    #[serde(rename = "expression")]
    Expression { expr: String },
}

/// Standard Vault claims structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub employee_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Additional custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Address claim structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl ClaimsTransformer {
    /// Create a new claims transformer with default mappings
    pub fn new() -> Self {
        Self {
            mappings: default_claim_mappings(),
        }
    }

    /// Create a transformer with custom mappings
    pub fn with_mappings(mappings: Vec<ClaimMapping>) -> Self {
        Self { mappings }
    }

    /// Transform external claims to Vault format
    pub fn transform(
        &self,
        external: &HashMap<String, String>,
        mapping_config: &HashMap<String, String>,
    ) -> VaultClaims {
        let mut result = VaultClaims::default();

        // Apply configured mappings
        for (vault_claim, source_claim) in mapping_config {
            if let Some(value) = external.get(source_claim) {
                let transformed = self.apply_transformation(vault_claim, value, external);
                self.set_vault_claim(&mut result, vault_claim, &transformed);
            }
        }

        // Apply additional hardcoded transformations for standard claims
        // Build name from given_name + family_name if not already set
        if result.name.is_none() {
            if let (Some(first), Some(last)) = (&result.given_name, &result.family_name) {
                result.name = Some(format!("{} {}", first, last));
            }
        }

        // Parse groups from comma-separated string if present
        if let Some(groups_str) = external.get("groups") {
            result.groups = groups_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Parse roles from comma-separated string if present
        if let Some(roles_str) = external.get("roles") {
            result.roles = roles_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Set external_id from sub if not already set
        if result.external_id.is_none() {
            result.external_id = result.sub.clone();
        }

        result
    }

    /// Apply transformation to a claim value
    fn apply_transformation(
        &self,
        _claim_name: &str,
        value: &str,
        _all_claims: &HashMap<String, String>,
    ) -> String {
        // Find matching mapping and apply transformation
        if let Some(mapping) = self.mappings.iter().find(|m| m.source_claim == _claim_name) {
            if let Some(ref transform) = mapping.transform {
                return self.execute_transform(value, transform);
            }
        }
        value.to_string()
    }

    /// Execute a transformation function
    fn execute_transform(&self, value: &str, transform: &TransformFunction) -> String {
        match transform {
            TransformFunction::Direct => value.to_string(),
            TransformFunction::Uppercase => value.to_uppercase(),
            TransformFunction::Lowercase => value.to_lowercase(),
            TransformFunction::Split { separator, index } => {
                value
                    .split(separator)
                    .nth(*index)
                    .unwrap_or(value)
                    .to_string()
            }
            TransformFunction::Regex { pattern, replacement } => {
                Regex::new(pattern)
                    .ok()
                    .and_then(|re| Some(re.replace(value, replacement).to_string()))
                    .unwrap_or_else(|| value.to_string())
            }
            TransformFunction::Concat { values, separator } => {
                let sep = separator.as_deref().unwrap_or("");
                let mut result = value.to_string();
                for v in values {
                    result.push_str(sep);
                    result.push_str(v);
                }
                result
            }
            TransformFunction::Map { mappings } => {
                mappings.get(value).cloned().unwrap_or_else(|| value.to_string())
            }
            TransformFunction::Domain => {
                value.split('@').nth(1).unwrap_or(value).to_string()
            }
            TransformFunction::LocalPart => {
                value.split('@').next().unwrap_or(value).to_string()
            }
            TransformFunction::Expression { expr: _ } => {
                // Placeholder for expression-based transformation
                // In production, could use a JS engine or expression evaluator
                value.to_string()
            }
        }
    }

    /// Set a value in VaultClaims by name
    fn set_vault_claim(&self, claims: &mut VaultClaims, name: &str, value: &str) {
        match name {
            "sub" => claims.sub = Some(value.to_string()),
            "email" => claims.email = Some(value.to_string()),
            "email_verified" => claims.email_verified = value.parse().ok(),
            "name" => claims.name = Some(value.to_string()),
            "given_name" => claims.given_name = Some(value.to_string()),
            "family_name" => claims.family_name = Some(value.to_string()),
            "middle_name" => claims.middle_name = Some(value.to_string()),
            "nickname" => claims.nickname = Some(value.to_string()),
            "preferred_username" => claims.preferred_username = Some(value.to_string()),
            "profile" => claims.profile = Some(value.to_string()),
            "picture" => claims.picture = Some(value.to_string()),
            "website" => claims.website = Some(value.to_string()),
            "gender" => claims.gender = Some(value.to_string()),
            "birthdate" => claims.birthdate = Some(value.to_string()),
            "zoneinfo" => claims.zoneinfo = Some(value.to_string()),
            "locale" => claims.locale = Some(value.to_string()),
            "phone_number" => claims.phone_number = Some(value.to_string()),
            "phone_number_verified" => claims.phone_number_verified = value.parse().ok(),
            "department" => claims.department = Some(value.to_string()),
            "employee_id" => claims.employee_id = Some(value.to_string()),
            "external_id" => claims.external_id = Some(value.to_string()),
            "provider_id" => claims.provider_id = Some(value.to_string()),
            _ => {
                // Store as custom claim
                claims.custom.insert(name.to_string(), serde_json::Value::String(value.to_string()));
            }
        }
    }

    /// Validate that required claims are present
    pub fn validate_required_claims(
        &self,
        claims: &VaultClaims,
        required: &[String],
    ) -> Result<(), Vec<String>> {
        let mut missing = Vec::new();

        for claim in required {
            let present = match claim.as_str() {
                "sub" => claims.sub.is_some(),
                "email" => claims.email.is_some(),
                "name" => claims.name.is_some(),
                "given_name" => claims.given_name.is_some(),
                "family_name" => claims.family_name.is_some(),
                _ => claims.custom.contains_key(claim),
            };

            if !present {
                missing.push(claim.clone());
            }
        }

        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }

    /// Merge multiple claim sources
    pub fn merge_claims(&self, primary: VaultClaims, secondary: VaultClaims) -> VaultClaims {
        VaultClaims {
            sub: primary.sub.or(secondary.sub),
            email: primary.email.or(secondary.email),
            email_verified: primary.email_verified.or(secondary.email_verified),
            name: primary.name.or(secondary.name),
            given_name: primary.given_name.or(secondary.given_name),
            family_name: primary.family_name.or(secondary.family_name),
            middle_name: primary.middle_name.or(secondary.middle_name),
            nickname: primary.nickname.or(secondary.nickname),
            preferred_username: primary.preferred_username.or(secondary.preferred_username),
            profile: primary.profile.or(secondary.profile),
            picture: primary.picture.or(secondary.picture),
            website: primary.website.or(secondary.website),
            gender: primary.gender.or(secondary.gender),
            birthdate: primary.birthdate.or(secondary.birthdate),
            zoneinfo: primary.zoneinfo.or(secondary.zoneinfo),
            locale: primary.locale.or(secondary.locale),
            phone_number: primary.phone_number.or(secondary.phone_number),
            phone_number_verified: primary.phone_number_verified.or(secondary.phone_number_verified),
            address: primary.address.or(secondary.address),
            updated_at: primary.updated_at.or(secondary.updated_at),
            groups: if primary.groups.is_empty() { secondary.groups } else { primary.groups },
            roles: if primary.roles.is_empty() { secondary.roles } else { primary.roles },
            permissions: if primary.permissions.is_empty() { secondary.permissions } else { primary.permissions },
            organization_id: primary.organization_id.or(secondary.organization_id),
            department: primary.department.or(secondary.department),
            employee_id: primary.employee_id.or(secondary.employee_id),
            external_id: primary.external_id.or(secondary.external_id),
            provider_id: primary.provider_id.or(secondary.provider_id),
            custom: {
                let mut custom = secondary.custom;
                custom.extend(primary.custom);
                custom
            },
        }
    }
}

impl Default for ClaimsTransformer {
    fn default() -> Self {
        Self::new()
    }
}

/// Default claim mappings for common IdPs
fn default_claim_mappings() -> Vec<ClaimMapping> {
    vec![
        ClaimMapping {
            source_claim: "sub".to_string(),
            vault_claim: "sub".to_string(),
            transform: None,
            default_value: None,
            required: true,
        },
        ClaimMapping {
            source_claim: "email".to_string(),
            vault_claim: "email".to_string(),
            transform: Some(TransformFunction::Lowercase),
            default_value: None,
            required: false,
        },
        ClaimMapping {
            source_claim: "name".to_string(),
            vault_claim: "name".to_string(),
            transform: None,
            default_value: None,
            required: false,
        },
    ]
}

/// Get OIDC-specific default claims mapping
pub fn oidc_default_mapping() -> HashMap<String, String> {
    [
        ("sub".to_string(), "sub".to_string()),
        ("email".to_string(), "email".to_string()),
        ("name".to_string(), "name".to_string()),
        ("given_name".to_string(), "given_name".to_string()),
        ("family_name".to_string(), "family_name".to_string()),
        ("picture".to_string(), "picture".to_string()),
        ("groups".to_string(), "groups".to_string()),
    ]
    .into_iter()
    .collect()
}

/// Get SAML-specific default attribute mappings
pub fn saml_default_mapping() -> HashMap<String, String> {
    [
        ("sub".to_string(), "NameID".to_string()),
        ("email".to_string(), "email".to_string()),
        ("email".to_string(), "mail".to_string()),
        ("name".to_string(), "displayName".to_string()),
        ("given_name".to_string(), "firstName".to_string()),
        ("family_name".to_string(), "lastName".to_string()),
        ("groups".to_string(), "groups".to_string()),
        ("groups".to_string(), "memberOf".to_string()),
    ]
    .into_iter()
    .collect()
}

/// Get LDAP-specific default attribute mappings
pub fn ldap_default_mapping() -> HashMap<String, String> {
    [
        ("sub".to_string(), "uid".to_string()),
        ("email".to_string(), "mail".to_string()),
        ("name".to_string(), "cn".to_string()),
        ("given_name".to_string(), "givenName".to_string()),
        ("family_name".to_string(), "sn".to_string()),
        ("groups".to_string(), "memberOf".to_string()),
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_basic() {
        let transformer = ClaimsTransformer::new();
        
        let mut external = HashMap::new();
        external.insert("sub".to_string(), "user123".to_string());
        external.insert("email".to_string(), "User@Example.com".to_string());
        external.insert("name".to_string(), "John Doe".to_string());
        
        let mut mapping = HashMap::new();
        mapping.insert("sub".to_string(), "sub".to_string());
        mapping.insert("email".to_string(), "email".to_string());
        mapping.insert("name".to_string(), "name".to_string());
        
        let claims = transformer.transform(&external, &mapping);
        
        assert_eq!(claims.sub, Some("user123".to_string()));
        assert_eq!(claims.email, Some("user@example.com".to_string())); // Lowercased
        assert_eq!(claims.name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_transform_name_building() {
        let transformer = ClaimsTransformer::new();
        
        let mut external = HashMap::new();
        external.insert("sub".to_string(), "user123".to_string());
        external.insert("firstName".to_string(), "John".to_string());
        external.insert("lastName".to_string(), "Doe".to_string());
        
        let mut mapping = HashMap::new();
        mapping.insert("sub".to_string(), "sub".to_string());
        mapping.insert("given_name".to_string(), "firstName".to_string());
        mapping.insert("family_name".to_string(), "lastName".to_string());
        
        let claims = transformer.transform(&external, &mapping);
        
        assert_eq!(claims.given_name, Some("John".to_string()));
        assert_eq!(claims.family_name, Some("Doe".to_string()));
        assert_eq!(claims.name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_transform_groups_parsing() {
        let transformer = ClaimsTransformer::new();
        
        let mut external = HashMap::new();
        external.insert("sub".to_string(), "user123".to_string());
        external.insert("groups".to_string(), "admin, users, editors".to_string());
        
        let mapping = oidc_default_mapping();
        let claims = transformer.transform(&external, &mapping);
        
        assert_eq!(claims.groups, vec!["admin", "users", "editors"]);
    }

    #[test]
    fn test_execute_transform_uppercase() {
        let transformer = ClaimsTransformer::new();
        let result = transformer.execute_transform("hello", &TransformFunction::Uppercase);
        assert_eq!(result, "HELLO");
    }

    #[test]
    fn test_execute_transform_split() {
        let transformer = ClaimsTransformer::new();
        let result = transformer.execute_transform(
            "john.doe@example.com",
            &TransformFunction::Split { separator: "@".to_string(), index: 1 }
        );
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_execute_transform_domain() {
        let transformer = ClaimsTransformer::new();
        let result = transformer.execute_transform(
            "john.doe@example.com",
            &TransformFunction::Domain
        );
        assert_eq!(result, "example.com");
    }
}
