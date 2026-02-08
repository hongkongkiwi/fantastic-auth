//! Privacy Policy Templates
//!
//! Template system for generating privacy policies with tenant-specific placeholders.

use serde_json::json;
use std::collections::HashMap;

/// Privacy policy template
#[derive(Debug, Clone)]
pub struct PrivacyPolicyTemplate {
    /// Template name
    pub name: String,
    /// Template content with placeholders
    pub content: String,
    /// Required placeholders
    pub required_placeholders: Vec<String>,
    /// Optional placeholders with defaults
    pub optional_placeholders: HashMap<String, String>,
}

impl PrivacyPolicyTemplate {
    /// Create a new template
    pub fn new(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            content: content.into(),
            required_placeholders: Vec::new(),
            optional_placeholders: HashMap::new(),
        }
    }

    /// Add required placeholder
    pub fn require_placeholder(mut self, name: impl Into<String>) -> Self {
        self.required_placeholders.push(name.into());
        self
    }

    /// Add optional placeholder with default
    pub fn optional_placeholder(
        mut self,
        name: impl Into<String>,
        default: impl Into<String>,
    ) -> Self {
        self.optional_placeholders
            .insert(name.into(), default.into());
        self
    }

    /// Render template with values
    pub fn render(&self, values: &HashMap<String, String>) -> Result<String, TemplateError> {
        // Check required placeholders
        for required in &self.required_placeholders {
            if !values.contains_key(required) {
                return Err(TemplateError::MissingPlaceholder(required.clone()));
            }
        }

        // Merge values with defaults
        let mut final_values = self.optional_placeholders.clone();
        for (k, v) in values {
            final_values.insert(k.clone(), v.clone());
        }

        // Replace placeholders
        let mut result = self.content.clone();
        for (key, value) in final_values {
            let placeholder = format!("{{{{{}}}}}", key);
            result = result.replace(&placeholder, &value);
        }

        // Check for unreplaced placeholders
        if result.contains("{{") {
            let unreplaced: Vec<String> = result
                .split("{{")
                .skip(1)
                .filter_map(|s| s.split("}}").next())
                .map(|s| format!("{{{{{}}}}}", s.trim()))
                .collect();

            if !unreplaced.is_empty() {
                return Err(TemplateError::UnreplacedPlaceholders(unreplaced));
            }
        }

        Ok(result)
    }
}

/// Template error
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("Missing required placeholder: {0}")]
    MissingPlaceholder(String),

    #[error("Unreplaced placeholders: {0:?}")]
    UnreplacedPlaceholders(Vec<String>),
}

/// Template registry
pub struct TemplateRegistry {
    templates: HashMap<String, PrivacyPolicyTemplate>,
}

impl TemplateRegistry {
    /// Create a new template registry with default templates
    pub fn new() -> Self {
        let mut registry = Self {
            templates: HashMap::new(),
        };
        registry.register_defaults();
        registry
    }

    /// Register a template
    pub fn register(&mut self, key: impl Into<String>, template: PrivacyPolicyTemplate) {
        self.templates.insert(key.into(), template);
    }

    /// Get a template
    pub fn get(&self, key: &str) -> Option<&PrivacyPolicyTemplate> {
        self.templates.get(key)
    }

    /// Render a template
    pub fn render(
        &self,
        key: &str,
        values: &HashMap<String, String>,
    ) -> Result<String, TemplateError> {
        self.get(key)
            .ok_or_else(|| TemplateError::MissingPlaceholder(format!("Template not found: {}", key)))
            .and_then(|t| t.render(values))
    }

    /// Register default templates
    fn register_defaults(&mut self) {
        // GDPR-compliant privacy policy template
        self.register(
            "gdpr_privacy_policy",
            PrivacyPolicyTemplate::new(
                "GDPR Privacy Policy",
                include_str!("templates/gdpr_privacy_policy.md"),
            )
            .require_placeholder("company_name")
            .require_placeholder("company_address")
            .require_placeholder("contact_email")
            .optional_placeholder("dpo_email", "{{contact_email}}")
            .optional_placeholder("company_website", "https://example.com")
            .optional_placeholder("data_retention_days", "365")
            .optional_placeholder("cookie_policy_url", "/cookies"),
        );

        // CCPA privacy policy template
        self.register(
            "ccpa_privacy_policy",
            PrivacyPolicyTemplate::new(
                "CCPA Privacy Policy",
                include_str!("templates/ccpa_privacy_policy.md"),
            )
            .require_placeholder("company_name")
            .require_placeholder("company_address")
            .require_placeholder("contact_email")
            .optional_placeholder("company_website", "https://example.com")
            .optional_placeholder("do_not_sell_url", "/do-not-sell"),
        );

        // Terms of Service template
        self.register(
            "terms_of_service",
            PrivacyPolicyTemplate::new(
                "Terms of Service",
                include_str!("templates/terms_of_service.md"),
            )
            .require_placeholder("company_name")
            .require_placeholder("company_address")
            .require_placeholder("contact_email")
            .optional_placeholder("company_website", "https://example.com")
            .optional_placeholder("governing_law", "Delaware, USA")
            .optional_placeholder("arbitration_location", "Delaware, USA"),
        );

        // Cookie Policy template
        self.register(
            "cookie_policy",
            PrivacyPolicyTemplate::new(
                "Cookie Policy",
                include_str!("templates/cookie_policy.md"),
            )
            .require_placeholder("company_name")
            .require_placeholder("contact_email")
            .optional_placeholder("company_website", "https://example.com")
            .optional_placeholder("privacy_policy_url", "/privacy"),
        );

        // Marketing Consent template
        self.register(
            "marketing_consent",
            PrivacyPolicyTemplate::new(
                "Marketing Consent",
                "I consent to receive marketing communications from {{company_name}} via email, SMS, and other channels. I understand that I can unsubscribe at any time.",
            )
            .require_placeholder("company_name"),
        );

        // Analytics Consent template
        self.register(
            "analytics_consent",
            PrivacyPolicyTemplate::new(
                "Analytics Consent",
                "I consent to the use of analytics cookies and tracking technologies to help {{company_name}} improve its services and user experience.",
            )
            .require_placeholder("company_name"),
        );
    }
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Get template variables as JSON schema
pub fn get_template_schema(template_key: &str) -> serde_json::Value {
    let registry = TemplateRegistry::new();
    
    match registry.get(template_key) {
        Some(template) => {
            let required: Vec<serde_json::Value> = template
                .required_placeholders
                .iter()
                .map(|p| {
                    json!({
                        "name": p,
                        "required": true,
                        "type": "string"
                    })
                })
                .collect();

            let optional: Vec<serde_json::Value> = template
                .optional_placeholders
                .iter()
                .map(|(k, v)| {
                    json!({
                        "name": k,
                        "required": false,
                        "type": "string",
                        "default": v
                    })
                })
                .collect();

            json!({
                "template": template_key,
                "placeholders": [required, optional].concat()
            })
        }
        None => json!({
            "error": "Template not found",
            "available_templates": get_available_templates()
        }),
    }
}

/// Get list of available templates
pub fn get_available_templates() -> Vec<String> {
    vec![
        "gdpr_privacy_policy".to_string(),
        "ccpa_privacy_policy".to_string(),
        "terms_of_service".to_string(),
        "cookie_policy".to_string(),
        "marketing_consent".to_string(),
        "analytics_consent".to_string(),
    ]
}

/// Render a template with values
pub fn render_template(
    template_key: &str,
    values: &HashMap<String, String>,
) -> Result<String, TemplateError> {
    let registry = TemplateRegistry::new();
    registry.render(template_key, values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_render() {
        let template = PrivacyPolicyTemplate::new(
            "Test",
            "Hello {{name}}, welcome to {{company}}!",
        )
        .require_placeholder("name")
        .optional_placeholder("company", "DefaultCorp");

        let mut values = HashMap::new();
        values.insert("name".to_string(), "John".to_string());

        let result = template.render(&values).unwrap();
        assert_eq!(result, "Hello John, welcome to DefaultCorp!");

        values.insert("company".to_string(), "Acme Inc".to_string());
        let result = template.render(&values).unwrap();
        assert_eq!(result, "Hello John, welcome to Acme Inc!");
    }

    #[test]
    fn test_missing_placeholder() {
        let template =
            PrivacyPolicyTemplate::new("Test", "Hello {{name}}!").require_placeholder("name");

        let values = HashMap::new();
        assert!(template.render(&values).is_err());
    }

    #[test]
    fn test_unreplaced_placeholder() {
        let template = PrivacyPolicyTemplate::new("Test", "Hello {{name}}, {{greeting}}!");

        let mut values = HashMap::new();
        values.insert("name".to_string(), "John".to_string());

        assert!(template.render(&values).is_err());
    }
}
