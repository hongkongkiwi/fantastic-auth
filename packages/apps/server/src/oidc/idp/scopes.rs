//! OAuth 2.0 / OIDC Scope Management
//!
//! This module implements scope handling for OIDC Identity Provider:
//! - Standard OIDC scopes (openid, profile, email, phone, address)
//! - Custom scopes per tenant
//! - Scope validation
//! - Claims mapping from scopes
//!
//! OIDC defines standard claims that are returned based on the requested scopes.
//! This module manages the relationship between scopes and claims.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Standard OIDC scopes as defined by OpenID Connect Core 1.0
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardScope {
    /// REQUIRED. Informs the authorization server that the client is making an OIDC request
    OpenId,
    /// OPTIONAL. Requests access to the end-user's default profile claims
    Profile,
    /// OPTIONAL. Requests access to the email and email_verified claims
    Email,
    /// OPTIONAL. Requests access to the phone_number and phone_number_verified claims
    Phone,
    /// OPTIONAL. Requests access to the address claim
    Address,
    /// OPTIONAL. Requests that an OAuth 2.0 refresh token be issued
    OfflineAccess,
}

impl StandardScope {
    /// Get the scope name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            StandardScope::OpenId => "openid",
            StandardScope::Profile => "profile",
            StandardScope::Email => "email",
            StandardScope::Phone => "phone",
            StandardScope::Address => "address",
            StandardScope::OfflineAccess => "offline_access",
        }
    }

    /// Get all standard scopes
    pub fn all() -> Vec<StandardScope> {
        vec![
            StandardScope::OpenId,
            StandardScope::Profile,
            StandardScope::Email,
            StandardScope::Phone,
            StandardScope::Address,
            StandardScope::OfflineAccess,
        ]
    }

    /// Parse a scope string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "openid" => Some(StandardScope::OpenId),
            "profile" => Some(StandardScope::Profile),
            "email" => Some(StandardScope::Email),
            "phone" => Some(StandardScope::Phone),
            "address" => Some(StandardScope::Address),
            "offline_access" => Some(StandardScope::OfflineAccess),
            _ => None,
        }
    }

    /// Check if this scope is required for OIDC
    pub fn is_required_for_oidc(&self) -> bool {
        matches!(self, StandardScope::OpenId)
    }

    /// Get the claims associated with this scope
    pub fn claims(&self) -> Vec<&'static str> {
        match self {
            StandardScope::OpenId => vec!["sub"],
            StandardScope::Profile => vec![
                "name",
                "family_name",
                "given_name",
                "middle_name",
                "nickname",
                "preferred_username",
                "profile",
                "picture",
                "website",
                "gender",
                "birthdate",
                "zoneinfo",
                "locale",
                "updated_at",
            ],
            StandardScope::Email => vec!["email", "email_verified"],
            StandardScope::Phone => vec!["phone_number", "phone_number_verified"],
            StandardScope::Address => vec!["address"],
            StandardScope::OfflineAccess => vec![],
        }
    }
}

impl std::fmt::Display for StandardScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// OIDC claims as defined by OpenID Connect Core 1.0
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardClaim {
    // Subject claim (always included)
    Sub,
    
    // Profile scope claims
    Name,
    FamilyName,
    GivenName,
    MiddleName,
    Nickname,
    PreferredUsername,
    Profile,
    Picture,
    Website,
    Gender,
    Birthdate,
    Zoneinfo,
    Locale,
    UpdatedAt,
    
    // Email scope claims
    Email,
    EmailVerified,
    
    // Phone scope claims
    PhoneNumber,
    PhoneNumberVerified,
    
    // Address scope claim
    Address,
}

impl StandardClaim {
    /// Get the claim name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            StandardClaim::Sub => "sub",
            StandardClaim::Name => "name",
            StandardClaim::FamilyName => "family_name",
            StandardClaim::GivenName => "given_name",
            StandardClaim::MiddleName => "middle_name",
            StandardClaim::Nickname => "nickname",
            StandardClaim::PreferredUsername => "preferred_username",
            StandardClaim::Profile => "profile",
            StandardClaim::Picture => "picture",
            StandardClaim::Website => "website",
            StandardClaim::Gender => "gender",
            StandardClaim::Birthdate => "birthdate",
            StandardClaim::Zoneinfo => "zoneinfo",
            StandardClaim::Locale => "locale",
            StandardClaim::UpdatedAt => "updated_at",
            StandardClaim::Email => "email",
            StandardClaim::EmailVerified => "email_verified",
            StandardClaim::PhoneNumber => "phone_number",
            StandardClaim::PhoneNumberVerified => "phone_number_verified",
            StandardClaim::Address => "address",
        }
    }

    /// Parse a claim string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "sub" => Some(StandardClaim::Sub),
            "name" => Some(StandardClaim::Name),
            "family_name" => Some(StandardClaim::FamilyName),
            "given_name" => Some(StandardClaim::GivenName),
            "middle_name" => Some(StandardClaim::MiddleName),
            "nickname" => Some(StandardClaim::Nickname),
            "preferred_username" => Some(StandardClaim::PreferredUsername),
            "profile" => Some(StandardClaim::Profile),
            "picture" => Some(StandardClaim::Picture),
            "website" => Some(StandardClaim::Website),
            "gender" => Some(StandardClaim::Gender),
            "birthdate" => Some(StandardClaim::Birthdate),
            "zoneinfo" => Some(StandardClaim::Zoneinfo),
            "locale" => Some(StandardClaim::Locale),
            "updated_at" => Some(StandardClaim::UpdatedAt),
            "email" => Some(StandardClaim::Email),
            "email_verified" => Some(StandardClaim::EmailVerified),
            "phone_number" => Some(StandardClaim::PhoneNumber),
            "phone_number_verified" => Some(StandardClaim::PhoneNumberVerified),
            "address" => Some(StandardClaim::Address),
            _ => None,
        }
    }
}

/// Scope definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    /// Scope name
    pub name: String,
    /// Scope description
    pub description: Option<String>,
    /// Whether this is a system scope (cannot be deleted)
    pub is_system: bool,
    /// Claims associated with this scope
    pub claims: Vec<String>,
    /// Tenant ID (None for system scopes)
    pub tenant_id: Option<String>,
}

impl Scope {
    /// Create a new scope
    pub fn new(
        name: impl Into<String>,
        description: Option<String>,
        claims: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description,
            is_system: false,
            claims,
            tenant_id: None,
        }
    }

    /// Create a system scope
    pub fn system(name: impl Into<String>, description: Option<String>, claims: Vec<String>) -> Self {
        Self {
            name: name.into(),
            description,
            is_system: true,
            claims,
            tenant_id: None,
        }
    }

    /// Set tenant ID
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Check if this scope is a standard OIDC scope
    pub fn is_standard(&self) -> bool {
        StandardScope::from_str(&self.name).is_some()
    }
}

/// Scope manager
#[derive(Debug, Clone)]
pub struct ScopeManager {
    /// System scopes (always available)
    system_scopes: HashMap<String, Scope>,
    /// Tenant-specific custom scopes
    tenant_scopes: HashMap<String, HashMap<String, Scope>>,
}

impl ScopeManager {
    /// Create a new scope manager with standard OIDC scopes
    pub fn new() -> Self {
        let mut system_scopes = HashMap::new();

        // Add standard OIDC scopes
        system_scopes.insert(
            "openid".to_string(),
            Scope::system(
                "openid",
                Some("Signals that the request is an OpenID Connect request".to_string()),
                vec!["sub".to_string()],
            ),
        );

        system_scopes.insert(
            "profile".to_string(),
            Scope::system(
                "profile",
                Some("Access to the user's basic profile information".to_string()),
                vec![
                    "name".to_string(),
                    "family_name".to_string(),
                    "given_name".to_string(),
                    "middle_name".to_string(),
                    "nickname".to_string(),
                    "preferred_username".to_string(),
                    "profile".to_string(),
                    "picture".to_string(),
                    "website".to_string(),
                    "gender".to_string(),
                    "birthdate".to_string(),
                    "zoneinfo".to_string(),
                    "locale".to_string(),
                    "updated_at".to_string(),
                ],
            ),
        );

        system_scopes.insert(
            "email".to_string(),
            Scope::system(
                "email",
                Some("Access to the user's email address".to_string()),
                vec!["email".to_string(), "email_verified".to_string()],
            ),
        );

        system_scopes.insert(
            "phone".to_string(),
            Scope::system(
                "phone",
                Some("Access to the user's phone number".to_string()),
                vec!["phone_number".to_string(), "phone_number_verified".to_string()],
            ),
        );

        system_scopes.insert(
            "address".to_string(),
            Scope::system(
                "address",
                Some("Access to the user's postal address".to_string()),
                vec!["address".to_string()],
            ),
        );

        system_scopes.insert(
            "offline_access".to_string(),
            Scope::system(
                "offline_access",
                Some("Request a refresh token for offline access".to_string()),
                vec![],
            ),
        );

        Self {
            system_scopes,
            tenant_scopes: HashMap::new(),
        }
    }

    /// Get a scope by name
    pub fn get_scope(&self, name: &str, tenant_id: Option<&str>) -> Option<&Scope> {
        // First check system scopes
        if let Some(scope) = self.system_scopes.get(name) {
            return Some(scope);
        }

        // Then check tenant-specific scopes
        if let Some(tenant_id) = tenant_id {
            if let Some(tenant_scopes) = self.tenant_scopes.get(tenant_id) {
                return tenant_scopes.get(name);
            }
        }

        None
    }

    /// Check if a scope exists
    pub fn has_scope(&self, name: &str, tenant_id: Option<&str>) -> bool {
        self.get_scope(name, tenant_id).is_some()
    }

    /// Check if a scope is valid (exists and is allowed)
    pub fn is_valid_scope(&self, name: &str, tenant_id: Option<&str>) -> bool {
        self.has_scope(name, tenant_id)
    }

    /// Validate a list of scopes
    /// 
    /// Returns true if all scopes are valid.
    pub fn validate_scopes(&self, scopes: &[String], tenant_id: Option<&str>) -> bool {
        scopes.iter().all(|s| self.is_valid_scope(s, tenant_id))
    }

    /// Get all valid scopes for a request
    /// 
    /// Filters out any invalid scopes and returns only valid ones.
    pub fn filter_valid_scopes(
        &self,
        scopes: &[String],
        tenant_id: Option<&str>,
    ) -> Vec<String> {
        scopes
            .iter()
            .filter(|s| self.is_valid_scope(s, tenant_id))
            .cloned()
            .collect()
    }

    /// Add a custom scope for a tenant
    pub fn add_scope(&mut self, scope: Scope, tenant_id: impl Into<String>) -> Result<(), ScopeError> {
        let tenant_id = tenant_id.into();
        let name = scope.name.clone();

        // Check if it's a system scope
        if self.system_scopes.contains_key(&name) {
            return Err(ScopeError::SystemScopeCannotBeModified(name));
        }

        let tenant_scopes = self.tenant_scopes.entry(tenant_id).or_default();
        tenant_scopes.insert(name, scope);

        Ok(())
    }

    /// Remove a custom scope
    pub fn remove_scope(
        &mut self,
        name: &str,
        tenant_id: impl Into<String>,
    ) -> Result<(), ScopeError> {
        let tenant_id = tenant_id.into();

        // Check if it's a system scope
        if self.system_scopes.contains_key(name) {
            return Err(ScopeError::SystemScopeCannotBeModified(name.to_string()));
        }

        if let Some(tenant_scopes) = self.tenant_scopes.get_mut(&tenant_id) {
            tenant_scopes.remove(name);
        }

        Ok(())
    }

    /// Get all scopes for a tenant
    pub fn get_all_scopes(&self, tenant_id: Option<&str>) -> Vec<&Scope> {
        let mut scopes: Vec<&Scope> = self.system_scopes.values().collect();

        if let Some(tenant_id) = tenant_id {
            if let Some(tenant_scopes) = self.tenant_scopes.get(tenant_id) {
                scopes.extend(tenant_scopes.values());
            }
        }

        scopes
    }

    /// Get all scope names
    pub fn get_scope_names(&self, tenant_id: Option<&str>) -> Vec<String> {
        self.get_all_scopes(tenant_id)
            .into_iter()
            .map(|s| s.name.clone())
            .collect()
    }

    /// Get claims for a list of scopes
    pub fn get_claims_for_scopes(
        &self,
        scopes: &[String],
        tenant_id: Option<&str>,
    ) -> HashSet<String> {
        let mut claims = HashSet::new();

        for scope_name in scopes {
            if let Some(scope) = self.get_scope(scope_name, tenant_id) {
                for claim in &scope.claims {
                    claims.insert(claim.clone());
                }
            }
        }

        claims
    }

    /// Check if a list of scopes includes openid
    pub fn is_oidc_request(scopes: &[String]) -> bool {
        scopes.iter().any(|s| s == "openid")
    }

    /// Parse a space-separated scope string
    pub fn parse_scope_string(scope_str: &str) -> Vec<String> {
        scope_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()
    }

    /// Join scopes into a space-separated string
    pub fn join_scopes(scopes: &[String]) -> String {
        scopes.join(" ")
    }

    /// Get the claims for the openid scope
    pub fn openid_claims() -> Vec<&'static str> {
        vec!["sub"]
    }

    /// Get the claims for the profile scope
    pub fn profile_claims() -> Vec<&'static str> {
        vec![
            "name",
            "family_name",
            "given_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
        ]
    }

    /// Get the claims for the email scope
    pub fn email_claims() -> Vec<&'static str> {
        vec!["email", "email_verified"]
    }

    /// Get the claims for the phone scope
    pub fn phone_claims() -> Vec<&'static str> {
        vec!["phone_number", "phone_number_verified"]
    }

    /// Get the claims for the address scope
    pub fn address_claims() -> Vec<&'static str> {
        vec!["address"]
    }
}

impl Default for ScopeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Scope errors
#[derive(Debug, Clone)]
pub enum ScopeError {
    /// Scope not found
    NotFound(String),
    /// System scope cannot be modified
    SystemScopeCannotBeModified(String),
    /// Invalid scope name
    InvalidName(String),
    /// Scope already exists
    AlreadyExists(String),
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeError::NotFound(s) => write!(f, "Scope not found: {}", s),
            ScopeError::SystemScopeCannotBeModified(s) => {
                write!(f, "System scope cannot be modified: {}", s)
            }
            ScopeError::InvalidName(s) => write!(f, "Invalid scope name: {}", s),
            ScopeError::AlreadyExists(s) => write!(f, "Scope already exists: {}", s),
        }
    }
}

impl std::error::Error for ScopeError {}

/// Scope validation result
#[derive(Debug, Clone)]
pub enum ScopeValidationResult {
    /// All scopes are valid
    Valid,
    /// Some scopes are invalid
    InvalidScopes(Vec<String>),
    /// Missing required openid scope for OIDC request
    MissingOpenId,
}

/// Requested claims parameter (OIDC)
/// 
/// The claims request parameter allows clients to request specific claims
/// to be included in the ID token or returned from the UserInfo endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsRequest {
    /// UserInfo endpoint claims
    pub userinfo: Option<ClaimRequests>,
    /// ID token claims
    pub id_token: Option<ClaimRequests>,
}

/// Claims request for a specific target (userinfo or id_token)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequests {
    /// Requested claims
    #[serde(flatten)]
    pub claims: HashMap<String, ClaimRequest>,
}

/// Individual claim request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// Whether the claim is essential (request fails if not available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub essential: Option<bool>,
    /// Requested value (claim must equal this value)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    /// Requested values (claim must be one of these)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,
}

/// Parse a claims request parameter
pub fn parse_claims_request(claims_json: &str) -> Result<ClaimsRequest, serde_json::Error> {
    let mut value: serde_json::Value = serde_json::from_str(claims_json)?;

    for target in ["userinfo", "id_token"] {
        if let Some(target_obj) = value.get_mut(target).and_then(|v| v.as_object_mut()) {
            for (_, claim_request) in target_obj.iter_mut() {
                if claim_request.is_null() {
                    *claim_request = serde_json::json!({});
                }
            }
        }
    }

    serde_json::from_value(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_scope_as_str() {
        assert_eq!(StandardScope::OpenId.as_str(), "openid");
        assert_eq!(StandardScope::Profile.as_str(), "profile");
        assert_eq!(StandardScope::Email.as_str(), "email");
        assert_eq!(StandardScope::Phone.as_str(), "phone");
        assert_eq!(StandardScope::Address.as_str(), "address");
        assert_eq!(StandardScope::OfflineAccess.as_str(), "offline_access");
    }

    #[test]
    fn test_standard_scope_from_str() {
        assert_eq!(StandardScope::from_str("openid"), Some(StandardScope::OpenId));
        assert_eq!(StandardScope::from_str("profile"), Some(StandardScope::Profile));
        assert_eq!(StandardScope::from_str("email"), Some(StandardScope::Email));
        assert_eq!(StandardScope::from_str("unknown"), None);
    }

    #[test]
    fn test_standard_scope_claims() {
        let openid_claims = StandardScope::OpenId.claims();
        assert!(openid_claims.contains(&"sub"));

        let email_claims = StandardScope::Email.claims();
        assert!(email_claims.contains(&"email"));
        assert!(email_claims.contains(&"email_verified"));

        let profile_claims = StandardScope::Profile.claims();
        assert!(profile_claims.contains(&"name"));
        assert!(profile_claims.contains(&"given_name"));
        assert!(profile_claims.contains(&"family_name"));
    }

    #[test]
    fn test_scope_manager_system_scopes() {
        let manager = ScopeManager::new();

        // Check system scopes exist
        assert!(manager.has_scope("openid", None));
        assert!(manager.has_scope("profile", None));
        assert!(manager.has_scope("email", None));
        assert!(manager.has_scope("phone", None));
        assert!(manager.has_scope("address", None));
        assert!(manager.has_scope("offline_access", None));

        // Check non-existent scope
        assert!(!manager.has_scope("custom", None));
    }

    #[test]
    fn test_scope_manager_get_scope() {
        let manager = ScopeManager::new();

        let profile = manager.get_scope("profile", None).unwrap();
        assert_eq!(profile.name, "profile");
        assert!(profile.is_system);
        assert!(profile.claims.contains(&"name".to_string()));
    }

    #[test]
    fn test_scope_manager_validate_scopes() {
        let manager = ScopeManager::new();

        assert!(manager.validate_scopes(
            &vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
            None
        ));

        assert!(!manager.validate_scopes(
            &vec!["openid".to_string(), "invalid".to_string()],
            None
        ));
    }

    #[test]
    fn test_scope_manager_filter_scopes() {
        let manager = ScopeManager::new();

        let scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "invalid".to_string(),
        ];
        let filtered = manager.filter_valid_scopes(&scopes, None);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&"openid".to_string()));
        assert!(filtered.contains(&"profile".to_string()));
        assert!(!filtered.contains(&"invalid".to_string()));
    }

    #[test]
    fn test_scope_manager_get_claims() {
        let manager = ScopeManager::new();

        let scopes = vec!["openid".to_string(), "email".to_string()];
        let claims = manager.get_claims_for_scopes(&scopes, None);

        assert!(claims.contains("sub"));
        assert!(claims.contains("email"));
        assert!(claims.contains("email_verified"));
        assert!(!claims.contains("name")); // profile claim
    }

    #[test]
    fn test_scope_manager_add_custom_scope() {
        let mut manager = ScopeManager::new();

        let custom = Scope::new(
            "custom:read",
            Some("Read access to custom resource".to_string()),
            vec!["custom_id".to_string(), "custom_name".to_string()],
        )
        .with_tenant("tenant-1");

        manager.add_scope(custom, "tenant-1").unwrap();

        assert!(manager.has_scope("custom:read", Some("tenant-1")));
        assert!(!manager.has_scope("custom:read", None)); // Not a system scope
        assert!(!manager.has_scope("custom:read", Some("tenant-2"))); // Different tenant
    }

    #[test]
    fn test_scope_manager_cannot_modify_system() {
        let mut manager = ScopeManager::new();

        let custom = Scope::new("openid", None, vec![]);

        let result = manager.add_scope(custom, "tenant-1");
        assert!(matches!(result, Err(ScopeError::SystemScopeCannotBeModified(_))));
    }

    #[test]
    fn test_parse_scope_string() {
        let scopes = ScopeManager::parse_scope_string("openid profile email");
        assert_eq!(scopes, vec!["openid", "profile", "email"]);

        let scopes = ScopeManager::parse_scope_string("openid");
        assert_eq!(scopes, vec!["openid"]);

        let scopes = ScopeManager::parse_scope_string("");
        assert!(scopes.is_empty());
    }

    #[test]
    fn test_join_scopes() {
        let scopes = vec!["openid".to_string(), "profile".to_string()];
        assert_eq!(ScopeManager::join_scopes(&scopes), "openid profile");
    }

    #[test]
    fn test_is_oidc_request() {
        assert!(ScopeManager::is_oidc_request(&vec!["openid".to_string()]));
        assert!(ScopeManager::is_oidc_request(&vec![
            "openid".to_string(),
            "profile".to_string()
        ]));
        assert!(!ScopeManager::is_oidc_request(&vec!["profile".to_string(), "email".to_string()]));
    }

    #[test]
    fn test_scope_validation_result() {
        let result = ScopeValidationResult::Valid;
        assert!(matches!(result, ScopeValidationResult::Valid));

        let result = ScopeValidationResult::InvalidScopes(vec!["bad".to_string()]);
        assert!(matches!(result, ScopeValidationResult::InvalidScopes(_)));
    }

    #[test]
    fn test_claim_request_parsing() {
        let json = r#"{
            "userinfo": {
                "email": {"essential": true},
                "name": null
            },
            "id_token": {
                "auth_time": {"essential": true}
            }
        }"#;

        let claims = parse_claims_request(json).unwrap();
        assert!(claims.userinfo.is_some());
        assert!(claims.id_token.is_some());

        let userinfo = claims.userinfo.unwrap();
        assert!(userinfo.claims.contains_key("email"));
        assert!(userinfo.claims.contains_key("name"));

        let email_claim = userinfo.claims.get("email").unwrap();
        assert_eq!(email_claim.essential, Some(true));
    }
}
