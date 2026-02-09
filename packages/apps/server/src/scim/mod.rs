//! SCIM 2.0 (System for Cross-domain Identity Management) Protocol Implementation
//!
//! This module implements RFC 7643 (SCIM Schema) and RFC 7644 (SCIM Protocol).
//!
//! SCIM provides a standardized REST API for user and group provisioning,
//! enabling automatic synchronization with enterprise identity providers
//! like Okta, Azure AD, OneLogin, and Ping Identity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod auth;
pub mod handlers;

/// SCIM 2.0 Core Schemas
pub mod schemas {
    /// User schema URN
    pub const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
    /// Group schema URN
    pub const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
    /// ServiceProviderConfig schema URN
    pub const SERVICE_PROVIDER_CONFIG: &str =
        "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
    /// ResourceType schema URN
    pub const RESOURCE_TYPE: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
    /// Schema URN
    pub const SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
    /// ListResponse schema URN
    pub const LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    /// Error schema URN
    pub const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
    /// PatchOp schema URN
    pub const PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    /// BulkRequest schema URN
    pub const BULK_REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
    /// BulkResponse schema URN
    pub const BULK_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
    /// Enterprise User schema extension URN
    pub const ENTERPRISE_USER: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
}

/// SCIM Resource Type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimResourceType {
    pub schemas: Vec<String>,
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_extensions: Option<Vec<SchemaExtension>>,
}

/// Schema Extension Reference
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaExtension {
    pub schema: String,
    pub required: bool,
}

/// SCIM Schema Definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimSchema {
    pub schemas: Vec<String>,
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<ScimAttribute>>,
}

/// SCIM Attribute Definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimAttribute {
    pub name: String,
    #[serde(rename = "type")]
    pub attr_type: String,
    pub multi_valued: bool,
    pub description: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_exact: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uniqueness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_attributes: Option<Vec<ScimAttribute>>,
}

/// SCIM List Response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse<T> {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: i64,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T> ListResponse<T> {
    pub fn new(resources: Vec<T>, total_results: i64, start_index: i64, count: i64) -> Self {
        Self {
            schemas: vec![schemas::LIST_RESPONSE.to_string()],
            total_results,
            start_index,
            items_per_page: count,
            resources,
        }
    }
}

/// SCIM User Resource
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Name>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nick_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emails: Option<Vec<Email>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_numbers: Option<Vec<PhoneNumber>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ims: Option<Vec<Im>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub photos: Option<Vec<Photo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<Address>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<GroupMembership>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlements: Option<Vec<Entitlement>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<Role>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificates: Option<Vec<X509Certificate>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")]
    pub enterprise_user: Option<EnterpriseUser>,
}

/// SCIM Group Resource
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<Member>>,
}

/// SCIM Meta Attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// SCIM Name Complex Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Name {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_suffix: Option<String>,
}

/// SCIM Email Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Email {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// SCIM Phone Number Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhoneNumber {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// SCIM Instant Messaging Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Im {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// SCIM Photo Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Photo {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// SCIM Address Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// SCIM Group Membership
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMembership {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$ref")]
    pub ref_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// SCIM Group Member
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$ref")]
    pub ref_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// SCIM Entitlement Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entitlement {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// SCIM Role Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// SCIM X509 Certificate Attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X509Certificate {
    pub value: String,
}

/// Enterprise User Extension
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub employee_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_center: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub division: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<Manager>,
}

/// Manager Reference
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manager {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "$ref")]
    pub ref_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Service Provider Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceProviderConfig {
    pub schemas: Vec<String>,
    pub documentation_uri: Option<String>,
    pub patch: Supported,
    pub bulk: BulkSupport,
    pub filter: FilterSupport,
    pub change_password: Supported,
    pub sort: Supported,
    pub etag: Supported,
    pub authentication_schemes: Vec<AuthenticationScheme>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
}

/// Supported Feature
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Supported {
    pub supported: bool,
}

/// Bulk Operation Support
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkSupport {
    pub supported: bool,
    #[serde(rename = "maxOperations")]
    pub max_operations: i32,
    #[serde(rename = "maxPayloadSize")]
    pub max_payload_size: i32,
}

/// Filter Support
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterSupport {
    pub supported: bool,
    #[serde(rename = "maxResults")]
    pub max_results: i32,
}

/// Authentication Scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationScheme {
    #[serde(rename = "type")]
    pub scheme_type: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

impl Default for ServiceProviderConfig {
    fn default() -> Self {
        Self {
            schemas: vec![schemas::SERVICE_PROVIDER_CONFIG.to_string()],
            documentation_uri: Some("https://docs.vault.example.com/scim".to_string()),
            patch: Supported { supported: true },
            bulk: BulkSupport {
                supported: false,
                max_operations: 0,
                max_payload_size: 0,
            },
            filter: FilterSupport {
                supported: true,
                max_results: 200,
            },
            change_password: Supported { supported: false },
            sort: Supported { supported: true },
            etag: Supported { supported: false },
            authentication_schemes: vec![AuthenticationScheme {
                scheme_type: "oauthbearertoken".to_string(),
                name: "OAuth Bearer Token".to_string(),
                description: "Authentication using OAuth Bearer tokens".to_string(),
                spec_uri: Some("https://www.rfc-editor.org/info/rfc6750".to_string()),
                documentation_uri: None,
                primary: Some(true),
            }],
            meta: Some(Meta {
                resource_type: "ServiceProviderConfig".to_string(),
                created: None,
                last_modified: None,
                location: Some("/scim/v2/ServiceProviderConfig".to_string()),
                version: None,
            }),
        }
    }
}

/// SCIM Error Response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ScimError {
    pub fn new(status: u16, scim_type: Option<&str>, detail: Option<&str>) -> Self {
        Self {
            schemas: vec![schemas::ERROR.to_string()],
            status: status.to_string(),
            scim_type: scim_type.map(|s| s.to_string()),
            detail: detail.map(|s| s.to_string()),
        }
    }

    pub fn invalid_filter(detail: &str) -> Self {
        Self::new(400, Some("invalidFilter"), Some(detail))
    }

    pub fn too_many(detail: &str) -> Self {
        Self::new(400, Some("tooMany"), Some(detail))
    }

    pub fn uniqueness(detail: &str) -> Self {
        Self::new(400, Some("uniqueness"), Some(detail))
    }

    pub fn mutability(detail: &str) -> Self {
        Self::new(400, Some("mutability"), Some(detail))
    }

    pub fn invalid_syntax(detail: &str) -> Self {
        Self::new(400, Some("invalidSyntax"), Some(detail))
    }

    pub fn invalid_path(detail: &str) -> Self {
        Self::new(400, Some("invalidPath"), Some(detail))
    }

    pub fn no_target(detail: &str) -> Self {
        Self::new(400, Some("noTarget"), Some(detail))
    }

    pub fn invalid_value(detail: &str) -> Self {
        Self::new(400, Some("invalidValue"), Some(detail))
    }

    pub fn invalid_version(detail: &str) -> Self {
        Self::new(400, Some("invalidVers"), Some(detail))
    }

    pub fn sensitive(detail: &str) -> Self {
        Self::new(403, Some("sensitive"), Some(detail))
    }

    pub fn not_found(detail: &str) -> Self {
        Self::new(404, None, Some(detail))
    }

    pub fn not_implemented(detail: &str) -> Self {
        Self::new(501, None, Some(detail))
    }
}

/// SCIM Patch Request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchRequest {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

/// SCIM Patch Operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchOperation {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// SCIM Bulk Request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkRequest {
    pub schemas: Vec<String>,
    #[serde(rename = "failOnErrors")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_on_errors: Option<i32>,
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperation>,
}

/// SCIM Bulk Operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// SCIM Bulk Response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkResponse {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<BulkOperationResult>,
}

/// SCIM Bulk Operation Result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkOperationResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    pub method: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
}

/// Query parameters for SCIM list operations
#[derive(Debug, Clone)]
pub struct ScimQuery {
    pub filter: Option<String>,
    pub start_index: i64,
    pub count: i64,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
    pub attributes: Option<String>,
    pub excluded_attributes: Option<String>,
}

impl Default for ScimQuery {
    fn default() -> Self {
        Self {
            filter: None,
            start_index: 1,
            count: 100,
            sort_by: None,
            sort_order: None,
            attributes: None,
            excluded_attributes: None,
        }
    }
}

/// SCIM Filter Expression
#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    AttributePresent {
        attr: String,
    },
    AttributeComparison {
        attr: String,
        op: ComparisonOperator,
        value: String,
    },
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
}

/// Comparison Operators
#[derive(Debug, Clone, PartialEq)]
pub enum ComparisonOperator {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Ge,
    Lt,
    Le,
}

impl std::str::FromStr for ComparisonOperator {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "eq" => Ok(Self::Eq),
            "ne" => Ok(Self::Ne),
            "co" => Ok(Self::Co),
            "sw" => Ok(Self::Sw),
            "ew" => Ok(Self::Ew),
            "gt" => Ok(Self::Gt),
            "ge" => Ok(Self::Ge),
            "lt" => Ok(Self::Lt),
            "le" => Ok(Self::Le),
            _ => Err(format!("Unknown operator: {}", s)),
        }
    }
}

/// Filter Parser
pub struct FilterParser;

impl FilterParser {
    /// Parse a SCIM filter expression
    pub fn parse(input: &str) -> Result<Filter, ScimError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ScimError::invalid_filter("Empty filter expression"));
        }

        // Handle parentheses for grouping
        if input.starts_with('(') && input.ends_with(')') {
            let inner = &input[1..input.len() - 1];
            return Self::parse(inner);
        }

        // Handle logical operators
        if let Some(pos) = Self::find_logical_op(input, " and ") {
            let left = &input[..pos];
            let right = &input[pos + 5..];
            return Ok(Filter::And(
                Box::new(Self::parse(left)?),
                Box::new(Self::parse(right)?),
            ));
        }

        if let Some(pos) = Self::find_logical_op(input, " or ") {
            let left = &input[..pos];
            let right = &input[pos + 4..];
            return Ok(Filter::Or(
                Box::new(Self::parse(left)?),
                Box::new(Self::parse(right)?),
            ));
        }

        if input.starts_with("not(") && input.ends_with(')') {
            let inner = &input[4..input.len() - 1];
            return Ok(Filter::Not(Box::new(Self::parse(inner)?)));
        }

        // Handle attribute presence
        if input.ends_with(" pr") {
            let attr = input[..input.len() - 3].trim();
            return Ok(Filter::AttributePresent {
                attr: attr.to_string(),
            });
        }

        // Handle attribute comparison
        Self::parse_comparison(input)
    }

    fn find_logical_op(input: &str, op: &str) -> Option<usize> {
        let mut depth = 0;
        for (i, c) in input.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ if depth == 0 => {
                    if input[i..].starts_with(op) {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn parse_comparison(input: &str) -> Result<Filter, ScimError> {
        let operators = [
            " eq ", " ne ", " co ", " sw ", " ew ", " gt ", " ge ", " lt ", " le ",
        ];

        for op_str in &operators {
            if let Some(pos) = input.find(op_str) {
                let attr = input[..pos].trim();
                let value_str = input[pos + op_str.len()..].trim();

                // Parse operator
                let op = op_str
                    .trim()
                    .parse::<ComparisonOperator>()
                    .map_err(|e| ScimError::invalid_filter(&e))?;

                // Parse value (handle quoted strings)
                let value = if value_str.starts_with('"') && value_str.ends_with('"') {
                    value_str[1..value_str.len() - 1].to_string()
                } else {
                    value_str.to_string()
                };

                return Ok(Filter::AttributeComparison {
                    attr: attr.to_string(),
                    op,
                    value,
                });
            }
        }

        Err(ScimError::invalid_filter(&format!(
            "Unable to parse filter: {}",
            input
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_eq() {
        let filter = FilterParser::parse("userName eq \"john\"").unwrap();
        match filter {
            Filter::AttributeComparison { attr, op, value } => {
                assert_eq!(attr, "userName");
                assert_eq!(op, ComparisonOperator::Eq);
                assert_eq!(value, "john");
            }
            _ => panic!("Expected AttributeComparison"),
        }
    }

    #[test]
    fn test_parse_presence() {
        let filter = FilterParser::parse("emails pr").unwrap();
        match filter {
            Filter::AttributePresent { attr } => {
                assert_eq!(attr, "emails");
            }
            _ => panic!("Expected AttributePresent"),
        }
    }

    #[test]
    fn test_parse_and() {
        let filter = FilterParser::parse("userName eq \"john\" and active eq true").unwrap();
        match filter {
            Filter::And(left, right) => {
                match *left {
                    Filter::AttributeComparison { attr, .. } => assert_eq!(attr, "userName"),
                    _ => panic!("Expected left to be AttributeComparison"),
                }
                match *right {
                    Filter::AttributeComparison { attr, .. } => assert_eq!(attr, "active"),
                    _ => panic!("Expected right to be AttributeComparison"),
                }
            }
            _ => panic!("Expected And"),
        }
    }

    #[test]
    fn test_parse_or() {
        let filter = FilterParser::parse("userName eq \"john\" or userName eq \"jane\"").unwrap();
        match filter {
            Filter::Or(_, _) => {}
            _ => panic!("Expected Or"),
        }
    }
}
