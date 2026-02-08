//! Plugin type definitions and traits
//!
//! This module defines the core plugin trait and related types that plugins
//! must implement to integrate with the Vault authentication system.

use crate::error::{Result, VaultError};
use crate::models::user::User;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Plugin name (unique identifier)
    pub name: String,
    /// Plugin version (semver)
    pub version: String,
    /// Plugin author
    pub author: String,
    /// Plugin description
    pub description: String,
    /// List of hooks this plugin implements
    pub hooks: Vec<HookType>,
    /// Plugin capabilities
    pub capabilities: Vec<PluginCapability>,
    /// Minimum required Vault version
    pub min_vault_version: Option<String>,
    /// Plugin configuration schema
    pub config_schema: Option<serde_json::Value>,
}

impl PluginMetadata {
    /// Create new plugin metadata
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        author: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            author: author.into(),
            description: description.into(),
            hooks: Vec::new(),
            capabilities: Vec::new(),
            min_vault_version: None,
            config_schema: None,
        }
    }

    /// Add a hook type
    pub fn with_hook(mut self, hook: HookType) -> Self {
        self.hooks.push(hook);
        self
    }

    /// Add a capability
    pub fn with_capability(mut self, capability: PluginCapability) -> Self {
        self.capabilities.push(capability);
        self
    }
}

/// Hook types that plugins can implement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookType {
    /// Called before authentication
    BeforeAuth,
    /// Called after successful authentication
    AfterAuth,
    /// Called before user registration
    BeforeRegister,
    /// Called after successful registration
    AfterRegister,
    /// Called before token refresh
    BeforeRefresh,
    /// Called after token refresh
    AfterRefresh,
    /// Called before logout
    BeforeLogout,
    /// Called after logout
    AfterLogout,
    /// Called before password reset
    BeforePasswordReset,
    /// Called after password reset
    AfterPasswordReset,
    /// Called during MFA verification
    MfaVerify,
    /// Called when user data is loaded
    UserLoad,
    /// Called when user data is saved
    UserSave,
    /// Called for custom validation
    Validate,
    /// Called for custom transformation
    Transform,
    /// Called for audit logging
    Audit,
}

impl fmt::Display for HookType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookType::BeforeAuth => write!(f, "before_auth"),
            HookType::AfterAuth => write!(f, "after_auth"),
            HookType::BeforeRegister => write!(f, "before_register"),
            HookType::AfterRegister => write!(f, "after_register"),
            HookType::BeforeRefresh => write!(f, "before_refresh"),
            HookType::AfterRefresh => write!(f, "after_refresh"),
            HookType::BeforeLogout => write!(f, "before_logout"),
            HookType::AfterLogout => write!(f, "after_logout"),
            HookType::BeforePasswordReset => write!(f, "before_password_reset"),
            HookType::AfterPasswordReset => write!(f, "after_password_reset"),
            HookType::MfaVerify => write!(f, "mfa_verify"),
            HookType::UserLoad => write!(f, "user_load"),
            HookType::UserSave => write!(f, "user_save"),
            HookType::Validate => write!(f, "validate"),
            HookType::Transform => write!(f, "transform"),
            HookType::Audit => write!(f, "audit"),
        }
    }
}

/// Plugin capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    /// Can provide custom authentication
    AuthProvider,
    /// Can provide custom MFA methods
    MfaProvider,
    /// Can provide custom OAuth providers
    OAuthProvider,
    /// Can sync with external directories
    DirectorySync,
    /// Can send webhooks
    WebhookSender,
    /// Can provide audit logging
    AuditLogger,
    /// Can enforce custom policies
    PolicyEnforcer,
    /// Can provide custom rate limiting
    RateLimiter,
    /// Can provide custom routes
    RouteProvider,
    /// Can transform user data
    UserTransformer,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Plugin name
    pub name: String,
    /// Whether plugin is enabled
    pub enabled: bool,
    /// Plugin-specific configuration
    pub config: serde_json::Value,
    /// Plugin priority (higher = executed first)
    pub priority: i32,
    /// Plugin timeout in milliseconds
    pub timeout_ms: Option<u64>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            config: serde_json::Value::Object(serde_json::Map::new()),
            priority: 0,
            timeout_ms: None,
        }
    }
}

/// Authentication context passed to plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Tenant ID
    pub tenant_id: String,
    /// Email address attempting to authenticate
    pub email: String,
    /// IP address of the request
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Request headers (sanitized)
    pub headers: HashMap<String, String>,
}

impl AuthContext {
    /// Create new authentication context
    pub fn new(tenant_id: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            email: email.into(),
            ip_address: None,
            user_agent: None,
            device_fingerprint: None,
            metadata: HashMap::new(),
            headers: HashMap::new(),
        }
    }

    /// Set IP address
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set user agent
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Authentication result passed to post-auth hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// Whether authentication was successful
    pub success: bool,
    /// User ID (if successful)
    pub user_id: Option<String>,
    /// Session ID (if successful)
    pub session_id: Option<String>,
    /// MFA required
    pub mfa_required: bool,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AuthResult {
    /// Create successful result
    pub fn success(user_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            success: true,
            user_id: Some(user_id.into()),
            session_id: Some(session_id.into()),
            mfa_required: false,
            error: None,
            metadata: HashMap::new(),
        }
    }

    /// Create failed result
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            user_id: None,
            session_id: None,
            mfa_required: false,
            error: Some(error.into()),
            metadata: HashMap::new(),
        }
    }
}

/// Registration context passed to plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterContext {
    /// Tenant ID
    pub tenant_id: String,
    /// Email address
    pub email: String,
    /// User's name (if provided)
    pub name: Option<String>,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl RegisterContext {
    /// Create new registration context
    pub fn new(tenant_id: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            email: email.into(),
            name: None,
            ip_address: None,
            user_agent: None,
            metadata: HashMap::new(),
        }
    }
}

/// Action to take after a hook execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthAction {
    /// Allow the operation to continue
    Allow,
    /// Deny the operation with optional reason
    Deny { reason: String },
    /// Require additional verification
    RequireVerification {
        method: String,
        challenge: serde_json::Value,
    },
    /// Modify the context (e.g., add roles, attributes)
    Modify {
        changes: HashMap<String, serde_json::Value>,
    },
    /// Redirect to custom flow
    Redirect { url: String },
}

/// Registration action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterAction {
    /// Allow registration to continue
    Allow,
    /// Deny registration
    Deny { reason: String },
    /// Require additional verification
    RequireVerification { method: String },
    /// Modify registration data
    Modify {
        changes: HashMap<String, serde_json::Value>,
    },
}

/// Plugin error type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginError {
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Additional details
    pub details: Option<serde_json::Value>,
}

impl PluginError {
    /// Create new plugin error
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    /// Add details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for PluginError {}

impl From<PluginError> for VaultError {
    fn from(err: PluginError) -> Self {
        VaultError::Plugin(err)
    }
}

/// Route definition for plugins that provide custom endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    /// HTTP method
    pub method: HttpMethod,
    /// Route path (relative to /api/v1/plugins/{plugin_name})
    pub path: String,
    /// Handler identifier
    pub handler: String,
    /// Required permissions
    pub permissions: Vec<String>,
    /// Rate limit key
    pub rate_limit_key: Option<String>,
}

impl Route {
    /// Create new route
    pub fn new(method: HttpMethod, path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            handler: handler.into(),
            permissions: Vec::new(),
            rate_limit_key: None,
        }
    }

    /// Add required permission
    pub fn with_permission(mut self, permission: impl Into<String>) -> Self {
        self.permissions.push(permission.into());
        self
    }
}

/// HTTP methods for routes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

/// Plugin type - how the plugin is loaded
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    /// Native Rust dynamic library
    Native,
    /// WebAssembly module
    Wasm,
    /// Built-in plugin
    Builtin,
}

/// Plugin health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginHealth {
    /// Plugin is healthy
    Healthy,
    /// Plugin is degraded
    Degraded,
    /// Plugin is unhealthy
    Unhealthy,
    /// Plugin is initializing
    Initializing,
    /// Plugin is not started
    Stopped,
}

/// Plugin status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginStatus {
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin type
    pub plugin_type: PluginType,
    /// Health status
    pub health: PluginHealth,
    /// Whether plugin is enabled
    pub enabled: bool,
    /// Last error message
    pub last_error: Option<String>,
    /// Hook execution statistics
    pub hook_stats: HookStats,
    /// Uptime in seconds
    pub uptime_secs: Option<u64>,
}

/// Hook execution statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookStats {
    /// Total hook executions
    pub total_executions: u64,
    /// Successful executions
    pub successful: u64,
    /// Failed executions
    pub failed: u64,
    /// Average execution time in milliseconds
    pub avg_execution_ms: f64,
}

/// Plugin API request context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiContext {
    /// Request ID
    pub request_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// User ID (if authenticated)
    pub user_id: Option<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Query parameters
    pub query: HashMap<String, String>,
    /// Path parameters
    pub path_params: HashMap<String, String>,
}

/// Plugin API request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequest {
    /// Request context
    pub context: ApiContext,
    /// Request body
    pub body: Option<serde_json::Value>,
}

/// Plugin API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse {
    /// HTTP status code
    pub status: u16,
    /// Response body
    pub body: serde_json::Value,
    /// Response headers
    pub headers: HashMap<String, String>,
}

impl ApiResponse {
    /// Create success response
    pub fn ok(body: impl Serialize) -> std::result::Result<Self, serde_json::Error> {
        Ok(Self {
            status: 200,
            body: serde_json::to_value(body)?,
            headers: HashMap::new(),
        })
    }

    /// Create created response
    pub fn created(body: impl Serialize) -> std::result::Result<Self, serde_json::Error> {
        Ok(Self {
            status: 201,
            body: serde_json::to_value(body)?,
            headers: HashMap::new(),
        })
    }

    /// Create error response
    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            body: serde_json::json!({
                "error": {
                    "code": format!("HTTP_{}", status),
                    "message": message.into(),
                }
            }),
            headers: HashMap::new(),
        }
    }
}

/// Trait for all plugins
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get plugin metadata
    fn metadata(&self) -> &PluginMetadata;

    /// Initialize the plugin with configuration
    async fn initialize(&mut self, config: &PluginConfig) -> std::result::Result<(), PluginError>;

    /// Called before authentication
    async fn before_auth(
        &self,
        _ctx: &AuthContext,
    ) -> std::result::Result<AuthAction, PluginError> {
        Ok(AuthAction::Allow)
    }

    /// Called after successful authentication
    async fn after_auth(
        &self,
        _ctx: &AuthContext,
        _result: &AuthResult,
    ) -> std::result::Result<(), PluginError> {
        Ok(())
    }

    /// Called before user registration
    async fn before_register(
        &self,
        _ctx: &RegisterContext,
    ) -> std::result::Result<RegisterAction, PluginError> {
        Ok(RegisterAction::Allow)
    }

    /// Called after successful registration
    async fn after_register(
        &self,
        _ctx: &RegisterContext,
        _user: &User,
    ) -> std::result::Result<(), PluginError> {
        Ok(())
    }

    /// Get custom routes provided by this plugin
    fn routes(&self) -> Vec<Route> {
        Vec::new()
    }

    /// Handle API request for custom routes
    async fn handle_request(
        &self,
        _route: &str,
        _request: ApiRequest,
    ) -> std::result::Result<ApiResponse, PluginError> {
        Err(PluginError::new(
            "NOT_IMPLEMENTED",
            "This plugin does not handle API requests",
        ))
    }

    /// Get plugin health status
    async fn health_check(&self) -> PluginHealth {
        PluginHealth::Healthy
    }

    /// Shutdown the plugin
    async fn shutdown(&self) -> std::result::Result<(), PluginError> {
        Ok(())
    }
}

/// Type alias for plugin result
pub type PluginResult<T> = std::result::Result<T, PluginError>;
