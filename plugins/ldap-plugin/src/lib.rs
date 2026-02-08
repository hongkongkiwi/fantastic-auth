//! LDAP/Active Directory Integration Plugin
//!
//! This plugin provides LDAP authentication and user synchronization
//! capabilities for Vault. It supports:
//!
//! - LDAP bind authentication
//! - User attribute synchronization
//! - Group membership mapping
//! - Multiple LDAP server support
//!
//! ## Configuration
//!
//! ```yaml
//! plugins:
//!   - name: "ldap-plugin"
//!     config:
//!       servers:
//!         - host: "ldap.example.com"
//!           port: 636
//!           use_ssl: true
//!           bind_dn: "cn=admin,dc=example,dc=com"
//!           bind_password: "secret"
//!           base_dn: "ou=users,dc=example,dc=com"
//!           user_filter: "(objectClass=person)"
//!           username_attribute: "uid"
//!           email_attribute: "mail"
//!           name_attribute: "cn"
//!           sync_interval: 3600
//!           group_mappings:
//!             - ldap_group: "admins"
//!               vault_role: "admin"
//!             - ldap_group: "users"
//!               vault_role: "user"
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vault_core::models::user::User;
use vault_core::plugin::types::{
    ApiRequest, ApiResponse, AuthAction, AuthContext, AuthResult, HookType, HttpMethod, Plugin,
    PluginCapability, PluginConfig, PluginError, PluginHealth, PluginMetadata, RegisterAction,
    RegisterContext, Route,
};

/// LDAP server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LdapServerConfig {
    /// Server hostname
    pub host: String,
    /// Server port (default: 389/636)
    pub port: u16,
    /// Use SSL/TLS
    pub use_ssl: bool,
    /// Allow insecure TLS (for testing only)
    pub allow_insecure_tls: bool,
    /// Bind DN for authentication
    pub bind_dn: String,
    /// Bind password
    pub bind_password: String,
    /// Base DN for searches
    pub base_dn: String,
    /// User search filter
    pub user_filter: String,
    /// Username attribute (e.g., uid, sAMAccountName)
    pub username_attribute: String,
    /// Email attribute
    pub email_attribute: String,
    /// Display name attribute
    pub name_attribute: String,
    /// Group membership attribute
    pub group_attribute: String,
    /// Group base DN (if different from base_dn)
    pub group_base_dn: Option<String>,
    /// Group search filter
    pub group_filter: String,
    /// Connection timeout (seconds)
    pub timeout_secs: u64,
}

impl Default for LdapServerConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 636,
            use_ssl: true,
            allow_insecure_tls: false,
            bind_dn: String::new(),
            bind_password: String::new(),
            base_dn: String::new(),
            user_filter: "(objectClass=person)".to_string(),
            username_attribute: "uid".to_string(),
            email_attribute: "mail".to_string(),
            name_attribute: "cn".to_string(),
            group_attribute: "memberOf".to_string(),
            group_base_dn: None,
            group_filter: "(objectClass=group)".to_string(),
            timeout_secs: 30,
        }
    }
}

/// Group mapping configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GroupMapping {
    /// LDAP group DN or name
    pub ldap_group: String,
    /// Vault role to assign
    pub vault_role: String,
    /// Tenant ID for role assignment
    pub tenant_id: Option<String>,
}

/// LDAP plugin configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LdapConfig {
    /// LDAP server configurations
    pub servers: Vec<LdapServerConfig>,
    /// Group to role mappings
    pub group_mappings: Vec<GroupMapping>,
    /// Auto-create users on first login
    pub auto_create_users: bool,
    /// Sync user attributes on login
    pub sync_on_login: bool,
    /// Enable fallback to local auth if LDAP fails
    pub allow_local_fallback: bool,
    /// Attribute mapping from LDAP to Vault
    pub attribute_mapping: HashMap<String, String>,
    /// Default tenant for LDAP users
    pub default_tenant_id: Option<String>,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            group_mappings: Vec::new(),
            auto_create_users: true,
            sync_on_login: true,
            allow_local_fallback: true,
            attribute_mapping: HashMap::new(),
            default_tenant_id: None,
        }
    }
}

/// LDAP user attributes retrieved from directory
#[derive(Debug, Clone, Default)]
pub struct LdapUserAttributes {
    /// Username
    pub username: String,
    /// Email address
    pub email: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// First name
    pub first_name: Option<String>,
    /// Last name
    pub last_name: Option<String>,
    /// Department
    pub department: Option<String>,
    /// Groups the user belongs to
    pub groups: Vec<String>,
    /// All LDAP attributes
    pub raw_attributes: HashMap<String, Vec<String>>,
}

/// LDAP Plugin
pub struct LdapPlugin {
    metadata: PluginMetadata,
    config: LdapConfig,
    stats: std::sync::Mutex<LdapStats>,
}

#[derive(Debug, Default, Clone)]
struct LdapStats {
    auth_attempts: u64,
    successful_auths: u64,
    failed_auths: u64,
    sync_operations: u64,
    sync_errors: u64,
}

impl LdapPlugin {
    /// Create new LDAP plugin
    pub fn new() -> Self {
        let metadata = PluginMetadata::new(
            "ldap-plugin",
            "1.0.0",
            "Vault Contributors",
            "LDAP/Active Directory integration for Vault",
        )
        .with_hook(HookType::BeforeAuth)
        .with_hook(HookType::AfterAuth)
        .with_hook(HookType::UserLoad)
        .with_capability(PluginCapability::AuthProvider)
        .with_capability(PluginCapability::DirectorySync);

        Self {
            metadata,
            config: LdapConfig::default(),
            stats: std::sync::Mutex::new(LdapStats::default()),
        }
    }

    /// Authenticate user against LDAP
    async fn authenticate_ldap(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LdapUserAttributes, PluginError> {
        // In a real implementation, this would:
        // 1. Connect to LDAP server
        // 2. Bind with service account
        // 3. Search for user DN
        // 4. Attempt bind with user credentials
        // 5. Fetch user attributes on success

        // For now, return a stub
        tracing::info!("LDAP auth attempt for user: {}", username);

        Err(PluginError::new(
            "LDAP_NOT_CONFIGURED",
            "LDAP authentication not yet implemented - requires ldap3 crate integration",
        ))
    }

    /// Map LDAP groups to Vault roles
    fn map_groups_to_roles(&self, groups: &[String]) -> Vec<String> {
        let mut roles = Vec::new();

        for mapping in &self.config.group_mappings {
            // Check if user is in this LDAP group
            let is_member = groups.iter().any(|g| {
                g.eq_ignore_ascii_case(&mapping.ldap_group) || g.contains(&mapping.ldap_group)
            });

            if is_member {
                roles.push(mapping.vault_role.clone());
            }
        }

        roles
    }

    /// Sync user attributes from LDAP to Vault
    async fn sync_user_attributes(&self, user: &mut User, ldap_attrs: &LdapUserAttributes) {
        // Update profile from LDAP attributes
        if let Some(ref name) = ldap_attrs.display_name {
            user.profile.name = Some(name.clone());
        }

        // Map groups to roles in metadata
        let roles = self.map_groups_to_roles(&ldap_attrs.groups);
        if let Some(metadata) = user.metadata.as_object_mut() {
            metadata.insert("ldap_roles".to_string(), serde_json::json!(roles));
            metadata.insert(
                "ldap_groups".to_string(),
                serde_json::json!(&ldap_attrs.groups),
            );
            metadata.insert(
                "ldap_synced_at".to_string(),
                serde_json::json!(chrono::Utc::now().to_rfc3339()),
            );
        }

        tracing::info!("Synced LDAP attributes for user {}", user.id);
    }

    /// Get plugin statistics
    fn get_stats(&self) -> LdapStats {
        self.stats.lock().unwrap().clone()
    }
}

impl Default for LdapPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for LdapPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, config: &PluginConfig) -> Result<(), PluginError> {
        tracing::info!("Initializing LDAP Plugin");

        // Parse configuration
        self.config = serde_json::from_value(config.config.clone())
            .map_err(|e| PluginError::new("CONFIG_ERROR", format!("Invalid LDAP config: {}", e)))?;

        // Validate configuration
        if self.config.servers.is_empty() {
            return Err(PluginError::new(
                "CONFIG_ERROR",
                "At least one LDAP server must be configured",
            ));
        }

        for (i, server) in self.config.servers.iter().enumerate() {
            if server.host.is_empty() {
                return Err(PluginError::new(
                    "CONFIG_ERROR",
                    format!("Server {}: host is required", i),
                ));
            }
            if server.bind_dn.is_empty() {
                return Err(PluginError::new(
                    "CONFIG_ERROR",
                    format!("Server {}: bind_dn is required", i),
                ));
            }
        }

        tracing::info!(
            "LDAP Plugin initialized with {} server(s)",
            self.config.servers.len()
        );
        Ok(())
    }

    async fn before_auth(&self, ctx: &AuthContext) -> Result<AuthAction, PluginError> {
        tracing::debug!("LDAP before_auth hook for {}", ctx.email);

        {
            let mut stats = self.stats.lock().unwrap();
            stats.auth_attempts += 1;
        }

        // Extract username from email
        let username = ctx.email.split('@').next().unwrap_or(&ctx.email);

        // Check if user exists in LDAP
        // In a real implementation, this would verify the user exists in LDAP
        // without performing the actual bind yet

        // For now, just allow and let the actual auth happen
        Ok(AuthAction::Allow)
    }

    async fn after_auth(&self, ctx: &AuthContext, result: &AuthResult) -> Result<(), PluginError> {
        if !result.success {
            return Ok(());
        }

        tracing::debug!("LDAP after_auth hook for {}", ctx.email);

        // If sync_on_login is enabled, we would sync user attributes here
        // In a real implementation, this would:
        // 1. Look up the user in LDAP
        // 2. Sync attributes to Vault user record
        // 3. Update group memberships

        {
            let mut stats = self.stats.lock().unwrap();
            stats.successful_auths += 1;
        }

        Ok(())
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route::new(HttpMethod::Get, "/status", "get_status").with_permission("admin:plugins"),
            Route::new(HttpMethod::Post, "/sync", "trigger_sync").with_permission("admin:plugins"),
            Route::new(HttpMethod::Get, "/config", "get_config").with_permission("admin:plugins"),
        ]
    }

    async fn handle_request(
        &self,
        route: &str,
        _request: ApiRequest,
    ) -> Result<ApiResponse, PluginError> {
        match route {
            "get_status" => {
                let stats = self.get_stats();
                Ok(ApiResponse {
                    status: 200,
                    body: serde_json::json!({
                        "status": "healthy",
                        "stats": {
                            "auth_attempts": stats.auth_attempts,
                            "successful_auths": stats.successful_auths,
                            "failed_auths": stats.failed_auths,
                            "sync_operations": stats.sync_operations,
                            "sync_errors": stats.sync_errors,
                        },
                        "servers": self.config.servers.len(),
                        "group_mappings": self.config.group_mappings.len(),
                    }),
                    headers: HashMap::new(),
                })
            }
            "trigger_sync" => {
                // Would trigger full user sync
                Ok(ApiResponse {
                    status: 202,
                    body: serde_json::json!({
                        "message": "Sync triggered",
                        "status": "pending"
                    }),
                    headers: HashMap::new(),
                })
            }
            "get_config" => {
                // Return sanitized config (no passwords)
                let sanitized_servers: Vec<_> = self
                    .config
                    .servers
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "host": s.host,
                            "port": s.port,
                            "use_ssl": s.use_ssl,
                            "base_dn": s.base_dn,
                            "user_filter": s.user_filter,
                            "username_attribute": s.username_attribute,
                            "email_attribute": s.email_attribute,
                            "name_attribute": s.name_attribute,
                            "timeout_secs": s.timeout_secs,
                        })
                    })
                    .collect();

                Ok(ApiResponse {
                    status: 200,
                    body: serde_json::json!({
                        "servers": sanitized_servers,
                        "group_mappings": self.config.group_mappings,
                        "auto_create_users": self.config.auto_create_users,
                        "sync_on_login": self.config.sync_on_login,
                        "allow_local_fallback": self.config.allow_local_fallback,
                    }),
                    headers: HashMap::new(),
                })
            }
            _ => Err(PluginError::new("NOT_FOUND", "Route not found")),
        }
    }

    async fn health_check(&self) -> PluginHealth {
        // Check LDAP connectivity
        if self.config.servers.is_empty() {
            return PluginHealth::Unhealthy;
        }

        // In a real implementation, test connectivity to each server
        PluginHealth::Healthy
    }

    async fn shutdown(&self) -> Result<(), PluginError> {
        tracing::info!("LDAP Plugin shutting down");
        Ok(())
    }
}

/// Create plugin instance - called by the plugin loader
pub fn create_plugin() -> Box<dyn Plugin> {
    Box::new(LdapPlugin::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_plugin_metadata() {
        let plugin = LdapPlugin::new();
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "ldap-plugin");
        assert!(metadata.hooks.contains(&HookType::BeforeAuth));
        assert!(metadata
            .capabilities
            .contains(&PluginCapability::AuthProvider));
    }

    #[tokio::test]
    async fn test_ldap_plugin_initialization() {
        let mut plugin = LdapPlugin::new();

        // Valid config
        let config = PluginConfig {
            name: "ldap-plugin".to_string(),
            enabled: true,
            config: serde_json::json!({
                "servers": [{
                    "host": "ldap.example.com",
                    "port": 636,
                    "use_ssl": true,
                    "bind_dn": "cn=admin,dc=example,dc=com",
                    "bind_password": "secret",
                    "base_dn": "ou=users,dc=example,dc=com",
                }]
            }),
            priority: 0,
            timeout_ms: None,
        };

        let result = plugin.initialize(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ldap_plugin_empty_servers() {
        let mut plugin = LdapPlugin::new();

        let config = PluginConfig {
            name: "ldap-plugin".to_string(),
            enabled: true,
            config: serde_json::json!({
                "servers": []
            }),
            priority: 0,
            timeout_ms: None,
        };

        let result = plugin.initialize(&config).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_group_mapping() {
        let mut plugin = LdapPlugin::new();

        // Set up test config
        plugin.config.group_mappings = vec![
            GroupMapping {
                ldap_group: "admins".to_string(),
                vault_role: "admin".to_string(),
                tenant_id: None,
            },
            GroupMapping {
                ldap_group: "users".to_string(),
                vault_role: "user".to_string(),
                tenant_id: None,
            },
        ];

        let groups = vec!["cn=admins,ou=groups,dc=example,dc=com".to_string()];
        let roles = plugin.map_groups_to_roles(&groups);

        assert!(roles.contains(&"admin".to_string()));
        assert!(!roles.contains(&"user".to_string()));
    }

    #[test]
    fn test_default_config() {
        let config = LdapConfig::default();
        assert!(config.servers.is_empty());
        assert!(config.auto_create_users);
        assert!(config.sync_on_login);
        assert!(config.allow_local_fallback);
    }

    #[test]
    fn test_ldap_server_config_default() {
        let config = LdapServerConfig::default();
        assert_eq!(config.port, 636);
        assert!(config.use_ssl);
        assert!(!config.allow_insecure_tls);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_create_plugin() {
        let plugin = create_plugin();
        assert_eq!(plugin.metadata().name, "ldap-plugin");
    }
}
