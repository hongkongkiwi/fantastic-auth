//! Example Vault Plugin
//!
//! This plugin demonstrates how to create custom Vault plugins.
//! It implements hooks for before_auth, after_auth, before_register,
//! and after_register, showing how to intercept and modify auth flows.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vault_core::plugin::types::{
    ApiContext, ApiRequest, ApiResponse, AuthAction, AuthContext, AuthResult,
    HookType, Plugin, PluginCapability, PluginConfig, PluginError, PluginMetadata,
    RegisterAction, RegisterContext, Route, PluginHealth,
};
use vault_core::models::user::User;

/// Example plugin configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExampleConfig {
    /// Whether to log all auth attempts
    pub log_auth: bool,
    /// Whether to add custom headers
    pub add_headers: bool,
    /// Custom attributes to add to users
    pub custom_attributes: HashMap<String, String>,
    /// Blocked email domains
    pub blocked_domains: Vec<String>,
}

impl Default for ExampleConfig {
    fn default() -> Self {
        Self {
            log_auth: true,
            add_headers: false,
            custom_attributes: HashMap::new(),
            blocked_domains: vec!["example.com".to_string()],
        }
    }
}

/// Example Plugin Implementation
pub struct ExamplePlugin {
    metadata: PluginMetadata,
    config: ExampleConfig,
    stats: std::sync::Mutex<PluginStats>,
}

#[derive(Debug, Default)]
struct PluginStats {
    auth_attempts: u64,
    registrations: u64,
}

impl ExamplePlugin {
    /// Create new example plugin
    pub fn new() -> Self {
        let metadata = PluginMetadata::new(
            "example-plugin",
            "1.0.0",
            "Vault Contributors",
            "Example plugin demonstrating Vault plugin API",
        )
        .with_hook(HookType::BeforeAuth)
        .with_hook(HookType::AfterAuth)
        .with_hook(HookType::BeforeRegister)
        .with_hook(HookType::AfterRegister)
        .with_capability(PluginCapability::AuthProvider)
        .with_capability(PluginCapability::AuditLogger);

        Self {
            metadata,
            config: ExampleConfig::default(),
            stats: std::sync::Mutex::new(PluginStats::default()),
        }
    }

    /// Check if email domain is blocked
    fn is_blocked_domain(&self, email: &str) -> bool {
        let domain = email.split('@').nth(1).unwrap_or("");
        self.config.blocked_domains.iter().any(|d| d == domain)
    }

    /// Log auth attempt
    fn log_auth_attempt(&self, ctx: &AuthContext, blocked: bool) {
        if self.config.log_auth {
            if blocked {
                tracing::warn!(
                    "[ExamplePlugin] BLOCKED auth attempt for {} from {:?}",
                    ctx.email,
                    ctx.ip_address
                );
            } else {
                tracing::info!(
                    "[ExamplePlugin] Auth attempt for {} from {:?}",
                    ctx.email,
                    ctx.ip_address
                );
            }
        }
    }
}

impl Default for ExamplePlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for ExamplePlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, config: &PluginConfig) -> Result<(), PluginError> {
        tracing::info!("Initializing ExamplePlugin");

        // Parse configuration
        self.config = serde_json::from_value(config.config.clone())
            .map_err(|e| PluginError::new("CONFIG_ERROR", format!("Invalid config: {}", e)))?;

        tracing::info!("ExamplePlugin initialized with config: {:?}", self.config);
        Ok(())
    }

    async fn before_auth(&self, ctx: &AuthContext) -> Result<AuthAction, PluginError> {
        tracing::debug!("ExamplePlugin before_auth hook called for {}", ctx.email);

        // Increment stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.auth_attempts += 1;
        }

        // Check for blocked domains
        if self.is_blocked_domain(&ctx.email) {
            self.log_auth_attempt(ctx, true);
            return Ok(AuthAction::Deny {
                reason: "Email domain is blocked".to_string(),
            });
        }

        self.log_auth_attempt(ctx, false);

        // Add custom metadata
        let mut changes = HashMap::new();
        changes.insert(
            "example_tracked".to_string(),
            serde_json::json!(true),
        );

        if self.config.add_headers {
            // In a real plugin, you might add custom headers here
            tracing::debug!("Would add custom headers for {}", ctx.email);
        }

        if changes.is_empty() {
            Ok(AuthAction::Allow)
        } else {
            Ok(AuthAction::Modify { changes })
        }
    }

    async fn after_auth(&self, ctx: &AuthContext, result: &AuthResult) -> Result<(), PluginError> {
        tracing::debug!("ExamplePlugin after_auth hook called for {}", ctx.email);

        if result.success {
            tracing::info!(
                "[ExamplePlugin] Successful authentication for user {:?}",
                result.user_id
            );
        } else {
            tracing::warn!(
                "[ExamplePlugin] Failed authentication for {}: {:?}",
                ctx.email,
                result.error
            );
        }

        Ok(())
    }

    async fn before_register(
        &self,
        ctx: &RegisterContext,
    ) -> Result<RegisterAction, PluginError> {
        tracing::debug!(
            "ExamplePlugin before_register hook called for {}",
            ctx.email
        );

        // Check for blocked domains
        if self.is_blocked_domain(&ctx.email) {
            return Ok(RegisterAction::Deny {
                reason: "Email domain is blocked".to_string(),
            });
        }

        // Add custom attributes if configured
        if !self.config.custom_attributes.is_empty() {
            let mut changes = HashMap::new();
            for (key, value) in &self.config.custom_attributes {
                changes.insert(key.clone(), serde_json::json!(value));
            }
            return Ok(RegisterAction::Modify { changes });
        }

        Ok(RegisterAction::Allow)
    }

    async fn after_register(
        &self,
        ctx: &RegisterContext,
        user: &User,
    ) -> Result<(), PluginError> {
        tracing::info!(
            "[ExamplePlugin] New user registered: {} ({}) in tenant {}",
            user.id,
            ctx.email,
            ctx.tenant_id
        );

        // Increment stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.registrations += 1;
        }

        Ok(())
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route::new(
                vault_core::plugin::types::HttpMethod::Get,
                "/stats",
                "get_stats",
            ),
            Route::new(
                vault_core::plugin::types::HttpMethod::Post,
                "/block-domain",
                "block_domain",
            )
            .with_permission("admin:plugins"),
        ]
    }

    async fn handle_request(
        &self,
        route: &str,
        request: ApiRequest,
    ) -> Result<ApiResponse, PluginError> {
        match route {
            "get_stats" => {
                let stats = self.stats.lock().unwrap();
                let body = serde_json::json!({
                    "auth_attempts": stats.auth_attempts,
                    "registrations": stats.registrations,
                    "config": self.config,
                });
                Ok(ApiResponse {
                    status: 200,
                    body,
                    headers: HashMap::new(),
                })
            }
            "block_domain" => {
                // Would add domain to blocked list
                Ok(ApiResponse {
                    status: 200,
                    body: serde_json::json!({
                        "message": "Domain blocked (not implemented in example)"
                    }),
                    headers: HashMap::new(),
                })
            }
            _ => Err(PluginError::new("NOT_FOUND", "Route not found")),
        }
    }

    async fn health_check(&self) -> PluginHealth {
        // This plugin is always healthy
        PluginHealth::Healthy
    }

    async fn shutdown(&self) -> Result<(), PluginError> {
        tracing::info!("ExamplePlugin shutting down");
        Ok(())
    }
}

/// Create plugin instance - called by the plugin loader
pub fn create_plugin() -> Box<dyn Plugin> {
    Box::new(ExamplePlugin::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_example_plugin_metadata() {
        let plugin = ExamplePlugin::new();
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "example-plugin");
        assert_eq!(metadata.version, "1.0.0");
        assert!(metadata.hooks.contains(&HookType::BeforeAuth));
        assert!(metadata.hooks.contains(&HookType::AfterAuth));
    }

    #[tokio::test]
    async fn test_before_auth_allows_valid_email() {
        let plugin = ExamplePlugin::new();
        let ctx = AuthContext::new("tenant_123", "user@valid.com");

        let result = plugin.before_auth(&ctx).await;
        assert!(matches!(result, Ok(AuthAction::Allow)));
    }

    #[tokio::test]
    async fn test_before_auth_blocks_blocked_domain() {
        let plugin = ExamplePlugin::new();
        let ctx = AuthContext::new("tenant_123", "user@example.com");

        let result = plugin.before_auth(&ctx).await;
        assert!(matches!(result, Ok(AuthAction::Deny { .. })));
    }

    #[tokio::test]
    async fn test_before_register_allows_valid_email() {
        let plugin = ExamplePlugin::new();
        let ctx = RegisterContext::new("tenant_123", "user@valid.com");

        let result = plugin.before_register(&ctx).await;
        assert!(matches!(result, Ok(RegisterAction::Allow)));
    }

    #[tokio::test]
    async fn test_is_blocked_domain() {
        let plugin = ExamplePlugin::new();
        assert!(plugin.is_blocked_domain("user@example.com"));
        assert!(!plugin.is_blocked_domain("user@other.com"));
    }

    #[test]
    fn test_example_config_default() {
        let config = ExampleConfig::default();
        assert!(config.log_auth);
        assert!(!config.add_headers);
        assert!(!config.blocked_domains.is_empty());
    }

    #[test]
    fn test_create_plugin() {
        let plugin = create_plugin();
        assert_eq!(plugin.metadata().name, "example-plugin");
    }
}
