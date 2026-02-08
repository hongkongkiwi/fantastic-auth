//! Vault Plugin System
//!
//! A flexible plugin system for extending Vault functionality without
//! modifying core code. Similar to SuperTokens' recipe system or Keycloak's SPI.
//!
//! ## Features
//!
//! - **Built-in Plugins**: Native Rust plugins compiled into the binary
//! - **Native Plugins**: Dynamic libraries (.so/.dll/.dylib) loaded at runtime
//! - **WASM Plugins**: Sandboxed WebAssembly modules for security
//! - **Hook System**: Intercept and modify auth flows at key points
//! - **Custom Routes**: Add custom API endpoints via plugins
//! - **Health Monitoring**: Track plugin health and performance
//!
//! ## Example Usage
//!
//! ```rust
//! use vault_core::plugin::{PluginRegistry, PluginConfig};
//! use vault_core::plugin::types::{Plugin, PluginMetadata, HookType};
//!
//! // Create registry
//! let registry = PluginRegistry::new_shared();
//!
//! // Register a built-in plugin
//! let mut plugin = MyCustomPlugin::new();
//! registry.register_builtin(
//!     Box::new(plugin),
//!     PluginConfig::default()
//! ).await.unwrap();
//!
//! // Execute hooks
//! let action = registry.before_auth(&auth_context).await.unwrap();
//! ```
//!
//! ## Plugin Types
//!
//! ### Built-in Plugins
//! Native Rust code compiled into the Vault binary. Best for:
//! - Core functionality extensions
//! - High-performance integrations
//! - Plugins that need deep system access
//!
//! ### Native Plugins
//! Dynamic libraries loaded at runtime. Best for:
//! - Third-party integrations
//! - Platform-specific features
//! - Binary size optimization
//!
//! ### WASM Plugins
//! WebAssembly modules running in a sandbox. Best for:
//! - Untrusted third-party code
//! - Multi-tenant environments
//! - Security-critical extensions

#![warn(missing_docs)]

pub mod hooks;
pub mod loader;
pub mod registry;
pub mod types;
pub mod wasm;

// Re-export main types for convenience
pub use hooks::{HookContext, HookError, HookExecutor, PluginMiddleware};
pub use loader::{
    load_plugins_from_config, DiscoveredPlugin, LoadResult, LoaderConfig, PluginConfigEntry,
    PluginLoader, PluginManifest, PluginSettings, PluginsConfig,
};
pub use registry::PluginRegistry;
pub use types::{
    ApiContext, ApiRequest, ApiResponse, AuthAction, AuthContext, AuthResult, HookStats, HookType,
    HttpMethod, Plugin, PluginCapability, PluginConfig, PluginError, PluginHealth,
    PluginMetadata, PluginResult, PluginStatus, PluginType, RegisterAction, RegisterContext, Route,
};
pub use wasm::{WasmPlugin, WasmPluginBuilder, WasmPluginConfig, WasmResourceLimits};

use std::sync::Arc;

/// Plugin manager - high-level API for managing plugins
pub struct PluginManager {
    /// Plugin registry
    pub registry: Arc<PluginRegistry>,
    /// Hook executor
    pub hooks: HookExecutor,
    /// Plugin loader
    pub loader: Option<PluginLoader>,
}

impl PluginManager {
    /// Create new plugin manager
    pub fn new() -> Self {
        let registry = PluginRegistry::new_shared();
        let hooks = HookExecutor::new(registry.clone());

        Self {
            registry,
            hooks,
            loader: None,
        }
    }

    /// Create with plugin directory
    pub fn with_plugin_dir(plugin_dir: impl AsRef<std::path::Path>) -> Self {
        let mut manager = Self::new();
        manager.loader = Some(PluginLoader::new(LoaderConfig::new(plugin_dir)));
        manager
    }

    /// Initialize with configuration
    pub async fn initialize(&mut self, config: &PluginsConfig) -> Result<LoadResult, PluginError> {
        // Set up loader if plugin directory configured
        if let Some(ref settings) = config.settings {
            if let Some(ref dir) = settings.directory {
                self.loader = Some(PluginLoader::new(LoaderConfig::new(dir)));
            }
        }

        // Load plugins from config
        load_plugins_from_config(&self.registry, config).await
    }

    /// Load and auto-discover plugins from directory
    pub async fn auto_load(&self) -> Result<LoadResult, PluginError> {
        let loader = self.loader.as_ref().ok_or_else(|| {
            PluginError::new("NO_LOADER", "Plugin loader not configured")
        })?;

        let configs = std::collections::HashMap::new();
        loader.load_all(&self.registry, &configs).await
    }

    /// Get middleware for integrating with auth flows
    pub fn middleware(&self) -> PluginMiddleware {
        PluginMiddleware::new(self.registry.clone())
    }

    /// Shutdown all plugins
    pub async fn shutdown(&self) {
        self.registry.shutdown_all().await;
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience error type alias
pub type Error = PluginError;

/// Convenience result type alias
pub type Result<T> = std::result::Result<T, Error>;

/// Version of the plugin API
pub const API_VERSION: &str = "1.0.0";

/// Minimum compatible Vault version for plugins
pub const MIN_VAULT_VERSION: &str = "0.1.0";

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct TestPlugin {
        metadata: PluginMetadata,
    }

    #[async_trait]
    impl Plugin for TestPlugin {
        fn metadata(&self) -> &PluginMetadata {
            &self.metadata
        }

        async fn initialize(&mut self, _config: &PluginConfig) -> Result<(), PluginError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_plugin_manager() {
        let manager = PluginManager::new();

        // Register a test plugin
        let plugin = TestPlugin {
            metadata: PluginMetadata::new(
                "test",
                "1.0.0",
                "Test",
                "Test plugin",
            ),
        };

        manager
            .registry
            .register_builtin(Box::new(plugin), PluginConfig::default())
            .await
            .unwrap();

        let plugins = manager.registry.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "test");
    }

    #[test]
    fn test_api_version() {
        assert!(!API_VERSION.is_empty());
        assert!(!MIN_VAULT_VERSION.is_empty());
    }
}
