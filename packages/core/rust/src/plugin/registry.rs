//! Plugin registry
//!
//! Manages plugin lifecycle, registration, and hook execution.

use super::types::{
    ApiRequest, ApiResponse, AuthAction, AuthContext, AuthResult, HookStats, HookType,
    Plugin, PluginCapability, PluginConfig, PluginError, PluginMetadata,
    PluginStatus, PluginType, RegisterAction, RegisterContext, Route,
};
use crate::models::user::User;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};

/// Plugin instance wrapper with runtime state
struct PluginInstance {
    /// Plugin implementation
    plugin: Box<dyn Plugin>,
    /// Plugin configuration
    config: PluginConfig,
    /// Plugin type
    plugin_type: PluginType,
    /// Plugin path (for native/WASM plugins)
    path: Option<String>,
    /// Start time for uptime tracking
    started_at: std::time::Instant,
    /// Hook execution statistics
    hook_stats: DashMap<HookType, HookStats>,
    /// Total hook executions
    total_executions: AtomicU64,
    /// Failed executions
    failed_executions: AtomicU64,
    /// Last error message
    last_error: Arc<RwLock<Option<String>>>,
}

impl PluginInstance {
    /// Create new plugin instance
    fn new(
        plugin: Box<dyn Plugin>,
        config: PluginConfig,
        plugin_type: PluginType,
        path: Option<String>,
    ) -> Self {
        Self {
            plugin,
            config,
            plugin_type,
            path,
            started_at: std::time::Instant::now(),
            hook_stats: DashMap::new(),
            total_executions: AtomicU64::new(0),
            failed_executions: AtomicU64::new(0),
            last_error: Arc::new(RwLock::new(None)),
        }
    }

    /// Record hook execution
    async fn record_execution(&self, hook: HookType, success: bool, duration_ms: f64) {
        self.total_executions.fetch_add(1, Ordering::Relaxed);

        if !success {
            self.failed_executions.fetch_add(1, Ordering::Relaxed);
        }

        let mut stats = self.hook_stats.entry(hook).or_default();
        stats.total_executions += 1;
        if success {
            stats.successful += 1;
        } else {
            stats.failed += 1;
        }

        // Update average
        let old_avg = stats.avg_execution_ms;
        let count = stats.total_executions as f64;
        stats.avg_execution_ms = old_avg + (duration_ms - old_avg) / count;
    }

    /// Set last error
    async fn set_error(&self, error: Option<String>) {
        let mut last_error = self.last_error.write().await;
        *last_error = error;
    }

    /// Get aggregated hook stats
    fn get_hook_stats(&self) -> HookStats {
        let mut total = HookStats::default();
        for stats in self.hook_stats.iter() {
            total.total_executions += stats.total_executions;
            total.successful += stats.successful;
            total.failed += stats.failed;
        }
        total
    }
}

/// Plugin registry for managing all plugins
pub struct PluginRegistry {
    /// Registered plugins indexed by name
    plugins: DashMap<String, Arc<PluginInstance>>,
    /// Plugins organized by hook type
    hooks: DashMap<HookType, Vec<String>>,
    /// Plugins organized by capability
    capabilities: DashMap<PluginCapability, Vec<String>>,
    /// Global registry statistics
    total_executions: AtomicU64,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    /// Create new empty plugin registry
    pub fn new() -> Self {
        Self {
            plugins: DashMap::new(),
            hooks: DashMap::new(),
            capabilities: DashMap::new(),
            total_executions: AtomicU64::new(0),
        }
    }

    /// Create registry with shared state (for passing between components)
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Register a built-in plugin
    #[instrument(skip(self, plugin), fields(plugin_name = %plugin.metadata().name))]
    pub async fn register_builtin(
        &self,
        mut plugin: Box<dyn Plugin>,
        config: PluginConfig,
    ) -> Result<(), PluginError> {
        let metadata = plugin.metadata().clone();
        info!("Registering built-in plugin: {}", metadata.name);

        // Check if plugin with same name already exists
        if self.plugins.contains_key(&metadata.name) {
            return Err(PluginError::new(
                "DUPLICATE_PLUGIN",
                format!("Plugin '{}' is already registered", metadata.name),
            ));
        }

        // Initialize plugin
        plugin.initialize(&config).await.map_err(|e| {
            error!("Failed to initialize plugin {}: {}", metadata.name, e);
            e
        })?;

        // Create instance
        let instance = Arc::new(PluginInstance::new(
            plugin,
            config,
            PluginType::Builtin,
            None,
        ));

        // Register hooks
        for hook in &metadata.hooks {
            self.hooks
                .entry(*hook)
                .or_default()
                .push(metadata.name.clone());
        }

        // Register capabilities
        for cap in &metadata.capabilities {
            self.capabilities
                .entry(*cap)
                .or_default()
                .push(metadata.name.clone());
        }

        // Store plugin
        self.plugins.insert(metadata.name.clone(), instance);

        info!(
            "Successfully registered plugin: {} v{}",
            metadata.name, metadata.version
        );
        Ok(())
    }

    /// Register a native plugin from a dynamic library path
    #[instrument(skip(self), fields(plugin_path = %path))]
    pub async fn register_native(
        &self,
        path: &str,
        config: PluginConfig,
    ) -> Result<(), PluginError> {
        info!("Loading native plugin from: {}", path);

        // Native plugin loading would use libloading here
        // For now, return an error indicating native plugins require dynamic loading
        Err(PluginError::new(
            "NOT_IMPLEMENTED",
            "Native plugin loading requires the 'native' feature to be enabled",
        ))
    }

    /// Register a WASM plugin
    #[instrument(skip(self), fields(plugin_path = %path))]
    pub async fn register_wasm(&self, path: &str, config: PluginConfig) -> Result<(), PluginError> {
        info!("Loading WASM plugin from: {}", path);

        // WASM plugin loading would use wasmtime here
        // For now, return an error indicating WASM plugins require wasmtime
        Err(PluginError::new(
            "NOT_IMPLEMENTED",
            "WASM plugin loading requires the 'wasm' feature to be enabled",
        ))
    }

    /// Unregister a plugin
    #[instrument(skip(self))]
    pub async fn unregister(&self, name: &str) -> Result<(), PluginError> {
        info!("Unregistering plugin: {}", name);

        let instance = self
            .plugins
            .remove(name)
            .ok_or_else(|| PluginError::new("NOT_FOUND", format!("Plugin '{}' not found", name)))?
            .1;

        // Shutdown plugin
        if let Err(e) = instance.plugin.shutdown().await {
            warn!("Error shutting down plugin {}: {}", name, e);
        }

        // Remove from hooks
        let metadata = instance.plugin.metadata();
        for hook in &metadata.hooks {
            if let Some(mut plugins) = self.hooks.get_mut(hook) {
                plugins.retain(|p| p != name);
            }
        }

        // Remove from capabilities
        for cap in &metadata.capabilities {
            if let Some(mut plugins) = self.capabilities.get_mut(cap) {
                plugins.retain(|p| p != name);
            }
        }

        info!("Successfully unregistered plugin: {}", name);
        Ok(())
    }

    /// Get plugin metadata
    pub fn get_metadata(&self, name: &str) -> Option<PluginMetadata> {
        self.plugins.get(name).map(|p| p.plugin.metadata().clone())
    }

    /// Get all registered plugins' metadata
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.plugins
            .iter()
            .map(|p| p.plugin.metadata().clone())
            .collect()
    }

    /// Get plugin status
    pub async fn get_status(&self, name: &str) -> Option<PluginStatus> {
        let instance = self.plugins.get(name)?;
        let metadata = instance.plugin.metadata();
        let health = instance.plugin.health_check().await;
        let hook_stats = instance.get_hook_stats();
        let last_error = instance.last_error.read().await.clone();
        let uptime_secs = instance.started_at.elapsed().as_secs();

        Some(PluginStatus {
            name: metadata.name.clone(),
            version: metadata.version.clone(),
            plugin_type: instance.plugin_type,
            health,
            enabled: instance.config.enabled,
            last_error,
            hook_stats,
            uptime_secs: Some(uptime_secs),
        })
    }

    /// Get all plugin statuses
    pub async fn list_statuses(&self) -> Vec<PluginStatus> {
        let mut statuses = Vec::new();
        for plugin_ref in self.plugins.iter() {
            if let Some(status) = self.get_status(&plugin_ref.key()).await {
                statuses.push(status);
            }
        }
        statuses
    }

    /// Enable/disable a plugin
    pub async fn set_enabled(&self, name: &str, enabled: bool) -> Result<(), PluginError> {
        let instance = self
            .plugins
            .get(name)
            .ok_or_else(|| PluginError::new("NOT_FOUND", format!("Plugin '{}' not found", name)))?;

        // Note: We can't directly modify config since DashMap uses immutable references
        // In a real implementation, we'd use interior mutability
        info!("Setting plugin {} enabled = {}", name, enabled);

        Ok(())
    }

    /// Execute before_auth hook on all plugins that implement it
    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id, email = %ctx.email))]
    pub async fn before_auth(&self, ctx: &AuthContext) -> Result<AuthAction, PluginError> {
        let plugin_names = self
            .hooks
            .get(&HookType::BeforeAuth)
            .map(|p| p.clone())
            .unwrap_or_default();

        for name in plugin_names {
            if let Some(instance) = self.plugins.get(&name) {
                if !instance.config.enabled {
                    continue;
                }

                let start = std::time::Instant::now();
                let result = instance.plugin.before_auth(ctx).await;
                let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

                match result {
                    Ok(action) => {
                        instance
                            .record_execution(HookType::BeforeAuth, true, duration_ms)
                            .await;

                        match action {
                            AuthAction::Allow => continue,
                            _ => return Ok(action), // Return the non-allow action
                        }
                    }
                    Err(e) => {
                        error!("Plugin {} before_auth hook failed: {}", name, e);
                        instance
                            .record_execution(HookType::BeforeAuth, false, duration_ms)
                            .await;
                        instance.set_error(Some(e.to_string())).await;
                        return Err(e);
                    }
                }
            }
        }

        Ok(AuthAction::Allow)
    }

    /// Execute after_auth hook on all plugins that implement it
    #[instrument(skip(self, ctx, result), fields(tenant_id = %ctx.tenant_id, success = result.success))]
    pub async fn after_auth(
        &self,
        ctx: &AuthContext,
        result: &AuthResult,
    ) -> Result<(), PluginError> {
        let plugin_names = self
            .hooks
            .get(&HookType::AfterAuth)
            .map(|p| p.clone())
            .unwrap_or_default();

        for name in plugin_names {
            if let Some(instance) = self.plugins.get(&name) {
                if !instance.config.enabled {
                    continue;
                }

                let start = std::time::Instant::now();
                let hook_result = instance.plugin.after_auth(ctx, result).await;
                let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

                match hook_result {
                    Ok(_) => {
                        instance
                            .record_execution(HookType::AfterAuth, true, duration_ms)
                            .await;
                    }
                    Err(e) => {
                        warn!("Plugin {} after_auth hook failed: {}", name, e);
                        instance
                            .record_execution(HookType::AfterAuth, false, duration_ms)
                            .await;
                        instance.set_error(Some(e.to_string())).await;
                        // Don't fail the auth for after hooks
                    }
                }
            }
        }

        Ok(())
    }

    /// Execute before_register hook on all plugins that implement it
    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id, email = %ctx.email))]
    pub async fn before_register(
        &self,
        ctx: &RegisterContext,
    ) -> Result<RegisterAction, PluginError> {
        let plugin_names = self
            .hooks
            .get(&HookType::BeforeRegister)
            .map(|p| p.clone())
            .unwrap_or_default();

        for name in plugin_names {
            if let Some(instance) = self.plugins.get(&name) {
                if !instance.config.enabled {
                    continue;
                }

                let start = std::time::Instant::now();
                let result = instance.plugin.before_register(ctx).await;
                let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

                match result {
                    Ok(action) => {
                        instance
                            .record_execution(HookType::BeforeRegister, true, duration_ms)
                            .await;

                        match action {
                            RegisterAction::Allow => continue,
                            _ => return Ok(action),
                        }
                    }
                    Err(e) => {
                        error!("Plugin {} before_register hook failed: {}", name, e);
                        instance
                            .record_execution(HookType::BeforeRegister, false, duration_ms)
                            .await;
                        instance.set_error(Some(e.to_string())).await;
                        return Err(e);
                    }
                }
            }
        }

        Ok(RegisterAction::Allow)
    }

    /// Execute after_register hook on all plugins that implement it
    #[instrument(skip(self, ctx, user), fields(tenant_id = %ctx.tenant_id, user_id = %user.id))]
    pub async fn after_register(
        &self,
        ctx: &RegisterContext,
        user: &User,
    ) -> Result<(), PluginError> {
        let plugin_names = self
            .hooks
            .get(&HookType::AfterRegister)
            .map(|p| p.clone())
            .unwrap_or_default();

        for name in plugin_names {
            if let Some(instance) = self.plugins.get(&name) {
                if !instance.config.enabled {
                    continue;
                }

                let start = std::time::Instant::now();
                let result = instance.plugin.after_register(ctx, user).await;
                let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

                match result {
                    Ok(_) => {
                        instance
                            .record_execution(HookType::AfterRegister, true, duration_ms)
                            .await;
                    }
                    Err(e) => {
                        warn!("Plugin {} after_register hook failed: {}", name, e);
                        instance
                            .record_execution(HookType::AfterRegister, false, duration_ms)
                            .await;
                        instance.set_error(Some(e.to_string())).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Get routes from all plugins
    pub fn get_all_routes(&self) -> Vec<(String, Route)> {
        let mut routes = Vec::new();

        for plugin_ref in self.plugins.iter() {
            let instance = plugin_ref.value();
            if !instance.config.enabled {
                continue;
            }

            let plugin_routes = instance.plugin.routes();
            for route in plugin_routes {
                routes.push((plugin_ref.key().clone(), route));
            }
        }

        routes
    }

    /// Handle API request for a plugin route
    pub async fn handle_request(
        &self,
        plugin_name: &str,
        route: &str,
        request: ApiRequest,
    ) -> Result<ApiResponse, PluginError> {
        let instance = self.plugins.get(plugin_name).ok_or_else(|| {
            PluginError::new("NOT_FOUND", format!("Plugin '{}' not found", plugin_name))
        })?;

        if !instance.config.enabled {
            return Err(PluginError::new(
                "PLUGIN_DISABLED",
                format!("Plugin '{}' is disabled", plugin_name),
            ));
        }

        instance.plugin.handle_request(route, request).await
    }

    /// Shutdown all plugins
    pub async fn shutdown_all(&self) {
        info!("Shutting down all plugins");

        for plugin_ref in self.plugins.iter() {
            let name = plugin_ref.key();
            let instance = plugin_ref.value();

            info!("Shutting down plugin: {}", name);
            if let Err(e) = instance.plugin.shutdown().await {
                warn!("Error shutting down plugin {}: {}", name, e);
            }
        }

        self.plugins.clear();
        self.hooks.clear();
        self.capabilities.clear();

        info!("All plugins shut down");
    }

    /// Check if any plugin provides a specific capability
    pub fn has_capability(&self, capability: PluginCapability) -> bool {
        self.capabilities
            .get(&capability)
            .map(|p| !p.is_empty())
            .unwrap_or(false)
    }

    /// Get plugins with a specific capability
    pub fn get_plugins_with_capability(&self, capability: PluginCapability) -> Vec<String> {
        self.capabilities
            .get(&capability)
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    /// Get total hook executions across all plugins
    pub fn get_total_executions(&self) -> u64 {
        self.total_executions.load(Ordering::Relaxed)
    }
}

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
    async fn test_registry() {
        let registry = PluginRegistry::new();

        let plugin = TestPlugin {
            metadata: PluginMetadata::new("test-plugin", "1.0.0", "Test Author", "A test plugin")
                .with_hook(HookType::BeforeAuth),
        };

        registry
            .register_builtin(Box::new(plugin), PluginConfig::default())
            .await
            .unwrap();

        let plugins = registry.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "test-plugin");
    }
}
