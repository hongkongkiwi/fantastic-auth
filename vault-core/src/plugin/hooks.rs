//! Plugin hook execution system
//!
//! Provides utilities for invoking plugin hooks with proper error handling,
//! timeouts, and execution context management.

use super::registry::PluginRegistry;
use super::types::{
    AuthAction, AuthContext, AuthResult, HookType, PluginError, RegisterAction, RegisterContext,
};
use crate::models::user::User;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};

/// Hook execution context
#[derive(Debug, Clone)]
pub struct HookContext {
    /// Hook type being executed
    pub hook_type: HookType,
    /// Tenant ID
    pub tenant_id: String,
    /// Request ID for tracing
    pub request_id: String,
    /// Maximum execution time
    pub timeout: Duration,
    /// Whether to continue on error
    pub continue_on_error: bool,
}

impl HookContext {
    /// Create new hook context
    pub fn new(hook_type: HookType, tenant_id: impl Into<String>) -> Self {
        Self {
            hook_type,
            tenant_id: tenant_id.into(),
            request_id: generate_request_id(),
            timeout: Duration::from_secs(5),
            continue_on_error: false,
        }
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set continue on error
    pub fn with_continue_on_error(mut self, continue_on_error: bool) -> Self {
        self.continue_on_error = continue_on_error;
        self
    }
}

/// Generate a unique request ID
fn generate_request_id() -> String {
    use uuid::Uuid;
    Uuid::new_v4().to_string()
}

/// Hook executor for running plugin hooks
pub struct HookExecutor {
    registry: Arc<PluginRegistry>,
    default_timeout: Duration,
}

impl HookExecutor {
    /// Create new hook executor
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self {
            registry,
            default_timeout: Duration::from_secs(5),
        }
    }

    /// Set default timeout for hook execution
    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Execute before_auth hooks
    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id, email = %ctx.email))]
    pub async fn before_auth(&self, ctx: &AuthContext) -> Result<AuthAction, HookError> {
        debug!("Executing before_auth hooks");

        let hook_ctx = HookContext::new(HookType::BeforeAuth, &ctx.tenant_id)
            .with_timeout(self.default_timeout);

        let result = timeout(
            hook_ctx.timeout,
            self.registry.before_auth(ctx),
        )
        .await;

        match result {
            Ok(Ok(action)) => {
                debug!("before_auth hooks completed successfully");
                Ok(action)
            }
            Ok(Err(e)) => {
                warn!("before_auth hook failed: {}", e);
                Err(HookError::Plugin(e))
            }
            Err(_) => {
                error!("before_auth hooks timed out");
                Err(HookError::Timeout {
                    hook: "before_auth".to_string(),
                    timeout_ms: hook_ctx.timeout.as_millis() as u64,
                })
            }
        }
    }

    /// Execute after_auth hooks
    #[instrument(skip(self, ctx, result), fields(tenant_id = %ctx.tenant_id, success = result.success))]
    pub async fn after_auth(
        &self,
        ctx: &AuthContext,
        result: &AuthResult,
    ) -> Result<(), HookError> {
        debug!("Executing after_auth hooks");

        let hook_ctx = HookContext::new(HookType::AfterAuth, &ctx.tenant_id)
            .with_timeout(self.default_timeout)
            .with_continue_on_error(true);

        match timeout(
            hook_ctx.timeout,
            self.registry.after_auth(ctx, result),
        )
        .await
        {
            Ok(Ok(())) => {
                debug!("after_auth hooks completed");
                Ok(())
            }
            Ok(Err(e)) => {
                if hook_ctx.continue_on_error {
                    warn!("after_auth hook failed (ignored): {}", e);
                    Ok(())
                } else {
                    Err(HookError::Plugin(e))
                }
            }
            Err(_) => {
                if hook_ctx.continue_on_error {
                    warn!("after_auth hooks timed out (ignored)");
                    Ok(())
                } else {
                    Err(HookError::Timeout {
                        hook: "after_auth".to_string(),
                        timeout_ms: hook_ctx.timeout.as_millis() as u64,
                    })
                }
            }
        }
    }

    /// Execute before_register hooks
    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id, email = %ctx.email))]
    pub async fn before_register(&self, ctx: &RegisterContext) -> Result<RegisterAction, HookError> {
        debug!("Executing before_register hooks");

        let hook_ctx = HookContext::new(HookType::BeforeRegister, &ctx.tenant_id)
            .with_timeout(self.default_timeout);

        match timeout(
            hook_ctx.timeout,
            self.registry.before_register(ctx),
        )
        .await
        {
            Ok(Ok(action)) => {
                debug!("before_register hooks completed successfully");
                Ok(action)
            }
            Ok(Err(e)) => Err(HookError::Plugin(e)),
            Err(_) => Err(HookError::Timeout {
                hook: "before_register".to_string(),
                timeout_ms: hook_ctx.timeout.as_millis() as u64,
            }),
        }
    }

    /// Execute after_register hooks
    #[instrument(skip(self, ctx, user), fields(tenant_id = %ctx.tenant_id, user_id = %user.id))]
    pub async fn after_register(
        &self,
        ctx: &RegisterContext,
        user: &User,
    ) -> Result<(), HookError> {
        debug!("Executing after_register hooks");

        let hook_ctx = HookContext::new(HookType::AfterRegister, &ctx.tenant_id)
            .with_timeout(self.default_timeout)
            .with_continue_on_error(true);

        match timeout(
            hook_ctx.timeout,
            self.registry.after_register(ctx, user),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                if hook_ctx.continue_on_error {
                    warn!("after_register hook failed (ignored): {}", e);
                    Ok(())
                } else {
                    Err(HookError::Plugin(e))
                }
            }
            Err(_) => {
                if hook_ctx.continue_on_error {
                    warn!("after_register hooks timed out (ignored)");
                    Ok(())
                } else {
                    Err(HookError::Timeout {
                        hook: "after_register".to_string(),
                        timeout_ms: hook_ctx.timeout.as_millis() as u64,
                    })
                }
            }
        }
    }
}

/// Hook execution error
#[derive(Debug, Clone)]
pub enum HookError {
    /// Plugin error
    Plugin(PluginError),
    /// Hook timed out
    Timeout { hook: String, timeout_ms: u64 },
    /// Registry error
    Registry(String),
    /// Execution cancelled
    Cancelled,
}

impl std::fmt::Display for HookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookError::Plugin(e) => write!(f, "Plugin error: {}", e),
            HookError::Timeout { hook, timeout_ms } => {
                write!(f, "Hook '{}' timed out after {}ms", hook, timeout_ms)
            }
            HookError::Registry(msg) => write!(f, "Registry error: {}", msg),
            HookError::Cancelled => write!(f, "Hook execution cancelled"),
        }
    }
}

impl std::error::Error for HookError {}

impl From<PluginError> for HookError {
    fn from(e: PluginError) -> Self {
        HookError::Plugin(e)
    }
}

/// Middleware for integrating hooks into auth flows
pub struct PluginMiddleware {
    executor: HookExecutor,
}

impl PluginMiddleware {
    /// Create new plugin middleware
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self {
            executor: HookExecutor::new(registry),
        }
    }

    /// Create with custom default timeout
    pub fn with_timeout(registry: Arc<PluginRegistry>, timeout: Duration) -> Self {
        Self {
            executor: HookExecutor::new(registry).with_default_timeout(timeout),
        }
    }

    /// Get the underlying executor
    pub fn executor(&self) -> &HookExecutor {
        &self.executor
    }

    /// Wrap authentication - runs hooks before and after auth
    pub async fn wrap_authentication<F, Fut>(
        &self,
        ctx: &AuthContext,
        auth_fn: F,
    ) -> Result<AuthResult, AuthMiddlewareError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<AuthResult, crate::error::VaultError>>,
    {
        // Run before_auth hooks
        match self.executor.before_auth(ctx).await {
            Ok(AuthAction::Allow) => {
                // Continue with authentication
            }
            Ok(AuthAction::Deny { reason }) => {
                return Err(AuthMiddlewareError::DeniedByPlugin(reason));
            }
            Ok(action) => {
                debug!("before_auth returned non-allow action: {:?}", action);
                // Handle other actions (redirect, require verification, etc.)
                return Err(AuthMiddlewareError::ActionRequired(action));
            }
            Err(e) => {
                error!("before_auth hook error: {}", e);
                return Err(AuthMiddlewareError::HookError(e));
            }
        }

        // Execute authentication
        let auth_result = match auth_fn().await {
            Ok(result) => result,
            Err(e) => return Err(AuthMiddlewareError::AuthError(e)),
        };

        // Run after_auth hooks (fire and forget for success)
        if let Err(e) = self.executor.after_auth(ctx, &auth_result).await {
            warn!("after_auth hook error (ignored): {}", e);
        }

        Ok(auth_result)
    }

    /// Wrap registration - runs hooks before and after registration
    pub async fn wrap_registration<F, Fut>(
        &self,
        ctx: &RegisterContext,
        register_fn: F,
    ) -> Result<User, RegisterMiddlewareError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<User, crate::error::VaultError>>,
    {
        // Run before_register hooks
        match self.executor.before_register(ctx).await {
            Ok(RegisterAction::Allow) => {
                // Continue with registration
            }
            Ok(RegisterAction::Deny { reason }) => {
                return Err(RegisterMiddlewareError::DeniedByPlugin(reason));
            }
            Ok(action) => {
                debug!("before_register returned non-allow action: {:?}", action);
                return Err(RegisterMiddlewareError::ActionRequired(action));
            }
            Err(e) => {
                error!("before_register hook error: {}", e);
                return Err(RegisterMiddlewareError::HookError(e));
            }
        }

        // Execute registration
        let user = match register_fn().await {
            Ok(user) => user,
            Err(e) => return Err(RegisterMiddlewareError::RegisterError(e)),
        };

        // Run after_register hooks
        if let Err(e) = self.executor.after_register(ctx, &user).await {
            warn!("after_register hook error (ignored): {}", e);
        }

        Ok(user)
    }
}

/// Authentication middleware error
#[derive(Debug)]
pub enum AuthMiddlewareError {
    /// Denied by plugin
    DeniedByPlugin(String),
    /// Action required (redirect, verification, etc.)
    ActionRequired(AuthAction),
    /// Hook execution error
    HookError(HookError),
    /// Authentication error
    AuthError(crate::error::VaultError),
}

impl std::fmt::Display for AuthMiddlewareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMiddlewareError::DeniedByPlugin(reason) => {
                write!(f, "Authentication denied by plugin: {}", reason)
            }
            AuthMiddlewareError::ActionRequired(action) => {
                write!(f, "Authentication action required: {:?}", action)
            }
            AuthMiddlewareError::HookError(e) => write!(f, "Hook error: {}", e),
            AuthMiddlewareError::AuthError(e) => write!(f, "Auth error: {}", e),
        }
    }
}

impl std::error::Error for AuthMiddlewareError {}

impl From<crate::error::VaultError> for AuthMiddlewareError {
    fn from(e: crate::error::VaultError) -> Self {
        AuthMiddlewareError::AuthError(e)
    }
}

/// Registration middleware error
#[derive(Debug)]
pub enum RegisterMiddlewareError {
    /// Denied by plugin
    DeniedByPlugin(String),
    /// Action required
    ActionRequired(RegisterAction),
    /// Hook execution error
    HookError(HookError),
    /// Registration error
    RegisterError(crate::error::VaultError),
}

impl std::fmt::Display for RegisterMiddlewareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterMiddlewareError::DeniedByPlugin(reason) => {
                write!(f, "Registration denied by plugin: {}", reason)
            }
            RegisterMiddlewareError::ActionRequired(action) => {
                write!(f, "Registration action required: {:?}", action)
            }
            RegisterMiddlewareError::HookError(e) => write!(f, "Hook error: {}", e),
            RegisterMiddlewareError::RegisterError(e) => write!(f, "Register error: {}", e),
        }
    }
}

impl std::error::Error for RegisterMiddlewareError {}

impl From<crate::error::VaultError> for RegisterMiddlewareError {
    fn from(e: crate::error::VaultError) -> Self {
        RegisterMiddlewareError::RegisterError(e)
    }
}

/// Metrics for hook execution
#[derive(Debug, Clone, Default)]
pub struct HookMetrics {
    /// Total hook executions
    pub total_executions: u64,
    /// Successful executions
    pub successful: u64,
    /// Failed executions
    pub failed: u64,
    /// Timed out executions
    pub timed_out: u64,
    /// Average execution time (ms)
    pub avg_execution_time_ms: f64,
    /// Total execution time (ms)
    pub total_execution_time_ms: u64,
}

/// Hook metrics collector
pub struct HookMetricsCollector {
    metrics: std::sync::Mutex<HookMetrics>,
}

impl HookMetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Self {
        Self {
            metrics: std::sync::Mutex::new(HookMetrics::default()),
        }
    }

    /// Record hook execution
    pub fn record(&self, success: bool, timed_out: bool, duration_ms: f64) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.total_executions += 1;

        if timed_out {
            metrics.timed_out += 1;
        } else if success {
            metrics.successful += 1;
        } else {
            metrics.failed += 1;
        }

        // Update rolling average
        let count = metrics.total_executions as f64;
        metrics.avg_execution_time_ms =
            (metrics.avg_execution_time_ms * (count - 1.0) + duration_ms) / count;
        metrics.total_execution_time_ms += duration_ms as u64;
    }

    /// Get current metrics
    pub fn get_metrics(&self) -> HookMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Reset metrics
    pub fn reset(&self) {
        *self.metrics.lock().unwrap() = HookMetrics::default();
    }
}

impl Default for HookMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_context() {
        let ctx = HookContext::new(HookType::BeforeAuth, "tenant_123");
        assert_eq!(ctx.hook_type, HookType::BeforeAuth);
        assert_eq!(ctx.tenant_id, "tenant_123");
        assert!(!ctx.request_id.is_empty());
    }

    #[test]
    fn test_hook_context_builder() {
        let ctx = HookContext::new(HookType::AfterAuth, "tenant_123")
            .with_timeout(Duration::from_secs(10))
            .with_continue_on_error(true);

        assert_eq!(ctx.timeout, Duration::from_secs(10));
        assert!(ctx.continue_on_error);
    }

    #[test]
    fn test_hook_error_display() {
        let error = HookError::Timeout {
            hook: "before_auth".to_string(),
            timeout_ms: 5000,
        };
        assert_eq!(
            error.to_string(),
            "Hook 'before_auth' timed out after 5000ms"
        );
    }

    #[test]
    fn test_hook_metrics() {
        let collector = HookMetricsCollector::new();
        collector.record(true, false, 100.0);
        collector.record(true, false, 200.0);
        collector.record(false, false, 50.0);

        let metrics = collector.get_metrics();
        assert_eq!(metrics.total_executions, 3);
        assert_eq!(metrics.successful, 2);
        assert_eq!(metrics.failed, 1);
        assert!((metrics.avg_execution_time_ms - 116.67).abs() < 1.0);
    }

    #[tokio::test]
    async fn test_hook_executor_creation() {
        let registry = PluginRegistry::new_shared();
        let executor = HookExecutor::new(registry);
        assert_eq!(executor.default_timeout, Duration::from_secs(5));
    }
}
