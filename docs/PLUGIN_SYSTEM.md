# Vault Plugin System

The Vault Plugin System allows extending Vault functionality without modifying core code. It's inspired by SuperTokens' recipe system and Keycloak's SPI.

## Overview

Plugins can:
- Intercept and modify authentication flows
- Add custom API endpoints
- Implement custom authentication providers
- Sync with external directories
- Send webhooks and audit logs

## Plugin Types

### 1. Built-in Plugins
Native Rust code compiled into the Vault binary.

**Best for:**
- Core functionality extensions
- High-performance integrations
- Plugins that need deep system access

```rust
use vault_core::plugin::{Plugin, PluginMetadata};

pub struct MyPlugin;

#[async_trait]
impl Plugin for MyPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &METADATA
    }
    
    async fn initialize(&mut self, config: &PluginConfig) -> Result<(), PluginError> {
        // Initialize plugin
        Ok(())
    }
}
```

### 2. Native Plugins
Dynamic libraries (.so/.dll/.dylib) loaded at runtime.

**Best for:**
- Third-party integrations
- Platform-specific features
- Binary size optimization

### 3. WASM Plugins
WebAssembly modules running in a sandboxed environment.

**Best for:**
- Untrusted third-party code
- Multi-tenant environments
- Security-critical extensions

## Hook System

Plugins implement hooks that are called at specific points in the authentication flow:

### Authentication Hooks

| Hook | Description | Can Block? |
|------|-------------|------------|
| `before_auth` | Called before authentication attempt | Yes |
| `after_auth` | Called after authentication completes | No |
| `before_register` | Called before user registration | Yes |
| `after_register` | Called after successful registration | No |
| `before_logout` | Called before logout | Yes |
| `after_logout` | Called after logout | No |

### Example Hook Implementation

```rust
async fn before_auth(&self, ctx: &AuthContext) -> Result<AuthAction, PluginError> {
    // Check if email domain is blocked
    if ctx.email.ends_with("@blocked.com") {
        return Ok(AuthAction::Deny { 
            reason: "Domain is blocked".to_string() 
        });
    }
    
    // Add custom metadata
    let mut changes = HashMap::new();
    changes.insert("custom_field".to_string(), json!("value"));
    
    Ok(AuthAction::Modify { changes })
}
```

## Plugin Configuration

Plugins are configured in `config.yaml`:

```yaml
plugins:
  # Example plugin - demonstrates plugin API
  - name: "example-plugin"
    enabled: true
    priority: 10
    config:
      log_auth: true
      add_headers: false
      blocked_domains:
        - "example.com"
      
  # LDAP integration
  - name: "ldap-plugin"
    enabled: true
    config:
      servers:
        - host: "ldap.example.com"
          port: 636
          use_ssl: true
          bind_dn: "cn=admin,dc=example,dc=com"
          bind_password: "${LDAP_PASSWORD}"  # Use env var
          base_dn: "ou=users,dc=example,dc=com"
          user_filter: "(objectClass=person)"
      auto_create_users: true
      sync_on_login: true
      group_mappings:
        - ldap_group: "admins"
          vault_role: "admin"
        - ldap_group: "users"
          vault_role: "user"
  
  # Advanced webhooks
  - name: "webhook-plugin"
    enabled: true
    config:
      webhooks:
        - name: "audit-log"
          url: "https://example.com/webhooks/audit"
          events: ["user.login", "user.created"]
          secret: "${WEBHOOK_SECRET}"
          retry_policy:
            max_retries: 3
            backoff_secs: 1
          rate_limit:
            requests_per_second: 10
```

## Creating a Plugin

### Using the CLI

```bash
# Create a new built-in plugin
vault plugins create my-plugin --type builtin

# Create a native plugin
vault plugins create my-plugin --type native

# Create a WASM plugin
vault plugins create my-plugin --type wasm
```

### Manual Creation

1. Create a new directory in `plugins/`:
```bash
mkdir plugins/my-plugin
cd plugins/my-plugin
cargo init --lib
```

2. Update `Cargo.toml`:
```toml
[package]
name = "my-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
vault-core = { path = "../../vault-core" }
async-trait = "0.1"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

3. Implement the Plugin trait in `src/lib.rs`:
```rust
use vault_core::plugin::*;

pub struct MyPlugin {
    metadata: PluginMetadata,
}

#[async_trait]
impl Plugin for MyPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
    
    async fn initialize(&mut self, config: &PluginConfig) -> Result<(), PluginError> {
        Ok(())
    }
    
    async fn before_auth(&self, ctx: &AuthContext) -> Result<AuthAction, PluginError> {
        Ok(AuthAction::Allow)
    }
}

pub fn create_plugin() -> Box<dyn Plugin> {
    Box::new(MyPlugin::new())
}
```

## Plugin Capabilities

Plugins can declare capabilities to indicate what functionality they provide:

| Capability | Description |
|------------|-------------|
| `AuthProvider` | Custom authentication methods |
| `MfaProvider` | Custom MFA methods |
| `OAuthProvider` | Custom OAuth providers |
| `DirectorySync` | External directory synchronization |
| `WebhookSender` | Webhook delivery |
| `AuditLogger` | Custom audit logging |
| `PolicyEnforcer` | Custom policy enforcement |
| `RateLimiter` | Custom rate limiting |
| `RouteProvider` | Custom API endpoints |
| `UserTransformer` | User data transformation |

## Custom Routes

Plugins can add custom API endpoints:

```rust
fn routes(&self) -> Vec<Route> {
    vec![
        Route::new(HttpMethod::Get, "/status", "get_status")
            .with_permission("admin:plugins"),
        Route::new(HttpMethod::Post, "/sync", "trigger_sync")
            .with_permission("admin:plugins"),
    ]
}

async fn handle_request(
    &self,
    route: &str,
    request: ApiRequest,
) -> Result<ApiResponse, PluginError> {
    match route {
        "get_status" => {
            Ok(ApiResponse::ok(json!({ "status": "healthy" }))?)
        }
        _ => Err(PluginError::new("NOT_FOUND", "Route not found")),
    }
}
```

The routes will be available at `/api/v1/plugins/{plugin_name}/{route}`.

## Plugin Management

### CLI Commands

```bash
# List installed plugins
vault plugins list
vault plugins list --detailed

# Install a plugin
vault plugins install /path/to/plugin.wasm --name my-plugin

# Enable/disable plugins
vault plugins enable my-plugin
vault plugins disable my-plugin

# Show plugin details
vault plugins show my-plugin

# Check plugin health
vault plugins health
vault plugins health my-plugin

# Uninstall a plugin
vault plugins uninstall my-plugin

# Create a new plugin scaffold
vault plugins create my-plugin --type builtin
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/plugins` | List all plugins |
| POST | `/api/v1/admin/plugins` | Install plugin |
| GET | `/api/v1/admin/plugins/{name}` | Get plugin details |
| PUT | `/api/v1/admin/plugins/{name}` | Update plugin |
| DELETE | `/api/v1/admin/plugins/{name}` | Uninstall plugin |
| POST | `/api/v1/admin/plugins/{name}/enable` | Enable plugin |
| POST | `/api/v1/admin/plugins/{name}/disable` | Disable plugin |
| GET | `/api/v1/admin/plugins/{name}/health` | Check plugin health |
| POST | `/api/v1/admin/plugins/{name}/reload` | Reload plugin |

## Security Considerations

### WASM Plugins
- Run in a sandboxed environment
- Memory and CPU time limits
- No direct filesystem access
- Controlled host function access

### Native Plugins
- Run in the same process as Vault
- Full system access
- Review carefully before installation
- Use code signing for verification

### Built-in Plugins
- Compiled into the binary
- Most secure option
- Reviewed as part of the codebase

## Performance

### Hook Execution Order
Plugins are executed by priority (higher first). Multiple plugins can modify the same context.

### Timeouts
Hooks have a default timeout of 5 seconds. Configure per-plugin timeouts:

```yaml
plugins:
  - name: "slow-plugin"
    config:
      timeout_ms: 10000  # 10 seconds
```

### Resource Limits
WASM plugins can be configured with resource limits:

```rust
let limits = WasmResourceLimits::default()
    .with_max_memory(64 * 1024 * 1024)  // 64MB
    .with_max_execution_time(5000);     // 5 seconds
```

## Included Plugins

### Example Plugin (`plugins/example-plugin`)
Demonstrates the plugin API with:
- Hook implementations
- Custom routes
- Configuration handling
- Event logging

### LDAP Plugin (`plugins/ldap-plugin`)
LDAP/Active Directory integration:
- User authentication
- Attribute synchronization
- Group membership mapping
- Multiple server support

### Webhook Plugin (`plugins/webhook-plugin`)
Advanced webhook delivery:
- Event signing (HMAC-SHA256)
- Retry with exponential backoff
- Rate limiting
- Delivery status tracking

## Best Practices

1. **Error Handling**: Always return proper errors; don't panic
2. **Timeouts**: Respect timeout limits in hooks
3. **Logging**: Use structured logging with `tracing`
4. **Configuration**: Validate configuration on initialization
5. **Health Checks**: Implement meaningful health checks
6. **Documentation**: Document your plugin's hooks and routes
7. **Testing**: Write unit and integration tests

## Troubleshooting

### Plugin Not Loading
1. Check the plugin is enabled in configuration
2. Verify the plugin file exists and has correct permissions
3. Check logs for initialization errors

### Hook Not Firing
1. Verify the hook is registered in metadata
2. Check plugin priority (higher priority plugins run first)
3. Enable debug logging to see hook execution

### Performance Issues
1. Reduce hook complexity
2. Use async operations for I/O
3. Implement caching where appropriate
4. Monitor hook execution times
