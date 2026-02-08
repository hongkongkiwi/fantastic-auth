//! Plugin management commands for the Vault CLI

use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Plugin management commands
#[derive(Parser, Debug)]
pub struct PluginArgs {
    #[command(subcommand)]
    pub command: PluginCommands,
}

#[derive(Subcommand, Debug)]
pub enum PluginCommands {
    /// List all installed plugins
    List {
        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
        /// Filter by status
        #[arg(short, long)]
        filter: Option<PluginStatusFilter>,
    },
    /// Install a plugin
    Install {
        /// Path to plugin file or directory
        path: PathBuf,
        /// Plugin name (optional, derived from path if not provided)
        #[arg(short, long)]
        name: Option<String>,
        /// Enable plugin immediately
        #[arg(short, long)]
        enable: bool,
        /// Plugin configuration as JSON
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Uninstall a plugin
    Uninstall {
        /// Plugin name
        name: String,
        /// Force uninstall even if plugin is enabled
        #[arg(short, long)]
        force: bool,
    },
    /// Enable a plugin
    Enable {
        /// Plugin name
        name: String,
    },
    /// Disable a plugin
    Disable {
        /// Plugin name
        name: String,
    },
    /// Show plugin details
    Show {
        /// Plugin name
        name: String,
    },
    /// Configure a plugin
    Config {
        /// Plugin name
        name: String,
        /// Configuration key-value pairs (key=value)
        #[arg(short, long = "set")]
        set_values: Vec<String>,
        /// Remove a configuration key
        #[arg(short, long)]
        remove: Vec<String>,
        /// Show current configuration
        #[arg(short, long)]
        show: bool,
    },
    /// Check plugin health
    Health {
        /// Plugin name (if not provided, checks all plugins)
        name: Option<String>,
    },
    /// Reload a plugin
    Reload {
        /// Plugin name
        name: String,
    },
    /// Get plugin logs
    Logs {
        /// Plugin name
        name: String,
        /// Number of lines to show
        #[arg(short, long, default_value = "100")]
        lines: usize,
        /// Follow log output
        #[arg(short, long)]
        follow: bool,
    },
    /// Discover available plugins in the plugin directory
    Discover {
        /// Path to plugin directory (default: ./plugins)
        #[arg(short, long)]
        path: Option<PathBuf>,
    },
    /// Create a new plugin scaffold
    Create {
        /// Plugin name
        name: String,
        /// Plugin type
        #[arg(short, long, default_value = "builtin")]
        plugin_type: PluginTypeArg,
        /// Output directory
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Plugin description
        #[arg(short, long)]
        description: Option<String>,
        /// Author name
        #[arg(short, long)]
        author: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PluginStatusFilter {
    Enabled,
    Disabled,
    Healthy,
    Unhealthy,
    Native,
    Wasm,
    Builtin,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PluginTypeArg {
    Native,
    Wasm,
    Builtin,
}

/// Plugin information returned by the API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub plugin_type: String,
    pub enabled: bool,
    pub health: String,
    pub hooks: Vec<String>,
    pub capabilities: Vec<String>,
}

/// Plugin status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginStatus {
    pub name: String,
    pub version: String,
    pub plugin_type: String,
    pub health: String,
    pub enabled: bool,
    pub uptime_secs: Option<u64>,
    pub stats: PluginStats,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginStats {
    pub total_executions: u64,
    pub successful: u64,
    pub failed: u64,
    pub avg_execution_ms: f64,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfiguration {
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub config: serde_json::Value,
}

/// CLI output formatter for plugins
pub struct PluginFormatter;

impl PluginFormatter {
    /// Format plugin list as table
    pub fn format_list(plugins: &[PluginInfo], detailed: bool) -> String {
        use comfy_table::{Table, Column};
        use comfy_table::modifiers::UTF8_ROUND_CORNERS;
        use comfy_table::presets::UTF8_FULL;

        let mut table = Table::new();
        table.set_header(vec!["Name", "Version", "Type", "Status", "Health"]);
        table.apply_modifier(UTF8_ROUND_CORNERS);
        table.load_preset(UTF8_FULL);

        for plugin in plugins {
            let status = if plugin.enabled {
                "✓ enabled"
            } else {
                "✗ disabled"
            };

            let health_indicator = match plugin.health.as_str() {
                "healthy" => "● healthy",
                "degraded" => "◐ degraded",
                "unhealthy" => "○ unhealthy",
                _ => "? unknown",
            };

            table.add_row(vec![
                &plugin.name,
                &plugin.version,
                &plugin.plugin_type,
                status,
                health_indicator,
            ]);

            if detailed {
                table.add_row(vec![
                    "",
                    &format!("Author: {}", plugin.author),
                    "",
                    "",
                    "",
                ]);
                table.add_row(vec![
                    "",
                    &format!("Description: {}", plugin.description),
                    "",
                    "",
                    "",
                ]);
                table.add_row(vec![
                    "",
                    &format!("Hooks: {}", plugin.hooks.join(", ")),
                    "",
                    "",
                    "",
                ]);
                table.add_row(vec![
                    "",
                    &format!("Capabilities: {}", plugin.capabilities.join(", ")),
                    "",
                    "",
                    "",
                ]);
            }
        }

        table.to_string()
    }

    /// Format plugin status
    pub fn format_status(status: &PluginStatus) -> String {
        let mut output = String::new();

        output.push_str(&format!("Name:        {}\n", status.name));
        output.push_str(&format!("Version:     {}\n", status.version));
        output.push_str(&format!("Type:        {}\n", status.plugin_type));
        output.push_str(&format!("Health:      {}\n", status.health));
        output.push_str(&format!("Enabled:     {}\n", status.enabled));

        if let Some(uptime) = status.uptime_secs {
            let hours = uptime / 3600;
            let mins = (uptime % 3600) / 60;
            let secs = uptime % 60;
            output.push_str(&format!("Uptime:      {}h {}m {}s\n", hours, mins, secs));
        }

        output.push_str("\nStatistics:\n");
        output.push_str(&format!("  Total Executions: {}\n", status.stats.total_executions));
        output.push_str(&format!("  Successful:       {}\n", status.stats.successful));
        output.push_str(&format!("  Failed:           {}\n", status.stats.failed));
        output.push_str(&format!("  Avg Execution:    {:.2}ms\n", status.stats.avg_execution_ms));

        if let Some(ref error) = status.last_error {
            output.push_str(&format!("\nLast Error:  {}\n", error));
        }

        output
    }

    /// Format plugin configuration
    pub fn format_config(config: &PluginConfiguration) -> String {
        let mut output = String::new();

        output.push_str(&format!("Name:     {}\n", config.name));
        output.push_str(&format!("Enabled:  {}\n", config.enabled));
        output.push_str(&format!("Priority: {}\n", config.priority));
        output.push_str("\nConfiguration:\n");

        match &config.config {
            serde_json::Value::Object(map) => {
                if map.is_empty() {
                    output.push_str("  (none)\n");
                } else {
                    for (key, value) in map {
                        output.push_str(&format!("  {}: {}\n", key, value));
                    }
                }
            }
            _ => {
                output.push_str(&format!("  {}\n", config.config));
            }
        }

        output
    }
}

/// Plugin scaffolding generator
pub struct PluginScaffold;

impl PluginScaffold {
    /// Create a new plugin scaffold
    pub fn create(
        name: &str,
        plugin_type: PluginTypeArg,
        output_dir: &PathBuf,
        description: &str,
        author: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create directory structure
        let plugin_dir = output_dir.join(name);
        std::fs::create_dir_all(&plugin_dir)?;
        std::fs::create_dir_all(plugin_dir.join("src"))?;

        // Create Cargo.toml
        let cargo_toml = Self::generate_cargo_toml(name, author);
        std::fs::write(plugin_dir.join("Cargo.toml"), cargo_toml)?;

        // Create lib.rs
        let lib_rs = Self::generate_lib_rs(name, plugin_type, description, author);
        std::fs::write(plugin_dir.join("src/lib.rs"), lib_rs)?;

        // Create plugin manifest
        let manifest = Self::generate_manifest(name, description, author, plugin_type);
        std::fs::write(plugin_dir.join("plugin.yaml"), manifest)?;

        // Create README
        let readme = Self::generate_readme(name, description);
        std::fs::write(plugin_dir.join("README.md"), readme)?;

        println!("Created plugin scaffold at: {}", plugin_dir.display());
        println!("\nTo build:");
        println!("  cd {}", plugin_dir.display());
        println!("  cargo build");

        Ok(())
    }

    fn generate_cargo_toml(name: &str, author: &str) -> String {
        format!(
            r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"
authors = ["{}"]
license = "MIT OR Apache-2.0"
description = "A custom Vault plugin"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
vault-core = {{ path = "../../vault-core" }}
async-trait = "0.1"
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
tokio = {{ version = "1.35", features = ["rt-multi-thread"] }}
tracing = "0.1"

[dev-dependencies]
tokio-test = "0.4"
"#,
            name, author
        )
    }

    fn generate_lib_rs(
        name: &str,
        plugin_type: PluginTypeArg,
        description: &str,
        _author: &str,
    ) -> String {
        let plugin_type_str = match plugin_type {
            PluginTypeArg::Native => "Native",
            PluginTypeArg::Wasm => "WASM",
            PluginTypeArg::Builtin => "Built-in",
        };

        format!(
            r#"//! {} Plugin
//!
//! {}
//! This is a {} plugin for Vault.

use async_trait::async_trait;
use serde::{{Deserialize, Serialize}};
use std::collections::HashMap;
use vault_core::plugin::types::{{
    ApiRequest, ApiResponse, AuthAction, AuthContext, AuthResult, HookType,
    HttpMethod, Plugin, PluginCapability, PluginConfig, PluginError, PluginMetadata,
    PluginHealth, RegisterAction, RegisterContext, Route,
}};
use vault_core::models::user::User;

/// Plugin configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct {}Config {{
    /// Example configuration field
    pub example_field: String,
}}

impl Default for {}Config {{
    fn default() -> Self {{
        Self {{
            example_field: "default".to_string(),
        }}
    }}
}}

/// {} Plugin
pub struct {}Plugin {{
    metadata: PluginMetadata,
    config: {}Config,
}}

impl {}Plugin {{
    /// Create new plugin instance
    pub fn new() -> Self {{
        let metadata = PluginMetadata::new(
            "{}",
            "0.1.0",
            "Plugin Author",
            "{}",
        )
        .with_hook(HookType::BeforeAuth)
        .with_hook(HookType::AfterAuth)
        .with_capability(PluginCapability::AuthProvider);

        Self {{
            metadata,
            config: {}Config::default(),
        }}
    }}
}}

impl Default for {}Plugin {{
    fn default() -> Self {{
        Self::new()
    }}
}}

#[async_trait]
impl Plugin for {}Plugin {{
    fn metadata(&self) -> &PluginMetadata {{
        &self.metadata
    }}

    async fn initialize(&mut self, config: &PluginConfig) -> Result<(), PluginError> {{
        tracing::info!("Initializing {} Plugin");

        // Parse configuration
        self.config = serde_json::from_value(config.config.clone())
            .map_err(|e| PluginError::new("CONFIG_ERROR", format!("Invalid config: {{}}", e)))?;

        tracing::info!("{} Plugin initialized");
        Ok(())
    }}

    async fn before_auth(&self, ctx: &AuthContext) -> Result<AuthAction, PluginError> {{
        tracing::debug!("{} before_auth hook for {{}}", ctx.email);
        Ok(AuthAction::Allow)
    }}

    async fn after_auth(&self, ctx: &AuthContext, result: &AuthResult) -> Result<(), PluginError> {{
        tracing::debug!("{} after_auth hook for {{}}", ctx.email);
        Ok(())
    }}

    fn routes(&self) -> Vec<Route> {{
        vec![
            Route::new(HttpMethod::Get, "/status", "get_status")
                .with_permission("admin:plugins"),
        ]
    }}

    async fn handle_request(
        &self,
        route: &str,
        _request: ApiRequest,
    ) -> Result<ApiResponse, PluginError> {{
        match route {{
            "get_status" => Ok(ApiResponse {{
                status: 200,
                body: serde_json::json!({{
                    "status": "healthy",
                    "plugin": "{}",
                }}),
                headers: HashMap::new(),
            }}),
            _ => Err(PluginError::new("NOT_FOUND", "Route not found")),
        }}
    }}

    async fn health_check(&self) -> PluginHealth {{
        PluginHealth::Healthy
    }}

    async fn shutdown(&self) -> Result<(), PluginError> {{
        tracing::info!("{} Plugin shutting down");
        Ok(())
    }}
}}

/// Create plugin instance - called by the plugin loader
pub fn create_plugin() -> Box<dyn Plugin> {{
    Box::new({}Plugin::new())
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[tokio::test]
    async fn test_plugin_initialization() {{
        let mut plugin = {}Plugin::new();
        let config = PluginConfig {{
            name: "{}".to_string(),
            enabled: true,
            config: serde_json::json!({{
                "example_field": "test"
            }}),
            priority: 0,
            timeout_ms: None,
        }};

        let result = plugin.initialize(&config).await;
        assert!(result.is_ok());
    }}

    #[test]
    fn test_create_plugin() {{
        let plugin = create_plugin();
        assert_eq!(plugin.metadata().name, "{}");
    }}
}}
"#,
            name, description, plugin_type_str,
            name, name,
            name, name, name,
            name, name, name, name, name,
            name, name, name, name, name, name, name, name,
            name, name, name, name, name, name, name
        )
    }

    fn generate_manifest(
        name: &str,
        description: &str,
        author: &str,
        plugin_type: PluginTypeArg,
    ) -> String {
        let plugin_type_str = match plugin_type {
            PluginTypeArg::Native => "native",
            PluginTypeArg::Wasm => "wasm",
            PluginTypeArg::Builtin => "builtin",
        };

        format!(
            r#"name: {}
version: "0.1.0"
author: {}
description: {}
type: {}
entry: "{}"
default_config:
  example_field: "default"
permissions:
  - admin:plugins
"#,
            name, author, description, plugin_type_str,
            match plugin_type {
                PluginTypeArg::Native => "target/release/libplugin.so",
                PluginTypeArg::Wasm => "target/wasm32-wasi/release/plugin.wasm",
                PluginTypeArg::Builtin => "N/A",
            }
        )
    }

    fn generate_readme(name: &str, description: &str) -> String {
        format!(
            r#"# {}

{}

## Installation

1. Build the plugin:
   ```bash
   cargo build --release
   ```

2. Copy to your plugins directory:
   ```bash
   cp target/release/lib{}.so /opt/vault/plugins/{}/
   ```

3. Configure in Vault:
   ```yaml
   plugins:
     - name: "{}"
       enabled: true
       config:
         example_field: "value"
   ```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `example_field` | string | `"default"` | Example configuration field |

## Development

Run tests:
```bash
cargo test
```

Build documentation:
```bash
cargo doc --open
```
"#,
            name, description, name, name, name
        )
    }
}

/// Parse key=value string into (key, value) tuple
pub fn parse_config_value(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid config format: {}. Expected key=value", s));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config_value() {
        assert_eq!(
            parse_config_value("key=value").unwrap(),
            ("key".to_string(), "value".to_string())
        );

        assert_eq!(
            parse_config_value("ldap_url=ldap://localhost:389").unwrap(),
            ("ldap_url".to_string(), "ldap://localhost:389".to_string())
        );

        assert!(parse_config_value("invalid").is_err());
    }

    #[test]
    fn test_plugin_formatter() {
        let plugins = vec![
            PluginInfo {
                name: "test-plugin".to_string(),
                version: "1.0.0".to_string(),
                author: "Test".to_string(),
                description: "Test plugin".to_string(),
                plugin_type: "builtin".to_string(),
                enabled: true,
                health: "healthy".to_string(),
                hooks: vec!["before_auth".to_string()],
                capabilities: vec!["auth_provider".to_string()],
            },
        ];

        let output = PluginFormatter::format_list(&plugins, false);
        assert!(output.contains("test-plugin"));
        assert!(output.contains("1.0.0"));
    }
}
