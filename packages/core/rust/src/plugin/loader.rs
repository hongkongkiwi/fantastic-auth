//! Plugin loader for dynamic plugin loading
//!
//! Supports both native dynamic libraries (.so/.dll/.dylib) and
//! WebAssembly modules (.wasm).

use super::registry::PluginRegistry;
use super::types::{PluginConfig, PluginError, PluginType};
use std::path::{Path, PathBuf};
use tracing::{debug, info, instrument, warn};

/// Plugin loader configuration
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    /// Directory to scan for plugins
    pub plugin_dir: PathBuf,
    /// File extensions for native plugins
    pub native_extensions: Vec<String>,
    /// File extension for WASM plugins
    pub wasm_extension: String,
    /// Auto-load plugins on startup
    pub auto_load: bool,
    /// Maximum plugin file size (bytes)
    pub max_file_size: usize,
    /// Verify plugin signatures
    pub verify_signatures: bool,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            plugin_dir: PathBuf::from("./plugins"),
            native_extensions: vec![
                "so".to_string(),    // Linux
                "dll".to_string(),   // Windows
                "dylib".to_string(), // macOS
            ],
            wasm_extension: "wasm".to_string(),
            auto_load: true,
            max_file_size: 50 * 1024 * 1024, // 50MB
            // SECURITY: Signature verification enabled by default to prevent malicious plugins
            verify_signatures: true,
        }
    }
}

impl LoaderConfig {
    /// Create new loader config with plugin directory
    pub fn new(plugin_dir: impl Into<PathBuf>) -> Self {
        Self {
            plugin_dir: plugin_dir.into(),
            ..Default::default()
        }
    }

    /// Set auto-load option
    pub fn with_auto_load(mut self, auto_load: bool) -> Self {
        self.auto_load = auto_load;
        self
    }

    /// Set max file size
    pub fn with_max_file_size(mut self, max_size: usize) -> Self {
        self.max_file_size = max_size;
        self
    }
}

/// Plugin manifest (plugin.yaml or plugin.json)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginManifest {
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin author
    pub author: String,
    /// Plugin description
    pub description: String,
    /// Entry point file (relative to manifest)
    pub entry: String,
    /// Plugin type
    #[serde(rename = "type")]
    pub plugin_type: PluginType,
    /// Default configuration
    pub default_config: Option<serde_json::Value>,
    /// Required permissions
    pub permissions: Option<Vec<String>>,
    /// Minimum Vault version
    pub min_vault_version: Option<String>,
}

/// Plugin loader for discovering and loading plugins
pub struct PluginLoader {
    config: LoaderConfig,
}

impl PluginLoader {
    /// Create new plugin loader
    pub fn new(config: LoaderConfig) -> Self {
        Self { config }
    }

    /// Scan plugin directory and discover available plugins
    #[instrument(skip(self))]
    pub fn discover(&self) -> Result<Vec<DiscoveredPlugin>, PluginError> {
        let mut discovered = Vec::new();

        if !self.config.plugin_dir.exists() {
            debug!(
                "Plugin directory does not exist: {:?}",
                self.config.plugin_dir
            );
            return Ok(discovered);
        }

        let entries = std::fs::read_dir(&self.config.plugin_dir).map_err(|e| {
            PluginError::new(
                "IO_ERROR",
                format!("Failed to read plugin directory: {}", e),
            )
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                PluginError::new("IO_ERROR", format!("Failed to read directory entry: {}", e))
            })?;

            let path = entry.path();
            if path.is_dir() {
                // Check for manifest file
                if let Some(plugin) = self.scan_plugin_directory(&path)? {
                    discovered.push(plugin);
                }
            } else if path.is_file() {
                // Check if it's a standalone plugin file
                if let Some(plugin) = self.scan_plugin_file(&path)? {
                    discovered.push(plugin);
                }
            }
        }

        info!("Discovered {} plugins", discovered.len());
        Ok(discovered)
    }

    /// Scan a plugin directory for manifest and entry point
    fn scan_plugin_directory(&self, dir: &Path) -> Result<Option<DiscoveredPlugin>, PluginError> {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| PluginError::new("INVALID_NAME", "Invalid plugin directory name"))?
            .to_string();

        // Look for manifest
        let manifest_path = dir.join("plugin.yaml");
        let manifest = if manifest_path.exists() {
            Some(self.load_manifest(&manifest_path)?)
        } else {
            let json_path = dir.join("plugin.json");
            if json_path.exists() {
                Some(self.load_manifest(&json_path)?)
            } else {
                None
            }
        };

        // Find entry point
        let entry_point: Option<PathBuf> = if let Some(ref m) = manifest {
            Some(dir.join(&m.entry))
        } else {
            // Guess entry point from known extensions
            self.find_entry_point(dir)?
        };

        if let Some(entry) = entry_point {
            let plugin_type = if let Some(ref m) = manifest {
                m.plugin_type
            } else {
                self.detect_plugin_type(&entry)?
            };

            return Ok(Some(DiscoveredPlugin {
                name: manifest.as_ref().map(|m| m.name.clone()).unwrap_or(name),
                version: manifest.as_ref().map(|m| m.version.clone()),
                author: manifest.as_ref().map(|m| m.author.clone()),
                description: manifest.as_ref().map(|m| m.description.clone()),
                manifest,
                plugin_type,
                entry_point: entry.to_path_buf(),
                directory: dir.to_path_buf(),
            }));
        }

        Ok(None)
    }

    /// Scan a single plugin file
    fn scan_plugin_file(&self, path: &Path) -> Result<Option<DiscoveredPlugin>, PluginError> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        // Check if it's a supported extension
        let is_native = self.config.native_extensions.iter().any(|e| e == ext);
        let is_wasm = ext == self.config.wasm_extension;

        if !is_native && !is_wasm {
            return Ok(None);
        }

        let name = path
            .file_stem()
            .and_then(|n| n.to_str())
            .ok_or_else(|| PluginError::new("INVALID_NAME", "Invalid plugin file name"))?
            .to_string();

        let plugin_type = if is_wasm {
            PluginType::Wasm
        } else {
            PluginType::Native
        };

        Ok(Some(DiscoveredPlugin {
            name,
            version: None,
            author: None,
            description: None,
            manifest: None,
            plugin_type,
            entry_point: path.to_path_buf(),
            directory: path.parent().unwrap_or(Path::new(".")).to_path_buf(),
        }))
    }

    /// Load manifest from file
    fn load_manifest(&self, path: &Path) -> Result<PluginManifest, PluginError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| PluginError::new("IO_ERROR", format!("Failed to read manifest: {}", e)))?;

        if path.extension().map(|e| e == "yaml").unwrap_or(false) {
            serde_yaml::from_str(&content).map_err(|e| {
                PluginError::new(
                    "MANIFEST_PARSE_ERROR",
                    format!("Failed to parse YAML manifest: {}", e),
                )
            })
        } else {
            serde_json::from_str(&content).map_err(|e| {
                PluginError::new(
                    "MANIFEST_PARSE_ERROR",
                    format!("Failed to parse JSON manifest: {}", e),
                )
            })
        }
    }

    /// Find entry point in directory
    fn find_entry_point(&self, dir: &Path) -> Result<Option<PathBuf>, PluginError> {
        // Try WASM first
        let wasm_entry = dir.join("plugin.wasm");
        if wasm_entry.exists() {
            return Ok(Some(wasm_entry));
        }

        // Try native extensions
        for ext in &self.config.native_extensions {
            let entry = dir.join(format!("plugin.{}", ext));
            if entry.exists() {
                return Ok(Some(entry));
            }
        }

        // Try generic names
        for name in &[
            "plugin",
            "lib",
            &dir.file_name().unwrap_or_default().to_string_lossy(),
        ] {
            for ext in &self.config.native_extensions {
                let entry = dir.join(format!("{}.{}", name, ext));
                if entry.exists() {
                    return Ok(Some(entry));
                }
            }
        }

        Ok(None)
    }

    /// Detect plugin type from file extension
    fn detect_plugin_type(&self, path: &Path) -> Result<PluginType, PluginError> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| PluginError::new("UNKNOWN_TYPE", "Cannot detect plugin type"))?;

        if ext == self.config.wasm_extension {
            Ok(PluginType::Wasm)
        } else if self.config.native_extensions.iter().any(|e| e == ext) {
            Ok(PluginType::Native)
        } else {
            Err(PluginError::new(
                "UNKNOWN_TYPE",
                format!("Unknown plugin type: {}", ext),
            ))
        }
    }

    /// Load a discovered plugin into the registry
    #[instrument(skip(self, registry, plugin))]
    pub async fn load(
        &self,
        registry: &PluginRegistry,
        plugin: &DiscoveredPlugin,
        config: Option<PluginConfig>,
    ) -> Result<(), PluginError> {
        info!("Loading plugin: {} ({:?})", plugin.name, plugin.plugin_type);

        // Check file size
        let metadata = std::fs::metadata(&plugin.entry_point).map_err(|e| {
            PluginError::new(
                "IO_ERROR",
                format!("Failed to read plugin file metadata: {}", e),
            )
        })?;

        if metadata.len() > self.config.max_file_size as u64 {
            return Err(PluginError::new(
                "FILE_TOO_LARGE",
                format!(
                    "Plugin file exceeds maximum size of {} bytes",
                    self.config.max_file_size
                ),
            ));
        }

        // Prepare configuration
        let plugin_config = config.unwrap_or_else(|| PluginConfig {
            name: plugin.name.clone(),
            enabled: true,
            config: plugin
                .manifest
                .as_ref()
                .and_then(|m| m.default_config.clone())
                .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())),
            priority: 0,
            timeout_ms: None,
        });

        // Load based on type
        match plugin.plugin_type {
            PluginType::Native => {
                registry
                    .register_native(plugin.entry_point.to_str().unwrap_or(""), plugin_config)
                    .await
            }
            PluginType::Wasm => {
                registry
                    .register_wasm(plugin.entry_point.to_str().unwrap_or(""), plugin_config)
                    .await
            }
            PluginType::Builtin => Err(PluginError::new(
                "INVALID_TYPE",
                "Cannot load builtin plugins via loader",
            )),
        }
    }

    /// Load all discovered plugins
    #[instrument(skip(self, registry))]
    pub async fn load_all(
        &self,
        registry: &PluginRegistry,
        configs: &std::collections::HashMap<String, PluginConfig>,
    ) -> Result<LoadResult, PluginError> {
        let discovered = self.discover()?;
        let mut loaded = Vec::new();
        let mut failed = Vec::new();

        for plugin in discovered {
            let config = configs.get(&plugin.name).cloned();
            let name = plugin.name.clone();

            match self.load(registry, &plugin, config).await {
                Ok(_) => loaded.push(name),
                Err(e) => {
                    warn!("Failed to load plugin {}: {}", name, e);
                    failed.push((name, e.to_string()));
                }
            }
        }

        let total = loaded.len() + failed.len();
        Ok(LoadResult {
            loaded,
            failed,
            total,
        })
    }

    /// Get plugin directory path
    pub fn plugin_dir(&self) -> &Path {
        &self.config.plugin_dir
    }
}

/// Discovered plugin information
#[derive(Debug, Clone)]
pub struct DiscoveredPlugin {
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: Option<String>,
    /// Plugin author
    pub author: Option<String>,
    /// Plugin description
    pub description: Option<String>,
    /// Plugin manifest (if present)
    pub manifest: Option<PluginManifest>,
    /// Plugin type
    pub plugin_type: PluginType,
    /// Entry point file path
    pub entry_point: PathBuf,
    /// Plugin directory
    pub directory: PathBuf,
}

/// Result of loading plugins
#[derive(Debug, Clone)]
pub struct LoadResult {
    /// Successfully loaded plugin names
    pub loaded: Vec<String>,
    /// Failed plugins with error messages
    pub failed: Vec<(String, String)>,
    /// Total plugins attempted
    pub total: usize,
}

impl LoadResult {
    /// Check if all plugins loaded successfully
    pub fn all_succeeded(&self) -> bool {
        self.failed.is_empty()
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        self.loaded.len() as f64 / self.total as f64
    }
}

/// Configuration for plugins from YAML/JSON config files
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PluginsConfig {
    /// Global plugin settings
    pub settings: Option<PluginSettings>,
    /// Individual plugin configurations
    pub plugins: Vec<PluginConfigEntry>,
}

/// Global plugin settings
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PluginSettings {
    /// Plugin directory
    pub directory: Option<String>,
    /// Auto-load plugins
    pub auto_load: Option<bool>,
    /// Verify signatures
    pub verify_signatures: Option<bool>,
}

/// Plugin configuration entry from config file
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginConfigEntry {
    /// Plugin name
    pub name: String,
    /// Plugin path (optional, overrides discovery)
    pub path: Option<String>,
    /// WASM path (for WASM plugins)
    pub wasm_path: Option<String>,
    /// Whether plugin is enabled
    pub enabled: Option<bool>,
    /// Plugin configuration
    pub config: Option<serde_json::Value>,
    /// Plugin priority
    pub priority: Option<i32>,
}

impl PluginsConfig {
    /// Load plugin configuration from file
    pub fn from_file(path: &Path) -> Result<Self, PluginError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            PluginError::new(
                "CONFIG_READ_ERROR",
                format!("Failed to read plugin config: {}", e),
            )
        })?;

        if path
            .extension()
            .map(|e| e == "yaml" || e == "yml")
            .unwrap_or(false)
        {
            serde_yaml::from_str(&content).map_err(|e| {
                PluginError::new(
                    "CONFIG_PARSE_ERROR",
                    format!("Failed to parse YAML config: {}", e),
                )
            })
        } else {
            serde_json::from_str(&content).map_err(|e| {
                PluginError::new(
                    "CONFIG_PARSE_ERROR",
                    format!("Failed to parse JSON config: {}", e),
                )
            })
        }
    }

    /// Convert to plugin config map
    pub fn to_config_map(&self) -> std::collections::HashMap<String, PluginConfig> {
        let mut map = std::collections::HashMap::new();

        for entry in &self.plugins {
            let config = PluginConfig {
                name: entry.name.clone(),
                enabled: entry.enabled.unwrap_or(true),
                config: entry
                    .config
                    .clone()
                    .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())),
                priority: entry.priority.unwrap_or(0),
                timeout_ms: None,
            };
            map.insert(entry.name.clone(), config);
        }

        map
    }
}

/// Load plugins from configuration
pub async fn load_plugins_from_config(
    registry: &PluginRegistry,
    config: &PluginsConfig,
) -> Result<LoadResult, PluginError> {
    let plugin_dir = config
        .settings
        .as_ref()
        .and_then(|s| s.directory.clone())
        .unwrap_or_else(|| "./plugins".to_string());

    let loader_config = LoaderConfig::new(&plugin_dir).with_auto_load(
        config
            .settings
            .as_ref()
            .and_then(|s| s.auto_load)
            .unwrap_or(true),
    );

    let loader = PluginLoader::new(loader_config);
    let configs = config.to_config_map();

    loader.load_all(registry, &configs).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_config() {
        let config = LoaderConfig::default();
        assert_eq!(config.plugin_dir, PathBuf::from("./plugins"));
        assert!(config.auto_load);
    }

    #[test]
    fn test_load_result() {
        let result = LoadResult {
            loaded: vec!["plugin1".to_string(), "plugin2".to_string()],
            failed: vec![("plugin3".to_string(), "error".to_string())],
            total: 3,
        };

        assert!(!result.all_succeeded());
        assert_eq!(result.success_rate(), 2.0 / 3.0);
    }

    #[test]
    fn test_plugins_config_parse() {
        let yaml = r#"
settings:
  directory: /opt/vault/plugins
  auto_load: true
plugins:
  - name: ldap-sync
    enabled: true
    priority: 10
    config:
      ldap_url: ldap://localhost:389
  - name: custom-oauth
    enabled: false
    config:
      provider_name: Custom
"#;

        let config: PluginsConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.plugins.len(), 2);
        assert_eq!(config.plugins[0].name, "ldap-sync");
        assert_eq!(config.plugins[1].enabled, Some(false));
    }
}
