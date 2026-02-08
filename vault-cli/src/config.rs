//! Configuration management for Vault CLI

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// CLI Configuration
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    /// Vault API URL
    pub api_url: Option<String>,
    /// Default tenant ID
    pub tenant_id: Option<String>,
    /// Saved authentication token
    pub token: Option<String>,
    /// Refresh token
    pub refresh_token: Option<String>,
}

impl Config {
    /// Get configuration directory
    pub fn config_dir() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .context("Could not find config directory")?
            .join("vault");

        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Get configuration file path
    pub fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.toml"))
    }

    /// Load configuration from disk
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(&path)?;
        let config = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save configuration to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Set a configuration value
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "api_url" => self.api_url = Some(value.to_string()),
            "tenant_id" => self.tenant_id = Some(value.to_string()),
            "token" => self.token = Some(value.to_string()),
            _ => anyhow::bail!("Unknown configuration key: {}", key),
        }
        self.save()
    }

    /// Get configuration value
    pub fn get(&self, key: &str) -> Option<&String> {
        match key {
            "api_url" => self.api_url.as_ref(),
            "tenant_id" => self.tenant_id.as_ref(),
            "token" => self.token.as_ref(),
            _ => None,
        }
    }

    /// Check if user is logged in
    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    /// Clear authentication tokens
    pub fn logout(&mut self) -> Result<()> {
        self.token = None;
        self.refresh_token = None;
        self.save()
    }
}

/// Interactive configuration setup
pub async fn init_interactive() -> Result<Config> {
    use dialoguer::{Input, Select};

    println!("🔐 Vault CLI Configuration\n");

    // API URL
    let api_url: String = Input::new()
        .with_prompt("Vault API URL")
        .default("https://api.vault.dev".to_string())
        .interact_text()?;

    // Tenant selection
    let tenant_choice = Select::new()
        .with_prompt("Authentication method")
        .items(&["User login (JWT)", "API Key (Service account)"])
        .interact()?;

    let mut config = Config {
        api_url: Some(api_url),
        ..Default::default()
    };

    if tenant_choice == 1 {
        // API Key auth
        let api_key: String = Input::new().with_prompt("API Key").interact_text()?;

        config.token = Some(api_key);

        let tenant_id: String = Input::new()
            .with_prompt("Default Tenant ID")
            .interact_text()?;

        config.tenant_id = Some(tenant_id);
    }

    config.save()?;
    println!("\n✅ Configuration saved!");

    Ok(config)
}
