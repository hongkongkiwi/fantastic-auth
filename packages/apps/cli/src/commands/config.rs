//! Configuration commands

use crate::commands::{confirm, OutputFormat};
use crate::config::Config;
use anyhow::Result;

/// Show current configuration
pub fn show(format: OutputFormat) -> Result<()> {
    let config = Config::load()?;

    match format {
        OutputFormat::Table => {
            println!("Current configuration:");
            println!(
                "  API URL:      {}",
                config.api_url.as_deref().unwrap_or("Not set")
            );
            println!(
                "  Tenant ID:    {}",
                config.tenant_id.as_deref().unwrap_or("Not set")
            );
            println!(
                "  Logged in:    {}",
                if config.is_authenticated() { "Yes" } else { "No" }
            );
            println!("\nConfig file: {}", Config::config_path()?.display());
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&config)?;
            println!("{}", json);
        }
        OutputFormat::Yaml => {
            // Don't print sensitive data in default YAML view
            println!("api_url: {}", config.api_url.as_deref().unwrap_or(""));
            println!("tenant_id: {}", config.tenant_id.as_deref().unwrap_or(""));
            println!("authenticated: {}", config.is_authenticated());
        }
    }

    Ok(())
}

/// Set configuration value
pub fn set(key: &str, value: &str) -> Result<()> {
    let mut config = Config::load()?;
    config.set(key, value)?;
    println!("✅ Set {} = {}", key, value);
    Ok(())
}

/// Initialize configuration interactively
pub async fn init() -> Result<()> {
    crate::config::init_interactive().await?;
    Ok(())
}

/// Reset configuration to defaults
pub fn reset(force: bool) -> Result<()> {
    if !force {
        let confirmed = confirm("Reset all configuration? This will remove all saved settings.")?;
        if !confirmed {
            println!("Cancelled");
            return Ok(());
        }
    }

    let config = Config::default();
    config.save()?;
    println!("✅ Configuration reset to defaults");
    Ok(())
}
