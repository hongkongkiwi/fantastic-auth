//! Authentication commands

use crate::client::{types::AuthResponse, VaultClient};
use crate::commands::{print_data, OutputFormat};
use crate::config::Config;
use anyhow::{Context, Result};

/// Login with email and password
pub async fn login(api_url: &str, email: &str, password: Option<&str>) -> Result<()> {
    let password = match password {
        Some(p) => p.to_string(),
        None => super::read_password("Password")?,
    };

    println!("🔐 Logging in as {}...", email);

    let client = VaultClient::new(api_url);

    #[derive(serde::Serialize)]
    struct LoginRequest {
        email: String,
        password: String,
    }

    let response: AuthResponse = client
        .post(
            "/auth/login",
            &LoginRequest {
                email: email.to_string(),
                password,
            },
        )
        .await
        .context("Login failed")?;

    // Save tokens (encrypted)
    let mut config = Config::load()?;
    config.api_url = Some(api_url.to_string());
    config.set_token(&response.access_token)?;
    config.set_refresh_token(&response.refresh_token)?;

    println!("✅ Logged in successfully!");
    println!(
        "   User: {} ({})",
        response.user.name.as_deref().unwrap_or("N/A"),
        response.user.email
    );
    println!("   Status: {}", response.user.status);

    Ok(())
}

/// Login with API key (service account)
pub async fn login_with_api_key(api_url: &str, api_key: &str, tenant_id: &str) -> Result<()> {
    println!("🔐 Authenticating with API key...");

    let client = VaultClient::new(api_url).with_token(api_key);

    // Verify the API key by making a request
    let user: crate::client::types::User = client
        .get("/users/me")
        .await
        .context("API key authentication failed")?;

    // Save configuration (token encrypted)
    let mut config = Config::load()?;
    config.api_url = Some(api_url.to_string());
    config.set_token(api_key)?;
    config.tenant_id = Some(tenant_id.to_string());
    config.save()?;

    println!("✅ Authenticated successfully!");
    println!("   User: {} ({})", user.name.as_deref().unwrap_or("N/A"), user.email);
    println!("   Tenant: {}", tenant_id);

    Ok(())
}

/// Logout and clear tokens
pub fn logout() -> Result<()> {
    let mut config = Config::load()?;

    if !config.is_authenticated() {
        println!("Not logged in");
        return Ok(());
    }

    config.logout()?;
    println!("👋 Logged out successfully");

    Ok(())
}

/// Show current user info
pub async fn whoami(api_url: &str, token: &str, format: OutputFormat) -> Result<()> {
    let client = VaultClient::new(api_url).with_token(token);

    let user: crate::client::types::User = client
        .get("/users/me")
        .await
        .context("Failed to get user info")?;

    match format {
        OutputFormat::Table => {
            println!("👤 Current user:");
            println!("   ID:       {}", user.id);
            println!("   Email:    {}", user.email);
            println!("   Name:     {}", user.name.as_deref().unwrap_or("N/A"));
            println!("   Status:   {}", user.status);
            println!(
                "   MFA:      {}",
                if user.mfa_enabled { "Enabled" } else { "Disabled" }
            );
            println!(
                "   Verified: {}",
                if user.email_verified { "Yes" } else { "No" }
            );
            println!("   Created:  {}", super::format_timestamp(&user.created_at));
        }
        _ => {
            print_data(&user, format)?;
        }
    }

    Ok(())
}
