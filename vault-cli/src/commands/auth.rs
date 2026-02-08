//! Authentication commands

use crate::client::{types::AuthResponse, VaultClient};
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

    // Save tokens
    let mut config = Config::load()?;
    config.api_url = Some(api_url.to_string());
    config.token = Some(response.access_token);
    config.save()?;

    println!("✅ Logged in successfully!");
    println!(
        "   User: {} ({})",
        response.user.name.as_deref().unwrap_or("N/A"),
        response.user.email
    );
    println!("   Status: {}", response.user.status);

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
pub async fn whoami(api_url: &str, token: &str) -> Result<()> {
    let client = VaultClient::new(api_url).with_token(token);

    let user: crate::client::types::User = client
        .get("/users/me")
        .await
        .context("Failed to get user info")?;

    println!("👤 Current user:");
    println!("   ID: {}", user.id);
    println!("   Email: {}", user.email);
    println!("   Name: {}", user.name.as_deref().unwrap_or("N/A"));
    println!("   Status: {}", user.status);
    println!(
        "   MFA: {}",
        if user.mfa_enabled {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!(
        "   Email verified: {}",
        if user.email_verified { "Yes" } else { "No" }
    );

    Ok(())
}
