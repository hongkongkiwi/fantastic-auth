//! Session management commands

use crate::client::VaultClient;
use crate::commands::{confirm, print_data, print_table, OutputFormat};
use anyhow::{Context, Result};

/// List sessions for current user
pub async fn list(api_url: &str, token: &str, tenant_id: &str, format: OutputFormat) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let sessions: Vec<crate::client::types::Session> = client
        .get("/users/me/sessions")
        .await
        .context("Failed to list sessions")?;

    match format {
        OutputFormat::Table => {
            if sessions.is_empty() {
                println!("No active sessions");
                return Ok(());
            }

            let rows: Vec<Vec<String>> = sessions
                .iter()
                .map(|s| {
                    vec![
                        s.id.clone(),
                        s.ip_address.clone().unwrap_or_else(|| "-".to_string()),
                        s.created_at.chars().take(10).collect(),
                        s.expires_at.chars().take(10).collect(),
                        if s.current { "✓ Current" } else { "" }.to_string(),
                    ]
                })
                .collect();

            print_table(vec!["ID", "IP Address", "Created", "Expires", ""], rows);

            println!("\n{} active session(s)", sessions.len());
        }
        _ => {
            print_data(&sessions, format)?;
        }
    }

    Ok(())
}

/// Revoke a specific session
pub async fn revoke(api_url: &str, token: &str, tenant_id: &str, session_id: &str) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let _: serde_json::Value = client
        .delete(&format!("/users/me/sessions/{}", session_id))
        .await
        .context("Failed to revoke session")?;

    println!("✅ Session {} revoked", session_id);
    Ok(())
}

/// Revoke all sessions (logout everywhere)
pub async fn revoke_all(api_url: &str, token: &str, tenant_id: &str, force: bool) -> Result<()> {
    if !force {
        let confirmed = confirm("Revoke all sessions? This will log you out everywhere.")?;
        if !confirmed {
            println!("Cancelled");
            return Ok(());
        }
    }

    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let _: serde_json::Value = client
        .delete("/users/me/sessions")
        .await
        .context("Failed to revoke all sessions")?;

    println!("✅ All sessions revoked. You have been logged out.");
    Ok(())
}
