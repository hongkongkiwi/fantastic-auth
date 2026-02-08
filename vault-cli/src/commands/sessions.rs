//! Session management commands

use crate::client::VaultClient;
use crate::commands::{confirm, format_timestamp, print_data, print_table, OutputFormat};
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
                        format_timestamp(&s.created_at),
                        format_timestamp(&s.expires_at),
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

/// List sessions for a specific user (admin)
pub async fn list_user_sessions(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    user_id: &str,
    format: OutputFormat,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let response: serde_json::Value = client
        .get(&format!("/admin/users/{}/sessions", user_id))
        .await
        .context("Failed to list user sessions")?;

    match format {
        OutputFormat::Table => {
            let empty_vec = vec![];
            let sessions = response.get("sessions").and_then(|s| s.as_array()).unwrap_or(&empty_vec);
            
            if sessions.is_empty() {
                println!("No sessions found for user {}", user_id);
                return Ok(());
            }

            let rows: Vec<Vec<String>> = sessions
                .iter()
                .map(|s| {
                    vec![
                        s["id"].as_str().unwrap_or("N/A").to_string(),
                        s["ipAddress"].as_str().unwrap_or("-").to_string(),
                        format_timestamp(s["createdAt"].as_str().unwrap_or("")),
                        format_timestamp(s["expiresAt"].as_str().unwrap_or("")),
                        s["status"].as_str().unwrap_or("unknown").to_string(),
                    ]
                })
                .collect();

            print_table(vec!["ID", "IP Address", "Created", "Expires", "Status"], rows);
            
            if let Some(current) = response["currentSessions"].as_u64() {
                if let Some(max) = response["maxSessions"].as_u64() {
                    println!("\n{} active session(s) (max: {})", current, max);
                }
            }
        }
        _ => {
            print_data(&response, format)?;
        }
    }

    Ok(())
}

/// Revoke a specific session
pub async fn revoke(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    session_id: &str,
) -> Result<()> {
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

/// Revoke a specific session for a user (admin)
pub async fn revoke_user_session(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    user_id: &str,
    session_id: &str,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let _: serde_json::Value = client
        .delete(&format!("/admin/users/{}/sessions/{}", user_id, session_id))
        .await
        .context("Failed to revoke user session")?;

    println!("✅ Session {} revoked for user {}", session_id, user_id);
    Ok(())
}

/// Revoke all sessions (logout everywhere)
pub async fn revoke_all(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    force: bool,
) -> Result<()> {
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

/// Revoke all sessions for a user (admin)
pub async fn revoke_all_user_sessions(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    user_id: &str,
    force: bool,
) -> Result<()> {
    if !force {
        let confirmed = confirm(&format!(
            "Revoke all sessions for user {}?",
            user_id
        ))?;
        if !confirmed {
            println!("Cancelled");
            return Ok(());
        }
    }

    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let response: serde_json::Value = client
        .delete(&format!("/admin/users/{}/sessions", user_id))
        .await
        .context("Failed to revoke user sessions")?;

    if let Some(msg) = response["message"].as_str() {
        println!("✅ {}", msg);
    } else {
        println!("✅ All sessions revoked for user {}", user_id);
    }
    
    Ok(())
}
