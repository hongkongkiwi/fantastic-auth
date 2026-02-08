//! User management commands

use crate::client::{types::UserList, VaultClient};
use crate::commands::{confirm, format_timestamp, print_data, print_table, OutputFormat};
use anyhow::{Context, Result};

/// List users with pagination
pub async fn list(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    email: Option<&str>,
    status: Option<&str>,
    page: i64,
    per_page: i64,
    format: OutputFormat,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let page_str = page.to_string();
    let per_page_str = per_page.to_string();
    let mut params = vec![
        ("page", page_str.as_str()),
        ("per_page", per_page_str.as_str()),
    ];
    
    if let Some(email) = email {
        params.push(("email", email));
    }
    if let Some(status) = status {
        params.push(("status", status));
    }

    let response: UserList = client
        .get_with_params("/admin/users", &params)
        .await
        .context("Failed to list users")?;

    match format {
        OutputFormat::Table => {
            if response.data.is_empty() {
                println!("No users found");
                return Ok(());
            }

            let rows: Vec<Vec<String>> = response
                .data
                .iter()
                .map(|u| {
                    vec![
                        u.id.clone(),
                        u.email.clone(),
                        u.name.clone().unwrap_or_else(|| "-".to_string()),
                        u.status.clone(),
                        if u.mfa_enabled { "✓".to_string() } else { "-".to_string() },
                        format_timestamp(&u.created_at),
                    ]
                })
                .collect();

            print_table(
                vec!["ID", "Email", "Name", "Status", "MFA", "Created"],
                rows,
            );

            println!(
                "\nShowing {} of {} users (page {} of {})",
                response.data.len(),
                response.pagination.total,
                response.pagination.page,
                response.pagination.total_pages
            );
        }
        _ => {
            print_data(&response, format)?;
        }
    }

    Ok(())
}

/// Get user details
pub async fn get(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    user_id: &str,
    format: OutputFormat,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let user: serde_json::Value = client
        .get(&format!("/admin/users/{}", user_id))
        .await
        .context("Failed to get user")?;

    print_data(&user, format)?;
    Ok(())
}

/// Create new user
pub async fn create(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    email: &str,
    password: Option<&str>,
    name: Option<&str>,
    email_verified: bool,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    // Get password interactively if not provided
    let _password = if let Some(p) = password {
        Some(p.to_string())
    } else {
        None
    };

    // Get name interactively if not provided
    let name = match name {
        Some(n) => n.to_string(),
        None => {
            println!("Creating user: {}", email);
            super::read_input("Full name", None)?
        }
    };

    #[derive(serde::Serialize)]
    struct CreateUserRequest {
        email: String,
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        #[serde(rename = "emailVerified")]
        email_verified: bool,
    }

    let user: serde_json::Value = client
        .post(
            "/admin/users",
            &CreateUserRequest {
                email: email.to_string(),
                name,
                password: _password,
                email_verified,
            },
        )
        .await
        .context("Failed to create user")?;

    println!("✅ User created successfully!");
    println!("   ID: {}", user["id"].as_str().unwrap_or("N/A"));
    println!("   Email: {}", email);
    if let Some(name) = user["name"].as_str() {
        println!("   Name: {}", name);
    }

    Ok(())
}

/// Update user
pub async fn update(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    user_id: &str,
    email: Option<&str>,
    name: Option<&str>,
    status: Option<&str>,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    #[derive(serde::Serialize, Default)]
    struct UpdateUserRequest {
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
    }

    let mut body = UpdateUserRequest::default();
    
    if let Some(email) = email {
        body.email = Some(email.to_string());
    }
    if let Some(name) = name {
        body.name = Some(name.to_string());
    }
    if let Some(status) = status {
        body.status = Some(status.to_string());
    }

    let user: serde_json::Value = client
        .patch(&format!("/admin/users/{}", user_id), &body)
        .await
        .context("Failed to update user")?;

    println!("✅ User updated successfully!");
    print_data(&user, OutputFormat::Table)?;

    Ok(())
}

/// Delete user
pub async fn delete(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    user_id: &str,
    force: bool,
) -> Result<()> {
    if !force {
        let confirmed = confirm(&format!(
            "Are you sure you want to delete user {}?",
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

    let _: serde_json::Value = client
        .delete(&format!("/admin/users/{}", user_id))
        .await
        .context("Failed to delete user")?;

    println!("✅ User {} deleted", user_id);
    Ok(())
}

/// Suspend user
pub async fn suspend(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    user_id: &str,
    reason: Option<&str>,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    #[derive(serde::Serialize)]
    struct SuspendRequest {
        reason: Option<String>,
    }

    let user: serde_json::Value = client
        .post(
            &format!("/admin/users/{}/suspend", user_id),
            &SuspendRequest {
                reason: reason.map(|r| r.to_string()),
            },
        )
        .await
        .context("Failed to suspend user")?;

    println!("✅ User suspended");
    if let Some(reason) = reason {
        println!("   Reason: {}", reason);
    }
    println!(
        "   Status: {}",
        user["status"].as_str().unwrap_or("unknown")
    );

    Ok(())
}

/// Activate user
pub async fn activate(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    user_id: &str,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let user: serde_json::Value = client
        .post(&format!("/admin/users/{}/activate", user_id), &{})
        .await
        .context("Failed to activate user")?;

    println!("✅ User activated");
    println!(
        "   Status: {}",
        user["status"].as_str().unwrap_or("unknown")
    );

    Ok(())
}
