//! Organization management commands

use crate::client::VaultClient;
use crate::commands::{print_data, print_table, OutputFormat};
use anyhow::{Context, Result};

/// List organizations
pub async fn list(api_url: &str, token: &str, tenant_id: &str, format: OutputFormat) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let response: crate::client::types::OrgList = client
        .get("/admin/organizations")
        .await
        .context("Failed to list organizations")?;

    match format {
        OutputFormat::Table => {
            if response.data.is_empty() {
                println!("No organizations found");
                return Ok(());
            }

            let rows: Vec<Vec<String>> = response
                .data
                .iter()
                .map(|o| {
                    vec![
                        o.id.clone(),
                        o.name.clone(),
                        o.slug.clone(),
                        o.member_count.to_string(),
                        o.status.clone(),
                    ]
                })
                .collect();

            print_table(vec!["ID", "Name", "Slug", "Members", "Status"], rows);

            println!(
                "\nShowing {} of {} organizations",
                response.data.len(),
                response.pagination.total
            );
        }
        _ => {
            print_data(&response.data, format)?;
        }
    }

    Ok(())
}

/// Get organization details
pub async fn get(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    org_id: &str,
    format: OutputFormat,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let org: serde_json::Value = client
        .get(&format!("/admin/organizations/{}", org_id))
        .await
        .context("Failed to get organization")?;

    print_data(&org, format)?;
    Ok(())
}

/// Create organization
pub async fn create(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    name: &str,
    slug: Option<&str>,
) -> Result<()> {
    let slug = slug
        .map(|s| s.to_string())
        .unwrap_or_else(|| name.to_lowercase().replace(" ", "-"));

    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    #[derive(serde::Serialize)]
    struct CreateOrgRequest {
        name: String,
        slug: String,
    }

    let org: serde_json::Value = client
        .post(
            "/admin/organizations",
            &CreateOrgRequest {
                name: name.to_string(),
                slug,
            },
        )
        .await
        .context("Failed to create organization")?;

    println!("✅ Organization created successfully!");
    println!("   ID: {}", org["id"].as_str().unwrap_or("N/A"));
    println!("   Name: {}", name);
    println!("   Slug: {}", org["slug"].as_str().unwrap_or("N/A"));

    Ok(())
}

/// Delete organization
pub async fn delete(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    org_id: &str,
    force: bool,
) -> Result<()> {
    if !force {
        let confirmed = super::confirm(&format!(
            "Are you sure you want to delete organization {}?",
            org_id
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
        .delete(&format!("/admin/organizations/{}", org_id))
        .await
        .context("Failed to delete organization")?;

    println!("✅ Organization {} deleted", org_id);
    Ok(())
}

/// List organization members
pub async fn members(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    org_id: &str,
    format: OutputFormat,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let members: Vec<serde_json::Value> = client
        .get(&format!("/admin/organizations/{}/members", org_id))
        .await
        .context("Failed to list members")?;

    match format {
        OutputFormat::Table => {
            if members.is_empty() {
                println!("No members found");
                return Ok(());
            }

            let rows: Vec<Vec<String>> = members
                .iter()
                .map(|m| {
                    vec![
                        m["userId"].as_str().unwrap_or("N/A").to_string(),
                        m["email"].as_str().unwrap_or("N/A").to_string(),
                        m["name"].as_str().unwrap_or("-").to_string(),
                        m["role"].as_str().unwrap_or("N/A").to_string(),
                        m["status"].as_str().unwrap_or("N/A").to_string(),
                    ]
                })
                .collect();

            print_table(vec!["User ID", "Email", "Name", "Role", "Status"], rows);
        }
        _ => {
            print_data(&members, format)?;
        }
    }

    Ok(())
}
