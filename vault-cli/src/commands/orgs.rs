//! Organization management commands

use crate::client::VaultClient;
use crate::commands::{confirm, format_timestamp, print_data, print_table, OutputFormat};
use anyhow::{Context, Result};

/// List organizations with pagination
pub async fn list(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    page: i64,
    per_page: i64,
    status: Option<&str>,
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
    
    if let Some(status) = status {
        params.push(("status", status));
    }

    let response: serde_json::Value = client
        .get_with_params("/admin/organizations", &params)
        .await
        .context("Failed to list organizations")?;

    match format {
        OutputFormat::Table => {
            let data = response.get("data").and_then(|d| d.as_array()).unwrap_or(&vec![]);
            
            if data.is_empty() {
                println!("No organizations found");
                return Ok(());
            }

            let rows: Vec<Vec<String>> = data
                .iter()
                .map(|o| {
                    vec![
                        o["id"].as_str().unwrap_or("N/A").to_string(),
                        o["name"].as_str().unwrap_or("N/A").to_string(),
                        o["slug"].as_str().unwrap_or("N/A").to_string(),
                        o["memberCount"].as_i64().map(|n| n.to_string()).unwrap_or_else(|| "0".to_string()),
                        o["status"].as_str().unwrap_or("N/A").to_string(),
                    ]
                })
                .collect();

            print_table(vec!["ID", "Name", "Slug", "Members", "Status"], rows);

            if let Some(pagination) = response.get("pagination") {
                let total = pagination["total"].as_i64().unwrap_or(0);
                let page = pagination["page"].as_i64().unwrap_or(1);
                let total_pages = pagination["totalPages"].as_i64().unwrap_or(1);
                println!("\nShowing {} of {} organizations (page {} of {})", data.len(), total, page, total_pages);
            }
        }
        _ => {
            print_data(&response, format)?;
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
    description: Option<&str>,
) -> Result<()> {
    let slug = slug
        .map(|s| s.to_string())
        .unwrap_or_else(|| name.to_lowercase().replace(" ", "-").replace("_", "-"));

    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    #[derive(serde::Serialize)]
    struct CreateOrgRequest {
        name: String,
        slug: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    }

    let org: serde_json::Value = client
        .post(
            "/admin/organizations",
            &CreateOrgRequest {
                name: name.to_string(),
                slug,
                description: description.map(|d| d.to_string()),
            },
        )
        .await
        .context("Failed to create organization")?;

    println!("✅ Organization created successfully!");
    println!("   ID: {}", org["id"].as_str().unwrap_or("N/A"));
    println!("   Name: {}", name);
    println!("   Slug: {}", org["slug"].as_str().unwrap_or("N/A"));
    if let Some(desc) = description {
        println!("   Description: {}", desc);
    }

    Ok(())
}

/// Update organization
pub async fn update(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    org_id: &str,
    name: Option<&str>,
    description: Option<&str>,
    website: Option<&str>,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    #[derive(serde::Serialize, Default)]
    struct UpdateOrgRequest {
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(rename = "website", skip_serializing_if = "Option::is_none")]
        website: Option<String>,
    }

    let mut body = UpdateOrgRequest::default();
    
    if let Some(name) = name {
        body.name = Some(name.to_string());
    }
    if let Some(description) = description {
        body.description = Some(description.to_string());
    }
    if let Some(website) = website {
        body.website = Some(website.to_string());
    }

    let org: serde_json::Value = client
        .patch(&format!("/admin/organizations/{}", org_id), &body)
        .await
        .context("Failed to update organization")?;

    println!("✅ Organization updated successfully!");
    print_data(&org, OutputFormat::Table)?;

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
        let confirmed = confirm(&format!(
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
            println!("\n{} member(s)", members.len());
        }
        _ => {
            print_data(&members, format)?;
        }
    }

    Ok(())
}

/// Add member to organization
pub async fn add_member(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    org_id: &str,
    user_id: &str,
    role: &str,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    #[derive(serde::Serialize)]
    struct AddMemberRequest {
        #[serde(rename = "userId")]
        user_id: String,
        role: String,
    }

    let _: serde_json::Value = client
        .post(
            &format!("/admin/organizations/{}/members", org_id),
            &AddMemberRequest {
                user_id: user_id.to_string(),
                role: role.to_string(),
            },
        )
        .await
        .context("Failed to add member")?;

    println!("✅ User {} added to organization {} as {}", user_id, org_id, role);
    Ok(())
}

/// Remove member from organization
pub async fn remove_member(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    org_id: &str,
    user_id: &str,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let _: serde_json::Value = client
        .delete(&format!("/admin/organizations/{}/members/{}", org_id, user_id))
        .await
        .context("Failed to remove member")?;

    println!("✅ User {} removed from organization {}", user_id, org_id);
    Ok(())
}

/// Update member role
pub async fn update_member(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    org_id: &str,
    user_id: &str,
    role: &str,
) -> Result<()> {
    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    #[derive(serde::Serialize)]
    struct UpdateMemberRequest {
        role: String,
    }

    let _: serde_json::Value = client
        .patch(
            &format!("/admin/organizations/{}/members/{}", org_id, user_id),
            &UpdateMemberRequest {
                role: role.to_string(),
            },
        )
        .await
        .context("Failed to update member role")?;

    println!("✅ User {} role updated to {} in organization {}", user_id, role, org_id);
    Ok(())
}
