//! Migration commands for importing users from external identity providers
//!
//! This module provides comprehensive migration tools for importing users from:
//! - Auth0
//! - Clerk
//! - Firebase Authentication
//! - Generic CSV/JSON files
//!
//! # Features
//!
//! - **Dry-run mode**: Preview migrations without making changes
//! - **Batch processing**: Efficiently handle large user bases
//! - **Resume capability**: Continue interrupted migrations
//! - **Conflict resolution**: Handle duplicate users gracefully
//! - **Progress reporting**: Real-time feedback during migration
//! - **Validation**: Pre-migration validation of credentials and data

use crate::client::VaultClient;
use anyhow::Result;

// Sub-modules
pub mod auth0;
pub mod clerk;
pub mod csv;
pub mod firebase;
pub mod types;

// Re-export types
pub use types::*;

// Legacy exports for backward compatibility
pub use csv::CsvMigration;
pub use types::{ConflictStrategy, ExportFormat, ImportFormat, MigrationOptions};

/// Import format (legacy compatibility)
pub use types::ImportFormat as LegacyImportFormat;
pub use types::ExportFormat as LegacyExportFormat;

/// Import users from file (legacy function)
pub async fn import_users(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    file: &std::path::PathBuf,
    format: Option<types::ImportFormat>,
    dry_run: bool,
) -> Result<()> {
    use csv::CsvImportOptions;
    
    let vault_client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);
    
    let options = CsvImportOptions {
        base: MigrationOptions::new().with_dry_run(dry_run),
        format,
        ..Default::default()
    };
    
    let mut migrator = CsvMigration::new(file.clone(), vault_client)
        .with_options(options);
    
    let preview = migrator.preview().await?;
    
    if dry_run {
        println!("🔍 DRY RUN MODE - No changes will be made");
        println!("   Would import {} users from {:?}", preview.user_count, file);
        return Ok(());
    }
    
    println!("📥 Importing {} users from {:?}...", preview.user_count, file);
    
    let report = migrator.import().await?;
    report.print_summary();
    
    Ok(())
}

/// Export users to file (legacy function)
pub async fn export_users(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    output: Option<&std::path::PathBuf>,
    format: types::ExportFormat,
    status_filter: Option<&str>,
) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};
    
    println!("📤 Exporting users...");

    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    // Fetch all users (with pagination)
    let mut all_users = Vec::new();
    let mut page = 1;
    let per_page = 100;

    loop {
        let page_str = page.to_string();
        let per_page_str = per_page.to_string();
        let mut params = vec![
            ("page", page_str.as_str()),
            ("per_page", per_page_str.as_str()),
        ];

        if let Some(status) = status_filter {
            params.push(("status", status));
        }

        let response: serde_json::Value = client
            .get_with_params("/admin/users", &params)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch users: {}", e))?;

        let users = response.get("users").and_then(|u| u.as_array());
        
        if let Some(users) = users {
            if users.is_empty() {
                break;
            }
            all_users.extend(users.clone());
        } else {
            break;
        }

        // Check if we've fetched all pages
        let total = response["pagination"]["total"].as_i64().unwrap_or(0);
        let current_total = all_users.len() as i64;
        
        if current_total >= total {
            break;
        }

        page += 1;
    }

    println!("   Exported {} user(s)", all_users.len());

    // Format output
    let output_str = match format {
        types::ExportFormat::Json => {
            serde_json::to_string_pretty(&all_users)?
        }
        types::ExportFormat::Yaml => {
            serde_yaml::to_string(&all_users)?
        }
        types::ExportFormat::Csv => {
            users_to_csv(&all_users)?
        }
    };

    // Write to file or stdout
    if let Some(path) = output {
        tokio::fs::write(path, output_str).await?;
        println!("✅ Users exported to {}", path.display());
    } else {
        println!("{}", output_str);
    }

    Ok(())
}

/// Convert users to CSV format
fn users_to_csv(users: &[serde_json::Value]) -> Result<String> {
    let mut output = String::new();
    
    // Header
    output.push_str("id,email,name,status,email_verified,created_at\n");
    
    // Data rows
    for user in users {
        let id = user["id"].as_str().unwrap_or("");
        let email = user["email"].as_str().unwrap_or("");
        let name = user["name"].as_str().unwrap_or("");
        let status = user["status"].as_str().unwrap_or("");
        let verified = user["emailVerified"].as_bool().unwrap_or(false);
        let created = user["createdAt"].as_str().unwrap_or("");
        
        output.push_str(&format!(
            "{},{},{},{},{},{}\n",
            escape_csv(id),
            escape_csv(email),
            escape_csv(name),
            escape_csv(status),
            verified,
            escape_csv(created)
        ));
    }
    
    Ok(output)
}

/// Escape a CSV field
fn escape_csv(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Import users from Auth0 (legacy function - delegates to new implementation)
pub async fn import_from_auth0(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    domain: &str,
    auth0_token: &str,
    connection: Option<&str>,
) -> Result<()> {
    use crate::commands::migrate::auth0::{Auth0Client, Auth0Migration};
    
    println!("📥 Importing users from Auth0...");
    println!("   Domain: {}", domain);

    let vault_client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    // Use the legacy method with direct token
    let http_client = reqwest::Client::new();
    let url = format!("https://{}/api/v2/users", domain);
    
    let mut request = http_client
        .get(&url)
        .header("Authorization", format!("Bearer {}", auth0_token))
        .header("Content-Type", "application/json");
    
    if let Some(conn) = connection {
        request = request.query(&[("connection", conn)]);
    }

    let response = request
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch users from Auth0: {}", e))?;

    if !response.status().is_success() {
        let error = response.text().await.unwrap_or_default();
        anyhow::bail!("Auth0 API error: {}", error);
    }

    let auth0_users: Vec<serde_json::Value> = response
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse Auth0 response: {}", e))?;

    println!("   Found {} user(s) in Auth0", auth0_users.len());

    // Import with progress bar
    use indicatif::{ProgressBar, ProgressStyle};
    
    let pb = ProgressBar::new(auth0_users.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut imported = 0;
    let mut failed = 0;

    for user in &auth0_users {
        #[derive(serde::Serialize)]
        struct CreateUserRequest {
            email: String,
            name: String,
            #[serde(rename = "emailVerified")]
            email_verified: bool,
        }

        let email = user.get("email").and_then(|e| e.as_str()).unwrap_or("");
        if email.is_empty() {
            pb.inc(1);
            continue;
        }

        let name = user.get("name").and_then(|n| n.as_str())
            .or_else(|| user.get("nickname").and_then(|n| n.as_str()))
            .or_else(|| user.get("given_name").and_then(|g| g.as_str()))
            .unwrap_or(email);

        let body = CreateUserRequest {
            email: email.to_string(),
            name: name.to_string(),
            email_verified: user.get("email_verified").and_then(|e| e.as_bool()).unwrap_or(false),
        };

        match vault_client.post::<serde_json::Value, _>("/admin/users", &body).await {
            Ok(_) => imported += 1,
            Err(e) => {
                if e.to_string().contains("already exists") {
                    // User already exists, skip silently
                } else {
                    eprintln!("\n   Failed to import {}: {}", email, e);
                    failed += 1;
                }
            }
        }
        pb.inc(1);
    }

    pb.finish_and_clear();

    println!("✅ Auth0 import complete!");
    println!("   Imported: {}", imported);
    println!("   Failed:   {}", failed);
    println!("   Skipped:  {} (already exist)", auth0_users.len() - imported - failed);

    Ok(())
}

/// Import users from Firebase (legacy function)
pub async fn import_from_firebase(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    credentials_path: &std::path::PathBuf,
    dry_run: bool,
) -> Result<()> {
    use crate::commands::migrate::firebase::{FirebaseMigration, ServiceAccountKey};
    
    // Read credentials file
    let credentials_content = tokio::fs::read_to_string(credentials_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read Firebase credentials file: {}", e))?;
    
    let credentials: ServiceAccountKey = serde_json::from_str(&credentials_content)
        .map_err(|e| anyhow::anyhow!("Invalid Firebase credentials JSON: {}", e))?;
    
    let vault_client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);
    
    let options = MigrationOptions::new().with_dry_run(dry_run);
    
    let mut migrator = FirebaseMigration::new(credentials, vault_client)
        .with_options(options);
    
    // Validate
    println!("🔍 Validating Firebase credentials...");
    migrator.validate().await
        .map_err(|e| anyhow::anyhow!("Failed to validate Firebase credentials: {}", e))?;
    println!("✅ Credentials validated successfully\n");
    
    // Preview
    let preview = migrator.preview().await?;
    println!("📊 Migration Preview");
    println!("   Users to migrate: {}", preview.user_count);
    
    if dry_run {
        println!("\n🔍 Dry run complete. No changes were made.");
        return Ok(());
    }
    
    // Confirm
    let proceed = dialoguer::Confirm::new()
        .with_prompt("Proceed with migration?")
        .default(false)
        .interact()?;
    
    if !proceed {
        println!("Migration cancelled.");
        return Ok(());
    }
    
    // Run migration
    println!("\n🚀 Starting migration...\n");
    let report = migrator.migrate().await?;
    report.print_summary();
    
    Ok(())
}
