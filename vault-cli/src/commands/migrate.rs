//! Migration commands for importing and exporting data

use crate::client::VaultClient;
use crate::commands::{print_data, success};
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;

/// Import format
#[derive(Clone, Copy, Debug)]
pub enum ImportFormat {
    Csv,
    Json,
}

/// Export format
#[derive(Clone, Copy, Debug)]
pub enum ExportFormat {
    Csv,
    Json,
    Yaml,
}

/// Import users from file
pub async fn import_users(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    file: &PathBuf,
    format: Option<ImportFormat>,
    dry_run: bool,
) -> Result<()> {
    // Auto-detect format from file extension if not specified
    let format = format.or_else(|| {
        file.extension()
            .and_then(|e| e.to_str())
            .map(|e| match e.to_lowercase().as_str() {
                "csv" => ImportFormat::Csv,
                "json" => ImportFormat::Json,
                _ => ImportFormat::Json,
            })
    });

    println!("📥 Importing users from {:?}...", file);
    if dry_run {
        println!("   (Dry run - no changes will be made)");
    }

    // Read file contents
    let contents = tokio::fs::read_to_string(file)
        .await
        .context("Failed to read import file")?;

    // Parse based on format
    let users: Vec<serde_json::Value> = match format {
        Some(ImportFormat::Csv) => {
            parse_csv_users(&contents)?
        }
        Some(ImportFormat::Json) | None => {
            serde_json::from_str(&contents).context("Failed to parse JSON file")?
        }
    };

    if users.is_empty() {
        println!("No users found in file");
        return Ok(());
    }

    println!("   Found {} user(s) to import", users.len());

    if dry_run {
        println!("\nDry run - would import the following users:");
        for (i, user) in users.iter().enumerate().take(5) {
            let email = user["email"].as_str().unwrap_or("unknown");
            let name = user["name"].as_str().unwrap_or("");
            println!("   {}. {} <{}>", i + 1, name, email);
        }
        if users.len() > 5 {
            println!("   ... and {} more", users.len() - 5);
        }
        return Ok(());
    }

    // Import with progress bar
    let pb = ProgressBar::new(users.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

    let mut imported = 0;
    let mut failed = 0;

    for user in users {
        match import_single_user(&client, &user).await {
            Ok(_) => imported += 1,
            Err(e) => {
                let email = user["email"].as_str().unwrap_or("unknown");
                eprintln!("\n   Failed to import {}: {}", email, e);
                failed += 1;
            }
        }
        pb.inc(1);
    }

    pb.finish_and_clear();

    println!("✅ Import complete!");
    println!("   Imported: {}", imported);
    println!("   Failed:   {}", failed);

    Ok(())
}

/// Parse users from CSV content
fn parse_csv_users(contents: &str) -> Result<Vec<serde_json::Value>> {
    let mut users = Vec::new();
    let mut lines = contents.lines();
    
    // Skip header
    let header = lines.next().context("CSV file is empty")?;
    let headers: Vec<&str> = header.split(',').map(|s| s.trim()).collect();
    
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        
        let values: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        let mut user = serde_json::Map::new();
        
        for (i, header) in headers.iter().enumerate() {
            if let Some(value) = values.get(i) {
                user.insert(header.to_string(), serde_json::Value::String(value.to_string()));
            }
        }
        
        users.push(serde_json::Value::Object(user));
    }
    
    Ok(users)
}

/// Import a single user
async fn import_single_user(
    client: &VaultClient,
    user: &serde_json::Value,
) -> Result<()> {
    let email = user["email"]
        .as_str()
        .context("User missing email")?;
    
    #[derive(serde::Serialize)]
    struct CreateUserRequest {
        email: String,
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    }

    let body = CreateUserRequest {
        email: email.to_string(),
        name: user["name"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| email.split('@').next().unwrap_or("").to_string()),
        password: user["password"].as_str().map(|s| s.to_string()),
    };

    let _: serde_json::Value = client
        .post("/admin/users", &body)
        .await
        .context("Failed to create user")?;

    Ok(())
}

/// Export users to file
pub async fn export_users(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    output: Option<&PathBuf>,
    format: ExportFormat,
    status_filter: Option<&str>,
) -> Result<()> {
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
            .context("Failed to fetch users")?;

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
        ExportFormat::Json => {
            serde_json::to_string_pretty(&all_users)?
        }
        ExportFormat::Yaml => {
            serde_yaml::to_string(&all_users)?
        }
        ExportFormat::Csv => {
            users_to_csv(&all_users)?
        }
    };

    // Write to file or stdout
    if let Some(path) = output {
        tokio::fs::write(path, output_str)
            .await
            .context("Failed to write output file")?;
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

/// Import users from Auth0
pub async fn import_from_auth0(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    domain: &str,
    auth0_token: &str,
    connection: Option<&str>,
) -> Result<()> {
    println!("📥 Importing users from Auth0...");
    println!("   Domain: {}", domain);

    // Fetch users from Auth0 Management API
    let client = reqwest::Client::new();
    let url = format!("https://{}/api/v2/users", domain);
    
    let mut request = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", auth0_token))
        .header("Content-Type", "application/json");
    
    if let Some(conn) = connection {
        request = request.query(&[("connection", conn)]);
    }

    let response = request
        .send()
        .await
        .context("Failed to fetch users from Auth0")?;

    if !response.status().is_success() {
        let error = response.text().await.unwrap_or_default();
        anyhow::bail!("Auth0 API error: {}", error);
    }

    let auth0_users: Vec<serde_json::Value> = response
        .json()
        .await
        .context("Failed to parse Auth0 response")?;

    println!("   Found {} user(s) in Auth0", auth0_users.len());

    // Transform and import to Vault
    let vault_client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);

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
        // Transform Auth0 user format to Vault format
        #[derive(serde::Serialize)]
        struct CreateUserRequest {
            email: String,
            name: String,
            #[serde(rename = "emailVerified")]
            email_verified: bool,
        }

        let email = user["email"].as_str().unwrap_or("");
        if email.is_empty() {
            pb.inc(1);
            continue;
        }

        let name = user["name"]
            .as_str()
            .or_else(|| user["nickname"].as_str())
            .or_else(|| user["given_name"].as_str())
            .unwrap_or(email);

        let body = CreateUserRequest {
            email: email.to_string(),
            name: name.to_string(),
            email_verified: user["email_verified"].as_bool().unwrap_or(false),
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

/// Import users from Firebase
pub async fn import_from_firebase(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    credentials_path: &PathBuf,
    dry_run: bool,
) -> Result<()> {
    println!("📥 Importing users from Firebase...");
    println!("   Credentials: {:?}", credentials_path);

    if dry_run {
        println!("   (Dry run - no changes will be made)");
    }

    // Read Firebase credentials
    let credentials = tokio::fs::read_to_string(credentials_path)
        .await
        .context("Failed to read Firebase credentials file")?;

    let _creds: serde_json::Value = serde_json::from_str(&credentials)
        .context("Invalid Firebase credentials JSON")?;

    println!("   Firebase credentials loaded successfully");

    // Note: In a real implementation, this would:
    // 1. Use the Firebase Admin SDK or REST API to fetch users
    // 2. Handle Firebase's pagination
    // 3. Import users to Vault
    // 4. Optionally import passwords (requires hash parameters)

    println!("\n⚠️  Firebase import requires Firebase Admin SDK integration.");
    println!("   To implement full Firebase import:");
    println!("   1. Set up Firebase Admin SDK");
    println!("   2. Fetch users using list_users() API");
    println!("   3. Import to Vault with password hashes");

    // Placeholder for demonstration
    println!("\n   Would import users with the following mapping:");
    println!("   - uid → metadata.firebase_uid");
    println!("   - email → email");
    println!("   - displayName → name");
    println!("   - emailVerified → emailVerified");
    println!("   - photoURL → metadata.avatar");

    Ok(())
}
