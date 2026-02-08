//! Auth0 migration implementation

use super::types::*;
use crate::client::VaultClient;
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Auth0 API client for fetching users
pub struct Auth0Client {
    domain: String,
    client_id: String,
    client_secret: String,
    audience: String,
    http_client: reqwest::Client,
    access_token: Option<String>,
}

impl Auth0Client {
    pub fn new(domain: impl Into<String>, client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        let domain = domain.into();
        let audience = format!("https://{}/api/v2/", domain);
        
        Self {
            domain,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            audience,
            http_client: reqwest::Client::new(),
            access_token: None,
        }
    }
    
    /// Authenticate and get access token
    pub async fn authenticate(&mut self) -> Result<(), MigrationError> {
        let url = format!("https://{}/oauth/token", self.domain);
        
        let body = serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": &self.client_id,
            "client_secret": &self.client_secret,
            "audience": &self.audience,
        });
        
        let response = self.http_client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| MigrationError::AuthenticationError(e.to_string()))?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(MigrationError::AuthenticationError(error_text));
        }
        
        let token_response: Auth0TokenResponse = response
            .json()
            .await
            .map_err(|e| MigrationError::ParseError(e.to_string()))?;
        
        self.access_token = Some(token_response.access_token);
        Ok(())
    }
    
    /// Fetch users from Auth0 with pagination
    pub async fn fetch_users(&self, page: usize, per_page: usize) -> Result<Vec<Auth0User>, MigrationError> {
        let token = self.access_token.as_ref()
            .ok_or_else(|| MigrationError::AuthenticationError("Not authenticated".to_string()))?;
        
        let url = format!("https://{}/api/v2/users", self.domain);
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
                ("include_totals", "true".to_string()),
            ])
            .send()
            .await?;
        
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(MigrationError::RateLimitExceeded);
        }
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(MigrationError::ApiError(error_text));
        }
        
        let users: Vec<Auth0User> = response
            .json()
            .await
            .map_err(|e| MigrationError::ParseError(e.to_string()))?;
        
        Ok(users)
    }
    
    /// Get total user count
    pub async fn get_user_count(&self) -> Result<usize, MigrationError> {
        let token = self.access_token.as_ref()
            .ok_or_else(|| MigrationError::AuthenticationError("Not authenticated".to_string()))?;
        
        let url = format!("https://{}/api/v2/users", self.domain);
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .query(&[
                ("page", "0".to_string()),
                ("per_page", "1".to_string()),
                ("include_totals", "true".to_string()),
            ])
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(MigrationError::ApiError(error_text));
        }
        
        // Auth0 returns total in the X-Total-Count header or in the response body
        let total: usize = response
            .headers()
            .get("X-Total-Count")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        
        Ok(total)
    }
    
    /// Fetch connections from Auth0
    pub async fn fetch_connections(&self) -> Result<Vec<Auth0Connection>, MigrationError> {
        let token = self.access_token.as_ref()
            .ok_or_else(|| MigrationError::AuthenticationError("Not authenticated".to_string()))?;
        
        let url = format!("https://{}/api/v2/connections", self.domain);
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(MigrationError::ApiError(error_text));
        }
        
        let connections: Vec<Auth0Connection> = response
            .json()
            .await
            .map_err(|e| MigrationError::ParseError(e.to_string()))?;
        
        Ok(connections)
    }
}

/// Auth0 OAuth token response
#[derive(Debug, Deserialize)]
struct Auth0TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

/// Auth0 user structure
#[derive(Debug, Deserialize, Clone)]
pub struct Auth0User {
    pub user_id: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub phone_number: Option<String>,
    pub phone_verified: Option<bool>,
    pub name: Option<String>,
    pub nickname: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub identities: Vec<Auth0Identity>,
    pub app_metadata: Option<HashMap<String, serde_json::Value>>,
    pub user_metadata: Option<HashMap<String, serde_json::Value>>,
    pub last_login: Option<String>,
    pub last_ip: Option<String>,
    pub logins_count: Option<i64>,
    pub blocked: Option<bool>,
}

/// Auth0 identity (social connections)
#[derive(Debug, Deserialize, Clone)]
pub struct Auth0Identity {
    pub connection: String,
    pub provider: String,
    pub user_id: String,
    pub is_social: bool,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

/// Auth0 connection
#[derive(Debug, Deserialize)]
pub struct Auth0Connection {
    pub id: String,
    pub name: String,
    pub strategy: String,
}

/// Auth0 migration implementation
pub struct Auth0Migration {
    auth0_client: Auth0Client,
    vault_client: VaultClient,
    options: MigrationOptions,
    report: MigrationReport,
}

impl Auth0Migration {
    pub fn new(
        domain: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        vault_client: VaultClient,
    ) -> Self {
        Self {
            auth0_client: Auth0Client::new(domain, client_id, client_secret),
            vault_client,
            options: MigrationOptions::new(),
            report: MigrationReport::new(),
        }
    }
    
    pub fn with_options(mut self, options: MigrationOptions) -> Self {
        self.options = options;
        self
    }
    
    /// Transform Auth0 user to Vault user format
    fn transform_user(&self, auth0_user: &Auth0User) -> ImportUser {
        let email = auth0_user.email.clone()
            .unwrap_or_else(|| format!("{}@placeholder.local", auth0_user.user_id));
        
        // Build name from available fields
        let name = auth0_user.name.clone()
            .or_else(|| {
                let given = auth0_user.given_name.as_deref().unwrap_or("");
                let family = auth0_user.family_name.as_deref().unwrap_or("");
                if !given.is_empty() || !family.is_empty() {
                    Some(format!("{} {}", given, family).trim().to_string())
                } else {
                    None
                }
            })
            .or_else(|| auth0_user.nickname.clone())
            .or_else(|| auth0_user.username.clone());
        
        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert("auth0_user_id".to_string(), serde_json::json!(auth0_user.user_id));
        metadata.insert("auth0_connection".to_string(), 
            serde_json::json!(auth0_user.identities.first().map(|i| i.connection.clone())));
        
        if let Some(app_meta) = &auth0_user.app_metadata {
            metadata.insert("auth0_app_metadata".to_string(), serde_json::json!(app_meta));
        }
        if let Some(user_meta) = &auth0_user.user_metadata {
            metadata.insert("auth0_user_metadata".to_string(), serde_json::json!(user_meta));
        }
        if let Some(logins) = auth0_user.logins_count {
            metadata.insert("auth0_logins_count".to_string(), serde_json::json!(logins));
        }
        if let Some(last_login) = &auth0_user.last_login {
            metadata.insert("auth0_last_login".to_string(), serde_json::json!(last_login));
        }
        
        // Transform identities
        let identities: Vec<UserIdentity> = auth0_user.identities.iter()
            .filter(|i| i.is_social)
            .map(|i| UserIdentity {
                provider: i.provider.clone(),
                provider_user_id: i.user_id.clone(),
                access_token: i.access_token.clone(),
                refresh_token: i.refresh_token.clone(),
                expires_at: None,
            })
            .collect();
        
        ImportUser {
            email,
            name,
            email_verified: auth0_user.email_verified.unwrap_or(false),
            password_hash: None, // Auth0 passwords require special export
            phone: auth0_user.phone_number.clone(),
            avatar_url: auth0_user.picture.clone(),
            created_at: auth0_user.created_at.clone(),
            metadata: Some(metadata),
            identities: if identities.is_empty() { None } else { Some(identities) },
        }
    }
    
    /// Import a single user to Vault
    async fn import_user(&self, user: &ImportUser) -> Result<(), MigrationError> {
        #[derive(Serialize)]
        struct CreateUserRequest {
            email: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            name: Option<String>,
            #[serde(rename = "emailVerified")]
            email_verified: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            phone: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            avatar_url: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            metadata: Option<HashMap<String, serde_json::Value>>,
        }
        
        let body = CreateUserRequest {
            email: user.email.clone(),
            name: user.name.clone(),
            email_verified: user.email_verified,
            phone: user.phone.clone(),
            avatar_url: user.avatar_url.clone(),
            metadata: user.metadata.clone(),
        };
        
        match self.vault_client.post::<serde_json::Value, _>("/admin/users", &body).await {
            Ok(_) => Ok(()),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("already exists") {
                    match self.options.conflict_strategy {
                        ConflictStrategy::Skip => Ok(()),
                        ConflictStrategy::Update => {
                            // TODO: Implement update logic
                            Ok(())
                        }
                        ConflictStrategy::Fail => Err(MigrationError::Conflict(err_str)),
                        _ => Ok(()),
                    }
                } else {
                    Err(MigrationError::ImportError(err_str))
                }
            }
        }
    }
    
    /// Get password migration recommendations
    pub async fn get_password_recommendations(&self) -> Vec<String> {
        vec![
            "Auth0 uses bcrypt for password hashing.".to_string(),
            "Vault uses Argon2id.".to_string(),
            "Options:".to_string(),
            "1. Force password reset (recommended) - Users will set new passwords on first login".to_string(),
            "2. Export bcrypt hashes from Auth0 and re-hash on first login".to_string(),
            "3. Use Auth0's password export feature (requires enterprise plan)".to_string(),
        ]
    }
}

#[async_trait::async_trait]
impl Migrator for Auth0Migration {
    async fn preview(&self) -> Result<MigrationPreview, MigrationError> {
        let mut client = Auth0Client {
            domain: self.auth0_client.domain.clone(),
            client_id: self.auth0_client.client_id.clone(),
            client_secret: self.auth0_client.client_secret.clone(),
            audience: self.auth0_client.audience.clone(),
            http_client: self.auth0_client.http_client.clone(),
            access_token: self.auth0_client.access_token.clone(),
        };
        
        client.authenticate().await?;
        let total = client.get_user_count().await?;
        let sample_users = client.fetch_users(0, 5).await?;
        
        let preview_users: Vec<PreviewUser> = sample_users.iter()
            .map(|u| PreviewUser {
                email: u.email.clone().unwrap_or_default(),
                name: u.name.clone().or_else(|| u.nickname.clone()),
                source_id: u.user_id.clone(),
            })
            .collect();
        
        Ok(MigrationPreview {
            user_count: total,
            organization_count: 0, // Auth0 doesn't have organizations in the same way
            sample_users: preview_users,
            estimated_time_secs: (total / 10) as u64, // Rough estimate
        })
    }
    
    async fn migrate(&mut self) -> Result<MigrationReport, MigrationError> {
        let start_time = std::time::Instant::now();
        
        // Authenticate with Auth0
        self.auth0_client.authenticate().await?;
        
        // Get total count for progress
        let total = self.auth0_client.get_user_count().await?;
        
        if self.options.dry_run {
            println!("🔍 DRY RUN MODE - No changes will be made");
            println!("   Would migrate {} users from Auth0", total);
            return Ok(MigrationReport {
                total_count: total,
                ..Default::default()
            });
        }
        
        // Create progress bar
        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        
        let batch_size = self.options.batch_size;
        let mut page = self.options.resume_offset.unwrap_or(0) / batch_size;
        let has_more = true;
        
        while has_more {
            let users = match self.auth0_client.fetch_users(page, batch_size).await {
                Ok(u) => u,
                Err(e) => {
                    if matches!(e, MigrationError::RateLimitExceeded) {
                        println!("\n⏳ Rate limit hit, waiting 60 seconds...");
                        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                        continue;
                    }
                    return Err(e);
                }
            };
            
            if users.is_empty() {
                break;
            }
            
            for auth0_user in users {
                let import_user = self.transform_user(&auth0_user);
                
                match self.import_user(&import_user).await {
                    Ok(()) => self.report.add_success(),
                    Err(e) if matches!(e, MigrationError::Conflict(_)) => {
                        self.report.add_skipped();
                    }
                    Err(e) => {
                        self.report.add_failure(
                            import_user.email.clone(),
                            e.to_string(),
                        );
                    }
                }
                
                pb.inc(1);
            }
            
            page += 1;
        }
        
        pb.finish_and_clear();
        
        self.report.duration_secs = start_time.elapsed().as_secs();
        Ok(self.report.clone())
    }
    
    async fn validate(&self) -> Result<(), MigrationError> {
        // Validate credentials by attempting authentication
        let mut client = Auth0Client {
            domain: self.auth0_client.domain.clone(),
            client_id: self.auth0_client.client_id.clone(),
            client_secret: self.auth0_client.client_secret.clone(),
            audience: self.auth0_client.audience.clone(),
            http_client: self.auth0_client.http_client.clone(),
            access_token: None,
        };
        
        client.authenticate().await?;
        
        // Check that we can fetch at least one user
        let _ = client.fetch_users(0, 1).await?;
        
        Ok(())
    }
}

/// CLI arguments for Auth0 migration
#[derive(clap::Args, Clone, Debug)]
pub struct MigrateAuth0Args {
    /// Auth0 domain (e.g., myapp.auth0.com)
    #[arg(long)]
    pub auth0_domain: String,
    
    /// Auth0 Management API client ID
    #[arg(long)]
    pub auth0_client_id: String,
    
    /// Auth0 Management API client secret
    #[arg(long)]
    pub auth0_client_secret: String,
    
    /// Dry run (preview without importing)
    #[arg(long, default_value = "false")]
    pub dry_run: bool,
    
    /// Batch size for processing
    #[arg(long, default_value = "100")]
    pub batch_size: usize,
    
    /// Conflict resolution strategy (skip/update/merge/fail)
    #[arg(long, default_value = "skip")]
    pub on_conflict: String,
    
    /// Resume from specific offset
    #[arg(long)]
    pub resume_from: Option<usize>,
    
    /// Show password migration recommendations
    #[arg(long)]
    pub password_help: bool,
}

/// Execute Auth0 migration from CLI
pub async fn execute(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    args: MigrateAuth0Args,
) -> Result<()> {
    // Show password help if requested
    if args.password_help {
        println!("🔐 Auth0 Password Migration Help");
        println!("═══════════════════════════════════════");
        let migration = Auth0Migration::new(
            &args.auth0_domain,
            &args.auth0_client_id,
            &args.auth0_client_secret,
            VaultClient::new(api_url), // dummy client
        );
        let recommendations = migration.get_password_recommendations().await;
        for rec in recommendations {
            println!("{}", rec);
        }
        return Ok(());
    }
    
    let vault_client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);
    
    let conflict_strategy = args.on_conflict.parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    
    let options = MigrationOptions::new()
        .with_dry_run(args.dry_run)
        .with_batch_size(args.batch_size)
        .with_conflict_strategy(conflict_strategy);
    
    let mut migrator = Auth0Migration::new(
        args.auth0_domain,
        args.auth0_client_id,
        args.auth0_client_secret,
        vault_client,
    ).with_options(options);
    
    // Validate first
    println!("🔍 Validating Auth0 credentials...");
    migrator.validate().await
        .map_err(|e| anyhow::anyhow!("Failed to validate Auth0 credentials: {}", e))?;
    println!("✅ Credentials validated successfully\n");
    
    // Preview
    let preview = migrator.preview().await?;
    println!("📊 Migration Preview");
    println!("   Users to migrate: {}", preview.user_count);
    println!("   Estimated time: {}s", preview.estimated_time_secs);
    
    if !preview.sample_users.is_empty() {
        println!("\n   Sample users:");
        for user in &preview.sample_users {
            println!("     - {} <{}>", 
                user.name.as_deref().unwrap_or("N/A"),
                user.email
            );
        }
    }
    
    if args.dry_run {
        println!("\n🔍 Dry run complete. No changes were made.");
        return Ok(());
    }
    
    // Confirm before proceeding
    if !args.dry_run {
        let proceed = dialoguer::Confirm::new()
            .with_prompt("Proceed with migration?")
            .default(false)
            .interact()?;
        
        if !proceed {
            println!("Migration cancelled.");
            return Ok(());
        }
    }
    
    // Run migration
    println!("\n🚀 Starting migration...\n");
    let report = migrator.migrate().await?;
    
    // Print report
    report.print_summary();
    
    Ok(())
}
