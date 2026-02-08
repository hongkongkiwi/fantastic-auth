//! Clerk migration implementation

use super::types::*;
use crate::client::VaultClient;
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Clerk API client
pub struct ClerkClient {
    secret_key: String,
    http_client: reqwest::Client,
}

impl ClerkClient {
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            secret_key: secret_key.into(),
            http_client: reqwest::Client::new(),
        }
    }
    
    fn base_url(&self) -> &'static str {
        "https://api.clerk.com/v1"
    }
    
    fn auth_header(&self) -> String {
        format!("Bearer {}", self.secret_key)
    }
    
    /// Fetch users with pagination
    pub async fn fetch_users(&self, offset: usize, limit: usize) -> Result<Vec<ClerkUser>, MigrationError> {
        let url = format!("{}/users", self.base_url());
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .query(&[
                ("offset", offset.to_string()),
                ("limit", limit.to_string()),
            ])
            .send()
            .await?;
        
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(MigrationError::AuthenticationError(
                "Invalid Clerk secret key".to_string()
            ));
        }
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(MigrationError::ApiError(error_text));
        }
        
        let users: Vec<ClerkUser> = response
            .json()
            .await
            .map_err(|e| MigrationError::ParseError(e.to_string()))?;
        
        Ok(users)
    }
    
    /// Fetch organizations
    pub async fn fetch_organizations(&self, offset: usize, limit: usize) -> Result<Vec<ClerkOrganization>, MigrationError> {
        let url = format!("{}/organizations", self.base_url());
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .query(&[
                ("offset", offset.to_string()),
                ("limit", limit.to_string()),
            ])
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(MigrationError::ApiError(error_text));
        }
        
        let orgs: Vec<ClerkOrganization> = response
            .json()
            .await
            .map_err(|e| MigrationError::ParseError(e.to_string()))?;
        
        Ok(orgs)
    }
    
    /// Fetch organization memberships
    pub async fn fetch_org_memberships(&self, org_id: &str) -> Result<Vec<ClerkOrgMembership>, MigrationError> {
        let url = format!("{}/organizations/{}/memberships", self.base_url(), org_id);
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(MigrationError::ApiError(error_text));
        }
        
        // Clerk returns { data: [...] } for memberships
        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| MigrationError::ParseError(e.to_string()))?;
        
        let memberships: Vec<ClerkOrgMembership> = serde_json::from_value(
            result.get("data").cloned().unwrap_or_default()
        ).map_err(|e| MigrationError::ParseError(e.to_string()))?;
        
        Ok(memberships)
    }
    
    /// Get total user count
    pub async fn get_user_count(&self) -> Result<usize, MigrationError> {
        // Clerk doesn't have a direct count endpoint, so we fetch with limit=1
        let url = format!("{}/users", self.base_url());
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .query(&[("limit", "1")])
            .send()
            .await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(MigrationError::ApiError(error_text));
        }
        
        // Try to get count from headers or just return 0
        let total: usize = response
            .headers()
            .get("X-Total-Count")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        
        Ok(total)
    }
}

/// Clerk user structure
#[derive(Debug, Deserialize, Clone)]
pub struct ClerkUser {
    pub id: String,
    #[serde(rename = "email_addresses")]
    pub email_addresses: Vec<ClerkEmail>,
    #[serde(rename = "primary_email_address_id")]
    pub primary_email_address_id: Option<String>,
    #[serde(rename = "phone_numbers")]
    pub phone_numbers: Vec<ClerkPhone>,
    #[serde(rename = "username")]
    pub username: Option<String>,
    #[serde(rename = "first_name")]
    pub first_name: Option<String>,
    #[serde(rename = "last_name")]
    pub last_name: Option<String>,
    #[serde(rename = "profile_image_url")]
    pub profile_image_url: Option<String>,
    #[serde(rename = "email_verified")]
    pub email_verified: Option<bool>,
    #[serde(rename = "created_at")]
    pub created_at: i64,
    #[serde(rename = "updated_at")]
    pub updated_at: i64,
    #[serde(rename = "last_sign_in_at")]
    pub last_sign_in_at: Option<i64>,
    #[serde(rename = "public_metadata")]
    pub public_metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "private_metadata")]
    pub private_metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "unsafe_metadata")]
    pub unsafe_metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Clerk email address
#[derive(Debug, Deserialize, Clone)]
pub struct ClerkEmail {
    pub id: String,
    #[serde(rename = "email_address")]
    pub email_address: String,
    pub verification: Option<ClerkVerification>,
}

/// Clerk phone number
#[derive(Debug, Deserialize, Clone)]
pub struct ClerkPhone {
    pub id: String,
    #[serde(rename = "phone_number")]
    pub phone_number: String,
    pub verification: Option<ClerkVerification>,
}

/// Clerk verification status
#[derive(Debug, Deserialize, Clone)]
pub struct ClerkVerification {
    pub status: String,
    pub strategy: Option<String>,
}

/// Clerk organization
#[derive(Debug, Deserialize)]
pub struct ClerkOrganization {
    pub id: String,
    pub name: String,
    pub slug: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: i64,
    #[serde(rename = "updated_at")]
    pub updated_at: i64,
    #[serde(rename = "admin_delete_enabled")]
    pub admin_delete_enabled: bool,
    #[serde(rename = "public_metadata")]
    pub public_metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "private_metadata")]
    pub private_metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "max_allowed_memberships")]
    pub max_allowed_memberships: Option<i64>,
}

/// Clerk organization membership
#[derive(Debug, Deserialize)]
pub struct ClerkOrgMembership {
    pub id: String,
    pub role: String,
    #[serde(rename = "created_at")]
    pub created_at: i64,
    #[serde(rename = "updated_at")]
    pub updated_at: i64,
    pub public_user_data: ClerkPublicUserData,
}

/// Public user data in membership
#[derive(Debug, Deserialize)]
pub struct ClerkPublicUserData {
    #[serde(rename = "user_id")]
    pub user_id: String,
    #[serde(rename = "first_name")]
    pub first_name: Option<String>,
    #[serde(rename = "last_name")]
    pub last_name: Option<String>,
    #[serde(rename = "profile_image_url")]
    pub profile_image_url: Option<String>,
    pub identifier: String, // Email
}

/// Clerk migration implementation
pub struct ClerkMigration {
    clerk_client: ClerkClient,
    vault_client: VaultClient,
    options: MigrationOptions,
    report: MigrationReport,
    org_report: MigrationReport,
}

impl ClerkMigration {
    pub fn new(
        secret_key: impl Into<String>,
        vault_client: VaultClient,
    ) -> Self {
        Self {
            clerk_client: ClerkClient::new(secret_key),
            vault_client,
            options: MigrationOptions::new(),
            report: MigrationReport::new(),
            org_report: MigrationReport::new(),
        }
    }
    
    pub fn with_options(mut self, options: MigrationOptions) -> Self {
        self.options = options;
        self
    }
    
    /// Get primary email from user
    fn get_primary_email(&self, user: &ClerkUser) -> Option<String> {
        if let Some(primary_id) = &user.primary_email_address_id {
            user.email_addresses.iter()
                .find(|e| &e.id == primary_id)
                .map(|e| e.email_address.clone())
        } else {
            user.email_addresses.first()
                .map(|e| e.email_address.clone())
        }
    }
    
    /// Transform Clerk user to Vault format
    fn transform_user(&self, clerk_user: &ClerkUser) -> ImportUser {
        let email = self.get_primary_email(clerk_user)
            .unwrap_or_else(|| format!("{}@placeholder.local", clerk_user.id));
        
        let name = if clerk_user.first_name.is_some() || clerk_user.last_name.is_some() {
            let first = clerk_user.first_name.as_deref().unwrap_or("");
            let last = clerk_user.last_name.as_deref().unwrap_or("");
            let full = format!("{} {}", first, last).trim().to_string();
            if full.is_empty() { None } else { Some(full) }
        } else {
            clerk_user.username.clone()
        };
        
        let phone = clerk_user.phone_numbers.first()
            .map(|p| p.phone_number.clone());
        
        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert("clerk_user_id".to_string(), serde_json::json!(clerk_user.id));
        metadata.insert("clerk_username".to_string(), serde_json::json!(clerk_user.username));
        
        if let Some(pub_meta) = &clerk_user.public_metadata {
            metadata.insert("clerk_public_metadata".to_string(), serde_json::json!(pub_meta));
        }
        if let Some(last_sign_in) = clerk_user.last_sign_in_at {
            metadata.insert("clerk_last_sign_in_at".to_string(), serde_json::json!(last_sign_in));
        }
        
        // Format timestamp
        let created_at = chrono::DateTime::from_timestamp(clerk_user.created_at, 0)
            .map(|dt| dt.to_rfc3339());
        
        ImportUser {
            email,
            name,
            email_verified: clerk_user.email_verified.unwrap_or(false),
            password_hash: None,
            phone,
            avatar_url: clerk_user.profile_image_url.clone(),
            created_at,
            metadata: Some(metadata),
            identities: None,
        }
    }
    
    /// Import a single user
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
                        _ => Err(MigrationError::Conflict(err_str)),
                    }
                } else {
                    Err(MigrationError::ImportError(err_str))
                }
            }
        }
    }
    
    /// Transform Clerk org to Vault format
    fn transform_org(&self, clerk_org: &ClerkOrganization) -> ImportOrganization {
        ImportOrganization {
            name: clerk_org.name.clone(),
            slug: clerk_org.slug.clone(),
            description: None,
            metadata: clerk_org.public_metadata.clone(),
            members: Vec::new(), // Will be populated separately
        }
    }
    
    /// Migrate organizations and their memberships
    pub async fn migrate_organizations(&mut self) -> Result<MigrationReport, MigrationError> {
        let start_time = std::time::Instant::now();
        let mut has_more = true;
        let mut offset = 0;
        let batch_size = self.options.batch_size;
        
        println!("\n🏢 Migrating organizations...");
        
        while has_more {
            let orgs = self.clerk_client.fetch_organizations(offset, batch_size).await?;
            
            if orgs.is_empty() {
                has_more = false;
                break;
            }
            
            for clerk_org in orgs {
                let org = self.transform_org(&clerk_org);
                
                // Create organization
                #[derive(Serialize)]
                struct CreateOrgRequest {
                    name: String,
                    slug: Option<String>,
                    description: Option<String>,
                }
                
                let body = CreateOrgRequest {
                    name: org.name,
                    slug: org.slug,
                    description: org.description,
                };
                
                match self.vault_client.post::<serde_json::Value, _>("/admin/orgs", &body).await {
                    Ok(created_org) => {
                        self.org_report.add_success();
                        
                        // Fetch and migrate memberships
                        if let Ok(memberships) = self.clerk_client.fetch_org_memberships(&clerk_org.id).await {
                            let org_id = created_org["id"].as_str().unwrap_or_default();
                            
                            for membership in memberships {
                                // Find or create user by email
                                let email = membership.public_user_data.identifier.clone();
                                let role = membership.role.clone();
                                
                                // Add member to org
                                #[derive(Serialize)]
                                struct AddMemberRequest {
                                    email: String,
                                    role: String,
                                }
                                
                                let member_body = AddMemberRequest { email, role };
                                let _ = self.vault_client
                                    .post::<serde_json::Value, _>(
                                        &format!("/admin/orgs/{}/members", org_id),
                                        &member_body
                                    )
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        self.org_report.add_failure(
                            clerk_org.name.clone(),
                            e.to_string(),
                        );
                    }
                }
            }
            
            offset += batch_size;
        }
        
        self.org_report.duration_secs = start_time.elapsed().as_secs();
        Ok(self.org_report.clone())
    }
}

#[async_trait::async_trait]
impl Migrator for ClerkMigration {
    async fn preview(&self) -> Result<MigrationPreview, MigrationError> {
        // Fetch sample users
        let sample_users = self.clerk_client.fetch_users(0, 5).await?;
        let total = self.clerk_client.get_user_count().await?;
        
        let preview_users: Vec<PreviewUser> = sample_users.iter()
            .map(|u| PreviewUser {
                email: self.get_primary_email(u).unwrap_or_default(),
                name: u.first_name.as_ref().map(|f| {
                    format!("{} {}", f, u.last_name.as_deref().unwrap_or("")).trim().to_string()
                }),
                source_id: u.id.clone(),
            })
            .collect();
        
        // Count organizations
        let orgs = self.clerk_client.fetch_organizations(0, 100).await?;
        let org_count = orgs.len();
        
        Ok(MigrationPreview {
            user_count: total,
            organization_count: org_count,
            sample_users: preview_users,
            estimated_time_secs: ((total + org_count) / 10) as u64,
        })
    }
    
    async fn migrate(&mut self) -> Result<MigrationReport, MigrationError> {
        let start_time = std::time::Instant::now();
        
        // Get estimated count
        let total = self.clerk_client.get_user_count().await?;
        
        if self.options.dry_run {
            println!("🔍 DRY RUN MODE - No changes will be made");
            println!("   Would migrate {} users from Clerk", total);
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
        let mut offset = self.options.resume_offset.unwrap_or(0);
        let has_more = true;
        
        while has_more {
            let users = self.clerk_client.fetch_users(offset, batch_size).await?;
            
            if users.is_empty() {
                break;
            }
            
            for clerk_user in users {
                let import_user = self.transform_user(&clerk_user);
                
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
            
            offset += batch_size;
        }
        
        pb.finish_and_clear();
        
        self.report.duration_secs = start_time.elapsed().as_secs();
        Ok(self.report.clone())
    }
    
    async fn validate(&self) -> Result<(), MigrationError> {
        // Test by fetching a single user
        let _ = self.clerk_client.fetch_users(0, 1).await?;
        Ok(())
    }
}

/// CLI arguments for Clerk migration
#[derive(clap::Args, Clone, Debug)]
pub struct MigrateClerkArgs {
    /// Clerk secret key (sk_...)
    #[arg(long)]
    pub clerk_secret_key: String,
    
    /// Dry run (preview without importing)
    #[arg(long, default_value = "false")]
    pub dry_run: bool,
    
    /// Batch size for processing
    #[arg(long, default_value = "100")]
    pub batch_size: usize,
    
    /// Conflict resolution strategy (skip/update/merge/fail)
    #[arg(long, default_value = "skip")]
    pub on_conflict: String,
    
    /// Also migrate organizations
    #[arg(long)]
    pub include_orgs: bool,
    
    /// Resume from specific offset
    #[arg(long)]
    pub resume_from: Option<usize>,
}

/// Execute Clerk migration from CLI
pub async fn execute(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    args: MigrateClerkArgs,
) -> Result<()> {
    let vault_client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);
    
    let conflict_strategy = args.on_conflict.parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    
    let options = MigrationOptions::new()
        .with_dry_run(args.dry_run)
        .with_batch_size(args.batch_size)
        .with_conflict_strategy(conflict_strategy);
    
    let mut migrator = ClerkMigration::new(
        args.clerk_secret_key,
        vault_client,
    ).with_options(options);
    
    // Validate first
    println!("🔍 Validating Clerk credentials...");
    migrator.validate().await
        .map_err(|e| anyhow::anyhow!("Failed to validate Clerk credentials: {}", e))?;
    println!("✅ Credentials validated successfully\n");
    
    // Preview
    let preview = migrator.preview().await?;
    println!("📊 Migration Preview");
    println!("   Users to migrate: {}", preview.user_count);
    println!("   Organizations to migrate: {}", preview.organization_count);
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
    let proceed = dialoguer::Confirm::new()
        .with_prompt("Proceed with migration?")
        .default(false)
        .interact()?;
    
    if !proceed {
        println!("Migration cancelled.");
        return Ok(());
    }
    
    // Run user migration
    println!("\n🚀 Starting user migration...\n");
    let report = migrator.migrate().await?;
    report.print_summary();
    
    // Migrate organizations if requested
    if args.include_orgs {
        println!("\n");
        let org_report = migrator.migrate_organizations().await?;
        org_report.print_summary();
    }
    
    Ok(())
}
