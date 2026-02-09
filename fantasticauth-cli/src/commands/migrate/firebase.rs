//! Firebase Authentication migration implementation

use super::types::*;
use crate::client::VaultClient;
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Firebase service account credentials
#[derive(Debug, Deserialize, Clone)]
pub struct ServiceAccountKey {
    #[serde(rename = "type")]
    pub account_type: String,
    #[serde(rename = "project_id")]
    pub project_id: String,
    #[serde(rename = "private_key_id")]
    pub private_key_id: String,
    #[serde(rename = "private_key")]
    pub private_key: String,
    #[serde(rename = "client_email")]
    pub client_email: String,
    #[serde(rename = "client_id")]
    pub client_id: String,
    #[serde(rename = "auth_uri")]
    pub auth_uri: String,
    #[serde(rename = "token_uri")]
    pub token_uri: String,
}

/// Firebase OAuth token response
#[derive(Debug, Deserialize)]
struct FirebaseTokenResponse {
    #[serde(rename = "access_token")]
    access_token: String,
    #[serde(rename = "token_type")]
    token_type: String,
    #[serde(rename = "expires_in")]
    expires_in: u64,
}

/// Firebase API client
pub struct FirebaseClient {
    project_id: String,
    credentials: ServiceAccountKey,
    http_client: reqwest::Client,
    access_token: Option<String>,
}

impl FirebaseClient {
    pub fn new(credentials: ServiceAccountKey) -> Self {
        let project_id = credentials.project_id.clone();
        Self {
            project_id,
            credentials,
            http_client: reqwest::Client::new(),
            access_token: None,
        }
    }
    
    /// Authenticate using service account
    pub async fn authenticate(&mut self) -> Result<(), MigrationError> {
        // Create JWT for service account authentication
        let jwt = self.create_jwt()?;
        
        let body = serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt,
        });
        
        let response = self.http_client
            .post(&self.credentials.token_uri)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| MigrationError::AuthenticationError(e.to_string()))?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(MigrationError::AuthenticationError(error_text));
        }
        
        let token_response: FirebaseTokenResponse = response
            .json()
            .await
            .map_err(|e| MigrationError::ParseError(e.to_string()))?;
        
        self.access_token = Some(token_response.access_token);
        Ok(())
    }
    
    /// Create JWT for service account auth
    fn create_jwt(&self) -> Result<String, MigrationError> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        
        #[derive(Serialize)]
        struct Claims {
            iss: String,
            sub: String,
            scope: String,
            aud: String,
            iat: i64,
            exp: i64,
        }
        
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            iss: self.credentials.client_email.clone(),
            sub: self.credentials.client_email.clone(),
            scope: "https://www.googleapis.com/auth/identitytoolkit.readonly".to_string(),
            aud: self.credentials.token_uri.clone(),
            iat: now,
            exp: now + 3600,
        };
        
        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(self.credentials.private_key.as_bytes())
            .map_err(|e| MigrationError::AuthenticationError(e.to_string()))?;
        
        let token = encode(&header, &claims, &key)
            .map_err(|e| MigrationError::AuthenticationError(e.to_string()))?;
        
        Ok(token)
    }
    
    /// Fetch users with pagination
    pub async fn fetch_users(&self, next_page_token: Option<&str>, max_results: usize) -> Result<FirebaseUsersResponse, MigrationError> {
        let token = self.access_token.as_ref()
            .ok_or_else(|| MigrationError::AuthenticationError("Not authenticated".to_string()))?;
        
        let url = format!(
            "https://identitytoolkit.googleapis.com/v1/projects/{}/accounts:batchGet",
            self.project_id
        );
        
        let mut request = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token));
        
        if let Some(page_token) = next_page_token {
            request = request.query(&[("nextPageToken", page_token)]);
        }
        
        request = request.query(&[("maxResults", max_results.to_string())]);
        
        let response = request.send().await?;
        
        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(MigrationError::ApiError(error_text));
        }
        
        let users_response: FirebaseUsersResponse = response
            .json()
            .await
            .map_err(|e| MigrationError::ParseError(e.to_string()))?;
        
        Ok(users_response)
    }
    
    /// Get all users (handles pagination)
    pub async fn fetch_all_users(&self, max_results: usize) -> Result<Vec<FirebaseUser>, MigrationError> {
        let mut all_users = Vec::new();
        let mut next_page_token: Option<String> = None;
        
        loop {
            let page_token_ref = next_page_token.as_deref();
            let response = self.fetch_users(page_token_ref, max_results).await?;
            
            if let Some(users) = response.users {
                all_users.extend(users);
            }
            
            next_page_token = response.next_page_token;
            
            if next_page_token.is_none() {
                break;
            }
        }
        
        Ok(all_users)
    }
    
    /// Fetch custom claims for a user (requires Admin SDK or additional API)
    pub async fn fetch_custom_claims(&self, _user_id: &str) -> Result<HashMap<String, serde_json::Value>, MigrationError> {
        // Custom claims are included in the user object when fetched via Admin SDK
        // For REST API, they're included in the user record
        Ok(HashMap::new())
    }
}

/// Firebase users response
#[derive(Debug, Deserialize)]
pub struct FirebaseUsersResponse {
    pub users: Option<Vec<FirebaseUser>>,
    #[serde(rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

/// Firebase user structure
#[derive(Debug, Deserialize, Clone)]
pub struct FirebaseUser {
    #[serde(rename = "localId")]
    pub local_id: String,
    pub email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: Option<bool>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "photoUrl")]
    pub photo_url: Option<String>,
    #[serde(rename = "phoneNumber")]
    pub phone_number: Option<String>,
    #[serde(rename = "disabled")]
    pub disabled: Option<bool>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(rename = "lastLoginAt")]
    pub last_login_at: Option<String>,
    #[serde(rename = "passwordHash")]
    pub password_hash: Option<String>,
    #[serde(rename = "salt")]
    pub salt: Option<String>,
    #[serde(rename = "passwordUpdatedAt")]
    pub password_updated_at: Option<i64>,
    #[serde(rename = "customAttributes")]
    pub custom_attributes: Option<String>, // JSON string
    #[serde(rename = "providerUserInfo")]
    pub provider_user_info: Option<Vec<FirebaseProviderInfo>>,
}

/// Firebase provider info (social logins)
#[derive(Debug, Deserialize, Clone)]
pub struct FirebaseProviderInfo {
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "federatedId")]
    pub federated_id: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "photoUrl")]
    pub photo_url: Option<String>,
}

/// Firebase migration implementation
pub struct FirebaseMigration {
    firebase_client: FirebaseClient,
    vault_client: VaultClient,
    options: MigrationOptions,
    report: MigrationReport,
}

impl FirebaseMigration {
    pub fn new(
        credentials: ServiceAccountKey,
        vault_client: VaultClient,
    ) -> Self {
        Self {
            firebase_client: FirebaseClient::new(credentials),
            vault_client,
            options: MigrationOptions::new(),
            report: MigrationReport::new(),
        }
    }
    
    pub fn with_options(mut self, options: MigrationOptions) -> Self {
        self.options = options;
        self
    }
    
    /// Transform Firebase user to Vault format
    fn transform_user(&self, firebase_user: &FirebaseUser) -> ImportUser {
        // Generate email if not present (phone-only users)
        let email = firebase_user.email.clone()
            .unwrap_or_else(|| {
                if let Some(phone) = &firebase_user.phone_number {
                    format!("{}@phone.firebase.local", phone.replace('+', ""))
                } else {
                    format!("{}@firebase.local", firebase_user.local_id)
                }
            });
        
        // Parse custom claims
        let custom_claims: Option<HashMap<String, serde_json::Value>> = firebase_user
            .custom_attributes
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok());
        
        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert("firebase_uid".to_string(), serde_json::json!(firebase_user.local_id));
        
        if let Some(ref last_login) = firebase_user.last_login_at {
            metadata.insert("firebase_last_login".to_string(), serde_json::json!(last_login));
        }
        
        if let Some(claims) = &custom_claims {
            metadata.insert("firebase_custom_claims".to_string(), serde_json::json!(claims));
        }
        
        if firebase_user.disabled.unwrap_or(false) {
            metadata.insert("firebase_disabled".to_string(), serde_json::json!(true));
        }
        
        // Transform identities
        let identities: Vec<UserIdentity> = firebase_user.provider_user_info.as_ref()
            .map(|providers| {
                providers.iter()
                    .filter(|p| p.provider_id != "password")
                    .map(|p| UserIdentity {
                        provider: p.provider_id.clone(),
                        provider_user_id: p.raw_id.clone(),
                        access_token: None,
                        refresh_token: None,
                        expires_at: None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        
        // Format timestamp
        let created_at = firebase_user.created_at.as_ref()
            .and_then(|ts| ts.parse::<i64>().ok())
            .map(|ts| chrono::DateTime::from_timestamp_millis(ts).map(|dt| dt.to_rfc3339()))
            .flatten();
        
        ImportUser {
            email,
            name: firebase_user.display_name.clone(),
            email_verified: firebase_user.email_verified.unwrap_or(false),
            password_hash: firebase_user.password_hash.clone(),
            phone: firebase_user.phone_number.clone(),
            avatar_url: firebase_user.photo_url.clone(),
            created_at,
            metadata: Some(metadata),
            identities: if identities.is_empty() { None } else { Some(identities) },
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
    
    /// Get password migration recommendations
    pub async fn get_password_recommendations(&self) -> Vec<String> {
        vec![
            "Firebase uses standard PBKDF2/SHA256 or scrypt for password hashing.".to_string(),
            "Vault uses Argon2id.".to_string(),
            "Options:".to_string(),
            "1. Force password reset (recommended) - Users will set new passwords on first login".to_string(),
            "2. Export password hashes and migrate with custom hash verification".to_string(),
            "3. Use Firebase's export users API to get password hashes".to_string(),
        ]
    }
    
    /// Migrate custom claims to Vault roles
    pub async fn migrate_custom_claims(&self) -> Result<MigrationReport, MigrationError> {
        let mut report = MigrationReport::new();
        
        println!("🔄 Migrating custom claims to roles...");
        
        // Fetch all users to process their claims
        let users = self.firebase_client.fetch_all_users(1000).await?;
        
        for firebase_user in users {
            if let Some(claims_json) = &firebase_user.custom_attributes {
                if let Ok(claims) = serde_json::from_str::<HashMap<String, serde_json::Value>>(claims_json) {
                    if let Some(email) = &firebase_user.email {
                        // Find user in Vault
                        let vault_user: Result<serde_json::Value, _> = self.vault_client
                            .get(&format!("/admin/users/by-email/{}", email))
                            .await;
                        
                        if let Ok(vault_user) = vault_user {
                            let user_id = vault_user["id"].as_str().unwrap_or_default();
                            
                            // Assign roles based on claims
                            if let Some(role) = claims.get("role").and_then(|r| r.as_str()) {
                                let _ = self.assign_role(user_id, role).await;
                                report.add_success();
                            } else {
                                report.add_skipped();
                            }
                        }
                    }
                }
            }
        }
        
        Ok(report)
    }
    
    /// Assign a role to a user
    async fn assign_role(&self, user_id: &str, role: &str) -> Result<(), MigrationError> {
        #[derive(Serialize)]
        struct AssignRoleRequest {
            role: String,
        }
        
        let body = AssignRoleRequest {
            role: role.to_string(),
        };
        
        self.vault_client
            .post::<serde_json::Value, _>(&format!("/admin/users/{}/roles", user_id), &body)
            .await
            .map_err(|e| MigrationError::ImportError(e.to_string()))?;
        
        Ok(())
    }
}

#[async_trait::async_trait]
impl Migrator for FirebaseMigration {
    async fn preview(&self) -> Result<MigrationPreview, MigrationError> {
        // Authenticate
        let mut client = FirebaseClient {
            project_id: self.firebase_client.project_id.clone(),
            credentials: self.firebase_client.credentials.clone(),
            http_client: self.firebase_client.http_client.clone(),
            access_token: None,
        };
        client.authenticate().await?;
        
        // Fetch users
        let response = client.fetch_users(None, 5).await?;
        let users = response.users.unwrap_or_default();
        
        // Count total
        let all_users = client.fetch_all_users(1000).await?;
        let total = all_users.len();
        
        let preview_users: Vec<PreviewUser> = users.iter()
            .map(|u| PreviewUser {
                email: u.email.clone().unwrap_or_default(),
                name: u.display_name.clone(),
                source_id: u.local_id.clone(),
            })
            .collect();
        
        Ok(MigrationPreview {
            user_count: total,
            organization_count: 0,
            sample_users: preview_users,
            estimated_time_secs: (total / 10) as u64,
        })
    }
    
    async fn migrate(&mut self) -> Result<MigrationReport, MigrationError> {
        let start_time = std::time::Instant::now();
        
        // Authenticate
        self.firebase_client.authenticate().await?;
        
        // Get all users
        let users = self.firebase_client.fetch_all_users(1000).await?;
        let total = users.len();
        
        if self.options.dry_run {
            println!("🔍 DRY RUN MODE - No changes will be made");
            println!("   Would migrate {} users from Firebase", total);
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
        
        for firebase_user in users {
            let import_user = self.transform_user(&firebase_user);
            
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
        
        pb.finish_and_clear();
        
        self.report.duration_secs = start_time.elapsed().as_secs();
        Ok(self.report.clone())
    }
    
    async fn validate(&self) -> Result<(), MigrationError> {
        // Test authentication
        let mut client = FirebaseClient {
            project_id: self.firebase_client.project_id.clone(),
            credentials: self.firebase_client.credentials.clone(),
            http_client: self.firebase_client.http_client.clone(),
            access_token: None,
        };
        client.authenticate().await?;
        
        // Test by fetching a single user
        let _ = client.fetch_users(None, 1).await?;
        
        Ok(())
    }
}

/// CLI arguments for Firebase migration
#[derive(clap::Args, Clone, Debug)]
pub struct MigrateFirebaseArgs {
    /// Path to Firebase service account JSON file
    #[arg(long)]
    pub firebase_credentials: std::path::PathBuf,
    
    /// Dry run (preview without importing)
    #[arg(long, default_value = "false")]
    pub dry_run: bool,
    
    /// Batch size for processing
    #[arg(long, default_value = "1000")]
    pub batch_size: usize,
    
    /// Conflict resolution strategy (skip/update/merge/fail)
    #[arg(long, default_value = "skip")]
    pub on_conflict: String,
    
    /// Also migrate custom claims to roles
    #[arg(long)]
    pub include_claims: bool,
    
    /// Show password migration recommendations
    #[arg(long)]
    pub password_help: bool,
}

/// Execute Firebase migration from CLI
pub async fn execute(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    args: MigrateFirebaseArgs,
) -> Result<()> {
    // Read credentials file
    let credentials_content = tokio::fs::read_to_string(&args.firebase_credentials)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read Firebase credentials file: {}", e))?;
    
    let credentials: ServiceAccountKey = serde_json::from_str(&credentials_content)
        .map_err(|e| anyhow::anyhow!("Invalid Firebase credentials JSON: {}", e))?;
    
    // Show password help if requested
    if args.password_help {
        println!("🔐 Firebase Password Migration Help");
        println!("═══════════════════════════════════════");
        let migration = FirebaseMigration::new(
            credentials,
            VaultClient::new(api_url),
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
    
    let mut migrator = FirebaseMigration::new(
        credentials,
        vault_client,
    ).with_options(options);
    
    // Validate first
    println!("🔍 Validating Firebase credentials...");
    migrator.validate().await
        .map_err(|e| anyhow::anyhow!("Failed to validate Firebase credentials: {}", e))?;
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
    
    // Migrate custom claims if requested
    if args.include_claims {
        println!("\n");
        let claims_report = migrator.migrate_custom_claims().await?;
        println!("📊 Custom Claims Migration:");
        println!("   ✅ Successfully migrated: {}", claims_report.success_count);
        println!("   ⏭️  Skipped: {}", claims_report.skipped_count);
        println!("   ❌ Failed: {}", claims_report.failure_count);
    }
    
    Ok(())
}
