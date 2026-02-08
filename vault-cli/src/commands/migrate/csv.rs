//! CSV/JSON import implementation

use super::types::*;
use crate::client::VaultClient;
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// CSV/JSON migration
pub struct CsvMigration {
    file_path: PathBuf,
    vault_client: VaultClient,
    options: CsvImportOptions,
    report: MigrationReport,
}

/// CSV import options
#[derive(Debug, Clone, Default)]
pub struct CsvImportOptions {
    pub base: MigrationOptions,
    /// Column mapping (source -> target)
    pub column_mapping: HashMap<String, String>,
    /// Date format for parsing dates
    pub date_format: Option<String>,
    /// CSV delimiter
    pub delimiter: char,
    /// Whether CSV has headers
    pub has_headers: bool,
    /// Skip rows with errors
    pub skip_errors: bool,
    /// File format override
    pub format: Option<ImportFormat>,
}

impl CsvMigration {
    pub fn new(
        file_path: PathBuf,
        vault_client: VaultClient,
    ) -> Self {
        Self {
            file_path,
            vault_client,
            options: CsvImportOptions::default(),
            report: MigrationReport::new(),
        }
    }
    
    pub fn with_options(mut self, options: CsvImportOptions) -> Self {
        self.options = options;
        self
    }
    
    /// Detect file format from extension
    fn detect_format(&self) -> ImportFormat {
        if let Some(ext) = self.file_path.extension() {
            match ext.to_str().unwrap_or("").to_lowercase().as_str() {
                "csv" => ImportFormat::Csv,
                "json" => ImportFormat::Json,
                "jsonl" => ImportFormat::Json,
                _ => ImportFormat::Csv,
            }
        } else {
            ImportFormat::Csv
        }
    }
    
    /// Read and parse the import file
    async fn read_file(&mut self) -> Result<Vec<ImportUser>, MigrationError> {
        let format = self.options.format.unwrap_or_else(|| self.detect_format());
        
        let content = tokio::fs::read_to_string(&self.file_path)
            .await
            .map_err(|e| MigrationError::Other(format!("Failed to read file: {}", e)))?;
        
        match format {
            ImportFormat::Csv => self.parse_csv(&content),
            ImportFormat::Json => self.parse_json(&content),
        }
    }
    
    /// Parse CSV content
    fn parse_csv(&mut self, content: &str) -> Result<Vec<ImportUser>, MigrationError> {
        let mut users = Vec::new();
        let mut lines = content.lines();
        
        // Parse headers
        let headers = if self.options.has_headers {
            let header_line = lines.next()
                .ok_or_else(|| MigrationError::ParseError("Empty CSV file".to_string()))?;
            header_line.split(self.options.delimiter)
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>()
        } else {
            // Default headers
            vec!["email".to_string(), "name".to_string(), "email_verified".to_string()]
        };
        
        // Parse rows
        for (line_num, line) in lines.enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            
            let values: Vec<&str> = line.split(self.options.delimiter)
                .map(|s| s.trim())
                .collect();
            
            let mut row_data: HashMap<String, String> = HashMap::new();
            for (i, header) in headers.iter().enumerate() {
                if let Some(value) = values.get(i) {
                    let mapped_header = self.options.column_mapping.get(header)
                        .cloned()
                        .unwrap_or_else(|| header.clone());
                    row_data.insert(mapped_header, value.to_string());
                }
            }
            
            match self.row_to_user(row_data) {
                Ok(user) => users.push(user),
                Err(e) if self.options.skip_errors => {
                    self.report.add_warning(format!("Row {}: {}", line_num + 1, e));
                }
                Err(e) => return Err(e),
            }
        }
        
        Ok(users)
    }
    
    /// Parse JSON content
    fn parse_json(&mut self, content: &str) -> Result<Vec<ImportUser>, MigrationError> {
        // Try parsing as array first
        if let Ok(array) = serde_json::from_str::<Vec<serde_json::Value>>(content) {
            let mut users = Vec::new();
            for value in array {
                match self.json_value_to_user(value) {
                    Ok(user) => users.push(user),
                    Err(e) if self.options.skip_errors => {
                        self.report.add_warning(e.to_string());
                    }
                    Err(e) => return Err(e),
                }
            }
            return Ok(users);
        }
        
        // Try parsing as JSONL (one JSON object per line)
        let mut users = Vec::new();
        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            
            let value: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| MigrationError::ParseError(
                    format!("Line {}: {}", line_num + 1, e)
                ))?;
            
            match self.json_value_to_user(value) {
                Ok(user) => users.push(user),
                Err(e) if self.options.skip_errors => {
                    self.report.add_warning(format!("Line {}: {}", line_num + 1, e));
                }
                Err(e) => return Err(e),
            }
        }
        
        Ok(users)
    }
    
    /// Convert row data to ImportUser
    fn row_to_user(&self, row: HashMap<String, String>) -> Result<ImportUser, MigrationError> {
        let email = row.get("email")
            .or_else(|| row.get("Email"))
            .or_else(|| row.get("EMAIL"))
            .ok_or_else(|| MigrationError::ValidationError("Missing email field".to_string()))?
            .clone();
        
        let name = row.get("name")
            .or_else(|| row.get("Name"))
            .or_else(|| row.get("displayName"))
            .or_else(|| row.get("full_name"))
            .cloned();
        
        let email_verified = row.get("email_verified")
            .or_else(|| row.get("emailVerified"))
            .or_else(|| row.get("verified"))
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        
        let phone = row.get("phone")
            .or_else(|| row.get("phoneNumber"))
            .or_else(|| row.get("phone_number"))
            .cloned();
        
        let password_hash = row.get("password_hash")
            .or_else(|| row.get("passwordHash"))
            .or_else(|| row.get("password"))
            .cloned();
        
        let avatar_url = row.get("avatar_url")
            .or_else(|| row.get("avatarUrl"))
            .or_else(|| row.get("photoURL"))
            .cloned();
        
        let created_at = row.get("created_at")
            .or_else(|| row.get("createdAt"))
            .cloned();
        
        // Store extra fields in metadata
        let mut metadata = HashMap::new();
        for (key, value) in &row {
            if !["email", "name", "email_verified", "phone", "password_hash", 
                 "avatar_url", "created_at"].contains(&key.as_str()) {
                metadata.insert(key.clone(), serde_json::json!(value));
            }
        }
        
        Ok(ImportUser {
            email,
            name,
            email_verified,
            password_hash,
            phone,
            avatar_url,
            created_at,
            metadata: if metadata.is_empty() { None } else { Some(metadata) },
            identities: None,
        })
    }
    
    /// Convert JSON value to ImportUser
    fn json_value_to_user(&self, value: serde_json::Value) -> Result<ImportUser, MigrationError> {
        let obj = value.as_object()
            .ok_or_else(|| MigrationError::ValidationError("Expected JSON object".to_string()))?;
        
        let email = obj.get("email")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MigrationError::ValidationError("Missing email field".to_string()))?
            .to_string();
        
        let name = obj.get("name")
            .or_else(|| obj.get("displayName"))
            .or_else(|| obj.get("fullName"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        let email_verified = obj.get("email_verified")
            .or_else(|| obj.get("emailVerified"))
            .or_else(|| obj.get("verified"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        
        let phone = obj.get("phone")
            .or_else(|| obj.get("phoneNumber"))
            .or_else(|| obj.get("phone_number"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        let password_hash = obj.get("password_hash")
            .or_else(|| obj.get("passwordHash"))
            .or_else(|| obj.get("password"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        let avatar_url = obj.get("avatar_url")
            .or_else(|| obj.get("avatarUrl"))
            .or_else(|| obj.get("photoURL"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        let created_at = obj.get("created_at")
            .or_else(|| obj.get("createdAt"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        // Extract metadata
        let mut metadata = HashMap::new();
        let known_fields = ["email", "name", "email_verified", "phone", "password_hash",
                           "avatar_url", "created_at"];
        for (key, value) in obj.iter() {
            if !known_fields.contains(&key.as_str()) {
                metadata.insert(key.clone(), value.clone());
            }
        }
        
        Ok(ImportUser {
            email,
            name,
            email_verified,
            password_hash,
            phone,
            avatar_url,
            created_at,
            metadata: if metadata.is_empty() { None } else { Some(metadata) },
            identities: None,
        })
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
                    match self.options.base.conflict_strategy {
                        ConflictStrategy::Skip => Ok(()),
                        _ => Err(MigrationError::Conflict(err_str)),
                    }
                } else {
                    Err(MigrationError::ImportError(err_str))
                }
            }
        }
    }
    
    /// Generate import template
    pub fn generate_template(format: ImportFormat) -> String {
        match format {
            ImportFormat::Csv => {
                "email,name,email_verified,phone,created_at\n\
                 john@example.com,John Doe,true,+1234567890,2024-01-01T00:00:00Z\n\
                 jane@example.com,Jane Smith,false,+0987654321,2024-02-01T00:00:00Z\n"
                .to_string()
            }
            ImportFormat::Json => {
                serde_json::to_string_pretty(&vec![
                    serde_json::json!({
                        "email": "john@example.com",
                        "name": "John Doe",
                        "email_verified": true,
                        "phone": "+1234567890",
                        "created_at": "2024-01-01T00:00:00Z"
                    }),
                    serde_json::json!({
                        "email": "jane@example.com",
                        "name": "Jane Smith",
                        "email_verified": false,
                        "phone": "+0987654321",
                        "created_at": "2024-02-01T00:00:00Z"
                    }),
                ]).unwrap()
            }
        }
    }
    
    /// Preview the import without importing
    pub async fn preview(&mut self) -> Result<MigrationPreview, MigrationError> {
        let users = self.read_file().await?;
        
        let sample_users: Vec<PreviewUser> = users.iter().take(5).map(|u| PreviewUser {
            email: u.email.clone(),
            name: u.name.clone(),
            source_id: u.email.clone(),
        }).collect();
        
        Ok(MigrationPreview {
            user_count: users.len(),
            organization_count: 0,
            sample_users,
            estimated_time_secs: (users.len() / 10) as u64,
        })
    }
    
    /// Execute the import
    pub async fn import(&mut self) -> Result<MigrationReport, MigrationError> {
        let start_time = std::time::Instant::now();
        let users = self.read_file().await?;
        
        if self.options.base.dry_run {
            println!("🔍 DRY RUN MODE - No changes will be made");
            println!("   Would import {} users from file", users.len());
            return Ok(MigrationReport {
                total_count: users.len(),
                ..Default::default()
            });
        }
        
        // Create progress bar
        let pb = ProgressBar::new(users.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        
        for user in users {
            match self.import_user(&user).await {
                Ok(()) => self.report.add_success(),
                Err(e) if matches!(e, MigrationError::Conflict(_)) => {
                    self.report.add_skipped();
                }
                Err(e) => {
                    self.report.add_failure(user.email.clone(), e.to_string());
                }
            }
            
            pb.inc(1);
        }
        
        pb.finish_and_clear();
        
        self.report.duration_secs = start_time.elapsed().as_secs();
        Ok(self.report.clone())
    }
}

/// CLI arguments for CSV migration
#[derive(clap::Args, Clone, Debug)]
pub struct MigrateCsvArgs {
    /// Path to CSV/JSON file
    #[arg(long)]
    pub file: PathBuf,
    
    /// File format (auto-detected if not specified)
    #[arg(long)]
    pub format: Option<String>,
    
    /// Column mapping (source=target, comma-separated)
    /// Example: email=email,fullName=name
    #[arg(long)]
    pub mapping: Option<String>,
    
    /// Dry run (preview without importing)
    #[arg(long, default_value = "false")]
    pub dry_run: bool,
    
    /// CSV delimiter (default: comma)
    #[arg(long, default_value = ",")]
    pub delimiter: String,
    
    /// File has no headers (use default column names)
    #[arg(long)]
    pub no_headers: bool,
    
    /// Skip rows with errors instead of failing
    #[arg(long)]
    pub skip_errors: bool,
    
    /// Conflict resolution strategy (skip/update/merge/fail)
    #[arg(long, default_value = "skip")]
    pub on_conflict: String,
    
    /// Generate template file instead of importing
    #[arg(long)]
    pub generate_template: Option<String>,
}

/// Execute CSV migration from CLI
pub async fn execute(
    api_url: &str,
    token: &str,
    tenant_id: &str,
    args: MigrateCsvArgs,
) -> Result<()> {
    // Generate template if requested
    if let Some(format_str) = args.generate_template {
        let format = match format_str.to_lowercase().as_str() {
            "csv" => ImportFormat::Csv,
            "json" => ImportFormat::Json,
            _ => anyhow::bail!("Unknown format: {}. Use 'csv' or 'json'", format_str),
        };
        
        let template = CsvMigration::generate_template(format);
        let template_path = PathBuf::from(format!("import_template.{}", format_str.to_lowercase()));
        tokio::fs::write(&template_path, template).await?;
        println!("✅ Template generated: {}", template_path.display());
        return Ok(());
    }
    
    // Parse column mapping
    let mut column_mapping = HashMap::new();
    if let Some(mapping_str) = args.mapping {
        for pair in mapping_str.split(',') {
            let parts: Vec<&str> = pair.splitn(2, '=').collect();
            if parts.len() == 2 {
                column_mapping.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
            }
        }
    }
    
    // Parse format
    let format = args.format.map(|f| match f.to_lowercase().as_str() {
        "csv" => ImportFormat::Csv,
        "json" => ImportFormat::Json,
        _ => ImportFormat::Csv,
    });
    
    let conflict_strategy = args.on_conflict.parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    
    let delimiter = args.delimiter.chars().next().unwrap_or(',');
    
    let vault_client = VaultClient::new(api_url)
        .with_token(token)
        .with_tenant(tenant_id);
    
    let options = CsvImportOptions {
        base: MigrationOptions::new()
            .with_dry_run(args.dry_run)
            .with_conflict_strategy(conflict_strategy),
        column_mapping,
        date_format: None,
        delimiter,
        has_headers: !args.no_headers,
        skip_errors: args.skip_errors,
        format,
    };
    
    let mut migrator = CsvMigration::new(args.file.clone(), vault_client)
        .with_options(options);
    
    // Preview
    let preview = migrator.preview().await?;
    println!("📊 Import Preview");
    println!("   File: {}", args.file.display());
    println!("   Users to import: {}", preview.user_count);
    
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
        .with_prompt("Proceed with import?")
        .default(false)
        .interact()?;
    
    if !proceed {
        println!("Import cancelled.");
        return Ok(());
    }
    
    // Run import
    println!("\n🚀 Starting import...\n");
    let report = migrator.import().await?;
    report.print_summary();
    
    Ok(())
}
