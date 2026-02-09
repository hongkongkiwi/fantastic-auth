//! CSV import support for user migrations

use csv::StringRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;

use crate::migration::models::{
    CreateUserFromMigration, ExternalUser, MigrationError, MigrationOptions, ValidationResult,
};
use vault_core::models::user::UserProfile;

/// CSV import configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsvConfig {
    #[serde(default = "default_true")]
    pub has_headers: bool,
    pub email_column: String,
    #[serde(default)]
    pub password_column: Option<String>,
    #[serde(default)]
    pub password_hash_column: Option<String>,
    #[serde(default)]
    pub name_column: Option<String>,
    #[serde(default)]
    pub given_name_column: Option<String>,
    #[serde(default)]
    pub family_name_column: Option<String>,
    #[serde(default)]
    pub phone_column: Option<String>,
    #[serde(default)]
    pub username_column: Option<String>,
    #[serde(default)]
    pub external_id_column: Option<String>,
    #[serde(default)]
    pub status_column: Option<String>,
    #[serde(default)]
    pub email_verified_column: Option<String>,
    #[serde(default)]
    pub created_at_column: Option<String>,
    #[serde(default)]
    pub metadata_columns: Vec<String>,
    #[serde(default)]
    pub skip_existing: bool,
    #[serde(default)]
    pub generate_passwords: bool,
    #[serde(default)]
    pub default_password: Option<String>,
    #[serde(default)]
    pub delimiter: Option<char>,
    #[serde(default)]
    pub quote_char: Option<char>,
}

impl Default for CsvConfig {
    fn default() -> Self {
        Self {
            has_headers: true,
            email_column: "email".to_string(),
            password_column: Some("password".to_string()),
            password_hash_column: None,
            name_column: Some("name".to_string()),
            given_name_column: None,
            family_name_column: None,
            phone_column: None,
            username_column: None,
            external_id_column: None,
            status_column: None,
            email_verified_column: None,
            created_at_column: None,
            metadata_columns: Vec::new(),
            skip_existing: true,
            generate_passwords: false,
            default_password: None,
            delimiter: Some(','),
            quote_char: Some('"'),
        }
    }
}

fn default_true() -> bool {
    true
}

/// CSV column mapping
#[derive(Debug, Clone)]
pub struct ColumnMapping {
    pub headers: Vec<String>,
    pub email_idx: Option<usize>,
    pub password_idx: Option<usize>,
    pub password_hash_idx: Option<usize>,
    pub name_idx: Option<usize>,
    pub given_name_idx: Option<usize>,
    pub family_name_idx: Option<usize>,
    pub phone_idx: Option<usize>,
    pub username_idx: Option<usize>,
    pub external_id_idx: Option<usize>,
    pub status_idx: Option<usize>,
    pub email_verified_idx: Option<usize>,
    pub created_at_idx: Option<usize>,
    pub metadata_indices: HashMap<String, usize>,
}

impl ColumnMapping {
    /// Build column mapping from headers and config
    pub fn from_headers(headers: &[String], config: &CsvConfig) -> Self {
        let mut mapping = ColumnMapping {
            headers: headers.to_vec(),
            email_idx: None,
            password_idx: None,
            password_hash_idx: None,
            name_idx: None,
            given_name_idx: None,
            family_name_idx: None,
            phone_idx: None,
            username_idx: None,
            external_id_idx: None,
            status_idx: None,
            email_verified_idx: None,
            created_at_idx: None,
            metadata_indices: HashMap::new(),
        };

        for (idx, header) in headers.iter().enumerate() {
            let header_lower = header.to_lowercase();
            match header_lower.as_str() {
                h if h == config.email_column.to_lowercase() => mapping.email_idx = Some(idx),
                h if config.password_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.password_idx = Some(idx)
                }
                h if config.password_hash_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.password_hash_idx = Some(idx)
                }
                h if config.name_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.name_idx = Some(idx)
                }
                h if config.given_name_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.given_name_idx = Some(idx)
                }
                h if config.family_name_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.family_name_idx = Some(idx)
                }
                h if config.phone_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.phone_idx = Some(idx)
                }
                h if config.username_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.username_idx = Some(idx)
                }
                h if config.external_id_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.external_id_idx = Some(idx)
                }
                h if config.status_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.status_idx = Some(idx)
                }
                h if config.email_verified_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.email_verified_idx = Some(idx)
                }
                h if config.created_at_column.as_ref().map(|c| c.to_lowercase()) == Some(h.to_string()) => {
                    mapping.created_at_idx = Some(idx)
                }
                _ => {
                    // Check if it's a metadata column
                    for meta_col in &config.metadata_columns {
                        if header_lower == meta_col.to_lowercase() {
                            mapping.metadata_indices.insert(meta_col.clone(), idx);
                        }
                    }
                }
            }
        }

        mapping
    }

    /// Build column mapping by index when no headers
    pub fn from_index(config: &CsvConfig, total_columns: usize) -> Self {
        let headers: Vec<String> = (0..total_columns).map(|i| format!("col_{}", i)).collect();

        let mut mapping = ColumnMapping {
            headers: headers.clone(),
            email_idx: Some(0), // Default: first column is email
            password_idx: None,
            password_hash_idx: None,
            name_idx: None,
            given_name_idx: None,
            family_name_idx: None,
            phone_idx: None,
            username_idx: None,
            external_id_idx: None,
            status_idx: None,
            email_verified_idx: None,
            created_at_idx: None,
            metadata_indices: HashMap::new(),
        };

        // Try to parse column indices from config (e.g., "0", "1", etc.)
        if let Ok(idx) = config.email_column.parse::<usize>() {
            mapping.email_idx = Some(idx);
        }
        if let Some(ref col) = config.password_column {
            if let Ok(idx) = col.parse::<usize>() {
                mapping.password_idx = Some(idx);
            }
        }
        if let Some(ref col) = config.password_hash_column {
            if let Ok(idx) = col.parse::<usize>() {
                mapping.password_hash_idx = Some(idx);
            }
        }
        if let Some(ref col) = config.name_column {
            if let Ok(idx) = col.parse::<usize>() {
                mapping.name_idx = Some(idx);
            }
        }

        mapping
    }

    /// Get value from record by index
    pub fn get_value(&self, record: &StringRecord, idx: Option<usize>) -> Option<String> {
        idx.and_then(|i| record.get(i).map(|s| s.to_string()))
    }
}

/// CSV importer
pub struct CsvImporter;

impl CsvImporter {
    /// Parse users from CSV data
    pub fn parse_users(
        data: &[u8],
        config: &CsvConfig,
        tenant_id: String,
        options: &MigrationOptions,
    ) -> anyhow::Result<(Vec<CreateUserFromMigration>, Vec<MigrationError>)> {
        let mut reader = Self::create_reader(data, config)?;
        let mut users = Vec::new();
        let mut errors = Vec::new();

        let mapping = if config.has_headers {
            let headers = reader
                .headers()?
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();
            ColumnMapping::from_headers(&headers, config)
        } else {
            // Peek at first record to determine column count
            let mut record = StringRecord::new();
            if reader.read_record(&mut record)? {
                let col_count = record.len();
                // Reset reader
                reader = Self::create_reader(data, config)?;
                ColumnMapping::from_index(config, col_count)
            } else {
                return Ok((users, errors));
            }
        };

        // Check required columns
        if mapping.email_idx.is_none() {
            return Err(anyhow::anyhow!(
                "Email column '{}' not found in CSV",
                config.email_column
            ));
        }

        let mut record = StringRecord::new();
        let mut row_num = if config.has_headers { 1 } else { 0 };

        while reader.read_record(&mut record)? {
            row_num += 1;

            match Self::parse_record(&record, &mapping, config, tenant_id.clone(), options) {
                Ok(Some(user)) => users.push(user),
                Ok(None) => {} // Skipped
                Err(e) => errors.push(MigrationError {
                    user_id: format!("row_{}", row_num),
                    email: mapping.get_value(&record, mapping.email_idx),
                    error: e.to_string(),
                    details: Some(serde_json::json!({"row": row_num})),
                }),
            }
        }

        Ok((users, errors))
    }

    /// Create CSV reader with configuration
    fn create_reader<'a>(data: &'a [u8], config: &CsvConfig) -> anyhow::Result<csv::Reader<&'a [u8]>> {
        let mut builder = csv::ReaderBuilder::new();
        builder.has_headers(config.has_headers);

        if let Some(delim) = config.delimiter {
            builder.delimiter(delim as u8);
        }
        if let Some(quote) = config.quote_char {
            builder.quote(quote as u8);
        }

        Ok(builder.from_reader(data))
    }

    /// Parse a single CSV record
    fn parse_record(
        record: &StringRecord,
        mapping: &ColumnMapping,
        config: &CsvConfig,
        tenant_id: String,
        options: &MigrationOptions,
    ) -> anyhow::Result<Option<CreateUserFromMigration>> {
        let email = mapping
            .get_value(record, mapping.email_idx)
            .ok_or_else(|| anyhow::anyhow!("Missing email"))?;

        // Validate email format
        if !email.contains('@') {
            return Err(anyhow::anyhow!("Invalid email format: {}", email));
        }

        let external_id = mapping.get_value(record, mapping.external_id_idx);
        let username = mapping.get_value(record, mapping.username_idx);

        // Parse name fields
        let display_name = mapping.get_value(record, mapping.name_idx);
        let given_name = mapping.get_value(record, mapping.given_name_idx);
        let family_name = mapping.get_value(record, mapping.family_name_idx);

        // Build full name if not provided but components are
        let name = display_name.or_else(|| {
            match (&given_name, &family_name) {
                (Some(g), Some(f)) => Some(format!("{} {}", g, f)),
                (Some(g), None) => Some(g.clone()),
                (None, Some(f)) => Some(f.clone()),
                (None, None) => None,
            }
        });

        let phone_number = mapping.get_value(record, mapping.phone_idx);

        // Parse email verified
        let email_verified = mapping
            .get_value(record, mapping.email_verified_idx)
            .map(|v| {
                v.to_lowercase() == "true"
                    || v == "1"
                    || v.to_lowercase() == "yes"
                    || v.to_lowercase() == "verified"
            })
            .unwrap_or(false);

        // Parse status
        let status = mapping.get_value(record, mapping.status_idx);

        // Parse created at
        let created_at = mapping
            .get_value(record, mapping.created_at_idx)
            .and_then(|v| Self::parse_datetime(&v));

        // Parse password
        let password = mapping.get_value(record, mapping.password_idx);
        let password_hash = mapping.get_value(record, mapping.password_hash_idx);

        // Use hash if provided, otherwise generate or use default
        let final_password_hash = if options.import_passwords {
            password_hash
        } else if options.generate_passwords {
            if let Some(ref pwd) = password {
                // Hash the plain text password
                Some(vault_core::crypto::VaultPasswordHasher::hash(pwd)?)
            } else if let Some(ref default) = config.default_password {
                Some(vault_core::crypto::VaultPasswordHasher::hash(default)?)
            } else {
                // Generate random password
                let random_pwd = Self::generate_random_password();
                Some(vault_core::crypto::VaultPasswordHasher::hash(&random_pwd)?)
            }
        } else {
            None
        };

        // Build metadata from additional columns
        let mut metadata = HashMap::new();
        for (col_name, idx) in &mapping.metadata_indices {
            if let Some(value) = record.get(*idx) {
                metadata.insert(col_name.clone(), serde_json::Value::String(value.to_string()));
            }
        }

        // Build profile
        let profile = UserProfile {
            name,
            given_name: given_name.clone(),
            family_name: family_name.clone(),
            preferred_username: username.clone(),
            phone_number: phone_number.clone(),
            phone_number_verified: None,
            ..Default::default()
        };

        Ok(Some(CreateUserFromMigration {
            tenant_id,
            email,
            email_verified,
            password_hash: final_password_hash,
            profile: Some(serde_json::to_value(profile).unwrap_or_default()),
            metadata: Some(serde_json::to_value(metadata).unwrap_or_default()),
            external_id,
            source: "csv".to_string(),
            status,
            created_at,
            oauth_connections: Vec::new(),
            mfa_methods: Vec::new(),
        }))
    }

    /// Parse datetime from various formats
    fn parse_datetime(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        // Try ISO 8601
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value) {
            return Some(dt.with_timezone(&chrono::Utc));
        }

        // Try common formats
        let formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y",
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y",
        ];

        for fmt in &formats {
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(value, fmt) {
                return Some(chrono::DateTime::from_naive_utc_and_offset(
                    dt,
                    chrono::Utc,
                ));
            }
            // Try just date
            if let Ok(d) = chrono::NaiveDate::parse_from_str(value, fmt) {
                return Some(chrono::DateTime::from_naive_utc_and_offset(
                    d.and_hms_opt(0, 0, 0).unwrap(),
                    chrono::Utc,
                ));
            }
        }

        // Try Unix timestamp (seconds)
        if let Ok(ts) = value.parse::<i64>() {
            return chrono::DateTime::from_timestamp(ts, 0);
        }

        None
    }

    /// Generate a random password
    fn generate_random_password() -> String {
        use rand::Rng;
        use rand_core::OsRng;
        
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789\
                                !@#$%^&*";
        const PASSWORD_LEN: usize = 16;

        // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
        // Migrated user passwords must be unpredictable to prevent unauthorized access
        let mut rng = OsRng;
        let password: String = (0..PASSWORD_LEN)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        password
    }

    /// Validate CSV data before processing
    pub fn validate_csv(data: &[u8], config: &CsvConfig) -> ValidationResult {
        let mut result = ValidationResult::valid();

        let mut reader = match Self::create_reader(data, config) {
            Ok(r) => r,
            Err(e) => return result.with_error(format!("Failed to parse CSV: {}", e)),
        };

        // Check headers if expected
        if config.has_headers {
            let headers = match reader.headers() {
                Ok(h) => h.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                Err(e) => return result.with_error(format!("Failed to read headers: {}", e)),
            };

            // Check for email column
            let email_found = headers
                .iter()
                .any(|h| h.to_lowercase() == config.email_column.to_lowercase());

            if !email_found {
                result = result.with_error(format!(
                    "Email column '{}' not found in headers: {:?}",
                    config.email_column, headers
                ));
            }
        }

        // Count rows
        let row_count = match reader.into_records().count() {
            0 => {
                result = result.with_warning("CSV file contains no data rows");
                0
            }
            n => n,
        };

        if row_count > 100000 {
            result = result.with_warning(format!(
                "Large CSV file with {} rows. Consider splitting into smaller files.",
                row_count
            ));
        }

        result
    }

    /// Detect CSV format from data sample
    pub fn detect_format(data: &[u8]) -> anyhow::Result<CsvConfig> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(data);

        let headers = reader.headers()?.iter().map(|s| s.to_lowercase()).collect::<Vec<_>>();

        let mut config = CsvConfig::default();

        // Try to detect email column
        for (idx, header) in headers.iter().enumerate() {
            match header.as_str() {
                "email" | "e-mail" | "mail" | "email_address" => {
                    config.email_column = header.clone();
                }
                "password" | "pwd" | "pass" => {
                    config.password_column = Some(header.clone());
                }
                "password_hash" | "passwordhash" | "hash" => {
                    config.password_hash_column = Some(header.clone());
                }
                "name" | "fullname" | "full_name" => {
                    config.name_column = Some(header.clone());
                }
                "first_name" | "firstname" | "given_name" | "givenname" => {
                    config.given_name_column = Some(header.clone());
                }
                "last_name" | "lastname" | "surname" | "family_name" | "familyname" => {
                    config.family_name_column = Some(header.clone());
                }
                "phone" | "phone_number" | "phonenumber" | "mobile" => {
                    config.phone_column = Some(header.clone());
                }
                "username" | "user_name" | "login" | "user_id" | "userid" => {
                    config.username_column = Some(header.clone());
                }
                "id" | "external_id" | "externalid" | "source_id" => {
                    config.external_id_column = Some(header.clone());
                }
                "status" | "user_status" | "account_status" => {
                    config.status_column = Some(header.clone());
                }
                "email_verified" | "verified" | "is_verified" => {
                    config.email_verified_column = Some(header.clone());
                }
                "created_at" | "created" | "registration_date" | "signup_date" => {
                    config.created_at_column = Some(header.clone());
                }
                _ => {
                    // Add to metadata columns if not standard
                    if ![
                        "email", "password", "name", "first_name", "last_name",
                        "phone", "username", "id", "status", "email_verified", "created_at",
                    ]
                    .contains(&header.as_str())
                    {
                        config.metadata_columns.push(header.clone());
                    }
                }
            }
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_users_with_headers() {
        let csv_data = r#"email,name,phone,status
john@example.com,John Doe,+1234567890,active
jane@example.com,Jane Smith,+0987654321,inactive"#;

        let config = CsvConfig {
            has_headers: true,
            email_column: "email".to_string(),
            name_column: Some("name".to_string()),
            phone_column: Some("phone".to_string()),
            status_column: Some("status".to_string()),
            ..Default::default()
        };

        let options = MigrationOptions::default();
        let (users, errors) =
            CsvImporter::parse_users(csv_data.as_bytes(), &config, "tenant123".to_string(), &options)
                .unwrap();

        assert_eq!(users.len(), 2);
        assert!(errors.is_empty());

        assert_eq!(users[0].email, "john@example.com");
        assert_eq!(users[1].email, "jane@example.com");
    }

    #[test]
    fn test_parse_users_without_headers() {
        let csv_data = r#"john@example.com,John Doe,active
jane@example.com,Jane Smith,inactive"#;

        let config = CsvConfig {
            has_headers: false,
            email_column: "0".to_string(), // First column
            name_column: Some("1".to_string()), // Second column
            ..Default::default()
        };

        let options = MigrationOptions::default();
        let (users, errors) =
            CsvImporter::parse_users(csv_data.as_bytes(), &config, "tenant123".to_string(), &options)
                .unwrap();

        assert_eq!(users.len(), 2);
        assert_eq!(users[0].email, "john@example.com");
    }

    #[test]
    fn test_parse_datetime() {
        // ISO 8601
        assert!(CsvImporter::parse_datetime("2024-01-15T10:30:00Z").is_some());
        
        // Common formats
        assert!(CsvImporter::parse_datetime("2024-01-15 10:30:00").is_some());
        assert!(CsvImporter::parse_datetime("2024-01-15").is_some());
        assert!(CsvImporter::parse_datetime("01/15/2024 10:30:00").is_some());
        
        // Unix timestamp
        assert!(CsvImporter::parse_datetime("1705315800").is_some());
        
        // Invalid
        assert!(CsvImporter::parse_datetime("not a date").is_none());
    }

    #[test]
    fn test_validate_csv() {
        let csv_data = r#"email,name
john@example.com,John Doe"#;

        let config = CsvConfig::default();
        let result = CsvImporter::validate_csv(csv_data.as_bytes(), &config);
        assert!(result.valid);

        // Missing email column
        let bad_csv = r#"name,phone
John Doe,+1234567890"#;

        let result = CsvImporter::validate_csv(bad_csv.as_bytes(), &config);
        assert!(!result.valid);
    }

    #[test]
    fn test_detect_format() {
        let csv_data = r#"email,first_name,last_name,phone_number,created_at
john@example.com,John,Doe,+1234567890,2024-01-15"#;

        let config = CsvImporter::detect_format(csv_data.as_bytes()).unwrap();
        assert_eq!(config.email_column, "email");
        assert_eq!(config.given_name_column, Some("first_name".to_string()));
        assert_eq!(config.family_name_column, Some("last_name".to_string()));
        assert_eq!(config.phone_column, Some("phone_number".to_string()));
        assert_eq!(config.created_at_column, Some("created_at".to_string()));
    }
}
