//! LDAP Synchronization Module
//!
//! Handles periodic synchronization of users and groups from LDAP/Active Directory.
//! Supports full sync, incremental sync, and JIT (Just-In-Time) provisioning.

use super::{LdapConfig, LdapConnection, LdapError, LdapGroup, LdapUser};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use uuid::Uuid;

/// Sync operation errors
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("LDAP error: {0}")]
    Ldap(#[from] LdapError),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Sync already in progress")]
    AlreadyRunning,

    #[error("Connection not found")]
    ConnectionNotFound,

    #[error("Sync failed: {0}")]
    SyncFailed(String),
}

/// Type of synchronization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncType {
    /// Full sync - sync all users and groups
    Full,
    /// Incremental sync - only sync changed entries
    Incremental,
    /// Test connection only, don't modify data
    Test,
}

/// Status of a sync operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    /// Sync is currently running
    Running,
    /// Sync completed successfully
    Success,
    /// Sync completed with some errors
    Partial,
    /// Sync failed
    Failed,
}

/// Sync statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncStats {
    pub users_found: usize,
    pub users_created: usize,
    pub users_updated: usize,
    pub users_disabled: usize,
    pub users_unchanged: usize,
    pub users_failed: usize,
    pub groups_found: usize,
    pub groups_created: usize,
    pub groups_updated: usize,
    pub groups_failed: usize,
}

/// Sync log entry for detailed tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncLogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub operation: String,
    pub ldap_dn: Option<String>,
    pub user_id: Option<String>,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

/// Log level for sync entries
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

/// LDAP Sync Job
///
/// Manages the synchronization process between LDAP and Vault.
pub struct LdapSyncJob {
    pool: sqlx::PgPool,
    connection_id: Uuid,
    tenant_id: Uuid,
    sync_type: SyncType,
    stats: SyncStats,
    log_entries: Vec<SyncLogEntry>,
    started_at: DateTime<Utc>,
    triggered_by: String,
}

/// User sync result
#[derive(Debug, Clone)]
pub struct UserSyncResult {
    pub user_id: String,
    pub action: UserSyncAction,
    pub ldap_user: LdapUser,
}

/// Action taken for a user during sync
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSyncAction {
    Created,
    Updated,
    Unchanged,
    Disabled,
    Failed,
}

/// Group sync result
#[derive(Debug, Clone)]
pub struct GroupSyncResult {
    pub group_id: String,
    pub action: GroupSyncAction,
    pub ldap_group: LdapGroup,
}

/// Action taken for a group during sync
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupSyncAction {
    Created,
    Updated,
    Unchanged,
    Failed,
}

impl LdapSyncJob {
    /// Create a new sync job
    pub fn new(
        pool: sqlx::PgPool,
        connection_id: Uuid,
        tenant_id: Uuid,
        sync_type: SyncType,
        triggered_by: String,
    ) -> Self {
        Self {
            pool,
            connection_id,
            tenant_id,
            sync_type,
            stats: SyncStats::default(),
            log_entries: Vec::new(),
            started_at: Utc::now(),
            triggered_by,
        }
    }

    /// Run the sync job
    pub async fn run(&mut self) -> Result<SyncStats, SyncError> {
        // Create sync log entry
        let log_id = self.create_sync_log().await?;

        // Check if another sync is already running
        if self.is_sync_running().await? {
            self.log(
                LogLevel::Error,
                "sync",
                None,
                None,
                "Another sync is already running",
                None,
            );
            self.update_sync_log(
                log_id,
                SyncStatus::Failed,
                Some("Another sync is already running".to_string()),
            )
            .await?;
            return Err(SyncError::AlreadyRunning);
        }

        self.log(
            LogLevel::Info,
            "sync_start",
            None,
            None,
            &format!("Starting {:?} sync", self.sync_type),
            None,
        );

        // Get connection configuration
        let config = self.get_connection_config().await?;

        if !config.enabled {
            self.log(
                LogLevel::Warning,
                "sync",
                None,
                None,
                "LDAP connection is disabled",
                None,
            );
            self.update_sync_log(
                log_id,
                SyncStatus::Failed,
                Some("Connection is disabled".to_string()),
            )
            .await?;
            return Err(SyncError::Config("Connection is disabled".to_string()));
        }

        // Create LDAP connection
        let ldap = LdapConnection::new(config.clone())?;

        // Test connection
        if let Err(e) = ldap.test().await {
            let msg = format!("LDAP connection test failed: {}", e);
            self.log(LogLevel::Error, "connection_test", None, None, &msg, None);
            self.update_sync_log(log_id, SyncStatus::Failed, Some(msg.clone()))
                .await?;
            return Err(SyncError::Ldap(e));
        }

        self.log(
            LogLevel::Info,
            "connection_test",
            None,
            None,
            "LDAP connection successful",
            None,
        );

        // For test sync, stop here
        if self.sync_type == SyncType::Test {
            self.update_sync_log(log_id, SyncStatus::Success, None)
                .await?;
            return Ok(self.stats.clone());
        }

        // Sync users
        if let Err(e) = self.sync_users(&ldap, &config).await {
            self.log(
                LogLevel::Error,
                "sync_users",
                None,
                None,
                &format!("User sync failed: {}", e),
                None,
            );
        }

        // Sync groups if enabled
        if config.group_sync_enabled {
            if let Err(e) = self.sync_groups(&ldap, &config).await {
                self.log(
                    LogLevel::Error,
                    "sync_groups",
                    None,
                    None,
                    &format!("Group sync failed: {}", e),
                    None,
                );
            }
        }

        // Determine final status
        let status = if self.stats.users_failed > 0 || self.stats.groups_failed > 0 {
            SyncStatus::Partial
        } else {
            SyncStatus::Success
        };

        // Update connection last sync info
        self.update_connection_sync_info(&status).await?;

        // Update sync log
        self.update_sync_log(log_id, status, None).await?;

        self.log(
            LogLevel::Info,
            "sync_complete",
            None,
            None,
            "Sync completed",
            Some(serde_json::json!({
                "stats": self.stats
            })),
        );

        Ok(self.stats.clone())
    }

    /// Sync users from LDAP
    async fn sync_users(
        &mut self,
        ldap: &LdapConnection,
        config: &LdapConfig,
    ) -> Result<(), SyncError> {
        self.log(
            LogLevel::Info,
            "sync_users",
            None,
            None,
            "Starting user sync",
            None,
        );

        // Get all users from LDAP
        let ldap_users = ldap.search_users(None).await?;
        self.stats.users_found = ldap_users.len();

        self.log(
            LogLevel::Info,
            "sync_users",
            None,
            None,
            &format!("Found {} users in LDAP", ldap_users.len()),
            None,
        );

        // Get existing user mappings
        let existing_mappings = self.get_existing_user_mappings().await?;
        let mut processed_dns: HashSet<String> = HashSet::new();

        for ldap_user in ldap_users {
            processed_dns.insert(ldap_user.dn.clone());

            match self.sync_user(ldap, &ldap_user, config).await {
                Ok(result) => match result.action {
                    UserSyncAction::Created => self.stats.users_created += 1,
                    UserSyncAction::Updated => self.stats.users_updated += 1,
                    UserSyncAction::Unchanged => self.stats.users_unchanged += 1,
                    UserSyncAction::Disabled => self.stats.users_disabled += 1,
                    UserSyncAction::Failed => self.stats.users_failed += 1,
                },
                Err(e) => {
                    self.stats.users_failed += 1;
                    self.log(
                        LogLevel::Error,
                        "sync_user",
                        Some(ldap_user.dn.clone()),
                        None,
                        &format!("Failed to sync user: {}", e),
                        None,
                    );
                }
            }
        }

        // Handle deprovisioning - find users that no longer exist in LDAP
        if config.jit_provisioning_enabled {
            for (dn, mapping) in existing_mappings {
                if !processed_dns.contains(&dn) {
                    self.deprovision_user(&mapping.user_id, &dn).await?;
                    self.stats.users_disabled += 1;
                }
            }
        }

        Ok(())
    }

    /// Sync a single user
    async fn sync_user(
        &mut self,
        ldap: &LdapConnection,
        ldap_user: &LdapUser,
        config: &LdapConfig,
    ) -> Result<UserSyncResult, SyncError> {
        // Check if user already exists
        let existing_mapping = self.get_user_mapping_by_dn(&ldap_user.dn).await?;

        if let Some(mapping) = existing_mapping {
            // User exists - check if needs update
            let current_hash = ldap_user.attribute_hash();

            if mapping.sync_hash == Some(current_hash.clone()) {
                // No changes
                return Ok(UserSyncResult {
                    user_id: mapping.user_id.clone(),
                    action: UserSyncAction::Unchanged,
                    ldap_user: ldap_user.clone(),
                });
            }

            // Update user
            match self.update_user(&mapping.user_id, ldap_user).await {
                Ok(_) => {
                    self.update_user_mapping(&mapping.user_id, ldap_user, &current_hash)
                        .await?;

                    self.log(
                        LogLevel::Info,
                        "update_user",
                        Some(ldap_user.dn.clone()),
                        Some(mapping.user_id.clone()),
                        "User updated",
                        None,
                    );

                    Ok(UserSyncResult {
                        user_id: mapping.user_id,
                        action: UserSyncAction::Updated,
                        ldap_user: ldap_user.clone(),
                    })
                }
                Err(e) => {
                    self.log(
                        LogLevel::Error,
                        "update_user",
                        Some(ldap_user.dn.clone()),
                        Some(mapping.user_id.clone()),
                        &format!("Failed to update user: {}", e),
                        None,
                    );
                    Ok(UserSyncResult {
                        user_id: mapping.user_id,
                        action: UserSyncAction::Failed,
                        ldap_user: ldap_user.clone(),
                    })
                }
            }
        } else {
            // New user - create if JIT provisioning is enabled
            if !config.jit_provisioning_enabled {
                return Ok(UserSyncResult {
                    user_id: String::new(),
                    action: UserSyncAction::Failed,
                    ldap_user: ldap_user.clone(),
                });
            }

            // Check if user already exists by email
            let existing_user = self.find_user_by_email(&ldap_user.email).await?;

            if let Some(user_id) = existing_user {
                // Link existing user to LDAP
                self.create_user_mapping(&user_id, ldap_user).await?;

                self.log(
                    LogLevel::Info,
                    "link_user",
                    Some(ldap_user.dn.clone()),
                    Some(user_id.clone()),
                    "Linked existing user to LDAP",
                    None,
                );

                return Ok(UserSyncResult {
                    user_id,
                    action: UserSyncAction::Updated,
                    ldap_user: ldap_user.clone(),
                });
            }

            // Create new user
            match self.create_user(ldap_user, config).await {
                Ok(user_id) => {
                    self.create_user_mapping(&user_id, ldap_user).await?;

                    self.log(
                        LogLevel::Info,
                        "create_user",
                        Some(ldap_user.dn.clone()),
                        Some(user_id.clone()),
                        "User created from LDAP",
                        None,
                    );

                    Ok(UserSyncResult {
                        user_id,
                        action: UserSyncAction::Created,
                        ldap_user: ldap_user.clone(),
                    })
                }
                Err(e) => {
                    self.log(
                        LogLevel::Error,
                        "create_user",
                        Some(ldap_user.dn.clone()),
                        None,
                        &format!("Failed to create user: {}", e),
                        None,
                    );
                    Ok(UserSyncResult {
                        user_id: String::new(),
                        action: UserSyncAction::Failed,
                        ldap_user: ldap_user.clone(),
                    })
                }
            }
        }
    }

    /// Create a new user from LDAP data
    async fn create_user(
        &self,
        ldap_user: &LdapUser,
        config: &LdapConfig,
    ) -> Result<String, SyncError> {
        let user_id = Uuid::new_v4().to_string();

        let profile = serde_json::json!({
            "name": ldap_user.full_name(),
            "first_name": ldap_user.first_name,
            "last_name": ldap_user.last_name,
            "department": ldap_user.department,
            "title": ldap_user.title,
            "phone": ldap_user.phone,
        });

        let status = if ldap_user.is_active && !ldap_user.is_expired() {
            "active"
        } else {
            "suspended"
        };

        sqlx::query(
            r#"
            INSERT INTO users (
                id, tenant_id, email, email_verified, password_hash,
                status, profile, metadata, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
            "#,
        )
        .bind(&user_id)
        .bind(&self.tenant_id)
        .bind(&ldap_user.email)
        .bind(true) // LDAP users have verified email
        .bind(None::<String>) // No password for LDAP users
        .bind(status)
        .bind(profile)
        .bind(serde_json::json!({
            "ldap_connection_id": self.connection_id.to_string(),
            "ldap_dn": ldap_user.dn,
            "source": "ldap"
        }))
        .execute(&self.pool)
        .await?;

        // Add to organization if configured
        if let Some(ref org_id) = config.jit_organization_id {
            self.add_user_to_organization(&user_id, org_id, &config.jit_default_role)
                .await?;
        }

        Ok(user_id)
    }

    /// Update an existing user from LDAP data
    async fn update_user(&self, user_id: &str, ldap_user: &LdapUser) -> Result<(), SyncError> {
        let profile = serde_json::json!({
            "name": ldap_user.full_name(),
            "first_name": ldap_user.first_name,
            "last_name": ldap_user.last_name,
            "department": ldap_user.department,
            "title": ldap_user.title,
            "phone": ldap_user.phone,
        });

        let status = if ldap_user.is_active && !ldap_user.is_expired() {
            "active"
        } else {
            "suspended"
        };

        sqlx::query(
            r#"
            UPDATE users 
            SET email = $1,
                status = $2,
                profile = $3,
                updated_at = NOW()
            WHERE id = $4 AND tenant_id = $5
            "#,
        )
        .bind(&ldap_user.email)
        .bind(status)
        .bind(profile)
        .bind(user_id)
        .bind(&self.tenant_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Deprovision a user (mark as suspended when removed from LDAP)
    async fn deprovision_user(&mut self, user_id: &str, ldap_dn: &str) -> Result<(), SyncError> {
        sqlx::query(
            r#"
            UPDATE users 
            SET status = 'suspended',
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(&self.tenant_id)
        .execute(&self.pool)
        .await?;

        // Update mapping
        sqlx::query(
            r#"
            UPDATE ldap_user_mappings
            SET deprovisioned_at = NOW(),
                deprovision_reason = 'Removed from LDAP',
                updated_at = NOW()
            WHERE user_id = $1 AND connection_id = $2
            "#,
        )
        .bind(user_id)
        .bind(&self.connection_id)
        .execute(&self.pool)
        .await?;

        self.log(
            LogLevel::Info,
            "deprovision_user",
            Some(ldap_dn.to_string()),
            Some(user_id.to_string()),
            "User deprovisioned (removed from LDAP)",
            None,
        );

        Ok(())
    }

    /// Sync groups from LDAP
    async fn sync_groups(
        &mut self,
        ldap: &LdapConnection,
        config: &LdapConfig,
    ) -> Result<(), SyncError> {
        self.log(
            LogLevel::Info,
            "sync_groups",
            None,
            None,
            "Starting group sync",
            None,
        );

        let ldap_groups = ldap.search_groups(None).await?;
        self.stats.groups_found = ldap_groups.len();

        self.log(
            LogLevel::Info,
            "sync_groups",
            None,
            None,
            &format!("Found {} groups in LDAP", ldap_groups.len()),
            None,
        );

        for ldap_group in ldap_groups {
            match self.sync_group(ldap, &ldap_group, config).await {
                Ok(result) => match result.action {
                    GroupSyncAction::Created => self.stats.groups_created += 1,
                    GroupSyncAction::Updated => self.stats.groups_updated += 1,
                    GroupSyncAction::Unchanged => (),
                    GroupSyncAction::Failed => self.stats.groups_failed += 1,
                },
                Err(e) => {
                    self.stats.groups_failed += 1;
                    self.log(
                        LogLevel::Error,
                        "sync_group",
                        Some(ldap_group.dn.clone()),
                        None,
                        &format!("Failed to sync group: {}", e),
                        None,
                    );
                }
            }
        }

        Ok(())
    }

    /// Sync a single group
    async fn sync_group(
        &mut self,
        _ldap: &LdapConnection,
        ldap_group: &LdapGroup,
        _config: &LdapConfig,
    ) -> Result<GroupSyncResult, SyncError> {
        // Check if group mapping exists
        let existing = self.get_group_mapping_by_dn(&ldap_group.dn).await?;

        if existing.is_some() {
            // Update group mapping
            sqlx::query(
                r#"
                UPDATE ldap_group_mappings
                SET ldap_name = $1,
                    member_count = $2,
                    last_synced_at = NOW(),
                    updated_at = NOW()
                WHERE connection_id = $3 AND ldap_dn = $4
                "#,
            )
            .bind(&ldap_group.name)
            .bind(ldap_group.member_count as i32)
            .bind(&self.connection_id)
            .bind(&ldap_group.dn)
            .execute(&self.pool)
            .await?;

            Ok(GroupSyncResult {
                group_id: existing.unwrap().id,
                action: GroupSyncAction::Updated,
                ldap_group: ldap_group.clone(),
            })
        } else {
            // Create new group mapping
            let mapping_id = Uuid::new_v4().to_string();

            sqlx::query(
                r#"
                INSERT INTO ldap_group_mappings (
                    id, tenant_id, connection_id, ldap_dn, ldap_guid,
                    ldap_name, member_count, metadata, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
                "#,
            )
            .bind(&mapping_id)
            .bind(&self.tenant_id)
            .bind(&self.connection_id)
            .bind(&ldap_group.dn)
            .bind(&ldap_group.guid)
            .bind(&ldap_group.name)
            .bind(ldap_group.member_count as i32)
            .bind(serde_json::json!({}))
            .execute(&self.pool)
            .await?;

            self.log(
                LogLevel::Info,
                "create_group_mapping",
                Some(ldap_group.dn.clone()),
                Some(mapping_id.clone()),
                "Group mapping created",
                None,
            );

            Ok(GroupSyncResult {
                group_id: mapping_id,
                action: GroupSyncAction::Created,
                ldap_group: ldap_group.clone(),
            })
        }
    }

    /// Get connection configuration from database
    async fn get_connection_config(&self) -> Result<LdapConfig, SyncError> {
        let row = sqlx::query(
            r#"
            SELECT 
                enabled, url, bind_dn, bind_password_encrypted,
                base_dn, user_search_base, user_search_filter,
                group_search_base, group_search_filter,
                user_attribute_mappings, sync_interval_minutes,
                tls_verify_cert, tls_ca_cert,
                connection_timeout_secs, search_timeout_secs, page_size,
                jit_provisioning_enabled, jit_default_role, jit_organization_id,
                group_sync_enabled
            FROM ldap_connections
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(&self.connection_id)
        .bind(&self.tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| SyncError::ConnectionNotFound)?;

        // TODO: Decrypt bind_password_encrypted
        let bind_password = String::new(); // Placeholder

        let config = LdapConfig {
            enabled: row.get("enabled"),
            url: row.get("url"),
            bind_dn: row.get("bind_dn"),
            bind_password,
            base_dn: row.get("base_dn"),
            user_search_base: row.get("user_search_base"),
            user_search_filter: row.get("user_search_filter"),
            group_search_base: row.get("group_search_base"),
            group_search_filter: row.get("group_search_filter"),
            user_attributes: serde_json::from_value(row.get("user_attribute_mappings"))
                .unwrap_or_default(),
            sync_interval_minutes: row.get::<i32, _>("sync_interval_minutes") as u32,
            tls_verify_cert: row.get("tls_verify_cert"),
            tls_ca_cert: row.get("tls_ca_cert"),
            connection_timeout_secs: row.get::<i32, _>("connection_timeout_secs") as u64,
            search_timeout_secs: row.get::<i32, _>("search_timeout_secs") as u64,
            page_size: row.get("page_size"),
            jit_provisioning_enabled: row.get("jit_provisioning_enabled"),
            jit_default_role: row.get("jit_default_role"),
            jit_organization_id: row
                .get::<Option<uuid::Uuid>, _>("jit_organization_id")
                .map(|id| id.to_string()),
            group_sync_enabled: row.get("group_sync_enabled"),
        };

        Ok(config)
    }

    /// Get existing user mappings for this connection
    async fn get_existing_user_mappings(&self) -> Result<HashMap<String, UserMapping>, SyncError> {
        let rows = sqlx::query(
            r#"
            SELECT ldap_dn, user_id, sync_hash
            FROM ldap_user_mappings
            WHERE connection_id = $1 AND tenant_id = $2 AND deprovisioned_at IS NULL
            "#,
        )
        .bind(&self.connection_id)
        .bind(&self.tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let mut mappings = HashMap::new();
        for row in rows {
            let dn: String = row.get("ldap_dn");
            mappings.insert(
                dn.clone(),
                UserMapping {
                    ldap_dn: dn,
                    user_id: row.get("user_id"),
                    sync_hash: row.get("sync_hash"),
                },
            );
        }

        Ok(mappings)
    }

    /// Get user mapping by LDAP DN
    async fn get_user_mapping_by_dn(&self, dn: &str) -> Result<Option<UserMapping>, SyncError> {
        let row = sqlx::query(
            r#"
            SELECT ldap_dn, user_id, sync_hash
            FROM ldap_user_mappings
            WHERE connection_id = $1 AND ldap_dn = $2 AND tenant_id = $3
            "#,
        )
        .bind(&self.connection_id)
        .bind(dn)
        .bind(&self.tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| UserMapping {
            ldap_dn: r.get("ldap_dn"),
            user_id: r.get("user_id"),
            sync_hash: r.get("sync_hash"),
        }))
    }

    /// Create user mapping
    async fn create_user_mapping(
        &self,
        user_id: &str,
        ldap_user: &LdapUser,
    ) -> Result<(), SyncError> {
        let mapping_id = Uuid::new_v4();
        let sync_hash = ldap_user.attribute_hash();

        sqlx::query(
            r#"
            INSERT INTO ldap_user_mappings (
                id, tenant_id, connection_id, user_id, ldap_dn,
                ldap_guid, ldap_object_sid, sync_hash, metadata, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
            "#,
        )
        .bind(&mapping_id)
        .bind(&self.tenant_id)
        .bind(&self.connection_id)
        .bind(user_id)
        .bind(&ldap_user.dn)
        .bind(&ldap_user.guid)
        .bind(&ldap_user.sid)
        .bind(&sync_hash)
        .bind(serde_json::json!({}))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update user mapping
    async fn update_user_mapping(
        &self,
        user_id: &str,
        ldap_user: &LdapUser,
        sync_hash: &str,
    ) -> Result<(), SyncError> {
        sqlx::query(
            r#"
            UPDATE ldap_user_mappings
            SET sync_hash = $1,
                last_synced_at = NOW(),
                updated_at = NOW()
            WHERE connection_id = $2 AND user_id = $3
            "#,
        )
        .bind(sync_hash)
        .bind(&self.connection_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Find user by email
    async fn find_user_by_email(&self, email: &str) -> Result<Option<String>, SyncError> {
        let row = sqlx::query(
            r#"
            SELECT id FROM users
            WHERE tenant_id = $1 AND email = $2 AND deleted_at IS NULL
            "#,
        )
        .bind(&self.tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.get("id")))
    }

    /// Get group mapping by DN
    async fn get_group_mapping_by_dn(&self, dn: &str) -> Result<Option<GroupMapping>, SyncError> {
        let row = sqlx::query(
            r#"
            SELECT id, ldap_dn, ldap_name
            FROM ldap_group_mappings
            WHERE connection_id = $1 AND ldap_dn = $2 AND tenant_id = $3
            "#,
        )
        .bind(&self.connection_id)
        .bind(dn)
        .bind(&self.tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| GroupMapping {
            id: r.get("id"),
            ldap_dn: r.get("ldap_dn"),
            ldap_name: r.get("ldap_name"),
        }))
    }

    /// Add user to organization
    async fn add_user_to_organization(
        &self,
        user_id: &str,
        org_id: &str,
        role: &str,
    ) -> Result<(), SyncError> {
        let member_id = Uuid::new_v4();

        sqlx::query(
            r#"
            INSERT INTO organization_members (
                id, tenant_id, organization_id, user_id, role, status, joined_at, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, 'active', NOW(), NOW(), NOW())
            ON CONFLICT (organization_id, user_id) DO NOTHING
            "#
        )
        .bind(&member_id)
        .bind(&self.tenant_id)
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Create sync log entry
    async fn create_sync_log(&self) -> Result<Uuid, SyncError> {
        let log_id = Uuid::new_v4();

        sqlx::query(
            r#"
            INSERT INTO ldap_sync_logs (
                id, tenant_id, connection_id, sync_type, status, started_at, triggered_by
            ) VALUES ($1, $2, $3, $4, 'running', NOW(), $5)
            "#,
        )
        .bind(&log_id)
        .bind(&self.tenant_id)
        .bind(&self.connection_id)
        .bind(format!("{:?}", self.sync_type).to_lowercase())
        .bind(&self.triggered_by)
        .execute(&self.pool)
        .await?;

        Ok(log_id)
    }

    /// Update sync log with completion status
    async fn update_sync_log(
        &mut self,
        log_id: Uuid,
        status: SyncStatus,
        error: Option<String>,
    ) -> Result<(), SyncError> {
        let duration = Utc::now().signed_duration_since(self.started_at);

        sqlx::query(
            r#"
            UPDATE ldap_sync_logs
            SET status = $1,
                completed_at = NOW(),
                users_found = $2,
                users_created = $3,
                users_updated = $4,
                users_disabled = $5,
                users_unchanged = $6,
                users_failed = $7,
                groups_found = $8,
                groups_created = $9,
                groups_updated = $10,
                groups_failed = $11,
                error_message = $12,
                error_details = $13,
                log_entries = $14,
                duration_ms = $15
            WHERE id = $16
            "#,
        )
        .bind(format!("{:?}", status).to_lowercase())
        .bind(self.stats.users_found as i32)
        .bind(self.stats.users_created as i32)
        .bind(self.stats.users_updated as i32)
        .bind(self.stats.users_disabled as i32)
        .bind(self.stats.users_unchanged as i32)
        .bind(self.stats.users_failed as i32)
        .bind(self.stats.groups_found as i32)
        .bind(self.stats.groups_created as i32)
        .bind(self.stats.groups_updated as i32)
        .bind(self.stats.groups_failed as i32)
        .bind(&error)
        .bind(error.as_ref().map(|e| serde_json::json!({ "message": e })))
        .bind(serde_json::to_value(&self.log_entries).unwrap_or_default())
        .bind(duration.num_milliseconds() as i32)
        .bind(&log_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Check if another sync is already running
    async fn is_sync_running(&self) -> Result<bool, SyncError> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM ldap_sync_logs
            WHERE connection_id = $1 AND status = 'running'
            "#,
        )
        .bind(&self.connection_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Update connection sync info
    async fn update_connection_sync_info(&self, status: &SyncStatus) -> Result<(), SyncError> {
        let next_sync = Utc::now()
            + chrono::Duration::minutes(self.get_sync_interval().await.unwrap_or(60) as i64);

        sqlx::query(
            r#"
            UPDATE ldap_connections
            SET last_sync_at = NOW(),
                last_sync_status = $1,
                next_sync_at = $2,
                updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(format!("{:?}", status).to_lowercase())
        .bind(next_sync)
        .bind(&self.connection_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get sync interval from connection config
    async fn get_sync_interval(&self) -> Result<i32, SyncError> {
        let interval: i32 =
            sqlx::query_scalar("SELECT sync_interval_minutes FROM ldap_connections WHERE id = $1")
                .bind(&self.connection_id)
                .fetch_one(&self.pool)
                .await?;

        Ok(interval)
    }

    /// Add a log entry
    fn log(
        &mut self,
        level: LogLevel,
        operation: &str,
        ldap_dn: Option<String>,
        user_id: Option<String>,
        message: &str,
        details: Option<serde_json::Value>,
    ) {
        let entry = SyncLogEntry {
            timestamp: Utc::now(),
            level,
            operation: operation.to_string(),
            ldap_dn,
            user_id,
            message: message.to_string(),
            details,
        };

        // Also log to tracing
        match level {
            LogLevel::Info => tracing::info!("LDAP sync: {}", message),
            LogLevel::Warning => tracing::warn!("LDAP sync: {}", message),
            LogLevel::Error => tracing::error!("LDAP sync: {}", message),
        }

        self.log_entries.push(entry);
    }

    /// Get sync statistics
    pub fn stats(&self) -> &SyncStats {
        &self.stats
    }
}

/// User mapping record
#[derive(Debug, Clone)]
struct UserMapping {
    pub ldap_dn: String,
    pub user_id: String,
    pub sync_hash: Option<String>,
}

/// Group mapping record
#[derive(Debug, Clone)]
struct GroupMapping {
    pub id: String,
    pub ldap_dn: String,
    pub ldap_name: String,
}

/// Sync scheduler for periodic LDAP synchronization
pub struct LdapSyncScheduler {
    pool: sqlx::PgPool,
}

impl LdapSyncScheduler {
    /// Create a new sync scheduler
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Run scheduled syncs for all enabled connections
    pub async fn run_scheduled_syncs(&self) -> Result<Vec<SyncStats>, SyncError> {
        let connections = self.get_due_connections().await?;
        let mut results = Vec::new();

        for (connection_id, tenant_id) in connections {
            tracing::info!("Running scheduled sync for connection {}", connection_id);

            let mut job = LdapSyncJob::new(
                self.pool.clone(),
                connection_id,
                tenant_id,
                SyncType::Incremental,
                "system".to_string(),
            );

            match job.run().await {
                Ok(stats) => results.push(stats),
                Err(e) => {
                    tracing::error!(
                        "Scheduled sync failed for connection {}: {}",
                        connection_id,
                        e
                    );
                }
            }
        }

        Ok(results)
    }

    /// Get connections that are due for sync
    async fn get_due_connections(&self) -> Result<Vec<(Uuid, Uuid)>, SyncError> {
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id
            FROM ldap_connections
            WHERE enabled = TRUE
              AND (next_sync_at IS NULL OR next_sync_at <= NOW())
              AND NOT EXISTS (
                  SELECT 1 FROM ldap_sync_logs
                  WHERE connection_id = ldap_connections.id
                    AND status = 'running'
              )
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut connections = Vec::new();
        for row in rows {
            connections.push((row.get("id"), row.get("tenant_id")));
        }

        Ok(connections)
    }
}

/// JIT (Just-In-Time) LDAP authentication handler
pub struct LdapJitAuth {
    pool: sqlx::PgPool,
}

impl LdapJitAuth {
    /// Create a new JIT auth handler
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Authenticate a user via LDAP with JIT provisioning
    pub async fn authenticate(
        &self,
        tenant_id: &str,
        email: &str,
        password: &str,
    ) -> Result<Option<LdapUser>, LdapError> {
        // Find LDAP connection for this tenant
        let connection = self
            .find_connection_for_tenant(tenant_id)
            .await
            .map_err(|e| LdapError::ConnectionFailed(e.to_string()))?;

        if let Some((config, connection_id)) = connection {
            if !config.enabled {
                return Ok(None);
            }

            // Try to authenticate
            let ldap = LdapConnection::new(config)?;

            // Extract username from email (e.g., user@example.com -> user)
            let username = email.split('@').next().unwrap_or(email);

            match ldap.authenticate(username, password).await {
                Ok(ldap_user) => {
                    // Provision/update user in database
                    if let Err(e) = self
                        .provision_user(tenant_id, &connection_id, &ldap_user)
                        .await
                    {
                        tracing::error!("Failed to provision LDAP user: {}", e);
                    }

                    Ok(Some(ldap_user))
                }
                Err(LdapError::InvalidCredentials) => Ok(None),
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }

    /// Find an LDAP connection for a tenant
    async fn find_connection_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Option<(LdapConfig, Uuid)>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT 
                id, url, bind_dn, bind_password_encrypted,
                base_dn, user_search_base, user_search_filter,
                user_attribute_mappings, tls_verify_cert,
                connection_timeout_secs, search_timeout_secs, page_size,
                jit_provisioning_enabled
            FROM ldap_connections
            WHERE tenant_id = $1 AND enabled = TRUE
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let connection_id: Uuid = row.get("id");

            // TODO: Decrypt password
            let config = LdapConfig {
                enabled: row.get("jit_provisioning_enabled"),
                url: row.get("url"),
                bind_dn: row.get("bind_dn"),
                bind_password: String::new(), // TODO: Decrypt
                base_dn: row.get("base_dn"),
                user_search_base: row.get("user_search_base"),
                user_search_filter: row.get("user_search_filter"),
                group_search_base: None,
                group_search_filter: "(objectClass=group)".to_string(),
                user_attributes: serde_json::from_value(row.get("user_attribute_mappings"))
                    .unwrap_or_default(),
                sync_interval_minutes: 60,
                tls_verify_cert: row.get("tls_verify_cert"),
                tls_ca_cert: None,
                connection_timeout_secs: row.get::<i32, _>("connection_timeout_secs") as u64,
                search_timeout_secs: row.get::<i32, _>("search_timeout_secs") as u64,
                page_size: row.get("page_size"),
                jit_provisioning_enabled: row.get("jit_provisioning_enabled"),
                jit_default_role: "member".to_string(),
                jit_organization_id: None,
                group_sync_enabled: false,
            };

            Ok(Some((config, connection_id)))
        } else {
            Ok(None)
        }
    }

    /// Provision or update a user from LDAP
    async fn provision_user(
        &self,
        tenant_id: &str,
        connection_id: &Uuid,
        ldap_user: &LdapUser,
    ) -> Result<(), sqlx::Error> {
        // Check if user mapping exists
        let existing: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT user_id FROM ldap_user_mappings
            WHERE connection_id = $1 AND ldap_dn = $2
            "#,
        )
        .bind(connection_id)
        .bind(&ldap_user.dn)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((user_id,)) = existing {
            // Update existing user
            sqlx::query(
                r#"
                UPDATE users
                SET email = $1,
                    profile = $2,
                    updated_at = NOW()
                WHERE id = $3 AND tenant_id = $4
                "#,
            )
            .bind(&ldap_user.email)
            .bind(serde_json::json!({
                "name": ldap_user.full_name(),
                "first_name": ldap_user.first_name,
                "last_name": ldap_user.last_name,
                "department": ldap_user.department,
                "title": ldap_user.title,
                "phone": ldap_user.phone,
            }))
            .bind(&user_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;

            // Update mapping
            sqlx::query(
                r#"
                UPDATE ldap_user_mappings
                SET last_synced_at = NOW(),
                    sync_hash = $1,
                    updated_at = NOW()
                WHERE connection_id = $2 AND user_id = $3
                "#,
            )
            .bind(ldap_user.attribute_hash())
            .bind(connection_id)
            .bind(&user_id)
            .execute(&self.pool)
            .await?;
        } else {
            // Check if user exists by email
            let existing_user: Option<(String,)> =
                sqlx::query_as("SELECT id FROM users WHERE tenant_id = $1 AND email = $2")
                    .bind(tenant_id)
                    .bind(&ldap_user.email)
                    .fetch_optional(&self.pool)
                    .await?;

            if let Some((user_id,)) = existing_user {
                // Create mapping for existing user
                sqlx::query(
                    r#"
                    INSERT INTO ldap_user_mappings (
                        id, tenant_id, connection_id, user_id, ldap_dn,
                        ldap_guid, sync_hash, created_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
                    "#,
                )
                .bind(Uuid::new_v4())
                .bind(tenant_id)
                .bind(connection_id)
                .bind(&user_id)
                .bind(&ldap_user.dn)
                .bind(&ldap_user.guid)
                .bind(ldap_user.attribute_hash())
                .execute(&self.pool)
                .await?;
            }
            // Note: If user doesn't exist and JIT is enabled, they should be created
            // This is handled by the sync job or explicit provisioning
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_type_serialization() {
        assert_eq!(serde_json::to_string(&SyncType::Full).unwrap(), "\"full\"");
        assert_eq!(
            serde_json::to_string(&SyncType::Incremental).unwrap(),
            "\"incremental\""
        );
    }

    #[test]
    fn test_sync_status_serialization() {
        assert_eq!(
            serde_json::to_string(&SyncStatus::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&SyncStatus::Success).unwrap(),
            "\"success\""
        );
    }

    #[test]
    fn test_sync_stats_default() {
        let stats = SyncStats::default();
        assert_eq!(stats.users_found, 0);
        assert_eq!(stats.users_created, 0);
        assert_eq!(stats.users_failed, 0);
    }
}
