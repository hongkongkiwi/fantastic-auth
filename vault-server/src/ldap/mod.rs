//! LDAP/Active Directory Integration Module
//!
//! Provides connectivity to LDAP servers for authentication and user synchronization.
//! Supports Active Directory, OpenLDAP, and other LDAP-compatible directories.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub mod sync;

/// LDAP operation errors
#[derive(Debug, Error)]
pub enum LdapError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Search failed: {0}")]
    SearchFailed(String),

    #[error("Bind failed: {0}")]
    BindFailed(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// LDAP connection configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LdapConfig {
    /// Connection enabled
    pub enabled: bool,
    /// LDAP server URL (e.g., ldaps://ad.company.com:636)
    pub url: String,
    /// Bind DN for service account (e.g., CN=admin,DC=company,DC=com)
    pub bind_dn: String,
    /// Bind password for service account
    pub bind_password: String,
    /// Base DN for searches (e.g., DC=company,DC=com)
    pub base_dn: String,
    /// User search base (optional, defaults to base_dn)
    pub user_search_base: Option<String>,
    /// User search filter (e.g., (objectClass=user))
    pub user_search_filter: String,
    /// Group search base (optional, defaults to base_dn)
    pub group_search_base: Option<String>,
    /// Group search filter (e.g., (objectClass=group))
    pub group_search_filter: String,
    /// Attribute mappings
    pub user_attributes: LdapUserAttributes,
    /// Sync interval in minutes
    pub sync_interval_minutes: u32,
    /// TLS verification
    pub tls_verify_cert: bool,
    /// Custom CA certificate (optional)
    pub tls_ca_cert: Option<String>,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Search timeout in seconds
    pub search_timeout_secs: u64,
    /// Page size for LDAP pagination
    pub page_size: i32,
    /// Enable JIT (Just-In-Time) provisioning
    pub jit_provisioning_enabled: bool,
    /// Default role for JIT provisioned users
    pub jit_default_role: String,
    /// Default organization ID for JIT provisioned users
    pub jit_organization_id: Option<String>,
    /// Enable group synchronization
    pub group_sync_enabled: bool,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            base_dn: String::new(),
            user_search_base: None,
            group_search_base: None,
            user_search_filter: "(objectClass=user)".to_string(),
            group_search_filter: "(objectClass=group)".to_string(),
            user_attributes: LdapUserAttributes::default(),
            sync_interval_minutes: 60,
            tls_verify_cert: true,
            tls_ca_cert: None,
            connection_timeout_secs: 10,
            search_timeout_secs: 30,
            page_size: 1000,
            jit_provisioning_enabled: true,
            jit_default_role: "member".to_string(),
            jit_organization_id: None,
            group_sync_enabled: false,
        }
    }
}

/// LDAP user attribute mappings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LdapUserAttributes {
    /// Email attribute (default: mail)
    pub email: String,
    /// Username attribute (default: sAMAccountName for AD, uid for OpenLDAP)
    pub username: String,
    /// First name attribute (default: givenName)
    pub first_name: String,
    /// Last name attribute (default: sn)
    pub last_name: String,
    /// Display name attribute (default: displayName)
    pub display_name: String,
    /// Phone number attribute (default: telephoneNumber)
    pub phone: String,
    /// Department attribute (default: department)
    pub department: String,
    /// Job title attribute (default: title)
    pub title: String,
    /// Employee ID attribute (default: employeeID)
    pub employee_id: String,
    /// Object GUID attribute (default: objectGUID for AD, entryUUID for OpenLDAP)
    pub object_guid: String,
    /// Member of attribute for group membership (default: memberOf)
    pub member_of: String,
}

impl Default for LdapUserAttributes {
    fn default() -> Self {
        Self {
            email: "mail".to_string(),
            username: "sAMAccountName".to_string(),
            first_name: "givenName".to_string(),
            last_name: "sn".to_string(),
            display_name: "displayName".to_string(),
            phone: "telephoneNumber".to_string(),
            department: "department".to_string(),
            title: "title".to_string(),
            employee_id: "employeeID".to_string(),
            object_guid: "objectGUID".to_string(),
            member_of: "memberOf".to_string(),
        }
    }
}

/// LDAP User representation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LdapUser {
    /// Distinguished Name (full LDAP path)
    pub dn: String,
    /// Object GUID (binary or string representation)
    pub guid: Option<String>,
    /// Object SID (Windows Security Identifier)
    pub sid: Option<String>,
    /// Username (sAMAccountName or uid)
    pub username: String,
    /// Email address
    pub email: String,
    /// First name
    pub first_name: Option<String>,
    /// Last name
    pub last_name: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// Phone number
    pub phone: Option<String>,
    /// Department
    pub department: Option<String>,
    /// Job title
    pub title: Option<String>,
    /// Employee ID
    pub employee_id: Option<String>,
    /// Whether the account is active/enabled
    pub is_active: bool,
    /// Account expiration date
    pub account_expires: Option<chrono::DateTime<chrono::Utc>>,
    /// Group memberships (DNs)
    pub member_of: Vec<String>,
    /// Raw LDAP attributes
    pub raw_attributes: HashMap<String, Vec<String>>,
    /// When the entry was created in LDAP
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the entry was last modified in LDAP
    pub modified_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl LdapUser {
    /// Get full name (first + last)
    pub fn full_name(&self) -> Option<String> {
        match (&self.first_name, &self.last_name) {
            (Some(first), Some(last)) => Some(format!("{} {}", first, last)),
            (Some(first), None) => Some(first.clone()),
            (None, Some(last)) => Some(last.clone()),
            (None, None) => self.display_name.clone(),
        }
    }

    /// Check if account is expired
    pub fn is_expired(&self) -> bool {
        match self.account_expires {
            Some(expires) => expires < chrono::Utc::now(),
            None => false,
        }
    }

    /// Get a hash of key attributes for change detection
    pub fn attribute_hash(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.email.hash(&mut hasher);
        self.first_name.hash(&mut hasher);
        self.last_name.hash(&mut hasher);
        self.display_name.hash(&mut hasher);
        self.phone.hash(&mut hasher);
        self.department.hash(&mut hasher);
        self.title.hash(&mut hasher);
        self.is_active.hash(&mut hasher);
        self.member_of.hash(&mut hasher);

        format!("{:x}", hasher.finish())
    }
}

/// LDAP Group representation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LdapGroup {
    /// Distinguished Name
    pub dn: String,
    /// Object GUID
    pub guid: Option<String>,
    /// Group name (cn)
    pub name: String,
    /// Group description
    pub description: Option<String>,
    /// Group type (security, distribution, etc.)
    pub group_type: Option<String>,
    /// Member DNs
    pub members: Vec<String>,
    /// Member count
    pub member_count: usize,
    /// Raw LDAP attributes
    pub raw_attributes: HashMap<String, Vec<String>>,
}

/// LDAP Connection handle
pub struct LdapConnection {
    config: LdapConfig,
    // Note: The actual ldap3 connection is created per-operation
    // to avoid connection pool complexity and handle timeouts properly
}

impl LdapConnection {
    /// Create a new LDAP connection configuration
    pub fn new(config: LdapConfig) -> Result<Self, LdapError> {
        // Validate configuration
        if config.url.is_empty() {
            return Err(LdapError::InvalidConfig("LDAP URL is required".to_string()));
        }
        if config.bind_dn.is_empty() {
            return Err(LdapError::InvalidConfig("Bind DN is required".to_string()));
        }
        if config.base_dn.is_empty() {
            return Err(LdapError::InvalidConfig("Base DN is required".to_string()));
        }

        Ok(Self { config })
    }

    /// Test the LDAP connection
    pub async fn test(&self) -> Result<(), LdapError> {
        // Perform a bind operation to verify credentials
        let _conn = self.connect().await?;
        Ok(())
    }

    /// Connect to the LDAP server
    async fn connect(&self) -> Result<LdapConn, LdapError> {
        let url = &self.config.url;

        // Parse URL to determine connection type
        let is_ldaps = url.starts_with("ldaps://");
        let is_ldap = url.starts_with("ldap://");

        if !is_ldaps && !is_ldap {
            return Err(LdapError::InvalidConfig(
                "URL must start with ldap:// or ldaps://".to_string(),
            ));
        }

        // Build LDAP connection options
        let opts = ldap3::LdapConnSettings::new().set_conn_timeout(std::time::Duration::from_secs(
            self.config.connection_timeout_secs,
        ));

        // Note: ldap3 v0.11 doesn't have set_no_tls_verify, so we handle TLS differently
        // Connect to the server
        let (conn, mut ldap) = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.connection_timeout_secs),
            ldap3::LdapConnAsync::from_url_with_settings(
                opts,
                &url.parse()
                    .map_err(|e| LdapError::InvalidConfig(format!("Invalid LDAP URL: {}", e)))?,
            ),
        )
        .await
        .map_err(|_| LdapError::Timeout("Connection timeout".to_string()))?
        .map_err(|e| LdapError::ConnectionFailed(e.to_string()))?;

        // Spawn the LDAP driver
        tokio::spawn(async move {
            let _ = conn.drive().await;
        });

        // Perform bind
        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)
            .await
            .map_err(|e| LdapError::BindFailed(e.to_string()))?;

        Ok(ldap)
    }

    /// Authenticate a user with username and password
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LdapUser, LdapError> {
        // First, find the user by username
        let user = self.search_user_by_username(username).await?;

        // Attempt to bind as the user with their password
        let url = &self.config.url;

        let opts = ldap3::LdapConnSettings::new().set_conn_timeout(std::time::Duration::from_secs(
            self.config.connection_timeout_secs,
        ));

        let (conn, mut ldap) = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.connection_timeout_secs),
            ldap3::LdapConnAsync::from_url_with_settings(
                opts,
                &url.parse()
                    .map_err(|e| LdapError::InvalidConfig(format!("Invalid LDAP URL: {}", e)))?,
            ),
        )
        .await
        .map_err(|_| LdapError::Timeout("Connection timeout".to_string()))?
        .map_err(|e| LdapError::ConnectionFailed(e.to_string()))?;

        // Spawn the LDAP driver
        tokio::spawn(async move {
            let _ = conn.drive().await;
        });

        // Try to bind as the user
        let result = ldap.simple_bind(&user.dn, password).await;

        match result {
            Ok(_) => Ok(user),
            Err(_) => Err(LdapError::InvalidCredentials),
        }
    }

    /// Search for a user by username
    pub async fn search_user_by_username(&self, username: &str) -> Result<LdapUser, LdapError> {
        let search_base = self
            .config
            .user_search_base
            .as_ref()
            .unwrap_or(&self.config.base_dn);

        let filter = format!(
            "(&{}({}={}))",
            self.config.user_search_filter,
            self.config.user_attributes.username,
            ldap3::ldap_escape(username)
        );

        let mut ldap = self.connect().await?;

        let (entries, _) = ldap
            .search(
                search_base,
                ldap3::Scope::Subtree,
                &filter,
                vec!["*"], // Return all attributes
            )
            .await
            .map_err(|e| LdapError::SearchFailed(e.to_string()))?
            .success()
            .map_err(|e| LdapError::SearchFailed(format!("Search failed: {:?}", e)))?;

        if entries.is_empty() {
            return Err(LdapError::UserNotFound);
        }

        // Parse the first result
        self.parse_user_entry(&entries[0])
    }

    /// Search for users
    pub async fn search_users(&self, filter: Option<&str>) -> Result<Vec<LdapUser>, LdapError> {
        let search_base = self
            .config
            .user_search_base
            .as_ref()
            .unwrap_or(&self.config.base_dn);

        let search_filter = filter.unwrap_or(&self.config.user_search_filter);

        let mut ldap = self.connect().await?;

        let (entries, _) = ldap
            .search(search_base, ldap3::Scope::Subtree, search_filter, vec!["*"])
            .await
            .map_err(|e| LdapError::SearchFailed(e.to_string()))?
            .success()
            .map_err(|e| LdapError::SearchFailed(format!("Search failed: {:?}", e)))?;

        let mut users = Vec::new();
        for entry in entries {
            match self.parse_user_entry(&entry) {
                Ok(user) => users.push(user),
                Err(e) => {
                    tracing::warn!("Failed to parse user entry: {}", e);
                }
            }
        }

        Ok(users)
    }

    /// Search for groups
    pub async fn search_groups(&self, filter: Option<&str>) -> Result<Vec<LdapGroup>, LdapError> {
        let search_base = self
            .config
            .group_search_base
            .as_ref()
            .unwrap_or(&self.config.base_dn);

        let search_filter = filter.unwrap_or(&self.config.group_search_filter);

        let mut ldap = self.connect().await?;

        let (entries, _) = ldap
            .search(search_base, ldap3::Scope::Subtree, search_filter, vec!["*"])
            .await
            .map_err(|e| LdapError::SearchFailed(e.to_string()))?
            .success()
            .map_err(|e| LdapError::SearchFailed(format!("Search failed: {:?}", e)))?;

        let mut groups = Vec::new();
        for entry in entries {
            match self.parse_group_entry(&entry) {
                Ok(group) => groups.push(group),
                Err(e) => {
                    tracing::warn!("Failed to parse group entry: {}", e);
                }
            }
        }

        Ok(groups)
    }

    /// Get user groups
    pub async fn get_user_groups(&self, user_dn: &str) -> Result<Vec<LdapGroup>, LdapError> {
        let search_base = self
            .config
            .group_search_base
            .as_ref()
            .unwrap_or(&self.config.base_dn);

        // Search for groups where this user is a member
        let filter = format!(
            "(&{}(member={}))",
            self.config.group_search_filter,
            ldap3::ldap_escape(user_dn)
        );

        let mut ldap = self.connect().await?;

        let (entries, _) = ldap
            .search(search_base, ldap3::Scope::Subtree, &filter, vec!["*"])
            .await
            .map_err(|e| LdapError::SearchFailed(e.to_string()))?
            .success()
            .map_err(|e| LdapError::SearchFailed(format!("Search failed: {:?}", e)))?;

        let mut groups = Vec::new();
        for entry in entries {
            match self.parse_group_entry(&entry) {
                Ok(group) => groups.push(group),
                Err(e) => {
                    tracing::warn!("Failed to parse group entry: {}", e);
                }
            }
        }

        Ok(groups)
    }

    /// Parse an LDAP entry into an LdapUser
    fn parse_user_entry(&self, entry: &ldap3::ResultEntry) -> Result<LdapUser, LdapError> {
        let entry = ldap3::SearchEntry::from(entry.clone());
        let attrs = &entry.attrs;

        let get_attr =
            |name: &str| -> Option<String> { attrs.get(name).and_then(|v| v.first()).cloned() };

        let get_attr_list =
            |name: &str| -> Vec<String> { attrs.get(name).cloned().unwrap_or_default() };

        // Convert raw attributes to HashMap<String, Vec<String>>
        let raw_attributes: HashMap<String, Vec<String>> =
            attrs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        // Check if account is active
        // In AD, userAccountControl bit 2 (0x2) indicates disabled account
        let is_active = if let Some(uac) = get_attr("userAccountControl") {
            match uac.parse::<u32>() {
                Ok(flags) => (flags & 0x2) == 0, // Account is active if bit 2 is NOT set
                Err(_) => true,                  // Default to active if we can't parse
            }
        } else {
            true // Default to active for non-AD LDAP
        };

        // Parse memberOf
        let member_of = get_attr_list(&self.config.user_attributes.member_of);

        Ok(LdapUser {
            dn: entry.dn.clone(),
            guid: get_attr(&self.config.user_attributes.object_guid),
            sid: get_attr("objectSid"),
            username: get_attr(&self.config.user_attributes.username).unwrap_or_default(),
            email: get_attr(&self.config.user_attributes.email).unwrap_or_default(),
            first_name: get_attr(&self.config.user_attributes.first_name),
            last_name: get_attr(&self.config.user_attributes.last_name),
            display_name: get_attr(&self.config.user_attributes.display_name),
            phone: get_attr(&self.config.user_attributes.phone),
            department: get_attr(&self.config.user_attributes.department),
            title: get_attr(&self.config.user_attributes.title),
            employee_id: get_attr(&self.config.user_attributes.employee_id),
            is_active,
            account_expires: None, // TODO: Parse accountExpires attribute
            member_of,
            raw_attributes,
            created_at: None,  // TODO: Parse whenCreated
            modified_at: None, // TODO: Parse whenChanged
        })
    }

    /// Parse an LDAP entry into an LdapGroup
    fn parse_group_entry(&self, entry: &ldap3::ResultEntry) -> Result<LdapGroup, LdapError> {
        let entry = ldap3::SearchEntry::from(entry.clone());
        let attrs = &entry.attrs;

        let get_attr =
            |name: &str| -> Option<String> { attrs.get(name).and_then(|v| v.first()).cloned() };

        let get_attr_list =
            |name: &str| -> Vec<String> { attrs.get(name).cloned().unwrap_or_default() };

        // Convert raw attributes
        let raw_attributes: HashMap<String, Vec<String>> =
            attrs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        // Get members
        let members = get_attr_list("member");
        let member_count = members.len();

        Ok(LdapGroup {
            dn: entry.dn.clone(),
            guid: get_attr("objectGUID"),
            name: get_attr("cn").unwrap_or_default(),
            description: get_attr("description"),
            group_type: get_attr("groupType"),
            members,
            member_count,
            raw_attributes,
        })
    }
}

// Wrapper type for ldap3 connection
type LdapConn = ldap3::Ldap;

/// Escape special characters in LDAP search filters
pub fn escape_filter(value: &str) -> String {
    ldap3::ldap_escape(value).to_string()
}

/// Build an LDAP filter for user search
pub fn build_user_filter(base_filter: &str, username_attr: &str, username: &str) -> String {
    format!(
        "(&{}({}={}))",
        base_filter,
        username_attr,
        escape_filter(username)
    )
}

/// Build an LDAP filter for group membership
pub fn build_group_member_filter(base_filter: &str, user_dn: &str) -> String {
    format!("(&{}(member={}))", base_filter, escape_filter(user_dn))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_config_validation() {
        let config = LdapConfig {
            enabled: true,
            url: "ldaps://ad.example.com:636".to_string(),
            bind_dn: "CN=admin,DC=example,DC=com".to_string(),
            bind_password: "password".to_string(),
            base_dn: "DC=example,DC=com".to_string(),
            ..Default::default()
        };

        let conn = LdapConnection::new(config);
        assert!(conn.is_ok());
    }

    #[test]
    fn test_ldap_config_validation_missing_url() {
        let config = LdapConfig {
            enabled: true,
            url: "".to_string(),
            bind_dn: "CN=admin,DC=example,DC=com".to_string(),
            bind_password: "password".to_string(),
            base_dn: "DC=example,DC=com".to_string(),
            ..Default::default()
        };

        let conn = LdapConnection::new(config);
        assert!(matches!(conn, Err(LdapError::InvalidConfig(_))));
    }

    #[test]
    fn test_escape_filter() {
        let input = "user(name)";
        let escaped = escape_filter(input);
        assert!(escaped.contains("\\"));
    }

    #[test]
    fn test_build_user_filter() {
        let filter = build_user_filter("(objectClass=user)", "sAMAccountName", "john.doe");
        assert_eq!(filter, "(&(objectClass=user)(sAMAccountName=john.doe))");
    }

    #[test]
    fn test_ldap_user_full_name() {
        let user = LdapUser {
            dn: "CN=John Doe,DC=example,DC=com".to_string(),
            guid: None,
            sid: None,
            username: "jdoe".to_string(),
            email: "john@example.com".to_string(),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            display_name: None,
            phone: None,
            department: None,
            title: None,
            employee_id: None,
            is_active: true,
            account_expires: None,
            member_of: vec![],
            raw_attributes: HashMap::new(),
            created_at: None,
            modified_at: None,
        };

        assert_eq!(user.full_name(), Some("John Doe".to_string()));
    }
}
