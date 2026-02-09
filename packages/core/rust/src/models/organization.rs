//! Organization (team/workspace) model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

/// Organization (shared account for teams)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Organization {
    /// Unique identifier
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Organization name
    pub name: String,
    /// Organization slug (unique within tenant)
    pub slug: String,
    /// Logo URL
    pub logo_url: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Website URL
    pub website: Option<String>,
    /// Metadata (custom JSON)
    pub metadata: serde_json::Value,
    /// Maximum members allowed
    pub max_members: Option<i32>,
    /// Whether SSO is required for this org
    pub sso_required: bool,
    /// SSO provider configuration
    pub sso_config: Option<SsoConfig>,
    /// Whether auto-enrollment via verified domains is enabled
    pub auto_enroll_domains: bool,
    /// Default role for auto-enrolled users
    pub auto_enroll_default_role: String,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
    /// Deleted at (soft delete)
    pub deleted_at: Option<DateTime<Utc>>,
}

/// SSO configuration for organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    /// SSO provider type
    pub provider_type: SsoProviderType,
    /// SAML configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml: Option<SamlConfig>,
    /// OIDC configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcConfig>,
    /// JIT (Just-In-Time) provisioning enabled
    pub jit_provisioning: bool,
    /// Default role for JIT provisioned users
    pub default_role: OrganizationRole,
    /// Domain restrictions
    pub allowed_domains: Vec<String>,
}

/// SSO provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "sso_provider_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SsoProviderType {
    /// SAML 2.0
    Saml,
    /// OpenID Connect
    Oidc,
    /// Microsoft Entra ID (formerly Azure AD)
    Microsoft,
    /// Google Workspace
    Google,
    /// Okta
    Okta,
    /// OneLogin
    Onelogin,
    /// Auth0
    Auth0,
    /// Custom/generic
    Custom,
}

/// SAML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    /// SAML entity ID
    pub entity_id: String,
    /// SSO URL (IdP)
    pub sso_url: String,
    /// IdP certificate (PEM)
    pub idp_certificate: String,
    /// SP certificate (PEM)
    pub sp_certificate: String,
    /// SP private key (encrypted)
    pub sp_private_key: String,
    /// Name ID format
    pub name_id_format: String,
    /// Request signing enabled
    pub sign_requests: bool,
    /// Response signature required
    pub require_signed_responses: bool,
    /// Attribute mappings
    pub attribute_mappings: SamlAttributeMappings,
}

/// SAML attribute mappings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SamlAttributeMappings {
    /// Email attribute name
    pub email: Option<String>,
    /// First name attribute
    pub first_name: Option<String>,
    /// Last name attribute
    pub last_name: Option<String>,
    /// Groups/Roles attribute
    pub groups: Option<String>,
}

/// OIDC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// Issuer URL
    pub issuer: String,
    /// Authorization endpoint
    pub authorization_endpoint: String,
    /// Token endpoint
    pub token_endpoint: String,
    /// Userinfo endpoint
    pub userinfo_endpoint: String,
    /// JWKS URI
    pub jwks_uri: String,
    /// Client ID
    pub client_id: String,
    /// Client secret (encrypted)
    pub client_secret: String,
    /// Scopes to request
    pub scopes: Vec<String>,
    /// PKCE enabled
    pub pkce_enabled: bool,
}

/// Organization membership role
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "org_role", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    /// Owner - full control
    Owner,
    /// Admin - can manage members and settings
    Admin,
    /// Member - standard access
    #[default]
    Member,
    /// Guest - limited access
    Guest,
    /// Custom role
    Custom,
}

impl OrganizationRole {
    /// Check if role can manage members
    pub fn can_manage_members(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// Check if role can manage settings
    pub fn can_manage_settings(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// Check if role can delete organization
    pub fn can_delete_org(&self) -> bool {
        matches!(self, Self::Owner)
    }

    /// Check if role has billing access
    pub fn can_access_billing(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::Guest => "guest",
            Self::Custom => "custom",
        }
    }
}

impl fmt::Display for OrganizationRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrganizationRole::Owner => write!(f, "owner"),
            OrganizationRole::Admin => write!(f, "admin"),
            OrganizationRole::Member => write!(f, "member"),
            OrganizationRole::Guest => write!(f, "guest"),
            OrganizationRole::Custom => write!(f, "custom"),
        }
    }
}

use std::fmt;

impl FromStr for OrganizationRole {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            "guest" => Ok(Self::Guest),
            "custom" => Ok(Self::Custom),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

impl FromStr for MembershipStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "removed" => Ok(Self::Removed),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}

/// Organization member
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrganizationMember {
    /// Unique ID
    pub id: String,
    /// Organization ID
    pub organization_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// User ID
    pub user_id: String,
    /// Role in organization
    pub role: OrganizationRole,
    /// Custom permissions (if role is Custom)
    pub permissions: Vec<String>,
    /// Whether membership is pending invitation
    pub status: MembershipStatus,
    /// Invited by (user ID)
    pub invited_by: Option<String>,
    /// Invited at
    pub invited_at: Option<DateTime<Utc>>,
    /// Joined at
    pub joined_at: Option<DateTime<Utc>>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
}

/// Membership status
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "membership_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MembershipStatus {
    /// Invitation pending
    #[default]
    Pending,
    /// Active member
    Active,
    /// Suspended
    Suspended,
    /// Removed
    Removed,
}

impl MembershipStatus {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Removed => "removed",
        }
    }
}

/// Alias for MembershipStatus (for backward compatibility)
pub type MemberStatus = MembershipStatus;

/// Organization invitation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationInvitation {
    /// Unique ID
    pub id: String,
    /// Organization ID
    pub organization_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Email invited
    pub email: String,
    /// Role to assign
    pub role: OrganizationRole,
    /// Invited by user ID
    pub invited_by: String,
    /// Invitation token
    pub token: String,
    /// Expires at
    pub expires_at: DateTime<Utc>,
    /// Accepted at
    pub accepted_at: Option<DateTime<Utc>>,
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl Organization {
    /// Create new organization
    pub fn new(
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        slug: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            slug: slug.into(),
            logo_url: None,
            description: None,
            website: None,
            metadata: serde_json::Value::Object(serde_json::Map::new()),
            max_members: None,
            sso_required: false,
            sso_config: None,
            auto_enroll_domains: false,
            auto_enroll_default_role: "member".to_string(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// Update organization details
    pub fn update(&mut self, name: Option<String>, description: Option<String>) {
        if let Some(n) = name {
            self.name = n;
        }
        if let Some(d) = description {
            self.description = Some(d);
        }
        self.updated_at = Utc::now();
    }

    /// Configure SSO
    pub fn configure_sso(&mut self, config: SsoConfig) {
        self.sso_config = Some(config);
        self.updated_at = Utc::now();
    }

    /// Require SSO for this organization
    pub fn require_sso(&mut self, required: bool) {
        self.sso_required = required;
        self.updated_at = Utc::now();
    }

    /// Soft delete organization
    pub fn delete(&mut self) {
        self.deleted_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Check if organization is active
    pub fn is_active(&self) -> bool {
        self.deleted_at.is_none()
    }

    /// Enable/disable auto-enrollment for verified domains
    pub fn set_auto_enroll_domains(&mut self, enabled: bool) {
        self.auto_enroll_domains = enabled;
        self.updated_at = Utc::now();
    }

    /// Set default role for auto-enrolled users
    pub fn set_auto_enroll_default_role(&mut self, role: impl Into<String>) {
        self.auto_enroll_default_role = role.into();
        self.updated_at = Utc::now();
    }
}

impl OrganizationMember {
    /// Create new organization member
    pub fn new(
        tenant_id: impl Into<String>,
        organization_id: impl Into<String>,
        user_id: impl Into<String>,
        role: OrganizationRole,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            organization_id: organization_id.into(),
            tenant_id: tenant_id.into(),
            user_id: user_id.into(),
            role,
            permissions: Vec::new(),
            status: MembershipStatus::Pending,
            invited_by: None,
            invited_at: None,
            joined_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Accept invitation
    pub fn accept(&mut self) {
        self.status = MembershipStatus::Active;
        self.joined_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Update role
    pub fn update_role(&mut self, role: OrganizationRole) {
        self.role = role;
        self.updated_at = Utc::now();
    }

    /// Suspend membership
    pub fn suspend(&mut self) {
        self.status = MembershipStatus::Suspended;
        self.updated_at = Utc::now();
    }

    /// Remove member
    pub fn remove(&mut self) {
        self.status = MembershipStatus::Removed;
        self.updated_at = Utc::now();
    }

    /// Check if member has specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        match self.role {
            OrganizationRole::Owner => true,
            OrganizationRole::Admin => !matches!(permission, "org:delete" | "org:transfer"),
            OrganizationRole::Member => matches!(
                permission,
                "org:read" | "org:projects:read" | "org:projects:write"
            ),
            OrganizationRole::Guest => matches!(permission, "org:read" | "org:projects:read"),
            OrganizationRole::Custom => self.permissions.contains(&permission.to_string()),
        }
    }
}

impl OrganizationInvitation {
    /// Create new invitation
    pub fn new(
        tenant_id: impl Into<String>,
        organization_id: impl Into<String>,
        email: impl Into<String>,
        role: OrganizationRole,
        invited_by: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            organization_id: organization_id.into(),
            tenant_id: tenant_id.into(),
            email: email.into(),
            role,
            invited_by: invited_by.into(),
            token: crate::crypto::generate_secure_random(32),
            expires_at: now + chrono::Duration::days(7),
            accepted_at: None,
            created_at: now,
        }
    }

    /// Check if invitation is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at || self.accepted_at.is_some()
    }

    /// Mark as accepted
    pub fn accept(&mut self) {
        self.accepted_at = Some(Utc::now());
    }
}

impl super::Model for Organization {
    fn id(&self) -> &str {
        &self.id
    }

    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

impl super::Model for OrganizationMember {
    fn id(&self) -> &str {
        &self.id
    }

    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

/// Create organization request
#[derive(Debug, Clone, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
}

/// Update organization request
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub logo_url: Option<String>,
    pub website: Option<String>,
}

/// Invite member request
#[derive(Debug, Clone, Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
    pub role: OrganizationRole,
}

/// Update member request
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateMemberRequest {
    pub role: OrganizationRole,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_creation() {
        let org = Organization::new("tenant_123", "My Org", "my-org");
        assert_eq!(org.name, "My Org");
        assert_eq!(org.slug, "my-org");
        assert!(org.is_active());
        assert!(!org.sso_required);
    }

    #[test]
    fn test_organization_roles() {
        assert!(OrganizationRole::Owner.can_delete_org());
        assert!(!OrganizationRole::Admin.can_delete_org());
        assert!(OrganizationRole::Admin.can_manage_members());
        assert!(!OrganizationRole::Member.can_manage_members());
    }

    #[test]
    fn test_member_permissions() {
        let member = OrganizationMember::new(
            "tenant_123",
            "org_456",
            "user_789",
            OrganizationRole::Member,
        );

        assert!(member.has_permission("org:read"));
        assert!(!member.has_permission("org:settings:write"));

        let admin =
            OrganizationMember::new("tenant_123", "org_456", "user_790", OrganizationRole::Admin);

        assert!(admin.has_permission("org:settings:write"));
        assert!(!admin.has_permission("org:delete"));
    }

    #[test]
    fn test_invitation() {
        let mut invitation = OrganizationInvitation::new(
            "tenant_123",
            "org_456",
            "newuser@example.com",
            OrganizationRole::Member,
            "inviter_789",
        );

        assert!(!invitation.is_expired());
        invitation.accept();
        assert!(invitation.is_expired());
    }

    #[test]
    fn test_invitation_expiry() {
        let mut invitation = OrganizationInvitation::new(
            "tenant_123",
            "org_456",
            "newuser@example.com",
            OrganizationRole::Member,
            "inviter_789",
        );

        // Set expiration in the past
        invitation.expires_at = Utc::now() - chrono::Duration::days(1);
        assert!(invitation.is_expired());
    }
}
