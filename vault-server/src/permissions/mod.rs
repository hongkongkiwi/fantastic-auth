//! RBAC++ Permission System
//!
//! A fine-grained, resource-level permission system inspired by Clerk.
//! Supports:
//! - Global permissions (e.g., `document:read`)
//! - Resource-specific permissions (e.g., `document:123:admin`)
//! - Role-based permission inheritance
//! - Redis caching for performance

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

pub mod checker;

/// A permission defines an action that can be performed on a resource type
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Permission {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub resource_type: String,
    pub action: String,
    pub created_at: DateTime<Utc>,
}

/// A role is a collection of permissions that can be assigned to users
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Role {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub is_system_role: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Junction table: many-to-many relationship between roles and permissions
#[derive(Debug, Clone, FromRow)]
pub struct RolePermission {
    pub role_id: Uuid,
    pub permission_id: Uuid,
}

/// User role assignment - can be tenant-level or organization-specific
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserRole {
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<Uuid>,
}

/// Resource-level permission assignment
/// Grants a specific permission on a specific resource instance
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ResourcePermission {
    pub id: Uuid,
    pub user_id: Uuid,
    pub permission_id: Uuid,
    pub resource_type: String,
    pub resource_id: String,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Permission with resource context for checking
#[derive(Debug, Clone)]
pub struct PermissionCheck {
    pub resource_type: String,
    pub action: String,
    pub resource_id: Option<String>,
}

impl PermissionCheck {
    /// Parse a permission string like "document:read" or "document:123:admin"
    pub fn parse(permission: &str) -> Option<Self> {
        let parts: Vec<&str> = permission.split(':').collect();
        
        match parts.len() {
            // Format: "resource:action" (e.g., "document:read")
            2 => Some(Self {
                resource_type: parts[0].to_string(),
                action: parts[1].to_string(),
                resource_id: None,
            }),
            // Format: "resource:resource_id:action" (e.g., "document:123:admin")
            3 => Some(Self {
                resource_type: parts[0].to_string(),
                resource_id: Some(parts[1].to_string()),
                action: parts[2].to_string(),
            }),
            _ => None,
        }
    }
    
    /// Format as a wildcard permission (without resource_id)
    pub fn to_wildcard(&self) -> String {
        format!("{}:{}", self.resource_type, self.action)
    }
    
    /// Format as a specific resource permission
    pub fn to_specific(&self) -> Option<String> {
        self.resource_id.as_ref()
            .map(|id| format!("{}:{}:{}", self.resource_type, id, self.action))
    }
}

/// Default system roles
pub mod system_roles {
    pub const SUPERADMIN: &str = "superadmin";
    pub const ADMIN: &str = "admin";
    pub const MEMBER: &str = "member";
    pub const VIEWER: &str = "viewer";
    pub const GUEST: &str = "guest";
}

/// Common permission actions
pub mod actions {
    pub const CREATE: &str = "create";
    pub const READ: &str = "read";
    pub const WRITE: &str = "write";
    pub const DELETE: &str = "delete";
    pub const ADMIN: &str = "admin";
    pub const MANAGE: &str = "manage";
    pub const INVITE: &str = "invite";
}

/// Resource types
pub mod resource_types {
    pub const USER: &str = "user";
    pub const ORGANIZATION: &str = "organization";
    pub const DOCUMENT: &str = "document";
    pub const BILLING: &str = "billing";
    pub const SETTINGS: &str = "settings";
    pub const AUDIT: &str = "audit";
    pub const WEBHOOK: &str = "webhook";
    pub const ROLE: &str = "role";
    pub const PERMISSION: &str = "permission";
}

/// Create default permissions for a tenant
pub fn default_permissions() -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    vec![
        // User permissions
        ("user:create", "Create users", "user", "create"),
        ("user:read", "Read user profiles", "user", "read"),
        ("user:write", "Update users", "user", "write"),
        ("user:delete", "Delete users", "user", "delete"),
        ("user:invite", "Invite users", "user", "invite"),
        ("user:manage", "Manage all user settings", "user", "manage"),
        
        // Organization permissions
        ("organization:create", "Create organizations", "organization", "create"),
        ("organization:read", "Read organizations", "organization", "read"),
        ("organization:write", "Update organizations", "organization", "write"),
        ("organization:delete", "Delete organizations", "organization", "delete"),
        ("organization:manage", "Manage organizations", "organization", "manage"),
        
        // Document permissions
        ("document:create", "Create documents", "document", "create"),
        ("document:read", "Read documents", "document", "read"),
        ("document:write", "Update documents", "document", "write"),
        ("document:delete", "Delete documents", "document", "delete"),
        ("document:admin", "Admin access to documents", "document", "admin"),
        
        // Billing permissions
        ("billing:read", "Read billing info", "billing", "read"),
        ("billing:manage", "Manage billing", "billing", "manage"),
        
        // Settings permissions
        ("settings:read", "Read settings", "settings", "read"),
        ("settings:write", "Update settings", "settings", "write"),
        ("settings:manage", "Manage all settings", "settings", "manage"),
        
        // Audit permissions
        ("audit:read", "Read audit logs", "audit", "read"),
        ("audit:export", "Export audit logs", "audit", "export"),
        
        // Webhook permissions
        ("webhook:read", "Read webhooks", "webhook", "read"),
        ("webhook:write", "Manage webhooks", "webhook", "write"),
        
        // Role/Permission management
        ("role:read", "Read roles", "role", "read"),
        ("role:write", "Manage roles", "role", "write"),
        ("permission:read", "Read permissions", "permission", "read"),
        ("permission:write", "Manage permissions", "permission", "write"),
        
        // Superadmin-only permissions
        ("system:admin", "System administration", "system", "admin"),
        ("tenant:manage", "Manage tenants", "tenant", "manage"),
    ]
}

/// Get default permissions for a system role
pub fn default_role_permissions(role: &str) -> Vec<&'static str> {
    match role {
        system_roles::SUPERADMIN => vec![
            "user:*", "organization:*", "document:*", "billing:*",
            "settings:*", "audit:*", "webhook:*", "role:*", "permission:*",
            "system:admin", "tenant:manage",
        ],
        system_roles::ADMIN => vec![
            "user:create", "user:read", "user:write", "user:invite", "user:manage",
            "organization:read", "organization:write", "organization:manage",
            "document:*", "billing:read", "billing:manage",
            "settings:read", "settings:write", "settings:manage",
            "audit:read", "webhook:*", "role:read", "role:write",
            "permission:read",
        ],
        system_roles::MEMBER => vec![
            "user:read", "organization:read",
            "document:create", "document:read", "document:write",
            "settings:read", "billing:read",
        ],
        system_roles::VIEWER => vec![
            "user:read", "organization:read",
            "document:read", "settings:read", "billing:read",
        ],
        system_roles::GUEST => vec![
            "user:read", "document:read",
        ],
        _ => vec![],
    }
}

/// Permission response for API
#[derive(Debug, Serialize)]
pub struct PermissionResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub resource_type: String,
    pub action: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

impl From<Permission> for PermissionResponse {
    fn from(p: Permission) -> Self {
        Self {
            id: p.id.to_string(),
            name: p.name,
            description: p.description,
            resource_type: p.resource_type,
            action: p.action,
            created_at: p.created_at,
        }
    }
}

/// Role response for API
#[derive(Debug, Serialize)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "isSystemRole")]
    pub is_system_role: bool,
    pub permissions: Vec<PermissionResponse>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

/// User role assignment response
#[derive(Debug, Serialize)]
pub struct UserRoleResponse {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "roleId")]
    pub role_id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "assignedAt")]
    pub assigned_at: DateTime<Utc>,
}

impl From<UserRole> for UserRoleResponse {
    fn from(ur: UserRole) -> Self {
        Self {
            user_id: ur.user_id.to_string(),
            role_id: ur.role_id.to_string(),
            organization_id: ur.organization_id.map(|id| id.to_string()),
            assigned_at: ur.assigned_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_permission_check_parse() {
        let check = PermissionCheck::parse("document:read").unwrap();
        assert_eq!(check.resource_type, "document");
        assert_eq!(check.action, "read");
        assert_eq!(check.resource_id, None);
        
        let check = PermissionCheck::parse("document:123:admin").unwrap();
        assert_eq!(check.resource_type, "document");
        assert_eq!(check.resource_id, Some("123".to_string()));
        assert_eq!(check.action, "admin");
        
        assert!(PermissionCheck::parse("invalid").is_none());
        assert!(PermissionCheck::parse("too:many:parts:here").is_none());
    }
    
    #[test]
    fn test_permission_check_formatting() {
        let check = PermissionCheck {
            resource_type: "document".to_string(),
            action: "read".to_string(),
            resource_id: None,
        };
        assert_eq!(check.to_wildcard(), "document:read");
        assert_eq!(check.to_specific(), None);
        
        let check = PermissionCheck {
            resource_type: "document".to_string(),
            action: "admin".to_string(),
            resource_id: Some("123".to_string()),
        };
        assert_eq!(check.to_wildcard(), "document:admin");
        assert_eq!(check.to_specific(), Some("document:123:admin".to_string()));
    }
}
