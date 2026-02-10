//! Permission Repository
//!
//! Database operations for the RBAC++ permission system.
//! Provides CRUD operations for permissions, roles, and user assignments.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::{debug, instrument};
use uuid::Uuid;

use crate::permissions::{Permission, ResourcePermission, Role, UserRole};

/// Repository for permission-related database operations
#[derive(Clone)]
pub struct PermissionRepository {
    pool: PgPool,
}

impl PermissionRepository {
    /// Create a new permission repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ==================== PERMISSION CRUD ====================

    /// Create a new permission
    #[instrument(skip(self), fields(name = %name))]
    pub async fn create_permission(
        &self,
        tenant_id: Option<Uuid>,
        name: &str,
        description: Option<&str>,
        resource_type: &str,
        action: &str,
    ) -> anyhow::Result<Permission> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let permission = sqlx::query_as(
            r#"
            INSERT INTO permissions (id, tenant_id, name, description, resource_type, action, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(description)
        .bind(resource_type)
        .bind(action)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        debug!("Created permission: {}", name);
        Ok(permission)
    }

    /// Get permission by ID
    pub async fn get_permission_by_id(&self, id: Uuid) -> anyhow::Result<Option<Permission>> {
        let permission = sqlx::query_as::<_, Permission>(
            "SELECT * FROM permissions WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(permission)
    }

    /// Get permission by name (optionally scoped to tenant)
    #[instrument(skip(self))]
    pub async fn get_permission_by_name(
        &self,
        tenant_id: Option<Uuid>,
        name: &str,
    ) -> anyhow::Result<Option<Permission>> {
        let permission = sqlx::query_as::<_, Permission>(
            r#"
            SELECT * FROM permissions 
            WHERE name = $1 AND (tenant_id = $2 OR (tenant_id IS NULL AND $2 IS NULL))
            "#
        )
        .bind(name)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(permission)
    }

    /// List all permissions with optional filtering
    #[instrument(skip(self))]
    pub async fn list_permissions(
        &self,
        tenant_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Permission>> {
        let permissions = sqlx::query_as::<_, Permission>(
            r#"
            SELECT * FROM permissions 
            WHERE tenant_id IS NULL OR tenant_id = $1
            ORDER BY resource_type, action
            LIMIT $2 OFFSET $3
            "#
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    /// Count total permissions
    pub async fn count_permissions(&self, tenant_id: Option<Uuid>) -> anyhow::Result<i64> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM permissions 
            WHERE tenant_id IS NULL OR tenant_id = $1
            "#
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Delete a permission
    #[instrument(skip(self))]
    pub async fn delete_permission(&self, id: Uuid, tenant_id: Option<Uuid>) -> anyhow::Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM permissions 
            WHERE id = $1 AND (tenant_id = $2 OR tenant_id IS NULL)
            "#
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // ==================== ROLE CRUD ====================

    /// Create a new role
    #[instrument(skip(self), fields(name = %name))]
    pub async fn create_role(
        &self,
        tenant_id: Option<Uuid>,
        name: &str,
        description: Option<&str>,
        is_system_role: bool,
    ) -> anyhow::Result<Role> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let role = sqlx::query_as(
            r#"
            INSERT INTO roles (id, tenant_id, name, description, is_system_role, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $6)
            RETURNING *
            "#
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(description)
        .bind(is_system_role)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        debug!("Created role: {}", name);
        Ok(role)
    }

    /// Get role by ID
    pub async fn get_role_by_id(&self, id: Uuid) -> anyhow::Result<Option<Role>> {
        let role = sqlx::query_as::<_, Role>(
            "SELECT * FROM roles WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(role)
    }

    /// Get role by name
    pub async fn get_role_by_name(
        &self,
        tenant_id: Option<Uuid>,
        name: &str,
    ) -> anyhow::Result<Option<Role>> {
        let role = sqlx::query_as::<_, Role>(
            r#"
            SELECT * FROM roles 
            WHERE name = $1 AND (tenant_id = $2 OR (tenant_id IS NULL AND $2 IS NULL))
            "#
        )
        .bind(name)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(role)
    }

    /// List all roles
    pub async fn list_roles(
        &self,
        tenant_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Role>> {
        let roles = sqlx::query_as::<_, Role>(
            r#"
            SELECT * FROM roles 
            WHERE tenant_id IS NULL OR tenant_id = $1
            ORDER BY is_system_role DESC, name
            LIMIT $2 OFFSET $3
            "#
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(roles)
    }

    /// Count total roles
    pub async fn count_roles(&self, tenant_id: Option<Uuid>) -> anyhow::Result<i64> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM roles 
            WHERE tenant_id IS NULL OR tenant_id = $1
            "#
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Update a role
    #[instrument(skip(self))]
    pub async fn update_role(
        &self,
        id: Uuid,
        tenant_id: Option<Uuid>,
        name: Option<&str>,
        description: Option<&str>,
    ) -> anyhow::Result<Option<Role>> {
        let now = Utc::now();

        let role = sqlx::query_as(
            r#"
            UPDATE roles 
            SET 
                name = COALESCE($1, name),
                description = COALESCE($2, description),
                updated_at = $3
            WHERE id = $4 AND (tenant_id = $5 OR tenant_id IS NULL)
            RETURNING *
            "#
        )
        .bind(name)
        .bind(description)
        .bind(now)
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(role)
    }

    /// Delete a role
    #[instrument(skip(self))]
    pub async fn delete_role(&self, id: Uuid, tenant_id: Option<Uuid>) -> anyhow::Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM roles 
            WHERE id = $1 AND (tenant_id = $2 OR tenant_id IS NULL) AND is_system_role = false
            "#
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // ==================== ROLE PERMISSIONS ====================

    /// Add permission to role
    #[instrument(skip(self))]
    pub async fn add_permission_to_role(
        &self,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO role_permissions (role_id, permission_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#
        )
        .bind(role_id)
        .bind(permission_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Remove permission from role
    #[instrument(skip(self))]
    pub async fn remove_permission_from_role(
        &self,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2"
        )
        .bind(role_id)
        .bind(permission_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get permissions for a role
    pub async fn get_role_permissions(&self, role_id: Uuid) -> anyhow::Result<Vec<Permission>> {
        let permissions = sqlx::query_as::<_, Permission>(
            r#"
            SELECT p.* FROM permissions p
            INNER JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = $1
            ORDER BY p.resource_type, p.action
            "#
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    /// Set permissions for a role (replaces all existing)
    #[instrument(skip(self))]
    pub async fn set_role_permissions(
        &self,
        role_id: Uuid,
        permission_ids: &[Uuid],
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;

        // Remove existing permissions
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
            .bind(role_id)
            .execute(&mut *tx)
            .await?;

        // Add new permissions
        for perm_id in permission_ids {
            sqlx::query(
                r#"
                INSERT INTO role_permissions (role_id, permission_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                "#
            )
            .bind(role_id)
            .bind(perm_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    // ==================== USER ROLES ====================

    /// Assign role to user
    #[instrument(skip(self))]
    pub async fn assign_role_to_user(
        &self,
        user_id: Uuid,
        role_id: Uuid,
        organization_id: Option<Uuid>,
        assigned_by: Option<Uuid>,
    ) -> anyhow::Result<UserRole> {
        let now = Utc::now();

        let user_role = sqlx::query_as(
            r#"
            INSERT INTO user_roles (user_id, role_id, organization_id, assigned_at, assigned_by)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id, role_id, COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'))
            DO UPDATE SET assigned_at = EXCLUDED.assigned_at, assigned_by = EXCLUDED.assigned_by
            RETURNING *
            "#
        )
        .bind(user_id)
        .bind(role_id)
        .bind(organization_id)
        .bind(now)
        .bind(assigned_by)
        .fetch_one(&self.pool)
        .await?;

        Ok(user_role)
    }

    /// Remove role from user
    #[instrument(skip(self))]
    pub async fn remove_role_from_user(
        &self,
        user_id: Uuid,
        role_id: Uuid,
        organization_id: Option<Uuid>,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM user_roles 
            WHERE user_id = $1 AND role_id = $2 
            AND (organization_id = $3 OR (organization_id IS NULL AND $3 IS NULL))
            "#
        )
        .bind(user_id)
        .bind(role_id)
        .bind(organization_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get all roles for a user
    pub async fn get_user_roles(&self, user_id: Uuid) -> anyhow::Result<Vec<(Role, Option<Uuid>)>> {
        #[derive(sqlx::FromRow)]
        struct RoleWithOrgRow {
            id: Uuid,
            tenant_id: Option<Uuid>,
            name: String,
            description: Option<String>,
            is_system_role: bool,
            created_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
            organization_id: Option<Uuid>,
        }

        let rows = sqlx::query_as::<_, RoleWithOrgRow>(
            r#"
            SELECT 
                r.id,
                r.tenant_id,
                r.name,
                r.description,
                r.is_system_role,
                r.created_at,
                r.updated_at,
                ur.organization_id
            FROM roles r
            INNER JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = $1
            ORDER BY r.name
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let roles = rows
            .into_iter()
            .map(|row| {
                (
                    Role {
                        id: row.id,
                        tenant_id: row.tenant_id,
                        name: row.name,
                        description: row.description,
                        is_system_role: row.is_system_role,
                        created_at: row.created_at,
                        updated_at: row.updated_at,
                    },
                    row.organization_id,
                )
            })
            .collect();

        Ok(roles)
    }

    /// Get all users with a specific role
    pub async fn get_users_with_role(&self, role_id: Uuid) -> anyhow::Result<Vec<Uuid>> {
        let user_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM user_roles WHERE role_id = $1"
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(user_ids)
    }

    // ==================== USER PERMISSIONS ====================

    /// Get all effective permissions for a user
    pub async fn get_user_permissions(&self, user_id: Uuid) -> anyhow::Result<Vec<String>> {
        // Get permissions from roles
        let role_permissions: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT p.name 
            FROM permissions p
            INNER JOIN role_permissions rp ON p.id = rp.permission_id
            INNER JOIN user_roles ur ON rp.role_id = ur.role_id
            WHERE ur.user_id = $1
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(role_permissions)
    }

    /// Check if user has a specific permission
    pub async fn user_has_permission(
        &self,
        user_id: Uuid,
        permission_name: &str,
    ) -> anyhow::Result<bool> {
        let has_permission: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM permissions p
                INNER JOIN role_permissions rp ON p.id = rp.permission_id
                INNER JOIN user_roles ur ON rp.role_id = ur.role_id
                WHERE ur.user_id = $1 AND p.name = $2
            )
            "#
        )
        .bind(user_id)
        .bind(permission_name)
        .fetch_one(&self.pool)
        .await?;

        Ok(has_permission)
    }

    // ==================== RESOURCE PERMISSIONS ====================

    /// Grant resource-level permission
    #[instrument(skip(self))]
    pub async fn grant_resource_permission(
        &self,
        user_id: Uuid,
        permission_id: Uuid,
        resource_type: &str,
        resource_id: &str,
        granted_by: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
    ) -> anyhow::Result<ResourcePermission> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let permission = sqlx::query_as(
            r#"
            INSERT INTO resource_permissions 
                (id, user_id, permission_id, resource_type, resource_id, granted_at, granted_by, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (user_id, permission_id, resource_type, resource_id)
            DO UPDATE SET granted_at = EXCLUDED.granted_at, granted_by = EXCLUDED.granted_by, expires_at = EXCLUDED.expires_at
            RETURNING *
            "#
        )
        .bind(id)
        .bind(user_id)
        .bind(permission_id)
        .bind(resource_type)
        .bind(resource_id)
        .bind(now)
        .bind(granted_by)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(permission)
    }

    /// Revoke resource-level permission
    #[instrument(skip(self))]
    pub async fn revoke_resource_permission(&self, id: Uuid) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "DELETE FROM resource_permissions WHERE id = $1"
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get resource permissions for a user
    pub async fn get_user_resource_permissions(
        &self,
        user_id: Uuid,
    ) -> anyhow::Result<Vec<ResourcePermission>> {
        let permissions = sqlx::query_as::<_, ResourcePermission>(
            r#"
            SELECT * FROM resource_permissions 
            WHERE user_id = $1 
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY granted_at DESC
            "#
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    /// Get resource permissions for a specific resource
    pub async fn get_resource_permissions(
        &self,
        resource_type: &str,
        resource_id: &str,
    ) -> anyhow::Result<Vec<ResourcePermission>> {
        let permissions = sqlx::query_as::<_, ResourcePermission>(
            r#"
            SELECT * FROM resource_permissions 
            WHERE resource_type = $1 AND resource_id = $2
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY granted_at DESC
            "#
        )
        .bind(resource_type)
        .bind(resource_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    /// List all resource permissions with pagination
    pub async fn list_resource_permissions(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<ResourcePermission>> {
        let permissions = sqlx::query_as::<_, ResourcePermission>(
            r#"
            SELECT * FROM resource_permissions 
            WHERE expires_at IS NULL OR expires_at > NOW()
            ORDER BY granted_at DESC
            LIMIT $1 OFFSET $2
            "#
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    /// Count total resource permissions
    pub async fn count_resource_permissions(&self) -> anyhow::Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM resource_permissions WHERE expires_at IS NULL OR expires_at > NOW()"
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Revoke resource permission by user, resource, and permission
    #[instrument(skip(self))]
    pub async fn revoke_resource_permission_by_details(
        &self,
        user_id: Uuid,
        permission_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM resource_permissions 
            WHERE user_id = $1 AND permission_id = $2 AND resource_type = $3 AND resource_id = $4
            "#
        )
        .bind(user_id)
        .bind(permission_id)
        .bind(resource_type)
        .bind(resource_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests would require a test database
    // For now, we just verify the code compiles

    #[test]
    fn test_repository_new() {
        // This is a compile-time check
        // let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        // let _repo = PermissionRepository::new(pool);
    }
}
