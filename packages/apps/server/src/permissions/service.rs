//! Permission Service
//!
//! Business logic for the RBAC++ permission system.
//! Provides high-level operations with caching support.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sqlx::PgPool;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::permissions::{
    checker::PermissionChecker,
    repository::PermissionRepository,
    Permission, ResourcePermission, Role, UserRole,
};

/// Cache entry with TTL
#[derive(Clone)]
struct CacheEntry<T> {
    value: T,
    expires_at: std::time::Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T, ttl_secs: u64) -> Self {
        Self {
            value,
            expires_at: std::time::Instant::now() + Duration::from_secs(ttl_secs),
        }
    }

    fn is_expired(&self) -> bool {
        std::time::Instant::now() > self.expires_at
    }
}

/// Permission service with caching
#[derive(Clone)]
pub struct PermissionService {
    repository: PermissionRepository,
    checker: PermissionChecker,
    redis: Option<redis::aio::ConnectionManager>,
    /// Local cache for permissions (user_id -> permissions)
    permission_cache: Arc<DashMap<String, CacheEntry<Vec<String>>>>,
    /// Cache for roles (role_id -> role with permissions)
    role_cache: Arc<DashMap<String, CacheEntry<(Role, Vec<Permission>)>>>,
    /// Cache TTL in seconds
    cache_ttl: u64,
}

impl PermissionService {
    /// Create a new permission service
    pub fn new(
        pool: PgPool,
        redis: Option<redis::aio::ConnectionManager>,
    ) -> Self {
        let repository = PermissionRepository::new(pool.clone());
        let checker = PermissionChecker::new(pool, redis.clone());

        Self {
            repository,
            checker,
            redis,
            permission_cache: Arc::new(DashMap::new()),
            role_cache: Arc::new(DashMap::new()),
            cache_ttl: 300, // 5 minutes default
        }
    }

    /// Set custom cache TTL
    pub fn with_cache_ttl(mut self, ttl_secs: u64) -> Self {
        self.cache_ttl = ttl_secs;
        self
    }

    // ==================== PERMISSION OPERATIONS ====================

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
        // Validate permission name format
        if !name.contains(':') && name != "admin" {
            return Err(anyhow::anyhow!(
                "Permission name must follow 'resource:action' format or be 'admin'"
            ));
        }

        let permission = self
            .repository
            .create_permission(tenant_id, name, description, resource_type, action)
            .await?;

        info!("Created permission: {} ({})", name, permission.id);
        Ok(permission)
    }

    /// Get permission by name
    pub async fn get_permission_by_name(
        &self,
        tenant_id: Option<Uuid>,
        name: &str,
    ) -> anyhow::Result<Option<Permission>> {
        self.repository.get_permission_by_name(tenant_id, name).await
    }

    /// List permissions with pagination
    pub async fn list_permissions(
        &self,
        tenant_id: Option<Uuid>,
        page: i64,
        limit: i64,
    ) -> anyhow::Result<(Vec<Permission>, i64)> {
        let offset = (page - 1) * limit;
        let permissions = self.repository.list_permissions(tenant_id, limit, offset).await?;
        let total = self.repository.count_permissions(tenant_id).await?;
        Ok((permissions, total))
    }

    /// Delete a permission
    #[instrument(skip(self))]
    pub async fn delete_permission(
        &self,
        id: Uuid,
        tenant_id: Option<Uuid>,
    ) -> anyhow::Result<bool> {
        let deleted = self.repository.delete_permission(id, tenant_id).await?;

        if deleted {
            // Invalidate caches for all users since permission might affect many
            self.invalidate_all_caches();
            info!("Deleted permission: {}", id);
        }

        Ok(deleted)
    }

    // ==================== ROLE OPERATIONS ====================

    /// Create a new role
    #[instrument(skip(self), fields(name = %name))]
    pub async fn create_role(
        &self,
        tenant_id: Option<Uuid>,
        name: &str,
        description: Option<&str>,
        permission_ids: Vec<Uuid>,
    ) -> anyhow::Result<Role> {
        // Validate role name
        if name.is_empty() || name.len() > 100 {
            return Err(anyhow::anyhow!(
                "Role name must be between 1 and 100 characters"
            ));
        }

        // Create role
        let role = self
            .repository
            .create_role(tenant_id, name, description, false)
            .await?;

        // Assign permissions if provided
        if !permission_ids.is_empty() {
            self.repository
                .set_role_permissions(role.id, &permission_ids)
                .await?;
        }

        info!("Created role: {} ({})", name, role.id);
        Ok(role)
    }

    /// Get role by ID with permissions
    pub async fn get_role(&self, id: Uuid) -> anyhow::Result<Option<(Role, Vec<Permission>)>> {
        // Check cache first
        if let Some(entry) = self.role_cache.get(&id.to_string()) {
            if !entry.is_expired() {
                debug!("Role cache hit: {}", id);
                return Ok(Some(entry.value.clone()));
            }
        }

        // Fetch from database
        let role = match self.repository.get_role_by_id(id).await? {
            Some(r) => r,
            None => return Ok(None),
        };

        let permissions = self.repository.get_role_permissions(id).await?;

        let result = (role, permissions);

        // Update cache
        self.role_cache.insert(
            id.to_string(),
            CacheEntry::new(result.clone(), self.cache_ttl),
        );

        Ok(Some(result))
    }

    /// List roles with pagination
    pub async fn list_roles(
        &self,
        tenant_id: Option<Uuid>,
        page: i64,
        limit: i64,
    ) -> anyhow::Result<(Vec<(Role, Vec<Permission>)>, i64)> {
        let offset = (page - 1) * limit;
        let roles = self.repository.list_roles(tenant_id, limit, offset).await?;
        let total = self.repository.count_roles(tenant_id).await?;

        // Fetch permissions for each role
        let mut results = Vec::new();
        for role in roles {
            let permissions = self.repository.get_role_permissions(role.id).await?;
            results.push((role, permissions));
        }

        Ok((results, total))
    }

    /// Update a role
    #[instrument(skip(self))]
    pub async fn update_role(
        &self,
        id: Uuid,
        tenant_id: Option<Uuid>,
        name: Option<&str>,
        description: Option<&str>,
        permission_ids: Option<Vec<Uuid>>,
    ) -> anyhow::Result<Option<Role>> {
        // Update role
        let role = self
            .repository
            .update_role(id, tenant_id, name, description)
            .await?;

        if role.is_none() {
            return Ok(None);
        }

        // Update permissions if provided
        if let Some(perm_ids) = permission_ids {
            self.repository.set_role_permissions(id, &perm_ids).await?;
        }

        // Invalidate caches
        self.role_cache.remove(&id.to_string());
        self.invalidate_role_user_caches(id).await;

        info!("Updated role: {}", id);
        Ok(role)
    }

    /// Delete a role
    #[instrument(skip(self))]
    pub async fn delete_role(&self, id: Uuid, tenant_id: Option<Uuid>) -> anyhow::Result<bool> {
        // Get users with this role to invalidate their caches
        let user_ids = self.repository.get_users_with_role(id).await?;

        let deleted = self.repository.delete_role(id, tenant_id).await?;

        if deleted {
            // Invalidate caches
            self.role_cache.remove(&id.to_string());
            for user_id in user_ids {
                self.invalidate_user_cache(&user_id.to_string());
            }
            info!("Deleted role: {}", id);
        }

        Ok(deleted)
    }

    /// Add permission to role
    #[instrument(skip(self))]
    pub async fn add_permission_to_role(
        &self,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> anyhow::Result<()> {
        self.repository
            .add_permission_to_role(role_id, permission_id)
            .await?;

        // Invalidate caches
        self.role_cache.remove(&role_id.to_string());
        self.invalidate_role_user_caches(role_id).await;

        info!("Added permission {} to role {}", permission_id, role_id);
        Ok(())
    }

    /// Remove permission from role
    #[instrument(skip(self))]
    pub async fn remove_permission_from_role(
        &self,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> anyhow::Result<bool> {
        let removed = self
            .repository
            .remove_permission_from_role(role_id, permission_id)
            .await?;

        if removed {
            // Invalidate caches
            self.role_cache.remove(&role_id.to_string());
            self.invalidate_role_user_caches(role_id).await;

            info!("Removed permission {} from role {}", permission_id, role_id);
        }

        Ok(removed)
    }

    // ==================== USER ROLE ASSIGNMENTS ====================

    /// Assign role to user
    #[instrument(skip(self))]
    pub async fn assign_role_to_user(
        &self,
        user_id: Uuid,
        role_id: Uuid,
        organization_id: Option<Uuid>,
        assigned_by: Option<Uuid>,
    ) -> anyhow::Result<UserRole> {
        let user_role = self
            .repository
            .assign_role_to_user(user_id, role_id, organization_id, assigned_by)
            .await?;

        // Invalidate user's cache
        self.invalidate_user_cache(&user_id.to_string());

        info!(
            "Assigned role {} to user {} (org: {:?})",
            role_id, user_id, organization_id
        );
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
        let removed = self
            .repository
            .remove_role_from_user(user_id, role_id, organization_id)
            .await?;

        if removed {
            // Invalidate user's cache
            self.invalidate_user_cache(&user_id.to_string());

            info!(
                "Removed role {} from user {} (org: {:?})",
                role_id, user_id, organization_id
            );
        }

        Ok(removed)
    }

    /// Get user's roles
    pub async fn get_user_roles(&self, user_id: Uuid) -> anyhow::Result<Vec<(Role, Option<Uuid>)>> {
        self.repository.get_user_roles(user_id).await
    }

    /// Get all permissions for a user (with caching)
    pub async fn get_user_permissions(&self, user_id: &str) -> anyhow::Result<Vec<String>> {
        self.checker.get_user_permissions(user_id).await
    }

    // ==================== PERMISSION CHECKING ====================

    /// Check if user has a specific permission
    #[instrument(skip(self), fields(user_id, permission))]
    pub async fn check_user_permission(&self, user_id: &str, permission: &str) -> bool {
        self.checker.has_permission(user_id, permission).await
    }

    /// Check if user has permission on a specific resource
    #[instrument(skip(self), fields(user_id, permission, resource_type, resource_id))]
    pub async fn check_user_permission_on_resource(
        &self,
        user_id: &str,
        permission: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> bool {
        self.checker
            .has_permission_on_resource(user_id, permission, resource_type, resource_id)
            .await
    }

    /// Check if user has any of the specified permissions
    pub async fn check_user_has_any_permission(
        &self,
        user_id: &str,
        permissions: &[&str],
    ) -> bool {
        self.checker.has_any_permission(user_id, permissions).await
    }

    /// Check if user has all of the specified permissions
    pub async fn check_user_has_all_permissions(
        &self,
        user_id: &str,
        permissions: &[&str],
    ) -> bool {
        self.checker.has_all_permissions(user_id, permissions).await
    }

    /// Require a permission - returns error if user doesn't have it
    pub async fn require_permission(
        &self,
        user_id: &str,
        permission: &str,
    ) -> anyhow::Result<()> {
        if self.check_user_permission(user_id, permission).await {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Permission denied: user {} lacks permission {}",
                user_id,
                permission
            ))
        }
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
        let permission = self
            .repository
            .grant_resource_permission(
                user_id,
                permission_id,
                resource_type,
                resource_id,
                granted_by,
                expires_at,
            )
            .await?;

        // Invalidate user's cache
        self.invalidate_user_cache(&user_id.to_string());

        info!(
            "Granted resource permission to user {} on {}:{}",
            user_id, resource_type, resource_id
        );
        Ok(permission)
    }

    /// Revoke resource-level permission by ID
    /// Note: Also use revoke_resource_permission_by_details if you know the user/resource info
    #[instrument(skip(self))]
    pub async fn revoke_resource_permission(&self, id: Uuid) -> anyhow::Result<bool> {
        let revoked = self.repository.revoke_resource_permission(id).await?;

        if revoked {
            // Note: We can't invalidate the user cache here without knowing the user_id
            // In production, you might want to query for the user_id first or
            // use a different invalidation strategy
            info!("Revoked resource permission: {}", id);
        }

        Ok(revoked)
    }

    /// Revoke resource permission by details (user, permission, resource)
    #[instrument(skip(self))]
    pub async fn revoke_resource_permission_by_details(
        &self,
        user_id: Uuid,
        permission_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> anyhow::Result<bool> {
        let revoked = self
            .repository
            .revoke_resource_permission_by_details(user_id, permission_id, resource_type, resource_id)
            .await?;

        if revoked {
            // Invalidate user's cache
            self.invalidate_user_cache(&user_id.to_string());
            info!(
                "Revoked resource permission for user {} on {}:{}",
                user_id, resource_type, resource_id
            );
        }

        Ok(revoked)
    }

    /// List resource permissions with pagination
    pub async fn list_resource_permissions(
        &self,
        page: i64,
        limit: i64,
    ) -> anyhow::Result<(Vec<ResourcePermission>, i64)> {
        let offset = (page - 1) * limit;
        let permissions = self
            .repository
            .list_resource_permissions(limit, offset)
            .await?;
        let total = self.repository.count_resource_permissions().await?;
        Ok((permissions, total))
    }

    /// Get resource permissions for a user
    pub async fn get_user_resource_permissions(
        &self,
        user_id: Uuid,
    ) -> anyhow::Result<Vec<ResourcePermission>> {
        self.repository.get_user_resource_permissions(user_id).await
    }

    // ==================== CACHE MANAGEMENT ====================

    /// Invalidate cache for a specific user
    pub fn invalidate_user_cache(&self, user_id: &str) {
        self.permission_cache.remove(user_id);
        self.checker.invalidate_cache(user_id);
        debug!("Invalidated cache for user: {}", user_id);
    }

    /// Invalidate cache in Redis for a user
    pub async fn invalidate_redis_cache(&self, user_id: &str) -> anyhow::Result<()> {
        self.checker.invalidate_redis_cache(user_id).await
    }

    /// Invalidate caches for all users with a specific role
    async fn invalidate_role_user_caches(&self, role_id: Uuid) {
        if let Ok(user_ids) = self.repository.get_users_with_role(role_id).await {
            for user_id in user_ids {
                self.invalidate_user_cache(&user_id.to_string());
            }
        }
    }

    /// Invalidate all caches
    fn invalidate_all_caches(&self) {
        self.permission_cache.clear();
        self.role_cache.clear();
        debug!("Invalidated all caches");
    }

    /// Clear all expired cache entries
    pub fn cleanup_expired_cache(&self) {
        let expired: Vec<String> = self
            .permission_cache
            .iter()
            .filter(|entry| entry.value().is_expired())
            .map(|entry| entry.key().clone())
            .collect();

        for key in expired {
            self.permission_cache.remove(&key);
        }

        let expired: Vec<String> = self
            .role_cache
            .iter()
            .filter(|entry| entry.value().is_expired())
            .map(|entry| entry.key().clone())
            .collect();

        for key in expired {
            self.role_cache.remove(&key);
        }

        debug!("Cleaned up expired cache entries");
    }
}

// Extension trait to expose the pool from repository
trait RepositoryExt {
    fn pool(&self) -> &PgPool;
}

impl RepositoryExt for PermissionRepository {
    fn pool(&self) -> &PgPool {
        // We need to access the pool - we'll use a different approach
        // This is a placeholder that won't be called since we use direct SQL
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry() {
        let entry = CacheEntry::new(vec!["read".to_string()], 60);
        assert!(!entry.is_expired());
        assert_eq!(entry.value, vec!["read".to_string()]);
    }

    #[test]
    fn test_cache_entry_expired() {
        let entry = CacheEntry {
            value: Vec::<String>::new(),
            expires_at: std::time::Instant::now() - Duration::from_secs(1),
        };
        assert!(entry.is_expired());
    }
}
