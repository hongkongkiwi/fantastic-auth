//! Permission Checker with Redis caching
//!
//! Provides efficient permission checking with:
//! - In-memory caching via DashMap
//! - Redis caching for distributed deployments
//! - Permission inheritance through roles
//! - Resource-specific permission overrides

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sqlx::PgPool;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

use crate::permissions::{Permission, PermissionCheck, Role, UserRole};

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

/// Permission checker with caching support
#[derive(Clone)]
pub struct PermissionChecker {
    db: PgPool,
    redis: Option<redis::aio::ConnectionManager>,
    /// Local cache for user permissions (user_id -> permissions)
    permission_cache: Arc<DashMap<String, CacheEntry<Vec<String>>>>,
    /// Cache TTL in seconds
    cache_ttl: u64,
}

impl PermissionChecker {
    /// Create a new permission checker
    pub fn new(db: PgPool, redis: Option<redis::aio::ConnectionManager>) -> Self {
        Self {
            db,
            redis,
            permission_cache: Arc::new(DashMap::new()),
            cache_ttl: 300, // 5 minutes default
        }
    }
    
    /// Set custom cache TTL
    pub fn with_cache_ttl(mut self, ttl_secs: u64) -> Self {
        self.cache_ttl = ttl_secs;
        self
    }
    
    /// Check if a user has a specific permission
    /// 
    /// Supports wildcard permissions (e.g., "document:read") and
    /// superadmin bypass.
    #[instrument(skip(self), fields(user_id, permission))]
    pub async fn has_permission(&self, user_id: &str, permission: &str) -> bool {
        // Superadmin check - superadmins have all permissions
        if self.is_superadmin(user_id).await {
            debug!("User is superadmin, granting permission");
            return true;
        }
        
        // Get user's effective permissions
        let permissions = match self.get_user_permissions(user_id).await {
            Ok(perms) => perms,
            Err(e) => {
                warn!("Failed to get user permissions: {}", e);
                return false;
            }
        };
        
        // Check for exact match or wildcard match
        self.check_permission_match(&permissions, permission)
    }
    
    /// Check if a user has a specific permission on a resource
    /// 
    /// Checks in order:
    /// 1. Superadmin bypass
    /// 2. Resource-specific permission (e.g., "document:123:admin")
    /// 3. Wildcard permission (e.g., "document:admin")
    /// 4. Global wildcard (e.g., "document:*")
    #[instrument(skip(self), fields(user_id, permission, resource_type, resource_id))]
    pub async fn has_permission_on_resource(
        &self,
        user_id: &str,
        permission: &str,
        resource_type: &str,
        resource_id: &str,
    ) -> bool {
        // Superadmin check
        if self.is_superadmin(user_id).await {
            return true;
        }
        
        // Parse the permission check
        let check = match PermissionCheck::parse(permission) {
            Some(c) => c,
            None => {
                warn!("Invalid permission format: {}", permission);
                return false;
            }
        };
        
        // Get user's effective permissions
        let permissions = match self.get_user_permissions(user_id).await {
            Ok(perms) => perms,
            Err(e) => {
                warn!("Failed to get user permissions: {}", e);
                return false;
            }
        };
        
        // Check resource-specific permission first
        let specific = format!("{}:{}:{}", resource_type, resource_id, check.action);
        if permissions.contains(&specific) {
            return true;
        }
        
        // Check wildcard permission on resource type
        let wildcard = format!("{}:*", resource_type);
        if permissions.contains(&wildcard) {
            return true;
        }
        
        // Check general permission
        self.check_permission_match(&permissions, permission)
    }
    
    /// Check if user has any of the specified permissions
    pub async fn has_any_permission(&self, user_id: &str, permissions: &[&str]) -> bool {
        // Superadmin check
        if self.is_superadmin(user_id).await {
            return true;
        }
        
        let user_perms = match self.get_user_permissions(user_id).await {
            Ok(perms) => perms,
            Err(e) => {
                warn!("Failed to get user permissions: {}", e);
                return false;
            }
        };
        
        permissions.iter().any(|p| self.check_permission_match(&user_perms, p))
    }
    
    /// Check if user has all of the specified permissions
    pub async fn has_all_permissions(&self, user_id: &str, permissions: &[&str]) -> bool {
        // Superadmin check
        if self.is_superadmin(user_id).await {
            return true;
        }
        
        let user_perms = match self.get_user_permissions(user_id).await {
            Ok(perms) => perms,
            Err(e) => {
                warn!("Failed to get user permissions: {}", e);
                return false;
            }
        };
        
        permissions.iter().all(|p| self.check_permission_match(&user_perms, p))
    }
    
    /// Check if user is a superadmin
    async fn is_superadmin(&self, user_id: &str) -> bool {
        match self.get_user_roles(user_id).await {
            Ok(roles) => roles.iter().any(|r| r == "superadmin"),
            Err(_) => false,
        }
    }
    
    /// Get all effective permissions for a user
    /// 
    /// Combines:
    /// - Direct permissions from roles
    /// - Resource-specific permissions
    /// - Cached results when available
    #[instrument(skip(self))]
    pub async fn get_user_permissions(&self, user_id: &str) -> anyhow::Result<Vec<String>> {
        // Check local cache first
        if let Some(entry) = self.permission_cache.get(user_id) {
            if !entry.is_expired() {
                debug!("Permission cache hit for user {}", user_id);
                return Ok(entry.value.clone());
            }
        }
        
        // Check Redis cache if available
        if let Some(ref redis) = self.redis {
            match self.get_cached_permissions_redis(redis, user_id).await {
                Ok(Some(permissions)) => {
                    // Update local cache
                    self.permission_cache.insert(
                        user_id.to_string(),
                        CacheEntry::new(permissions.clone(), self.cache_ttl),
                    );
                    return Ok(permissions);
                }
                Ok(None) => {} // Cache miss, continue to DB
                Err(e) => warn!("Redis cache error: {}", e),
            }
        }
        
        // Fetch from database
        let permissions = self.fetch_user_permissions(user_id).await?;
        
        // Update caches
        self.permission_cache.insert(
            user_id.to_string(),
            CacheEntry::new(permissions.clone(), self.cache_ttl),
        );
        
        if let Some(ref redis) = self.redis {
            if let Err(e) = self.cache_permissions_redis(redis, user_id, &permissions).await {
                warn!("Failed to cache permissions in Redis: {}", e);
            }
        }
        
        Ok(permissions)
    }
    
    /// Get user role names
    async fn get_user_roles(&self, user_id: &str) -> anyhow::Result<Vec<String>> {
        let user_uuid = Uuid::parse_str(user_id)?;
        
        let roles: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT r.name 
            FROM roles r
            INNER JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = $1
            "#
        )
        .bind(user_uuid)
        .fetch_all(&self.db)
        .await?;
        
        Ok(roles)
    }
    
    /// Fetch user permissions from database
    async fn fetch_user_permissions(&self, user_id: &str) -> anyhow::Result<Vec<String>> {
        let user_uuid = Uuid::parse_str(user_id)?;
        
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
        .bind(user_uuid)
        .fetch_all(&self.db)
        .await?;
        
        // Get resource-specific permissions
        let resource_permissions: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT 
                CASE 
                    WHEN rp.resource_id IS NOT NULL THEN 
                        rp.resource_type || ':' || rp.resource_id || ':' || p.action
                    ELSE 
                        p.name
                END as permission
            FROM resource_permissions rp
            INNER JOIN permissions p ON rp.permission_id = p.id
            WHERE rp.user_id = $1
            AND (rp.expires_at IS NULL OR rp.expires_at > NOW())
            "#
        )
        .bind(user_uuid)
        .fetch_all(&self.db)
        .await?;
        
        // Combine and deduplicate
        let mut all_permissions = role_permissions;
        all_permissions.extend(resource_permissions);
        all_permissions.sort();
        all_permissions.dedup();
        
        Ok(all_permissions)
    }
    
    /// Get cached permissions from Redis
    async fn get_cached_permissions_redis(
        &self,
        redis: &redis::aio::ConnectionManager,
        user_id: &str,
    ) -> redis::RedisResult<Option<Vec<String>>> {
        let mut conn = redis.clone();
        let key = format!("permissions:{}", user_id);
        
        let data: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await?;
        
        match data {
            Some(json) => {
                let permissions: Vec<String> = serde_json::from_str(&json)
                    .map_err(|e| redis::RedisError::from((
                        redis::ErrorKind::TypeError,
                        "JSON parse error",
                        e.to_string(),
                    )))?;
                Ok(Some(permissions))
            }
            None => Ok(None),
        }
    }
    
    /// Cache permissions in Redis
    async fn cache_permissions_redis(
        &self,
        redis: &redis::aio::ConnectionManager,
        user_id: &str,
        permissions: &[String],
    ) -> redis::RedisResult<()> {
        let mut conn = redis.clone();
        let key = format!("permissions:{}", user_id);
        let json = serde_json::to_string(permissions)
            .map_err(|e| redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "JSON serialize error",
                e.to_string(),
            )))?;
        
        redis::cmd("SETEX")
            .arg(&key)
            .arg(self.cache_ttl)
            .arg(json)
            .query_async(&mut conn)
            .await?;
        
        Ok(())
    }
    
    /// Check if permission matches, supporting wildcards
    fn check_permission_match(&self, user_permissions: &[String], required: &str) -> bool {
        // Direct match
        if user_permissions.contains(&required.to_string()) {
            return true;
        }
        
        // Parse required permission
        let check = match PermissionCheck::parse(required) {
            Some(c) => c,
            None => return false,
        };
        
        // Check for resource-type wildcard (e.g., "document:*")
        let type_wildcard = format!("{}:*", check.resource_type);
        if user_permissions.contains(&type_wildcard) {
            return true;
        }
        
        // Check for global wildcard action on resource type
        // This handles cases like having "document:*" and checking "document:read"
        for perm in user_permissions {
            if let Some(user_check) = PermissionCheck::parse(perm) {
                // Match if same resource type and user has wildcard action
                if user_check.resource_type == check.resource_type 
                    && user_check.action == "*" {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Invalidate permission cache for a user
    pub fn invalidate_cache(&self, user_id: &str) {
        self.permission_cache.remove(user_id);
    }
    
    /// Invalidate permission cache in Redis for a user
    pub async fn invalidate_redis_cache(&self, user_id: &str) -> anyhow::Result<()> {
        if let Some(ref redis) = self.redis {
            let mut conn = redis.clone();
            let key = format!("permissions:{}", user_id);
            redis::cmd("DEL")
                .arg(&key)
                .query_async::<_, ()>(&mut conn)
                .await?;
        }
        Ok(())
    }
    
    /// Get roles for a user with their permissions
    pub async fn get_user_roles_with_permissions(
        &self,
        user_id: &str,
    ) -> anyhow::Result<Vec<(Role, Vec<Permission>)>> {
        let user_uuid = Uuid::parse_str(user_id)?;
        
        #[derive(sqlx::FromRow)]
        struct RolePermissionRow {
            role_id: Uuid,
            role_tenant_id: Option<Uuid>,
            role_name: String,
            role_description: Option<String>,
            role_is_system_role: bool,
            role_created_at: DateTime<Utc>,
            role_updated_at: DateTime<Utc>,
            permission_id: Option<Uuid>,
            permission_tenant_id: Option<Uuid>,
            permission_name: Option<String>,
            permission_description: Option<String>,
            permission_resource_type: Option<String>,
            permission_action: Option<String>,
            permission_created_at: Option<DateTime<Utc>>,
        }

        let rows = sqlx::query_as::<_, RolePermissionRow>(
            r#"
            SELECT 
                r.id as role_id,
                r.tenant_id as role_tenant_id,
                r.name as role_name,
                r.description as role_description,
                r.is_system_role as role_is_system_role,
                r.created_at as role_created_at,
                r.updated_at as role_updated_at,
                p.id as permission_id,
                p.tenant_id as permission_tenant_id,
                p.name as permission_name,
                p.description as permission_description,
                p.resource_type as permission_resource_type,
                p.action as permission_action,
                p.created_at as permission_created_at
            FROM roles r
            INNER JOIN user_roles ur ON r.id = ur.role_id
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            LEFT JOIN permissions p ON rp.permission_id = p.id
            WHERE ur.user_id = $1
            "#
        )
        .bind(user_uuid)
        .fetch_all(&self.db)
        .await?;
        
        // Group permissions by role
        use std::collections::HashMap;
        let mut role_map: HashMap<Uuid, (Role, Vec<Permission>)> = HashMap::new();

        for row in rows {
            let role = Role {
                id: row.role_id,
                tenant_id: row.role_tenant_id,
                name: row.role_name,
                description: row.role_description,
                is_system_role: row.role_is_system_role,
                created_at: row.role_created_at,
                updated_at: row.role_updated_at,
            };

            let entry = role_map.entry(role.id).or_insert_with(|| (role, Vec::new()));

            if let Some(permission_id) = row.permission_id {
                let permission = Permission {
                    id: permission_id,
                    tenant_id: row.permission_tenant_id,
                    name: row.permission_name.unwrap_or_else(|| "unknown".to_string()),
                    description: row.permission_description,
                    resource_type: row
                        .permission_resource_type
                        .unwrap_or_else(|| "unknown".to_string()),
                    action: row.permission_action.unwrap_or_else(|| "unknown".to_string()),
                    created_at: row
                        .permission_created_at
                        .unwrap_or_else(|| chrono::Utc::now()),
                };
                entry.1.push(permission);
            }
        }
        
        Ok(role_map.into_values().collect())
    }
    
    /// Check if a user has a specific role
    pub async fn has_role(&self, user_id: &str, role_name: &str) -> anyhow::Result<bool> {
        let roles = self.get_user_roles(user_id).await?;
        Ok(roles.iter().any(|r| r == role_name))
    }
    
    /// Check if a user has a specific role in an organization
    pub async fn has_role_in_org(
        &self,
        user_id: &str,
        role_name: &str,
        org_id: &str,
    ) -> anyhow::Result<bool> {
        let user_uuid = Uuid::parse_str(user_id)?;
        let org_uuid = Uuid::parse_str(org_id)?;
        
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 
                FROM user_roles ur
                INNER JOIN roles r ON ur.role_id = r.id
                WHERE ur.user_id = $1 
                AND r.name = $2
                AND ur.organization_id = $3
            )
            "#
        )
        .bind(user_uuid)
        .bind(role_name)
        .bind(org_uuid)
        .fetch_one(&self.db)
        .await?;
        
        Ok(exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cache_entry() {
        let entry = CacheEntry::new(vec!["read".to_string()], 1);
        assert!(!entry.is_expired());
        assert_eq!(entry.value, vec!["read".to_string()]);
        
        // Test expired entry (would need to wait, so we test creation instead)
        let entry = CacheEntry {
            value: Vec::<String>::new(),
            expires_at: std::time::Instant::now() - Duration::from_secs(1),
        };
        assert!(entry.is_expired());
    }
    
    #[tokio::test]
    async fn test_permission_match() {
        let checker = PermissionChecker {
            db: PgPool::connect_lazy("postgres://localhost/test").unwrap(),
            redis: None,
            permission_cache: Arc::new(DashMap::new()),
            cache_ttl: 300,
        };
        
        let perms = vec![
            "document:read".to_string(),
            "document:write".to_string(),
            "user:*".to_string(),
        ];
        
        assert!(checker.check_permission_match(&perms, "document:read"));
        assert!(checker.check_permission_match(&perms, "document:write"));
        assert!(!checker.check_permission_match(&perms, "document:delete"));
        
        // Wildcard match
        assert!(checker.check_permission_match(&perms, "user:read"));
        assert!(checker.check_permission_match(&perms, "user:write"));
    }
}
