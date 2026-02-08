//! Project repository implementation

use crate::db::set_connection_context;
use crate::error::Result;
use crate::models::project::{
    Project, ProjectGrant, ProjectRole, ProjectRoleAssignment, ProjectStatus,
};
use sqlx::{FromRow, PgPool};
use std::sync::Arc;

pub struct ProjectRepository {
    pool: Arc<PgPool>,
}

#[derive(Debug, FromRow)]
struct ProjectRow {
    id: String,
    tenant_id: String,
    organization_id: String,
    name: String,
    slug: String,
    description: Option<String>,
    status: String,
    metadata: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<ProjectRow> for Project {
    fn from(row: ProjectRow) -> Self {
        Project {
            id: row.id,
            tenant_id: row.tenant_id,
            organization_id: row.organization_id,
            name: row.name,
            slug: row.slug,
            description: row.description,
            status: row.status.parse().unwrap_or(ProjectStatus::Active),
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deleted_at: row.deleted_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct ProjectRoleRow {
    id: String,
    tenant_id: String,
    project_id: String,
    name: String,
    description: Option<String>,
    permissions: serde_json::Value,
    is_system_role: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ProjectRoleRow> for ProjectRole {
    fn from(row: ProjectRoleRow) -> Self {
        ProjectRole {
            id: row.id,
            tenant_id: row.tenant_id,
            project_id: row.project_id,
            name: row.name,
            description: row.description,
            permissions: row
                .permissions
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            is_system_role: row.is_system_role,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, FromRow)]
struct ProjectRoleAssignmentRow {
    id: String,
    tenant_id: String,
    project_id: String,
    role_id: String,
    user_id: String,
    assigned_at: chrono::DateTime<chrono::Utc>,
    assigned_by: Option<String>,
}

impl From<ProjectRoleAssignmentRow> for ProjectRoleAssignment {
    fn from(row: ProjectRoleAssignmentRow) -> Self {
        ProjectRoleAssignment {
            id: row.id,
            tenant_id: row.tenant_id,
            project_id: row.project_id,
            role_id: row.role_id,
            user_id: row.user_id,
            assigned_at: row.assigned_at,
            assigned_by: row.assigned_by,
        }
    }
}

#[derive(Debug, FromRow)]
struct ProjectGrantRow {
    id: String,
    tenant_id: String,
    project_id: String,
    granted_organization_id: String,
    default_role_id: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<ProjectGrantRow> for ProjectGrant {
    fn from(row: ProjectGrantRow) -> Self {
        ProjectGrant {
            id: row.id,
            tenant_id: row.tenant_id,
            project_id: row.project_id,
            granted_organization_id: row.granted_organization_id,
            default_role_id: row.default_role_id,
            created_at: row.created_at,
        }
    }
}

impl ProjectRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    async fn tenant_conn(
        &self,
        tenant_id: &str,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        let mut conn = self.pool.acquire().await?;
        set_connection_context(&mut conn, tenant_id).await?;
        Ok(conn)
    }

    pub async fn create(&self, project: &Project) -> Result<Project> {
        let mut conn = self.tenant_conn(&project.tenant_id).await?;
        let row = sqlx::query_as::<_, ProjectRow>(
            r#"INSERT INTO projects (id, tenant_id, organization_id, name, slug, description, status, metadata, created_at, updated_at)
               VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7::project_status, $8, $9, $10)
               RETURNING id::text, tenant_id::text, organization_id::text, name, slug, description, status::text, metadata,
                        created_at, updated_at, deleted_at"#,
        )
        .bind(&project.id)
        .bind(&project.tenant_id)
        .bind(&project.organization_id)
        .bind(&project.name)
        .bind(&project.slug)
        .bind(&project.description)
        .bind(project.status)
        .bind(&project.metadata)
        .bind(project.created_at)
        .bind(project.updated_at)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    pub async fn get_by_id(&self, tenant_id: &str, id: &str) -> Result<Option<Project>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, ProjectRow>(
            r#"SELECT id::text, tenant_id::text, organization_id::text, name, slug, description, status::text, metadata,
                created_at, updated_at, deleted_at
             FROM projects
             WHERE tenant_id = $1::uuid AND id = $2::uuid AND deleted_at IS NULL"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn list_by_org(
        &self,
        tenant_id: &str,
        organization_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Project>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, ProjectRow>(
            r#"SELECT id::text, tenant_id::text, organization_id::text, name, slug, description, status::text, metadata,
                created_at, updated_at, deleted_at
             FROM projects
             WHERE tenant_id = $1::uuid AND organization_id = $2::uuid AND deleted_at IS NULL
             ORDER BY created_at DESC
             LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(organization_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn update(&self, tenant_id: &str, project: &Project) -> Result<Project> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, ProjectRow>(
            r#"UPDATE projects
               SET name = $1, slug = $2, description = $3, status = $4::project_status, metadata = $5, updated_at = $6
               WHERE tenant_id = $7::uuid AND id = $8::uuid AND deleted_at IS NULL
               RETURNING id::text, tenant_id::text, organization_id::text, name, slug, description, status::text, metadata,
                        created_at, updated_at, deleted_at"#,
        )
        .bind(&project.name)
        .bind(&project.slug)
        .bind(&project.description)
        .bind(project.status)
        .bind(&project.metadata)
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(&project.id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    pub async fn delete(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            "UPDATE projects SET deleted_at = $1 WHERE tenant_id = $2::uuid AND id = $3::uuid",
        )
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    pub async fn create_role(&self, role: &ProjectRole) -> Result<ProjectRole> {
        let mut conn = self.tenant_conn(&role.tenant_id).await?;
        let row = sqlx::query_as::<_, ProjectRoleRow>(
            r#"INSERT INTO project_roles (id, tenant_id, project_id, name, description, permissions, is_system_role, created_at, updated_at)
               VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9)
               RETURNING id::text, tenant_id::text, project_id::text, name, description, permissions, is_system_role,
                        created_at, updated_at"#,
        )
        .bind(&role.id)
        .bind(&role.tenant_id)
        .bind(&role.project_id)
        .bind(&role.name)
        .bind(&role.description)
        .bind(serde_json::Value::Array(
            role.permissions.iter().cloned().map(serde_json::Value::String).collect(),
        ))
        .bind(role.is_system_role)
        .bind(role.created_at)
        .bind(role.updated_at)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    pub async fn list_roles(&self, tenant_id: &str, project_id: &str) -> Result<Vec<ProjectRole>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, ProjectRoleRow>(
            r#"SELECT id::text, tenant_id::text, project_id::text, name, description, permissions, is_system_role,
                created_at, updated_at
             FROM project_roles
             WHERE tenant_id = $1::uuid AND project_id = $2::uuid
             ORDER BY created_at DESC"#,
        )
        .bind(tenant_id)
        .bind(project_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn get_role_by_id(
        &self,
        tenant_id: &str,
        role_id: &str,
    ) -> Result<Option<ProjectRole>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, ProjectRoleRow>(
            r#"SELECT id::text, tenant_id::text, project_id::text, name, description, permissions, is_system_role,
                created_at, updated_at
             FROM project_roles
             WHERE tenant_id = $1::uuid AND id = $2::uuid"#,
        )
        .bind(tenant_id)
        .bind(role_id)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row.map(Into::into))
    }

    pub async fn update_role(&self, tenant_id: &str, role: &ProjectRole) -> Result<ProjectRole> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, ProjectRoleRow>(
            r#"UPDATE project_roles
               SET name = $1, description = $2, permissions = $3, updated_at = $4
               WHERE tenant_id = $5::uuid AND id = $6::uuid
               RETURNING id::text, tenant_id::text, project_id::text, name, description, permissions, is_system_role,
                        created_at, updated_at"#,
        )
        .bind(&role.name)
        .bind(&role.description)
        .bind(serde_json::Value::Array(
            role.permissions.iter().cloned().map(serde_json::Value::String).collect(),
        ))
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(&role.id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    pub async fn delete_role(&self, tenant_id: &str, role_id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query("DELETE FROM project_roles WHERE tenant_id = $1::uuid AND id = $2::uuid")
            .bind(tenant_id)
            .bind(role_id)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    pub async fn assign_role(
        &self,
        assignment: &ProjectRoleAssignment,
    ) -> Result<ProjectRoleAssignment> {
        let mut conn = self.tenant_conn(&assignment.tenant_id).await?;
        let row = sqlx::query_as::<_, ProjectRoleAssignmentRow>(
            r#"INSERT INTO project_role_assignments (id, tenant_id, project_id, role_id, user_id, assigned_at, assigned_by)
               VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, $7::uuid)
               RETURNING id::text, tenant_id::text, project_id::text, role_id::text, user_id::text, assigned_at, assigned_by::text"#,
        )
        .bind(&assignment.id)
        .bind(&assignment.tenant_id)
        .bind(&assignment.project_id)
        .bind(&assignment.role_id)
        .bind(&assignment.user_id)
        .bind(assignment.assigned_at)
        .bind(&assignment.assigned_by)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    pub async fn list_assignments(
        &self,
        tenant_id: &str,
        project_id: &str,
    ) -> Result<Vec<ProjectRoleAssignment>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, ProjectRoleAssignmentRow>(
            r#"SELECT id::text, tenant_id::text, project_id::text, role_id::text, user_id::text, assigned_at, assigned_by::text
             FROM project_role_assignments
             WHERE tenant_id = $1::uuid AND project_id = $2::uuid
             ORDER BY assigned_at DESC"#,
        )
        .bind(tenant_id)
        .bind(project_id)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn remove_assignment(&self, tenant_id: &str, assignment_id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            "DELETE FROM project_role_assignments WHERE tenant_id = $1::uuid AND id = $2::uuid",
        )
        .bind(tenant_id)
        .bind(assignment_id)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    pub async fn create_grant(&self, grant: &ProjectGrant) -> Result<ProjectGrant> {
        let mut conn = self.tenant_conn(&grant.tenant_id).await?;
        let row = sqlx::query_as::<_, ProjectGrantRow>(
            r#"INSERT INTO project_grants (id, tenant_id, project_id, granted_organization_id, default_role_id, created_at)
               VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6)
               RETURNING id::text, tenant_id::text, project_id::text, granted_organization_id::text, default_role_id::text, created_at"#,
        )
        .bind(&grant.id)
        .bind(&grant.tenant_id)
        .bind(&grant.project_id)
        .bind(&grant.granted_organization_id)
        .bind(&grant.default_role_id)
        .bind(grant.created_at)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    pub async fn list_grants(
        &self,
        tenant_id: &str,
        project_id: &str,
    ) -> Result<Vec<ProjectGrant>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, ProjectGrantRow>(
            r#"SELECT id::text, tenant_id::text, project_id::text, granted_organization_id::text, default_role_id::text, created_at
             FROM project_grants
             WHERE tenant_id = $1::uuid AND project_id = $2::uuid
             ORDER BY created_at DESC"#,
        )
        .bind(tenant_id)
        .bind(project_id)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn delete_grant(&self, tenant_id: &str, grant_id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query("DELETE FROM project_grants WHERE tenant_id = $1::uuid AND id = $2::uuid")
            .bind(tenant_id)
            .bind(grant_id)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
}
