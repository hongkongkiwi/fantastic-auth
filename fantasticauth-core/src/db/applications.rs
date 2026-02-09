//! Application repository implementation

use crate::db::set_connection_context;
use crate::error::Result;
use crate::models::project::{Application, ApplicationStatus, ApplicationType};
use sqlx::{FromRow, PgPool};
use std::sync::Arc;

pub struct ApplicationRepository {
    pool: Arc<PgPool>,
}

#[derive(Debug, FromRow)]
struct ApplicationRow {
    id: String,
    tenant_id: String,
    organization_id: String,
    project_id: String,
    name: String,
    app_type: String,
    status: String,
    settings: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ApplicationRow> for Application {
    fn from(row: ApplicationRow) -> Self {
        Application {
            id: row.id,
            tenant_id: row.tenant_id,
            organization_id: row.organization_id,
            project_id: row.project_id,
            name: row.name,
            app_type: row.app_type.parse().unwrap_or(ApplicationType::Oidc),
            status: row.status.parse().unwrap_or(ApplicationStatus::Active),
            settings: row.settings,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

impl ApplicationRepository {
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

    pub async fn create(&self, app: &Application) -> Result<Application> {
        let mut conn = self.tenant_conn(&app.tenant_id).await?;
        let row = sqlx::query_as::<_, ApplicationRow>(
            r#"INSERT INTO applications (id, tenant_id, organization_id, project_id, name, app_type, status, settings, created_at, updated_at)
               VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6::application_type, $7::application_status, $8, $9, $10)
               RETURNING id::text, tenant_id::text, organization_id::text, project_id::text, name, app_type::text,
                        status::text, settings, created_at, updated_at"#,
        )
        .bind(&app.id)
        .bind(&app.tenant_id)
        .bind(&app.organization_id)
        .bind(&app.project_id)
        .bind(&app.name)
        .bind(app.app_type)
        .bind(app.status)
        .bind(&app.settings)
        .bind(app.created_at)
        .bind(app.updated_at)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    pub async fn get_by_id(&self, tenant_id: &str, id: &str) -> Result<Option<Application>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, ApplicationRow>(
            r#"SELECT id::text, tenant_id::text, organization_id::text, project_id::text, name, app_type::text,
                status::text, settings, created_at, updated_at
             FROM applications
             WHERE tenant_id = $1::uuid AND id = $2::uuid"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    pub async fn list_by_project(
        &self,
        tenant_id: &str,
        project_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Application>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, ApplicationRow>(
            r#"SELECT id::text, tenant_id::text, organization_id::text, project_id::text, name, app_type::text,
                status::text, settings, created_at, updated_at
             FROM applications
             WHERE tenant_id = $1::uuid AND project_id = $2::uuid
             ORDER BY created_at DESC
             LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(project_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn update(&self, tenant_id: &str, app: &Application) -> Result<Application> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, ApplicationRow>(
            r#"UPDATE applications
               SET name = $1, app_type = $2::application_type, status = $3::application_status, settings = $4, updated_at = $5
               WHERE tenant_id = $6::uuid AND id = $7::uuid
               RETURNING id::text, tenant_id::text, organization_id::text, project_id::text, name, app_type::text,
                        status::text, settings, created_at, updated_at"#,
        )
        .bind(&app.name)
        .bind(app.app_type)
        .bind(app.status)
        .bind(&app.settings)
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(&app.id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    pub async fn delete(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query("DELETE FROM applications WHERE tenant_id = $1::uuid AND id = $2::uuid")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
}
