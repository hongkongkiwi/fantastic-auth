//! Database module for Vault Core
//!
//! Provides repository implementations for database access with tenant isolation.

pub mod mfa;
pub mod organizations;
pub mod sessions;
pub mod users;

use sqlx::{postgres::PgPoolOptions, PgConnection, PgPool};
use std::future::Future;
use std::sync::Arc;
use tokio::task_local;

pub use mfa::MfaRepository;
pub use organizations::OrganizationRepository;
pub use sessions::SessionRepository;
pub use users::UserRepository;

#[derive(Clone, Debug, Default)]
pub struct RequestContext {
    pub user_id: Option<String>,
    pub role: Option<String>,
}

task_local! {
    static REQUEST_CONTEXT: RequestContext;
}

pub async fn with_request_context<Fut, T>(ctx: RequestContext, fut: Fut) -> T
where
    Fut: Future<Output = T>,
{
    REQUEST_CONTEXT.scope(ctx, fut).await
}

pub fn current_request_context() -> Option<RequestContext> {
    REQUEST_CONTEXT.try_with(|ctx| ctx.clone()).ok()
}

pub async fn set_connection_context(
    conn: &mut PgConnection,
    tenant_id: &str,
) -> Result<(), sqlx::Error> {
    // Ensure RLS policies apply by operating under the application role
    sqlx::query("SET ROLE vault_app")
        .execute(&mut *conn)
        .await?;

    sqlx::query("SELECT set_config('app.current_tenant_id', $1, false)")
        .bind(tenant_id)
        .execute(&mut *conn)
        .await?;

    if let Some(ctx) = current_request_context() {
        if let Some(user_id) = ctx.user_id {
            sqlx::query("SELECT set_config('app.current_user_id', $1, false)")
                .bind(user_id)
                .execute(&mut *conn)
                .await?;
        } else {
            sqlx::query("SELECT set_config('app.current_user_id', '00000000-0000-0000-0000-000000000000', false)")
                .execute(&mut *conn)
                .await?;
        }
        if let Some(role) = ctx.role {
            sqlx::query("SELECT set_config('app.current_user_role', $1, false)")
                .bind(role)
                .execute(&mut *conn)
                .await?;
        } else {
            sqlx::query("RESET app.current_user_role")
                .execute(&mut *conn)
                .await?;
        }
    } else {
        sqlx::query("SELECT set_config('app.current_user_id', '00000000-0000-0000-0000-000000000000', false)")
            .execute(&mut *conn)
            .await?;
        sqlx::query("RESET app.current_user_role")
            .execute(&mut *conn)
            .await?;
    }

    Ok(())
}

/// Database context with repositories
#[derive(Clone)]
pub struct DbContext {
    pool: Arc<PgPool>,
}

impl DbContext {
    /// Create a new database context
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool: Arc::new(pool),
        }
    }

    /// Get a reference to the pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// User repository
    pub fn users(&self) -> UserRepository {
        UserRepository::new(self.pool.clone())
    }

    /// Session repository
    pub fn sessions(&self) -> SessionRepository {
        SessionRepository::new(self.pool.clone())
    }

    /// Organization repository
    pub fn organizations(&self) -> OrganizationRepository {
        OrganizationRepository::new(self.pool.clone())
    }

    /// MFA repository
    pub fn mfa(&self) -> MfaRepository {
        MfaRepository::new(self.pool.clone())
    }

    /// Set tenant context for RLS
    pub async fn set_tenant_context(
        &self,
        tenant_id: &str,
        user_id: Option<&str>,
        role: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let mut conn = self.pool.acquire().await?;

        // Set tenant ID for RLS policies
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, false)")
            .bind(tenant_id)
            .execute(&mut *conn)
            .await?;

        // Set user ID if provided
        if let Some(uid) = user_id {
            sqlx::query("SELECT set_config('app.current_user_id', $1, false)")
                .bind(uid)
                .execute(&mut *conn)
                .await?;
        } else {
            sqlx::query("SELECT set_config('app.current_user_id', '00000000-0000-0000-0000-000000000000', false)")
                .execute(&mut *conn)
                .await?;
        }

        // Set role if provided
        if let Some(r) = role {
            sqlx::query("SELECT set_config('app.current_user_role', $1, false)")
                .bind(r)
                .execute(&mut *conn)
                .await?;
        } else {
            sqlx::query("RESET app.current_user_role")
                .execute(&mut *conn)
                .await?;
        }

        Ok(())
    }

    /// Health check
    pub async fn health_check(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").fetch_one(&*self.pool).await?;
        Ok(())
    }
}

/// Legacy DbConn alias for backwards compatibility
pub type DbConn = DbContext;
