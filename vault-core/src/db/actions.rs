use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Action {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub trigger: String,
    pub status: String,
    pub runtime: String,
    pub code: Vec<u8>,
    pub timeout_ms: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ActionExecution {
    pub id: String,
    pub tenant_id: String,
    pub action_id: String,
    pub user_id: Option<String>,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub output: Option<serde_json::Value>,
}

pub struct ActionsRepository {
    pool: Arc<PgPool>,
}

impl ActionsRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub async fn list_actions(&self, tenant_id: &str, trigger: Option<&str>) -> Result<Vec<Action>> {
        let actions = sqlx::query_as::<_, Action>(
            r#"
            SELECT id::text, tenant_id::text, name, trigger::text, status::text, runtime, code, timeout_ms,
                   created_at, updated_at
            FROM actions
            WHERE tenant_id = $1::uuid AND ($2::action_trigger IS NULL OR trigger = $2::action_trigger)
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(trigger)
        .fetch_all(&*self.pool)
        .await?;

        Ok(actions)
    }

    pub async fn get_action(&self, tenant_id: &str, action_id: &str) -> Result<Option<Action>> {
        let action = sqlx::query_as::<_, Action>(
            r#"
            SELECT id::text, tenant_id::text, name, trigger::text, status::text, runtime, code, timeout_ms,
                   created_at, updated_at
            FROM actions
            WHERE tenant_id = $1::uuid AND id = $2::uuid
            "#,
        )
        .bind(tenant_id)
        .bind(action_id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(action)
    }

    pub async fn create_action(
        &self,
        tenant_id: &str,
        name: &str,
        trigger: &str,
        status: &str,
        runtime: &str,
        code: &[u8],
        timeout_ms: i32,
    ) -> Result<Action> {
        let action = sqlx::query_as::<_, Action>(
            r#"
            INSERT INTO actions (tenant_id, name, trigger, status, runtime, code, timeout_ms, created_at, updated_at)
            VALUES ($1::uuid, $2, $3::action_trigger, $4::action_status, $5, $6, $7, NOW(), NOW())
            RETURNING id::text, tenant_id::text, name, trigger::text, status::text, runtime, code, timeout_ms,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(trigger)
        .bind(status)
        .bind(runtime)
        .bind(code)
        .bind(timeout_ms)
        .fetch_one(&*self.pool)
        .await?;

        Ok(action)
    }

    pub async fn update_action(
        &self,
        tenant_id: &str,
        action_id: &str,
        name: Option<&str>,
        status: Option<&str>,
        code: Option<&[u8]>,
        timeout_ms: Option<i32>,
    ) -> Result<Action> {
        let action = sqlx::query_as::<_, Action>(
            r#"
            UPDATE actions
            SET name = COALESCE($3, name),
                status = COALESCE($4, status),
                code = COALESCE($5, code),
                timeout_ms = COALESCE($6, timeout_ms),
                updated_at = NOW()
            WHERE tenant_id = $1::uuid AND id = $2::uuid
            RETURNING id::text, tenant_id::text, name, trigger::text, status::text, runtime, code, timeout_ms,
                      created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(action_id)
        .bind(name)
        .bind(status)
        .bind(code)
        .bind(timeout_ms)
        .fetch_one(&*self.pool)
        .await?;

        Ok(action)
    }

    pub async fn delete_action(&self, tenant_id: &str, action_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM actions WHERE tenant_id = $1::uuid AND id = $2::uuid")
            .bind(tenant_id)
            .bind(action_id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    pub async fn record_execution(
        &self,
        tenant_id: &str,
        action_id: &str,
        user_id: Option<&str>,
        status: &str,
        started_at: DateTime<Utc>,
        finished_at: Option<DateTime<Utc>>,
        error: Option<&str>,
        output: Option<serde_json::Value>,
    ) -> Result<ActionExecution> {
        let execution = sqlx::query_as::<_, ActionExecution>(
            r#"
            INSERT INTO action_executions (
                tenant_id, action_id, user_id, status, started_at, finished_at, error, output
            ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::action_execution_status, $5, $6, $7, $8)
            RETURNING id::text, tenant_id::text, action_id::text, user_id::text, status::text,
                      started_at, finished_at, error, output
            "#,
        )
        .bind(tenant_id)
        .bind(action_id)
        .bind(user_id)
        .bind(status)
        .bind(started_at)
        .bind(finished_at)
        .bind(error)
        .bind(output)
        .fetch_one(&*self.pool)
        .await?;

        Ok(execution)
    }
}
