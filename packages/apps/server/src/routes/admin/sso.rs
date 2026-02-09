//! Admin SSO Routes

use axum::{
    extract::{Path, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::db::set_connection_context;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/sso/saml/connections",
            get(list_saml_connections).post(create_saml_connection),
        )
        .route(
            "/sso/saml/connections/:connection_id",
            get(get_saml_connection)
                .patch(update_saml_connection)
                .delete(delete_saml_connection),
        )
        .route(
            "/sso/oidc/connections",
            get(list_oidc_connections).post(create_oidc_connection),
        )
        .route(
            "/sso/oidc/connections/:connection_id",
            get(get_oidc_connection)
                .patch(update_oidc_connection)
                .delete(delete_oidc_connection),
        )
        .route("/organizations/:org_id/sso", patch(update_org_sso))
}

#[derive(Debug, Deserialize)]
struct SsoConnectionRequest {
    name: String,
    domains: Option<Vec<String>>,
    config: serde_json::Value,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateSsoConnectionRequest {
    name: Option<String>,
    domains: Option<Vec<String>>,
    config: Option<serde_json::Value>,
    status: Option<String>,
}

#[derive(Debug, Serialize)]
struct SsoConnectionResponse {
    id: String,
    #[serde(rename = "type")]
    connection_type: String,
    name: String,
    status: String,
    domains: Vec<String>,
    config: serde_json::Value,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Debug, FromRow)]
struct SsoConnectionRow {
    id: String,
    #[sqlx(rename = "type")]
    connection_type: String,
    name: String,
    status: String,
    config: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
struct UpdateOrgSsoRequest {
    #[serde(rename = "connectionId")]
    connection_id: Option<String>,
    required: Option<bool>,
    #[serde(rename = "jitEnabled")]
    jit_enabled: Option<bool>,
    #[serde(rename = "defaultRole")]
    default_role: Option<String>,
}

#[derive(Debug, Serialize)]
struct OrganizationSsoResponse {
    #[serde(rename = "orgId")]
    org_id: String,
    #[serde(rename = "connectionId")]
    connection_id: Option<String>,
    required: bool,
    #[serde(rename = "jitEnabled")]
    jit_enabled: bool,
    #[serde(rename = "defaultRole")]
    default_role: String,
}

async fn list_saml_connections(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let rows = list_connections_by_type(&state, &current_user.tenant_id, "saml").await?;
    Ok(Json(serde_json::json!({"data": rows})))
}

async fn create_saml_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<SsoConnectionRequest>,
) -> Result<Json<SsoConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let response = create_connection(&state, &current_user.tenant_id, "saml", req).await?;
    Ok(Json(response))
}

async fn get_saml_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<SsoConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let response = get_connection(&state, &current_user.tenant_id, &connection_id).await?;
    Ok(Json(response))
}

async fn update_saml_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
    Json(req): Json<UpdateSsoConnectionRequest>,
) -> Result<Json<SsoConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let response = update_connection(&state, &current_user.tenant_id, &connection_id, req).await?;
    Ok(Json(response))
}

async fn delete_saml_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(_connection_id): Path<String>,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    delete_connection(&state, &current_user.tenant_id, &_connection_id).await?;
    Ok(())
}

async fn list_oidc_connections(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let rows = list_connections_by_type(&state, &current_user.tenant_id, "oidc").await?;
    Ok(Json(serde_json::json!({"data": rows})))
}

async fn create_oidc_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<SsoConnectionRequest>,
) -> Result<Json<SsoConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let response = create_connection(&state, &current_user.tenant_id, "oidc", req).await?;
    Ok(Json(response))
}

async fn get_oidc_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<SsoConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let response = get_connection(&state, &current_user.tenant_id, &connection_id).await?;
    Ok(Json(response))
}

async fn update_oidc_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
    Json(req): Json<UpdateSsoConnectionRequest>,
) -> Result<Json<SsoConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let response = update_connection(&state, &current_user.tenant_id, &connection_id, req).await?;
    Ok(Json(response))
}

async fn delete_oidc_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(_connection_id): Path<String>,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    delete_connection(&state, &current_user.tenant_id, &_connection_id).await?;
    Ok(())
}

async fn update_org_sso(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
    Json(req): Json<UpdateOrgSsoRequest>,
) -> Result<Json<OrganizationSsoResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let row = sqlx::query_as::<_, (String, Option<String>, bool, bool, String)>(
        r#"
        INSERT INTO org_sso_settings (tenant_id, organization_id, connection_id, required, jit_enabled, default_role)
        VALUES ($1, $2, $3, $4, $5, $6::org_role)
        ON CONFLICT (organization_id) DO UPDATE
          SET connection_id = EXCLUDED.connection_id,
              required = EXCLUDED.required,
              jit_enabled = EXCLUDED.jit_enabled,
              default_role = EXCLUDED.default_role,
              updated_at = NOW()
        RETURNING organization_id, connection_id, required, jit_enabled, default_role::text
        "#
    )
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .bind(&req.connection_id)
    .bind(req.required.unwrap_or(false))
    .bind(req.jit_enabled.unwrap_or(true))
    .bind(req.default_role.unwrap_or_else(|| "member".to_string()))
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(OrganizationSsoResponse {
        org_id: row.0,
        connection_id: row.1,
        required: row.2,
        jit_enabled: row.3,
        default_role: row.4,
    }))
}

async fn list_connections_by_type(
    state: &AppState,
    tenant_id: &str,
    connection_type: &str,
) -> Result<Vec<SsoConnectionResponse>, ApiError> {
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let rows = sqlx::query_as::<_, SsoConnectionRow>(
        r#"
        SELECT id, type::text, name, status, config, created_at, updated_at
        FROM sso_connections
        WHERE tenant_id = $1 AND type = $2::sso_provider_type
        ORDER BY created_at DESC
        "#,
    )
    .bind(tenant_id)
    .bind(connection_type)
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    let mut responses = Vec::with_capacity(rows.len());
    for row in rows {
        let domains = load_domains(state, tenant_id, &row.id).await?;
        responses.push(SsoConnectionResponse {
            id: row.id,
            connection_type: row.connection_type,
            name: row.name,
            status: row.status,
            domains,
            config: row.config,
            created_at: row.created_at.to_rfc3339(),
            updated_at: row.updated_at.to_rfc3339(),
        });
    }

    Ok(responses)
}

async fn create_connection(
    state: &AppState,
    tenant_id: &str,
    connection_type: &str,
    req: SsoConnectionRequest,
) -> Result<SsoConnectionResponse, ApiError> {
    let id = uuid::Uuid::new_v4().to_string();
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    sqlx::query(
        r#"
        INSERT INTO sso_connections (id, tenant_id, type, name, status, config)
        VALUES ($1, $2, $3::sso_provider_type, $4, $5, $6)
        "#,
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(connection_type)
    .bind(&req.name)
    .bind(req.status.as_deref().unwrap_or("active"))
    .bind(&req.config)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    // Insert domains if provided
    if let Some(domains) = req.domains {
        for domain in domains {
            sqlx::query(
                r#"
                INSERT INTO sso_domains (id, tenant_id, connection_id, domain)
                VALUES ($1, $2, $3, $4)
                "#,
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(tenant_id)
            .bind(&id)
            .bind(domain)
            .execute(&mut *conn)
            .await
            .map_err(|_| ApiError::internal())?;
        }
    }

    get_connection(state, tenant_id, &id).await
}

async fn get_connection(
    state: &AppState,
    tenant_id: &str,
    connection_id: &str,
) -> Result<SsoConnectionResponse, ApiError> {
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let row = sqlx::query_as::<_, SsoConnectionRow>(
        r#"
        SELECT id, type::text, name, status, config, created_at, updated_at
        FROM sso_connections
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(connection_id)
    .bind(tenant_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::NotFound)?;

    let domains = load_domains(state, tenant_id, connection_id).await?;

    Ok(SsoConnectionResponse {
        id: row.id,
        connection_type: row.connection_type,
        name: row.name,
        status: row.status,
        domains,
        config: row.config,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    })
}

async fn update_connection(
    state: &AppState,
    tenant_id: &str,
    connection_id: &str,
    req: UpdateSsoConnectionRequest,
) -> Result<SsoConnectionResponse, ApiError> {
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    if let Some(name) = req.name {
        sqlx::query("UPDATE sso_connections SET name = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(name)
            .bind(connection_id)
            .bind(tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(|_| ApiError::internal())?;
    }

    if let Some(status) = req.status {
        sqlx::query("UPDATE sso_connections SET status = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(status)
            .bind(connection_id)
            .bind(tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(|_| ApiError::internal())?;
    }

    if let Some(config) = req.config {
        sqlx::query("UPDATE sso_connections SET config = $1 WHERE id = $2 AND tenant_id = $3")
            .bind(config)
            .bind(connection_id)
            .bind(tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(|_| ApiError::internal())?;
    }

    // Update domains if provided
    if let Some(domains) = req.domains {
        // Delete existing domains
        sqlx::query("DELETE FROM sso_domains WHERE connection_id = $1 AND tenant_id = $2")
            .bind(connection_id)
            .bind(tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(|_| ApiError::internal())?;

        // Insert new domains
        for domain in domains {
            sqlx::query(
                r#"
                INSERT INTO sso_domains (id, tenant_id, connection_id, domain)
                VALUES ($1, $2, $3, $4)
                "#,
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(tenant_id)
            .bind(connection_id)
            .bind(domain)
            .execute(&mut *conn)
            .await
            .map_err(|_| ApiError::internal())?;
        }
    }

    get_connection(state, tenant_id, connection_id).await
}

async fn delete_connection(
    state: &AppState,
    tenant_id: &str,
    connection_id: &str,
) -> Result<(), ApiError> {
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    sqlx::query("DELETE FROM sso_connections WHERE id = $1 AND tenant_id = $2")
        .bind(connection_id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(())
}

async fn load_domains(
    state: &AppState,
    tenant_id: &str,
    connection_id: &str,
) -> Result<Vec<String>, ApiError> {
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT domain FROM sso_domains WHERE connection_id = $1 AND tenant_id = $2",
    )
    .bind(connection_id)
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(rows.into_iter().map(|r| r.0).collect())
}
