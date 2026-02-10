//! Admin IdP Brokering Routes

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, patch},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::db::set_connection_context;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/idp/providers", get(list_providers).post(create_provider))
        .route(
            "/idp/providers/:provider_id",
            patch(update_provider).delete(delete_provider),
        )
        .route("/idp/domains", get(list_domains).post(create_domain))
        .route("/idp/domains/:domain_id", delete(delete_domain))
}

#[derive(Debug, Deserialize)]
struct ListProvidersQuery {
    #[serde(rename = "orgId")]
    organization_id: Option<String>,
    #[serde(rename = "appId")]
    application_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateProviderRequest {
    #[serde(rename = "orgId")]
    organization_id: String,
    #[serde(rename = "appId")]
    application_id: Option<String>,
    name: String,
    #[serde(rename = "providerType")]
    provider_type: String,
    status: Option<String>,
    config: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct UpdateProviderRequest {
    name: Option<String>,
    #[serde(rename = "providerType")]
    provider_type: Option<String>,
    status: Option<String>,
    config: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, FromRow)]
struct ProviderResponse {
    id: String,
    #[serde(rename = "orgId")]
    organization_id: String,
    #[serde(rename = "appId")]
    application_id: Option<String>,
    name: String,
    #[serde(rename = "providerType")]
    provider_type: String,
    status: String,
    config: serde_json::Value,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct ListDomainsQuery {
    #[serde(rename = "orgId")]
    organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateDomainRequest {
    #[serde(rename = "orgId")]
    organization_id: String,
    #[serde(rename = "appId")]
    application_id: Option<String>,
    #[serde(rename = "providerId")]
    provider_id: String,
    domain: String,
}

#[derive(Debug, Serialize, FromRow)]
struct DomainResponse {
    id: String,
    #[serde(rename = "orgId")]
    organization_id: String,
    #[serde(rename = "appId")]
    application_id: Option<String>,
    #[serde(rename = "providerId")]
    provider_id: String,
    domain: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

async fn list_providers(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListProvidersQuery>,
) -> Result<Json<Vec<ProviderResponse>>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let mut qb = sqlx::QueryBuilder::new(
        "SELECT id::text, organization_id::text as organization_id, application_id::text as application_id, name, provider_type::text as provider_type, status::text as status, config, created_at::text as created_at, updated_at::text as updated_at FROM idp_providers WHERE tenant_id = ",
    );
    qb.push_bind(&current_user.tenant_id);

    if let Some(org_id) = &query.organization_id {
        qb.push(" AND organization_id = ");
        qb.push_bind(org_id);
    }
    if let Some(app_id) = &query.application_id {
        qb.push(" AND application_id = ");
        qb.push_bind(app_id);
    }

    let rows = qb
        .build_query_as::<ProviderResponse>()
        .fetch_all(&mut *conn)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(rows))
}

async fn create_provider(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateProviderRequest>,
) -> Result<Json<ProviderResponse>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let status = req.status.unwrap_or_else(|| "active".to_string());
    let config = req.config.unwrap_or_else(|| serde_json::json!({}));

    let row = sqlx::query_as::<_, ProviderResponse>(
        r#"INSERT INTO idp_providers (tenant_id, organization_id, application_id, name, provider_type, status, config)
           VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::idp_provider_type, $6::idp_provider_status, $7)
           RETURNING id::text, organization_id::text as organization_id, application_id::text as application_id, name,
                    provider_type::text as provider_type, status::text as status, config,
                    created_at::text as created_at, updated_at::text as updated_at"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&req.organization_id)
    .bind(&req.application_id)
    .bind(&req.name)
    .bind(&req.provider_type)
    .bind(&status)
    .bind(&config)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(row))
}

async fn update_provider(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(provider_id): Path<String>,
    Json(req): Json<UpdateProviderRequest>,
) -> Result<Json<ProviderResponse>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let row = sqlx::query_as::<_, ProviderResponse>(
        r#"UPDATE idp_providers
           SET name = COALESCE($1, name),
               provider_type = COALESCE($2::idp_provider_type, provider_type),
               status = COALESCE($3::idp_provider_status, status),
               config = COALESCE($4, config),
               updated_at = NOW()
           WHERE tenant_id = $5::uuid AND id = $6::uuid
           RETURNING id::text, organization_id::text as organization_id, application_id::text as application_id, name,
                    provider_type::text as provider_type, status::text as status, config,
                    created_at::text as created_at, updated_at::text as updated_at"#,
    )
    .bind(req.name)
    .bind(req.provider_type)
    .bind(req.status)
    .bind(req.config)
    .bind(&current_user.tenant_id)
    .bind(&provider_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(row))
}

async fn delete_provider(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(provider_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    sqlx::query("DELETE FROM idp_providers WHERE tenant_id = $1::uuid AND id = $2::uuid")
        .bind(&current_user.tenant_id)
        .bind(&provider_id)
        .execute(&mut *conn)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"deleted": true})))
}

async fn list_domains(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListDomainsQuery>,
) -> Result<Json<Vec<DomainResponse>>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let mut qb = sqlx::QueryBuilder::new(
        "SELECT id::text, organization_id::text as organization_id, application_id::text as application_id, provider_id::text as provider_id, domain, created_at::text as created_at FROM idp_domains WHERE tenant_id = ",
    );
    qb.push_bind(&current_user.tenant_id);

    if let Some(org_id) = &query.organization_id {
        qb.push(" AND organization_id = ");
        qb.push_bind(org_id);
    }

    let rows = qb
        .build_query_as::<DomainResponse>()
        .fetch_all(&mut *conn)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(rows))
}

async fn create_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateDomainRequest>,
) -> Result<Json<DomainResponse>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let row = sqlx::query_as::<_, DomainResponse>(
        r#"INSERT INTO idp_domains (tenant_id, organization_id, application_id, provider_id, domain)
           VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5)
           RETURNING id::text, organization_id::text as organization_id, application_id::text as application_id,
                    provider_id::text as provider_id, domain, created_at::text as created_at"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&req.organization_id)
    .bind(&req.application_id)
    .bind(&req.provider_id)
    .bind(&req.domain)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(row))
}

async fn delete_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(domain_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    sqlx::query("DELETE FROM idp_domains WHERE tenant_id = $1::uuid AND id = $2::uuid")
        .bind(&current_user.tenant_id)
        .bind(&domain_id)
        .execute(&mut *conn)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"deleted": true})))
}
