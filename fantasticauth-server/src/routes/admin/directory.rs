//! Admin Directory Connector Routes
//!
//! API endpoints for managing LDAP/Active Directory connections and synchronization.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

use crate::ldap::sync::{LdapJitAuth, LdapSyncJob, SyncType};
use crate::ldap::{LdapConfig, LdapConnection, LdapUserAttributes};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

pub fn routes() -> Router<AppState> {
    Router::new()
        // LDAP Connections
        .route(
            "/directory/ldap",
            get(list_connections).post(create_connection),
        )
        .route(
            "/directory/ldap/:connection_id",
            get(get_connection)
                .put(update_connection)
                .delete(delete_connection),
        )
        .route("/directory/ldap/:connection_id/test", post(test_connection))
        // LDAP Sync
        .route("/directory/ldap/:connection_id/sync", post(trigger_sync))
        .route(
            "/directory/ldap/:connection_id/sync/status",
            get(get_sync_status),
        )
        // LDAP Logs
        .route("/directory/ldap/:connection_id/logs", get(list_sync_logs))
        .route("/directory/ldap/logs/:log_id", get(get_sync_log))
        // LDAP JIT Auth (for login flow integration)
        .route("/directory/ldap/authenticate", post(ldap_authenticate))
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
struct CreateLdapConnectionRequest {
    name: String,
    url: String,
    bind_dn: String,
    bind_password: String,
    base_dn: String,
    #[serde(default)]
    user_search_base: Option<String>,
    #[serde(default)]
    user_search_filter: Option<String>,
    #[serde(default)]
    group_search_base: Option<String>,
    #[serde(default)]
    group_search_filter: Option<String>,
    #[serde(default)]
    user_attributes: Option<LdapUserAttributesRequest>,
    #[serde(default = "default_sync_interval")]
    sync_interval_minutes: u32,
    #[serde(default = "default_true")]
    tls_verify_cert: bool,
    #[serde(default)]
    tls_ca_cert: Option<String>,
    #[serde(default = "default_timeout")]
    connection_timeout_secs: u64,
    #[serde(default = "default_search_timeout")]
    search_timeout_secs: u64,
    #[serde(default)]
    jit_provisioning_enabled: Option<bool>,
    #[serde(default)]
    jit_default_role: Option<String>,
    #[serde(default)]
    jit_organization_id: Option<String>,
    #[serde(default)]
    group_sync_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
struct LdapUserAttributesRequest {
    #[serde(default = "default_attr_email")]
    email: String,
    #[serde(default = "default_attr_username")]
    username: String,
    #[serde(default = "default_attr_first_name")]
    first_name: String,
    #[serde(default = "default_attr_last_name")]
    last_name: String,
    #[serde(default = "default_attr_display_name")]
    display_name: String,
    #[serde(default = "default_attr_phone")]
    phone: String,
    #[serde(default = "default_attr_department")]
    department: String,
    #[serde(default = "default_attr_title")]
    title: String,
    #[serde(default = "default_attr_employee_id")]
    employee_id: String,
    #[serde(default = "default_attr_object_guid")]
    object_guid: String,
}

impl From<LdapUserAttributesRequest> for LdapUserAttributes {
    fn from(req: LdapUserAttributesRequest) -> Self {
        Self {
            email: req.email,
            username: req.username,
            first_name: req.first_name,
            last_name: req.last_name,
            display_name: req.display_name,
            phone: req.phone,
            department: req.department,
            title: req.title,
            employee_id: req.employee_id,
            object_guid: req.object_guid,
            member_of: "memberOf".to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct UpdateLdapConnectionRequest {
    name: Option<String>,
    url: Option<String>,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    base_dn: Option<String>,
    user_search_base: Option<String>,
    user_search_filter: Option<String>,
    group_search_base: Option<String>,
    group_search_filter: Option<String>,
    user_attributes: Option<LdapUserAttributesRequest>,
    sync_interval_minutes: Option<u32>,
    enabled: Option<bool>,
    tls_verify_cert: Option<bool>,
    tls_ca_cert: Option<String>,
    connection_timeout_secs: Option<u64>,
    search_timeout_secs: Option<u64>,
    jit_provisioning_enabled: Option<bool>,
    jit_default_role: Option<String>,
    jit_organization_id: Option<String>,
    group_sync_enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
struct LdapConnectionResponse {
    id: String,
    name: String,
    enabled: bool,
    url: String,
    bind_dn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bind_password: Option<String>, // Only included if explicitly requested
    base_dn: String,
    user_search_base: Option<String>,
    user_search_filter: String,
    group_search_base: Option<String>,
    group_search_filter: String,
    user_attributes: HashMap<String, String>,
    sync_interval_minutes: u32,
    #[serde(rename = "lastSyncAt")]
    last_sync_at: Option<DateTime<Utc>>,
    #[serde(rename = "lastSyncStatus")]
    last_sync_status: Option<String>,
    #[serde(rename = "nextSyncAt")]
    next_sync_at: Option<DateTime<Utc>>,
    #[serde(rename = "connectionStatus")]
    connection_status: String,
    #[serde(rename = "connectionTestedAt")]
    connection_tested_at: Option<DateTime<Utc>>,
    jit_provisioning_enabled: bool,
    jit_default_role: String,
    #[serde(rename = "jitOrganizationId")]
    jit_organization_id: Option<String>,
    group_sync_enabled: bool,
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct LdapConnectionListResponse {
    data: Vec<LdapConnectionResponse>,
    pagination: PaginationInfo,
}

#[derive(Debug, Serialize)]
struct PaginationInfo {
    total: i64,
    page: i64,
    per_page: i64,
}

#[derive(Debug, Deserialize)]
struct ListConnectionsQuery {
    #[serde(default)]
    page: Option<i64>,
    #[serde(default)]
    per_page: Option<i64>,
    #[serde(default)]
    enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
struct TestConnectionResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct TriggerSyncRequest {
    #[serde(default = "default_sync_type")]
    sync_type: String, // "full" or "incremental"
}

#[derive(Debug, Serialize)]
struct TriggerSyncResponse {
    sync_id: String,
    status: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct SyncStatusResponse {
    connection_id: String,
    is_syncing: bool,
    #[serde(rename = "currentSync")]
    current_sync: Option<CurrentSyncInfo>,
    last_sync: Option<LastSyncInfo>,
    stats: Option<SyncStatsResponse>,
}

#[derive(Debug, Serialize)]
struct CurrentSyncInfo {
    sync_id: String,
    started_at: DateTime<Utc>,
    triggered_by: String,
}

#[derive(Debug, Serialize)]
struct LastSyncInfo {
    sync_id: String,
    status: String,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct SyncStatsResponse {
    users_found: usize,
    users_created: usize,
    users_updated: usize,
    users_disabled: usize,
    users_failed: usize,
    groups_found: usize,
    groups_created: usize,
    groups_updated: usize,
    groups_failed: usize,
}

#[derive(Debug, Serialize)]
struct SyncLogResponse {
    id: String,
    #[serde(rename = "connectionId")]
    connection_id: String,
    #[serde(rename = "syncType")]
    sync_type: String,
    status: String,
    #[serde(rename = "startedAt")]
    started_at: DateTime<Utc>,
    #[serde(rename = "completedAt")]
    completed_at: Option<DateTime<Utc>>,
    #[serde(rename = "usersFound")]
    users_found: i32,
    #[serde(rename = "usersCreated")]
    users_created: i32,
    #[serde(rename = "usersUpdated")]
    users_updated: i32,
    #[serde(rename = "usersFailed")]
    users_failed: i32,
    #[serde(rename = "groupsFound")]
    groups_found: i32,
    #[serde(rename = "durationMs")]
    duration_ms: Option<i32>,
    #[serde(rename = "errorMessage")]
    error_message: Option<String>,
    #[serde(rename = "triggeredBy")]
    triggered_by: String,
}

#[derive(Debug, Serialize)]
struct SyncLogDetailResponse {
    #[serde(flatten)]
    log: SyncLogResponse,
    #[serde(rename = "logEntries")]
    log_entries: Vec<SyncLogEntryResponse>,
}

#[derive(Debug, Serialize)]
struct SyncLogEntryResponse {
    timestamp: DateTime<Utc>,
    level: String,
    operation: String,
    #[serde(rename = "ldapDn")]
    ldap_dn: Option<String>,
    #[serde(rename = "userId")]
    user_id: Option<String>,
    message: String,
}

#[derive(Debug, Serialize)]
struct SyncLogListResponse {
    data: Vec<SyncLogResponse>,
    pagination: PaginationInfo,
}

#[derive(Debug, Deserialize)]
struct ListSyncLogsQuery {
    #[serde(default)]
    page: Option<i64>,
    #[serde(default)]
    per_page: Option<i64>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LdapAuthenticateRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LdapAuthenticateResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<LdapUserInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct LdapUserInfo {
    email: String,
    username: String,
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    department: Option<String>,
    title: Option<String>,
}

// Default functions for serde
fn default_sync_interval() -> u32 {
    60
}
fn default_true() -> bool {
    true
}
fn default_timeout() -> u64 {
    10
}
fn default_search_timeout() -> u64 {
    30
}
fn default_sync_type() -> String {
    "incremental".to_string()
}
fn default_attr_email() -> String {
    "mail".to_string()
}
fn default_attr_username() -> String {
    "sAMAccountName".to_string()
}
fn default_attr_first_name() -> String {
    "givenName".to_string()
}
fn default_attr_last_name() -> String {
    "sn".to_string()
}
fn default_attr_display_name() -> String {
    "displayName".to_string()
}
fn default_attr_phone() -> String {
    "telephoneNumber".to_string()
}
fn default_attr_department() -> String {
    "department".to_string()
}
fn default_attr_title() -> String {
    "title".to_string()
}
fn default_attr_employee_id() -> String {
    "employeeID".to_string()
}
fn default_attr_object_guid() -> String {
    "objectGUID".to_string()
}

// ============ Handlers ============

/// List all LDAP connections for the tenant
async fn list_connections(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListConnectionsQuery>,
) -> Result<Json<LdapConnectionListResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = (page - 1) * per_page;

    // Build query
    let mut sql = String::from(
        "SELECT id, name, enabled, url, bind_dn, base_dn, user_search_base, user_search_filter,
         group_search_base, group_search_filter, user_attribute_mappings, sync_interval_minutes,
         last_sync_at, last_sync_status, next_sync_at, connection_status, connection_tested_at,
         jit_provisioning_enabled, jit_default_role, jit_organization_id, group_sync_enabled,
         created_at, updated_at
         FROM ldap_connections WHERE tenant_id = $1",
    );

    if let Some(enabled) = query.enabled {
        if enabled {
            sql.push_str(" AND enabled = true");
        } else {
            sql.push_str(" AND enabled = false");
        }
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT $2 OFFSET $3");

    let rows = sqlx::query(&sql)
        .bind(&current_user.tenant_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to list LDAP connections: {}", e);
            ApiError::Internal
        })?;

    // Get total count
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ldap_connections WHERE tenant_id = $1")
            .bind(&current_user.tenant_id)
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0);

    let connections: Vec<LdapConnectionResponse> = rows
        .into_iter()
        .map(|row| row_to_response(pg_row_to_connection_row(row)))
        .collect();

    Ok(Json(LdapConnectionListResponse {
        data: connections,
        pagination: PaginationInfo {
            total,
            page,
            per_page,
        },
    }))
}

/// Create a new LDAP connection
async fn create_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateLdapConnectionRequest>,
) -> Result<(StatusCode, Json<LdapConnectionResponse>), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Validate request
    if req.name.is_empty() {
        return Err(ApiError::Validation("Name is required".to_string()));
    }
    if req.url.is_empty() {
        return Err(ApiError::Validation("URL is required".to_string()));
    }
    if !req.url.starts_with("ldap://") && !req.url.starts_with("ldaps://") {
        return Err(ApiError::Validation(
            "URL must start with ldap:// or ldaps://".to_string(),
        ));
    }

    let connection_id = Uuid::new_v4();
    let user_attributes: LdapUserAttributes =
        req.user_attributes.map(Into::into).unwrap_or_default();

    let encrypted_password =
        encrypt_bind_password(&state, &current_user.tenant_id, &req.bind_password).await?;

    sqlx::query(
        r#"
        INSERT INTO ldap_connections (
            id, tenant_id, name, enabled, url, bind_dn, bind_password_encrypted,
            base_dn, user_search_base, user_search_filter,
            group_search_base, group_search_filter,
            user_attribute_mappings, sync_interval_minutes,
            tls_verify_cert, tls_ca_cert, connection_timeout_secs, search_timeout_secs,
            jit_provisioning_enabled, jit_default_role, jit_organization_id,
            group_sync_enabled, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, true, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, NOW(), NOW())
        "#
    )
    .bind(&connection_id)
    .bind(&current_user.tenant_id)
    .bind(&req.name)
    .bind(&req.url)
    .bind(&req.bind_dn)
    .bind(&encrypted_password)
    .bind(&req.base_dn)
    .bind(&req.user_search_base)
    .bind(req.user_search_filter.as_deref().unwrap_or("(objectClass=user)"))
    .bind(&req.group_search_base)
    .bind(req.group_search_filter.as_deref().unwrap_or("(objectClass=group)"))
    .bind(serde_json::to_value(&user_attributes).unwrap_or_default())
    .bind(req.sync_interval_minutes as i32)
    .bind(req.tls_verify_cert)
    .bind(&req.tls_ca_cert)
    .bind(req.connection_timeout_secs as i32)
    .bind(req.search_timeout_secs as i32)
    .bind(req.jit_provisioning_enabled.unwrap_or(true))
    .bind(req.jit_default_role.as_deref().unwrap_or("member"))
    .bind(req.jit_organization_id.as_deref().map(Uuid::parse_str).transpose().map_err(|_| ApiError::Validation("Invalid organization ID".to_string()))?)
    .bind(req.group_sync_enabled.unwrap_or(false))
    .bind(&current_user.user_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to create LDAP connection: {}", e);
        if e.to_string().contains("unique constraint") {
            ApiError::Conflict("A connection with this name already exists".to_string())
        } else {
            ApiError::Internal
        }
    })?;

    // Fetch the created connection
    let row = fetch_connection_row(state.db.pool(), &connection_id, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok((StatusCode::CREATED, Json(row_to_response(row))))
}

/// Get a single LDAP connection
async fn get_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<LdapConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let connection_uuid = Uuid::parse_str(&connection_id)
        .map_err(|_| ApiError::BadRequest("Invalid connection ID".to_string()))?;

    let row = fetch_connection_row(state.db.pool(), &connection_uuid, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::NotFound)?;

    Ok(Json(row_to_response(row)))
}

/// Update an LDAP connection
async fn update_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
    Json(req): Json<UpdateLdapConnectionRequest>,
) -> Result<Json<LdapConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let connection_uuid = Uuid::parse_str(&connection_id)
        .map_err(|_| ApiError::BadRequest("Invalid connection ID".to_string()))?;

    let mut builder = sqlx::QueryBuilder::new("UPDATE ldap_connections SET ");
    let mut set = builder.separated(", ");
    let mut has_updates = false;

    if let Some(name) = &req.name {
        set.push("name = ").push_bind(name);
        has_updates = true;
    }
    if let Some(url) = &req.url {
        set.push("url = ").push_bind(url);
        has_updates = true;
    }
    if let Some(bind_dn) = &req.bind_dn {
        set.push("bind_dn = ").push_bind(bind_dn);
        has_updates = true;
    }
    if let Some(bind_password) = &req.bind_password {
        let encrypted =
            encrypt_bind_password(&state, &current_user.tenant_id, bind_password).await?;
        set.push("bind_password_encrypted = ").push_bind(encrypted);
        has_updates = true;
    }
    if let Some(base_dn) = &req.base_dn {
        set.push("base_dn = ").push_bind(base_dn);
        has_updates = true;
    }
    if req.user_search_base.is_some() {
        set.push("user_search_base = ").push_bind(req.user_search_base.clone());
        has_updates = true;
    }
    if let Some(user_search_filter) = &req.user_search_filter {
        set.push("user_search_filter = ").push_bind(user_search_filter);
        has_updates = true;
    }
    if req.group_search_base.is_some() {
        set.push("group_search_base = ").push_bind(req.group_search_base.clone());
        has_updates = true;
    }
    if let Some(group_search_filter) = &req.group_search_filter {
        set.push("group_search_filter = ").push_bind(group_search_filter);
        has_updates = true;
    }
    if let Some(user_attributes) = &req.user_attributes {
        let mappings = serde_json::to_value(user_attributes).unwrap_or_default();
        set.push("user_attribute_mappings = ").push_bind(mappings);
        has_updates = true;
    }
    if let Some(sync_interval) = req.sync_interval_minutes {
        set.push("sync_interval_minutes = ").push_bind(sync_interval as i32);
        has_updates = true;
    }
    if let Some(enabled) = req.enabled {
        set.push("enabled = ").push_bind(enabled);
        has_updates = true;
    }
    if let Some(tls_verify_cert) = req.tls_verify_cert {
        set.push("tls_verify_cert = ").push_bind(tls_verify_cert);
        has_updates = true;
    }
    if req.tls_ca_cert.is_some() {
        set.push("tls_ca_cert = ").push_bind(req.tls_ca_cert.clone());
        has_updates = true;
    }
    if let Some(connection_timeout) = req.connection_timeout_secs {
        set.push("connection_timeout_secs = ").push_bind(connection_timeout as i32);
        has_updates = true;
    }
    if let Some(search_timeout) = req.search_timeout_secs {
        set.push("search_timeout_secs = ").push_bind(search_timeout as i32);
        has_updates = true;
    }
    if let Some(jit_enabled) = req.jit_provisioning_enabled {
        set.push("jit_provisioning_enabled = ").push_bind(jit_enabled);
        has_updates = true;
    }
    if let Some(jit_role) = &req.jit_default_role {
        set.push("jit_default_role = ").push_bind(jit_role);
        has_updates = true;
    }
    if req.jit_organization_id.is_some() {
        let org_id = req
            .jit_organization_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| ApiError::Validation("Invalid organization ID".to_string()))?;
        set.push("jit_organization_id = ").push_bind(org_id);
        has_updates = true;
    }
    if let Some(group_sync) = req.group_sync_enabled {
        set.push("group_sync_enabled = ").push_bind(group_sync);
        has_updates = true;
    }

    if !has_updates {
        return Err(ApiError::BadRequest("No fields to update".to_string()));
    }

    set.push("updated_at = NOW()");

    let tenant_uuid = Uuid::parse_str(&current_user.tenant_id)
        .map_err(|_| ApiError::Validation("Invalid tenant ID".to_string()))?;

    builder
        .push(" WHERE id = ")
        .push_bind(connection_uuid)
        .push(" AND tenant_id = ")
        .push_bind(tenant_uuid)
        .push(" RETURNING *");

    let row = builder
        .build_query_as::<LdapConnectionRow>()
        .fetch_one(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to update LDAP connection: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(row_to_response(row)))
}

/// Delete an LDAP connection
async fn delete_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let connection_uuid = Uuid::parse_str(&connection_id)
        .map_err(|_| ApiError::BadRequest("Invalid connection ID".to_string()))?;

    let result = sqlx::query("DELETE FROM ldap_connections WHERE id = $1 AND tenant_id = $2")
        .bind(&connection_uuid)
        .bind(&current_user.tenant_id)
        .execute(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Test LDAP connection
async fn test_connection(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<TestConnectionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let connection_uuid = Uuid::parse_str(&connection_id)
        .map_err(|_| ApiError::BadRequest("Invalid connection ID".to_string()))?;

    // Fetch connection config
    let config =
        fetch_connection_config(&state, &connection_uuid, &current_user.tenant_id)
            .await
            .map_err(|_| ApiError::NotFound)?;

    // Test the connection
    match LdapConnection::new(config) {
        Ok(ldap) => {
            match ldap.test().await {
                Ok(_) => {
                    // Update connection status
                    sqlx::query(
                        "UPDATE ldap_connections SET connection_status = 'connected', connection_tested_at = NOW() WHERE id = $1"
                    )
                    .bind(&connection_uuid)
                    .execute(state.db.pool())
                    .await
                    .ok();

                    Ok(Json(TestConnectionResponse {
                        success: true,
                        message: "Connection successful".to_string(),
                        details: None,
                    }))
                }
                Err(e) => {
                    // Update connection status
                    sqlx::query(
                        "UPDATE ldap_connections SET connection_status = 'error', connection_error = $1, connection_tested_at = NOW() WHERE id = $2"
                    )
                    .bind(e.to_string())
                    .bind(&connection_uuid)
                    .execute(state.db.pool())
                    .await
                    .ok();

                    Ok(Json(TestConnectionResponse {
                        success: false,
                        message: format!("Connection failed: {}", e),
                        details: Some(serde_json::json!({ "error": e.to_string() })),
                    }))
                }
            }
        }
        Err(e) => Ok(Json(TestConnectionResponse {
            success: false,
            message: format!("Invalid configuration: {}", e),
            details: Some(serde_json::json!({ "error": e.to_string() })),
        })),
    }
}

/// Trigger a sync for an LDAP connection
async fn trigger_sync(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
    Json(req): Json<TriggerSyncRequest>,
) -> Result<Json<TriggerSyncResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let connection_uuid = Uuid::parse_str(&connection_id)
        .map_err(|_| ApiError::BadRequest("Invalid connection ID".to_string()))?;

    let tenant_uuid = Uuid::parse_str(&current_user.tenant_id).map_err(|_| ApiError::Internal)?;

    // Check if connection exists and is enabled
    let connection_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ldap_connections WHERE id = $1 AND tenant_id = $2 AND enabled = true)"
    )
    .bind(&connection_uuid)
    .bind(&tenant_uuid)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    if !connection_exists {
        return Err(ApiError::NotFound);
    }

    // Check if sync is already running
    let is_running: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ldap_sync_logs WHERE connection_id = $1 AND status = 'running')"
    )
    .bind(&connection_uuid)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    if is_running {
        return Err(ApiError::Conflict(
            "A sync is already running for this connection".to_string(),
        ));
    }

    // Create sync job
    let sync_type = match req.sync_type.as_str() {
        "full" => SyncType::Full,
        "test" => SyncType::Test,
        _ => SyncType::Incremental,
    };

    // Start sync in background
    let pool = state.db.pool().clone();
    let conn_id = connection_uuid;
    let tenant_id = tenant_uuid;
    let triggered_by = current_user.user_id.clone();
    let tenant_keys = state.tenant_key_service.clone();

    tokio::spawn(async move {
        let mut job =
            LdapSyncJob::new(pool, conn_id, tenant_id, sync_type, triggered_by, tenant_keys);
        if let Err(e) = job.run().await {
            tracing::error!("LDAP sync failed: {}", e);
        }
    });

    // Get the sync log ID that was created
    let sync_id: Option<String> = sqlx::query_scalar(
        "SELECT id::text FROM ldap_sync_logs WHERE connection_id = $1 AND status = 'running' ORDER BY started_at DESC LIMIT 1"
    )
    .bind(&connection_uuid)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(TriggerSyncResponse {
        sync_id: sync_id.unwrap_or_else(|| "pending".to_string()),
        status: "running".to_string(),
        message: "Sync started".to_string(),
    }))
}

/// Get sync status for a connection
async fn get_sync_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
) -> Result<Json<SyncStatusResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let connection_uuid = Uuid::parse_str(&connection_id)
        .map_err(|_| ApiError::BadRequest("Invalid connection ID".to_string()))?;

    // Check if sync is running
    let current_sync: Option<(String, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT id::text, started_at, triggered_by FROM ldap_sync_logs 
         WHERE connection_id = $1 AND status = 'running' 
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(&connection_uuid)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    // Get last completed sync
    let last_sync: Option<(String, String, DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT id::text, status, started_at, completed_at FROM ldap_sync_logs 
         WHERE connection_id = $1 AND status != 'running' 
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(&connection_uuid)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let current_sync_info = current_sync.map(|(id, started, triggered)| CurrentSyncInfo {
        sync_id: id,
        started_at: started,
        triggered_by: triggered,
    });

    let last_sync_info = last_sync.map(|(id, status, started, completed)| LastSyncInfo {
        sync_id: id,
        status,
        started_at: started,
        completed_at: completed.unwrap_or(started),
    });

    // Get stats from last sync if available
    let stats: Option<SyncStatsResponse> = if let Some(ref last) = last_sync_info {
        sqlx::query_as::<_, (i32, i32, i32, i32, i32, i32, i32, i32, i32)>(
            "SELECT users_found, users_created, users_updated, users_disabled, users_failed, groups_found, groups_created, groups_updated, groups_failed 
             FROM ldap_sync_logs WHERE id = $1"
        )
        .bind(&last.sync_id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?
        .map(|(users_found, users_created, users_updated, users_disabled, users_failed, groups_found, groups_created, groups_updated, groups_failed)| {
            SyncStatsResponse {
                users_found: users_found as usize,
                users_created: users_created as usize,
                users_updated: users_updated as usize,
                users_disabled: users_disabled as usize,
                users_failed: users_failed as usize,
                groups_found: groups_found as usize,
                groups_created: groups_created as usize,
                groups_updated: groups_updated as usize,
                groups_failed: groups_failed as usize,
            }
        })
    } else {
        None
    };

    Ok(Json(SyncStatusResponse {
        connection_id,
        is_syncing: current_sync_info.is_some(),
        current_sync: current_sync_info,
        last_sync: last_sync_info,
        stats,
    }))
}

/// List sync logs for a connection
async fn list_sync_logs(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(connection_id): Path<String>,
    Query(query): Query<ListSyncLogsQuery>,
) -> Result<Json<SyncLogListResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let connection_uuid = Uuid::parse_str(&connection_id)
        .map_err(|_| ApiError::BadRequest("Invalid connection ID".to_string()))?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = (page - 1) * per_page;

    let mut sql = String::from(
        "SELECT id::text, connection_id::text, sync_type, status, started_at, completed_at,
         users_found, users_created, users_updated, users_failed, groups_found,
         duration_ms, error_message, triggered_by
         FROM ldap_sync_logs 
         WHERE connection_id = $1",
    );

    if let Some(status) = &query.status {
        sql.push_str(&format!(" AND status = '{}'", status));
    }

    sql.push_str(" ORDER BY started_at DESC LIMIT $2 OFFSET $3");

    let rows: Vec<SyncLogRow> = sqlx::query_as::<_, SyncLogRow>(&sql)
        .bind(&connection_uuid)
        .bind(per_page)
        .bind(offset)
        .fetch_all(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to list sync logs: {}", e);
            ApiError::Internal
        })?;

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ldap_sync_logs WHERE connection_id = $1")
            .bind(&connection_uuid)
            .fetch_one(state.db.pool())
            .await
            .unwrap_or(0);

    let logs: Vec<SyncLogResponse> = rows
        .into_iter()
        .map(|row| SyncLogResponse {
            id: row.id,
            connection_id: row.connection_id,
            sync_type: row.sync_type,
            status: row.status,
            started_at: row.started_at,
            completed_at: row.completed_at,
            users_found: row.users_found,
            users_created: row.users_created,
            users_updated: row.users_updated,
            users_failed: row.users_failed,
            groups_found: row.groups_found,
            duration_ms: row.duration_ms,
            error_message: row.error_message,
            triggered_by: row.triggered_by,
        })
        .collect();

    Ok(Json(SyncLogListResponse {
        data: logs,
        pagination: PaginationInfo {
            total,
            page,
            per_page,
        },
    }))
}

/// Get detailed sync log
async fn get_sync_log(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(log_id): Path<String>,
) -> Result<Json<SyncLogDetailResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Fetch log with connection verification
    #[derive(sqlx::FromRow)]
    struct SyncLogDetailRow {
        id: String,
        connection_id: String,
        sync_type: String,
        status: String,
        started_at: DateTime<Utc>,
        completed_at: Option<DateTime<Utc>>,
        users_found: i32,
        users_created: i32,
        users_updated: i32,
        users_failed: i32,
        groups_found: i32,
        duration_ms: Option<i32>,
        error_message: Option<String>,
        triggered_by: String,
        log_entries: serde_json::Value,
    }

    let row: Option<SyncLogDetailRow> = sqlx::query_as::<_, SyncLogDetailRow>(
        r#"
        SELECT 
            l.id::text, l.connection_id::text, l.sync_type, l.status, l.started_at, l.completed_at,
            l.users_found, l.users_created, l.users_updated, l.users_failed, l.groups_found,
            l.duration_ms, l.error_message, l.triggered_by,
            l.log_entries
        FROM ldap_sync_logs l
        JOIN ldap_connections c ON l.connection_id = c.id
        WHERE l.id = $1 AND c.tenant_id = $2
        "#,
    )
    .bind(&log_id)
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let row = row.ok_or(ApiError::NotFound)?;

    // Parse log entries
    let log_entries: Vec<SyncLogEntryResponse> = (&row.log_entries)
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    Some(SyncLogEntryResponse {
                        timestamp: entry.get("timestamp")?.as_str()?.parse().ok()?,
                        level: entry.get("level")?.as_str()?.to_string(),
                        operation: entry.get("operation")?.as_str()?.to_string(),
                        ldap_dn: entry
                            .get("ldap_dn")
                            .and_then(|v| v.as_str().map(String::from)),
                        user_id: entry
                            .get("user_id")
                            .and_then(|v| v.as_str().map(String::from)),
                        message: entry.get("message")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(SyncLogDetailResponse {
        log: SyncLogResponse {
            id: row.id,
            connection_id: row.connection_id,
            sync_type: row.sync_type,
            status: row.status,
            started_at: row.started_at,
            completed_at: row.completed_at,
            users_found: row.users_found,
            users_created: row.users_created,
            users_updated: row.users_updated,
            users_failed: row.users_failed,
            groups_found: row.groups_found,
            duration_ms: row.duration_ms,
            error_message: row.error_message,
            triggered_by: row.triggered_by,
        },
        log_entries,
    }))
}

/// LDAP authenticate endpoint (for JIT provisioning during login)
async fn ldap_authenticate(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<LdapAuthenticateRequest>,
) -> Result<Json<LdapAuthenticateResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let jit_auth = LdapJitAuth::new(state.db.pool().clone(), state.tenant_key_service.clone());

    match jit_auth
        .authenticate(&current_user.tenant_id, &req.email, &req.password)
        .await
    {
        Ok(Some(ldap_user)) => Ok(Json(LdapAuthenticateResponse {
            success: true,
            user: Some(LdapUserInfo {
                email: ldap_user.email,
                username: ldap_user.username,
                first_name: ldap_user.first_name,
                last_name: ldap_user.last_name,
                display_name: ldap_user.display_name,
                department: ldap_user.department,
                title: ldap_user.title,
            }),
            message: None,
        })),
        Ok(None) => Ok(Json(LdapAuthenticateResponse {
            success: false,
            user: None,
            message: Some("Authentication failed".to_string()),
        })),
        Err(e) => {
            tracing::error!("LDAP authentication error: {}", e);
            Err(ApiError::Internal)
        }
    }
}

// ============ Helper Functions ============

#[derive(sqlx::FromRow)]
struct LdapConnectionRow {
    id: Uuid,
    name: String,
    enabled: bool,
    url: String,
    bind_dn: String,
    base_dn: String,
    user_search_base: Option<String>,
    user_search_filter: String,
    group_search_base: Option<String>,
    group_search_filter: String,
    user_attribute_mappings: serde_json::Value,
    sync_interval_minutes: i32,
    last_sync_at: Option<DateTime<Utc>>,
    last_sync_status: Option<String>,
    next_sync_at: Option<DateTime<Utc>>,
    connection_status: String,
    connection_tested_at: Option<DateTime<Utc>>,
    jit_provisioning_enabled: bool,
    jit_default_role: String,
    jit_organization_id: Option<Uuid>,
    group_sync_enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct SyncLogRow {
    id: String,
    connection_id: String,
    sync_type: String,
    status: String,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    users_found: i32,
    users_created: i32,
    users_updated: i32,
    users_failed: i32,
    groups_found: i32,
    duration_ms: Option<i32>,
    error_message: Option<String>,
    triggered_by: String,
}

async fn fetch_connection_row(
    pool: &sqlx::PgPool,
    connection_id: &Uuid,
    tenant_id: &str,
) -> Result<LdapConnectionRow, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, name, enabled, url, bind_dn, base_dn, user_search_base, user_search_filter,
         group_search_base, group_search_filter, user_attribute_mappings, sync_interval_minutes,
         last_sync_at, last_sync_status, next_sync_at, connection_status, connection_tested_at,
         jit_provisioning_enabled, jit_default_role, jit_organization_id, group_sync_enabled,
         created_at, updated_at
         FROM ldap_connections 
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(connection_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;

    Ok(LdapConnectionRow {
        id: row.get("id"),
        name: row.get("name"),
        enabled: row.get("enabled"),
        url: row.get("url"),
        bind_dn: row.get("bind_dn"),
        base_dn: row.get("base_dn"),
        user_search_base: row.get("user_search_base"),
        user_search_filter: row.get("user_search_filter"),
        group_search_base: row.get("group_search_base"),
        group_search_filter: row.get("group_search_filter"),
        user_attribute_mappings: row.get("user_attribute_mappings"),
        sync_interval_minutes: row.get("sync_interval_minutes"),
        last_sync_at: row.get("last_sync_at"),
        last_sync_status: row.get("last_sync_status"),
        next_sync_at: row.get("next_sync_at"),
        connection_status: row.get("connection_status"),
        connection_tested_at: row.get("connection_tested_at"),
        jit_provisioning_enabled: row.get("jit_provisioning_enabled"),
        jit_default_role: row.get("jit_default_role"),
        jit_organization_id: row.get("jit_organization_id"),
        group_sync_enabled: row.get("group_sync_enabled"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

async fn fetch_connection_config(
    state: &AppState,
    connection_id: &Uuid,
    tenant_id: &str,
) -> Result<LdapConfig, sqlx::Error> {
    let row = sqlx::query(
        "SELECT url, bind_dn, bind_password_encrypted, base_dn, user_search_base, user_search_filter,
         user_attribute_mappings, tls_verify_cert, connection_timeout_secs, search_timeout_secs, page_size
         FROM ldap_connections 
         WHERE id = $1 AND tenant_id = $2"
    )
    .bind(connection_id)
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await?;

    let user_attributes: LdapUserAttributes = row
        .get::<serde_json::Value, _>("user_attribute_mappings")
        .pipe(|v| serde_json::from_value(v).unwrap_or_default());

    let encrypted: Option<String> = row.get("bind_password_encrypted");
    let bind_password = match encrypted {
        Some(value) => decrypt_bind_password(state, tenant_id, &value)
            .await
            .unwrap_or_default(),
        None => String::new(),
    };

    Ok(LdapConfig {
        enabled: true,
        url: row.get("url"),
        bind_dn: row.get("bind_dn"),
        bind_password,
        base_dn: row.get("base_dn"),
        user_search_base: row.get("user_search_base"),
        user_search_filter: row.get("user_search_filter"),
        group_search_base: None,
        group_search_filter: "(objectClass=group)".to_string(),
        user_attributes,
        sync_interval_minutes: 60,
        tls_verify_cert: row.get("tls_verify_cert"),
        tls_ca_cert: None,
        connection_timeout_secs: row.get::<i32, _>("connection_timeout_secs") as u64,
        search_timeout_secs: row.get::<i32, _>("search_timeout_secs") as u64,
        page_size: row.get("page_size"),
        jit_provisioning_enabled: true,
        jit_default_role: "member".to_string(),
        jit_organization_id: None,
        group_sync_enabled: false,
    })
}

fn pg_row_to_connection_row(row: sqlx::postgres::PgRow) -> LdapConnectionRow {
    use sqlx::Row;
    LdapConnectionRow {
        id: row.get("id"),
        name: row.get("name"),
        enabled: row.get("enabled"),
        url: row.get("url"),
        bind_dn: row.get("bind_dn"),
        base_dn: row.get("base_dn"),
        user_search_base: row.get("user_search_base"),
        user_search_filter: row.get("user_search_filter"),
        group_search_base: row.get("group_search_base"),
        group_search_filter: row.get("group_search_filter"),
        user_attribute_mappings: row.get("user_attribute_mappings"),
        sync_interval_minutes: row.get("sync_interval_minutes"),
        last_sync_at: row.get("last_sync_at"),
        last_sync_status: row.get("last_sync_status"),
        next_sync_at: row.get("next_sync_at"),
        connection_status: row.get("connection_status"),
        connection_tested_at: row.get("connection_tested_at"),
        jit_provisioning_enabled: row.get("jit_provisioning_enabled"),
        jit_default_role: row.get("jit_default_role"),
        jit_organization_id: row.get("jit_organization_id"),
        group_sync_enabled: row.get("group_sync_enabled"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

async fn encrypt_bind_password(
    state: &AppState,
    tenant_id: &str,
    password: &str,
) -> Result<String, ApiError> {
    let key = state
        .tenant_key_service
        .get_data_key(tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load tenant key: {}", e);
            ApiError::Internal
        })?;
    crate::security::encryption::encrypt_to_base64(&key, password.as_bytes()).map_err(|e| {
        tracing::error!("Failed to encrypt bind password: {}", e);
        ApiError::Internal
    })
}

async fn decrypt_bind_password(
    state: &AppState,
    tenant_id: &str,
    encrypted: &str,
) -> Result<String, ApiError> {
    let key = state
        .tenant_key_service
        .get_data_key(tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load tenant key: {}", e);
            ApiError::Internal
        })?;
    let bytes = crate::security::encryption::decrypt_from_base64(&key, encrypted).map_err(|e| {
        tracing::error!("Failed to decrypt bind password: {}", e);
        ApiError::Internal
    })?;
    String::from_utf8(bytes).map_err(|_| ApiError::Internal)
}

fn row_to_response(row: LdapConnectionRow) -> LdapConnectionResponse {
    let user_attrs: HashMap<String, String> = row
        .user_attribute_mappings
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    LdapConnectionResponse {
        id: row.id.to_string(),
        name: row.name,
        enabled: row.enabled,
        url: row.url,
        bind_dn: row.bind_dn,
        bind_password: None, // Never return password
        base_dn: row.base_dn,
        user_search_base: row.user_search_base,
        user_search_filter: row.user_search_filter,
        group_search_base: row.group_search_base,
        group_search_filter: row.group_search_filter,
        user_attributes: user_attrs,
        sync_interval_minutes: row.sync_interval_minutes as u32,
        last_sync_at: row.last_sync_at,
        last_sync_status: row.last_sync_status,
        next_sync_at: row.next_sync_at,
        connection_status: row.connection_status,
        connection_tested_at: row.connection_tested_at,
        jit_provisioning_enabled: row.jit_provisioning_enabled,
        jit_default_role: row.jit_default_role,
        jit_organization_id: row.jit_organization_id.map(|id| id.to_string()),
        group_sync_enabled: row.group_sync_enabled,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

// Helper trait for piped operations
trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_url_validation() {
        let valid_urls = vec![
            "ldap://localhost:389",
            "ldaps://ad.company.com:636",
            "ldap://192.168.1.1:389",
        ];

        for url in valid_urls {
            assert!(url.starts_with("ldap://") || url.starts_with("ldaps://"));
        }
    }

    #[test]
    fn test_default_attributes() {
        assert_eq!(default_attr_email(), "mail");
        assert_eq!(default_attr_username(), "sAMAccountName");
    }
}
