//! SCIM 2.0 API Handlers
//!
//! Implements the SCIM Protocol (RFC 7644) endpoints:
//! - Users: Create, Read, Update, Delete, Search
//! - Groups: Create, Read, Update, Delete, Search
//! - ServiceProviderConfig: Discovery
//! - ResourceTypes: Discovery
//! - Schemas: Discovery

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::FromRow;

use crate::routes::ApiError;
use crate::scim::{
    Filter, FilterParser, ListResponse, Meta, PatchOperation, PatchRequest, ScimAttribute,
    GroupMembership, ScimError, ScimGroup, ScimQuery, ScimResourceType, ScimSchema, ScimUser,
    ServiceProviderConfig,
};
use crate::state::AppState;

use super::auth::ScimAuthContext;
use super::schemas;

/// Query parameters for SCIM list requests
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(rename = "filter")]
    pub filter: Option<String>,
    #[serde(rename = "startIndex")]
    pub start_index: Option<i64>,
    #[serde(default = "default_count")]
    pub count: i64,
    #[serde(rename = "sortBy")]
    pub sort_by: Option<String>,
    #[serde(rename = "sortOrder")]
    pub sort_order: Option<String>,
    pub attributes: Option<String>,
    #[serde(rename = "excludedAttributes")]
    pub excluded_attributes: Option<String>,
}

fn default_count() -> i64 {
    100
}

impl From<ListQuery> for ScimQuery {
    fn from(q: ListQuery) -> Self {
        Self {
            filter: q.filter,
            start_index: q.start_index.unwrap_or(1),
            count: q.count.max(1).min(200), // Limit to 200 items per page
            sort_by: q.sort_by,
            sort_order: q.sort_order,
            attributes: q.attributes,
            excluded_attributes: q.excluded_attributes,
        }
    }
}

/// Convert ApiError to SCIM Error Response
fn scim_error_response(error: ApiError) -> (StatusCode, Json<ScimError>) {
    let (status, scim_error) = match error {
        ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, ScimError::invalid_syntax(&msg)),
        ApiError::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            ScimError::new(401, None, Some("Authentication required")),
        ),
        ApiError::Forbidden => (StatusCode::FORBIDDEN, ScimError::sensitive("Access denied")),
        ApiError::NotFound => (
            StatusCode::NOT_FOUND,
            ScimError::not_found("Resource not found"),
        ),
        ApiError::Conflict(msg) => (StatusCode::CONFLICT, ScimError::uniqueness(&msg)),
        ApiError::Validation(msg) => (StatusCode::BAD_REQUEST, ScimError::invalid_value(&msg)),
        ApiError::Internal(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ScimError::new(500, None, Some("Internal server error")),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ScimError::new(500, None, Some("Internal server error")),
        ),
    };

    (status, Json(scim_error))
}

// ============================================================================
// Service Provider Configuration
// ============================================================================

/// GET /scim/v2/ServiceProviderConfig
///
/// Returns the SCIM service provider configuration.
/// This endpoint is publicly accessible (no auth required).
pub async fn get_service_provider_config() -> impl IntoResponse {
    Json(ServiceProviderConfig::default())
}

// ============================================================================
// Resource Types
// ============================================================================

/// GET /scim/v2/ResourceTypes
///
/// Returns the list of available resource types.
pub async fn list_resource_types() -> impl IntoResponse {
    let resource_types = vec![
        ScimResourceType {
            schemas: vec![schemas::RESOURCE_TYPE.to_string()],
            id: "User".to_string(),
            name: "User".to_string(),
            endpoint: "/scim/v2/Users".to_string(),
            description: "User Account".to_string(),
            schema: Some(schemas::USER.to_string()),
            schema_extensions: Some(vec![super::SchemaExtension {
                schema: schemas::ENTERPRISE_USER.to_string(),
                required: false,
            }]),
        },
        ScimResourceType {
            schemas: vec![schemas::RESOURCE_TYPE.to_string()],
            id: "Group".to_string(),
            name: "Group".to_string(),
            endpoint: "/scim/v2/Groups".to_string(),
            description: "Group".to_string(),
            schema: Some(schemas::GROUP.to_string()),
            schema_extensions: None,
        },
    ];

    Json(json!({
        "schemas": [schemas::LIST_RESPONSE],
        "totalResults": resource_types.len(),
        "Resources": resource_types
    }))
}

/// GET /scim/v2/ResourceTypes/:id
///
/// Returns a specific resource type by ID.
pub async fn get_resource_type(Path(id): Path<String>) -> impl IntoResponse {
    match id.as_str() {
        "User" => {
            let resource_type = ScimResourceType {
                schemas: vec![schemas::RESOURCE_TYPE.to_string()],
                id: "User".to_string(),
                name: "User".to_string(),
                endpoint: "/scim/v2/Users".to_string(),
                description: "User Account".to_string(),
                schema: Some(schemas::USER.to_string()),
                schema_extensions: Some(vec![super::SchemaExtension {
                    schema: schemas::ENTERPRISE_USER.to_string(),
                    required: false,
                }]),
            };
            Ok(Json(serde_json::to_value(resource_type).unwrap()))
        }
        "Group" => {
            let resource_type = ScimResourceType {
                schemas: vec![schemas::RESOURCE_TYPE.to_string()],
                id: "Group".to_string(),
                name: "Group".to_string(),
                endpoint: "/scim/v2/Groups".to_string(),
                description: "Group".to_string(),
                schema: Some(schemas::GROUP.to_string()),
                schema_extensions: None,
            };
            Ok(Json(serde_json::to_value(resource_type).unwrap()))
        }
        _ => Err(scim_error_response(ApiError::NotFound)),
    }
}

// ============================================================================
// Schemas
// ============================================================================

/// GET /scim/v2/Schemas
///
/// Returns the list of supported schemas.
pub async fn list_schemas() -> impl IntoResponse {
    let schemas_list = vec![
        get_user_schema(),
        get_group_schema(),
        get_enterprise_user_schema(),
        get_service_provider_config_schema(),
        get_resource_type_schema(),
        get_schema_definition(),
    ];

    Json(json!({
        "schemas": [schemas::LIST_RESPONSE],
        "totalResults": schemas_list.len(),
        "Resources": schemas_list
    }))
}

/// GET /scim/v2/Schemas/:id
///
/// Returns a specific schema by ID.
pub async fn get_schema(Path(id): Path<String>) -> impl IntoResponse {
    let schema = match id.as_str() {
        schemas::USER => Some(get_user_schema()),
        schemas::GROUP => Some(get_group_schema()),
        schemas::ENTERPRISE_USER => Some(get_enterprise_user_schema()),
        schemas::SERVICE_PROVIDER_CONFIG => Some(get_service_provider_config_schema()),
        schemas::RESOURCE_TYPE => Some(get_resource_type_schema()),
        schemas::SCHEMA => Some(get_schema_definition()),
        _ => None,
    };

    match schema {
        Some(s) => Ok(Json(serde_json::to_value(s).unwrap())),
        None => Err(scim_error_response(ApiError::NotFound)),
    }
}

fn get_user_schema() -> ScimSchema {
    ScimSchema {
        schemas: vec![schemas::SCHEMA.to_string()],
        id: schemas::USER.to_string(),
        name: "User".to_string(),
        description: "User Account".to_string(),
        attributes: Some(vec![
            ScimAttribute {
                name: "userName".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                description: "Unique identifier for the User".to_string(),
                required: true,
                case_exact: Some(false),
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: Some("server".to_string()),
                canonical_values: None,
                sub_attributes: None,
            },
            ScimAttribute {
                name: "name".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: false,
                description: "The components of the user's name".to_string(),
                required: false,
                case_exact: None,
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: Some(vec![
                    ScimAttribute {
                        name: "formatted".to_string(),
                        attr_type: "string".to_string(),
                        multi_valued: false,
                        description: "The full name".to_string(),
                        required: false,
                        case_exact: Some(false),
                        mutability: Some("readWrite".to_string()),
                        returned: Some("default".to_string()),
                        uniqueness: None,
                        canonical_values: None,
                        sub_attributes: None,
                    },
                    ScimAttribute {
                        name: "familyName".to_string(),
                        attr_type: "string".to_string(),
                        multi_valued: false,
                        description: "The family name".to_string(),
                        required: false,
                        case_exact: Some(false),
                        mutability: Some("readWrite".to_string()),
                        returned: Some("default".to_string()),
                        uniqueness: None,
                        canonical_values: None,
                        sub_attributes: None,
                    },
                    ScimAttribute {
                        name: "givenName".to_string(),
                        attr_type: "string".to_string(),
                        multi_valued: false,
                        description: "The given name".to_string(),
                        required: false,
                        case_exact: Some(false),
                        mutability: Some("readWrite".to_string()),
                        returned: Some("default".to_string()),
                        uniqueness: None,
                        canonical_values: None,
                        sub_attributes: None,
                    },
                ]),
            },
            ScimAttribute {
                name: "displayName".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                description: "The name of the User".to_string(),
                required: false,
                case_exact: Some(false),
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: None,
            },
            ScimAttribute {
                name: "active".to_string(),
                attr_type: "boolean".to_string(),
                multi_valued: false,
                description: "A Boolean value indicating the User's administrative status"
                    .to_string(),
                required: false,
                case_exact: None,
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: None,
            },
            ScimAttribute {
                name: "emails".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: true,
                description: "Email addresses for the user".to_string(),
                required: false,
                case_exact: None,
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: Some(vec![
                    ScimAttribute {
                        name: "value".to_string(),
                        attr_type: "string".to_string(),
                        multi_valued: false,
                        description: "Email address value".to_string(),
                        required: false,
                        case_exact: Some(false),
                        mutability: Some("readWrite".to_string()),
                        returned: Some("default".to_string()),
                        uniqueness: None,
                        canonical_values: None,
                        sub_attributes: None,
                    },
                    ScimAttribute {
                        name: "primary".to_string(),
                        attr_type: "boolean".to_string(),
                        multi_valued: false,
                        description: "Whether this is the primary email".to_string(),
                        required: false,
                        case_exact: None,
                        mutability: Some("readWrite".to_string()),
                        returned: Some("default".to_string()),
                        uniqueness: None,
                        canonical_values: None,
                        sub_attributes: None,
                    },
                ]),
            },
            ScimAttribute {
                name: "groups".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: true,
                description: "A list of groups to which the user belongs".to_string(),
                required: false,
                case_exact: None,
                mutability: Some("readOnly".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: Some(vec![
                    ScimAttribute {
                        name: "value".to_string(),
                        attr_type: "string".to_string(),
                        multi_valued: false,
                        description: "The identifier of the User's group".to_string(),
                        required: false,
                        case_exact: None,
                        mutability: Some("readOnly".to_string()),
                        returned: Some("default".to_string()),
                        uniqueness: None,
                        canonical_values: None,
                        sub_attributes: None,
                    },
                    ScimAttribute {
                        name: "$ref".to_string(),
                        attr_type: "reference".to_string(),
                        multi_valued: false,
                        description: "The URI of the corresponding Group resource".to_string(),
                        required: false,
                        case_exact: None,
                        mutability: Some("readOnly".to_string()),
                        returned: Some("default".to_string()),
                        uniqueness: None,
                        canonical_values: None,
                        sub_attributes: None,
                    },
                ]),
            },
        ]),
    }
}

fn get_group_schema() -> ScimSchema {
    ScimSchema {
        schemas: vec![schemas::SCHEMA.to_string()],
        id: schemas::GROUP.to_string(),
        name: "Group".to_string(),
        description: "Group".to_string(),
        attributes: Some(vec![
            ScimAttribute {
                name: "displayName".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                description: "A human-readable name for the Group".to_string(),
                required: true,
                case_exact: Some(false),
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: Some("server".to_string()),
                canonical_values: None,
                sub_attributes: None,
            },
            ScimAttribute {
                name: "members".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: true,
                description: "A list of members of the Group".to_string(),
                required: false,
                case_exact: None,
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: Some(vec![
                    ScimAttribute {
                        name: "value".to_string(),
                        attr_type: "string".to_string(),
                        multi_valued: false,
                        description: "Identifier of the member".to_string(),
                        required: false,
                        case_exact: None,
                        mutability: Some("immutable".to_string()),
                        returned: Some("default".to_string()),
                        uniqueness: None,
                        canonical_values: None,
                        sub_attributes: None,
                    },
                    ScimAttribute {
                        name: "$ref".to_string(),
                        attr_type: "reference".to_string(),
                        multi_valued: false,
                        description: "The URI corresponding to a SCIM resource".to_string(),
                        required: false,
                        case_exact: None,
                        mutability: Some("immutable".to_string()),
                        returned: Some("default".to_string()),
                        uniqueness: None,
                        canonical_values: None,
                        sub_attributes: None,
                    },
                    ScimAttribute {
                        name: "type".to_string(),
                        attr_type: "string".to_string(),
                        multi_valued: false,
                        description: "A label indicating the type of resource".to_string(),
                        required: false,
                        case_exact: None,
                        mutability: Some("immutable".to_string()),
                        returned: Some("default".to_string()),
                        uniqueness: None,
                        canonical_values: Some(vec!["User".to_string(), "Group".to_string()]),
                        sub_attributes: None,
                    },
                ]),
            },
        ]),
    }
}

fn get_enterprise_user_schema() -> ScimSchema {
    ScimSchema {
        schemas: vec![schemas::SCHEMA.to_string()],
        id: schemas::ENTERPRISE_USER.to_string(),
        name: "EnterpriseUser".to_string(),
        description: "Enterprise User".to_string(),
        attributes: Some(vec![
            ScimAttribute {
                name: "employeeNumber".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                description: "Numeric or alphanumeric identifier assigned to a person".to_string(),
                required: false,
                case_exact: Some(false),
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: None,
            },
            ScimAttribute {
                name: "costCenter".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                description: "Identifies the name of a cost center".to_string(),
                required: false,
                case_exact: Some(false),
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: None,
            },
            ScimAttribute {
                name: "organization".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                description: "Identifies the name of an organization".to_string(),
                required: false,
                case_exact: Some(false),
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: None,
            },
            ScimAttribute {
                name: "department".to_string(),
                attr_type: "string".to_string(),
                multi_valued: false,
                description: "Identifies the name of a department".to_string(),
                required: false,
                case_exact: Some(false),
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: None,
            },
            ScimAttribute {
                name: "manager".to_string(),
                attr_type: "complex".to_string(),
                multi_valued: false,
                description: "The User's manager".to_string(),
                required: false,
                case_exact: None,
                mutability: Some("readWrite".to_string()),
                returned: Some("default".to_string()),
                uniqueness: None,
                canonical_values: None,
                sub_attributes: Some(vec![ScimAttribute {
                    name: "value".to_string(),
                    attr_type: "string".to_string(),
                    multi_valued: false,
                    description: "The ID of the SCIM resource representing the manager".to_string(),
                    required: false,
                    case_exact: None,
                    mutability: Some("readWrite".to_string()),
                    returned: Some("default".to_string()),
                    uniqueness: None,
                    canonical_values: None,
                    sub_attributes: None,
                }]),
            },
        ]),
    }
}

fn get_service_provider_config_schema() -> ScimSchema {
    ScimSchema {
        schemas: vec![schemas::SCHEMA.to_string()],
        id: schemas::SERVICE_PROVIDER_CONFIG.to_string(),
        name: "ServiceProviderConfig".to_string(),
        description: "Service Provider Configuration".to_string(),
        attributes: None,
    }
}

fn get_resource_type_schema() -> ScimSchema {
    ScimSchema {
        schemas: vec![schemas::SCHEMA.to_string()],
        id: schemas::RESOURCE_TYPE.to_string(),
        name: "ResourceType".to_string(),
        description: "Specifies the schema that describes a SCIM resource type".to_string(),
        attributes: None,
    }
}

fn get_schema_definition() -> ScimSchema {
    ScimSchema {
        schemas: vec![schemas::SCHEMA.to_string()],
        id: schemas::SCHEMA.to_string(),
        name: "Schema".to_string(),
        description: "Specifies the schema that describes a SCIM schema".to_string(),
        attributes: None,
    }
}

// ============================================================================
// Users
// ============================================================================

/// Database row for SCIM users
#[derive(Debug, FromRow)]
struct ScimUserRow {
    id: String,
    user_name: String,
    active: bool,
    external_id: Option<String>,
    data: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// GET /scim/v2/Users
///
/// Search/Query users with optional filtering.
pub async fn list_users(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    let scim_query: ScimQuery = query.into();

    // Parse filter if provided
    let filter = if let Some(ref filter_str) = scim_query.filter {
        match FilterParser::parse(filter_str) {
            Ok(f) => Some(f),
            Err(e) => return Err((StatusCode::BAD_REQUEST, Json(e))),
        }
    } else {
        None
    };

    // Build the query
    let (sql, params) = build_user_query(&auth_ctx.tenant_id, &scim_query, filter.as_ref());

    // Execute count query for total results
    let count_sql = format!(
        "SELECT COUNT(*) FROM ({}) AS count_query",
        sql.replace("ORDER BY ", "ORDER BY ")
            .split(" ORDER BY ")
            .next()
            .unwrap_or(&sql)
    );

    let total_result = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(&auth_ctx.tenant_id)
        .fetch_one(state.db.pool())
        .await;

    let total_results = match total_result {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to count users: {}", e);
            return Err(scim_error_response(ApiError::internal()));
        }
    };

    // Execute main query with pagination
    let offset = scim_query.start_index - 1;
    let limit = scim_query.count;

    let rows = match sqlx::query_as::<_, ScimUserRow>(&format!(
        "{} LIMIT {} OFFSET {}",
        sql, limit, offset
    ))
    .bind(&auth_ctx.tenant_id)
    .fetch_all(state.db.pool())
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("Failed to fetch users: {}", e);
            return Err(scim_error_response(ApiError::internal()));
        }
    };

    let mut users: Vec<ScimUser> = Vec::with_capacity(rows.len());
    for row in rows {
        users.push(row_to_scim_user(&state, row, &auth_ctx.tenant_id).await);
    }

    let users_len = users.len() as i64;
    let response = ListResponse::new(
        users,
        total_results,
        scim_query.start_index,
        users_len,
    );

    Ok(Json(response))
}

/// POST /scim/v2/Users
///
/// Create a new user.
pub async fn create_user(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Json(mut user): Json<ScimUser>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    // Validate required fields
    if user.user_name.is_empty() {
        return Err(scim_error_response(ApiError::Validation(
            "userName is required".to_string(),
        )));
    }

    // Check for duplicate userName
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT id FROM scim_users WHERE tenant_id = $1 AND user_name = $2")
            .bind(&auth_ctx.tenant_id)
            .bind(&user.user_name)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|_| scim_error_response(ApiError::internal()))?;

    if existing.is_some() {
        return Err(scim_error_response(ApiError::Conflict(format!(
            "User with userName '{}' already exists",
            user.user_name
        ))));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    // Build the data JSON
    let data = serde_json::json!({
        "name": user.name,
        "displayName": user.display_name,
        "nickName": user.nick_name,
        "profileUrl": user.profile_url,
        "title": user.title,
        "userType": user.user_type,
        "preferredLanguage": user.preferred_language,
        "locale": user.locale,
        "timezone": user.timezone,
        "emails": user.emails,
        "phoneNumbers": user.phone_numbers,
        "addresses": user.addresses,
        "photos": user.photos,
        "ims": user.ims,
        "entitlements": user.entitlements,
        "roles": user.roles,
        "x509Certificates": user.x509_certificates,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": user.enterprise_user,
    });

    // Insert into database
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO scim_users (id, tenant_id, user_name, active, external_id, data, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
        "#
    )
    .bind(&id)
    .bind(&auth_ctx.tenant_id)
    .bind(&user.user_name)
    .bind(user.active)
    .bind(&user.external_id)
    .bind(&data)
    .bind(&now)
    .execute(state.db.pool())
    .await {
        tracing::error!("Failed to create user: {}", e);
        return Err(scim_error_response(ApiError::internal()));
    }

    // Also create a corresponding vault user if not exists
    create_vault_user_from_scim(&state, &auth_ctx.tenant_id, &user, &id)
        .await
        .ok();

    // Build response
    user.id = id.clone();
    user.schemas = vec![schemas::USER.to_string()];
    user.meta = Some(Meta {
        resource_type: "User".to_string(),
        created: Some(now),
        last_modified: Some(now),
        location: Some(format!("/scim/v2/Users/{}", id)),
        version: Some(format!("W/\"{}\"", now.timestamp())),
    });

    // Log the creation
    log_scim_audit(&state, &auth_ctx, "create", "User", &id, true, None).await;

    Ok((StatusCode::CREATED, Json(user)))
}

/// GET /scim/v2/Users/:id
///
/// Get a user by ID.
pub async fn get_user(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    let row = match sqlx::query_as::<_, ScimUserRow>(
        "SELECT id, user_name, active, external_id, data, created_at, updated_at FROM scim_users WHERE tenant_id = $1 AND id = $2"
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .fetch_optional(state.db.pool())
    .await {
        Ok(Some(row)) => row,
        Ok(None) => return Err(scim_error_response(ApiError::NotFound)),
        Err(e) => {
            tracing::error!("Failed to fetch user: {}", e);
            return Err(scim_error_response(ApiError::internal()));
        }
    };

    let user = row_to_scim_user(&state, row, &auth_ctx.tenant_id).await;
    Ok(Json(user))
}

/// PUT /scim/v2/Users/:id
///
/// Full update (replace) of a user.
pub async fn update_user(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Path(id): Path<String>,
    Json(user): Json<ScimUser>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    // Check if user exists
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT id FROM scim_users WHERE tenant_id = $1 AND id = $2")
            .bind(&auth_ctx.tenant_id)
            .bind(&id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|_| scim_error_response(ApiError::internal()))?;

    if existing.is_none() {
        return Err(scim_error_response(ApiError::NotFound));
    }

    let now = Utc::now();

    // Build the data JSON
    let data = serde_json::json!({
        "name": user.name,
        "displayName": user.display_name,
        "nickName": user.nick_name,
        "profileUrl": user.profile_url,
        "title": user.title,
        "userType": user.user_type,
        "preferredLanguage": user.preferred_language,
        "locale": user.locale,
        "timezone": user.timezone,
        "emails": user.emails,
        "phoneNumbers": user.phone_numbers,
        "addresses": user.addresses,
        "photos": user.photos,
        "ims": user.ims,
        "entitlements": user.entitlements,
        "roles": user.roles,
        "x509Certificates": user.x509_certificates,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": user.enterprise_user,
    });

    // Update database
    if let Err(e) = sqlx::query(
        r#"
        UPDATE scim_users
        SET user_name = $3, active = $4, external_id = $5, data = $6, updated_at = $7
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .bind(&user.user_name)
    .bind(user.active)
    .bind(&user.external_id)
    .bind(&data)
    .bind(&now)
    .execute(state.db.pool())
    .await
    {
        tracing::error!("Failed to update user: {}", e);
        return Err(scim_error_response(ApiError::internal()));
    }

    // Update vault user
    update_vault_user_from_scim(&state, &auth_ctx.tenant_id, &user, &id)
        .await
        .ok();

    // Fetch and return updated user
    let row = sqlx::query_as::<_, ScimUserRow>(
        "SELECT id, user_name, active, external_id, data, created_at, updated_at FROM scim_users WHERE tenant_id = $1 AND id = $2"
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| scim_error_response(ApiError::internal()))?;

    let mut updated_user = row_to_scim_user(&state, row, &auth_ctx.tenant_id).await;
    updated_user.password = None; // Never return password

    // Log the update
    log_scim_audit(&state, &auth_ctx, "update", "User", &id, true, None).await;

    Ok(Json(updated_user))
}

/// PATCH /scim/v2/Users/:id
///
/// Partial update of a user.
pub async fn patch_user(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Path(id): Path<String>,
    Json(patch): Json<PatchRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    // Validate schema
    if !patch.schemas.contains(&schemas::PATCH_OP.to_string()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ScimError::invalid_syntax(
                "Missing required schema: urn:ietf:params:scim:api:messages:2.0:PatchOp",
            )),
        ));
    }

    // Fetch current user
    let row = match sqlx::query_as::<_, ScimUserRow>(
        "SELECT id, user_name, active, external_id, data, created_at, updated_at FROM scim_users WHERE tenant_id = $1 AND id = $2"
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .fetch_optional(state.db.pool())
    .await {
        Ok(Some(row)) => row,
        Ok(None) => return Err(scim_error_response(ApiError::NotFound)),
        Err(e) => {
            tracing::error!("Failed to fetch user for patch: {}", e);
            return Err(scim_error_response(ApiError::internal()));
        }
    };

    let mut user = row_to_scim_user(&state, row, &auth_ctx.tenant_id).await;
    let now = Utc::now();

    // Apply operations
    for op in &patch.operations {
        apply_patch_operation(&mut user, op)?;
    }

    // Build the data JSON
    let data = serde_json::json!({
        "name": user.name,
        "displayName": user.display_name,
        "nickName": user.nick_name,
        "profileUrl": user.profile_url,
        "title": user.title,
        "userType": user.user_type,
        "preferredLanguage": user.preferred_language,
        "locale": user.locale,
        "timezone": user.timezone,
        "emails": user.emails,
        "phoneNumbers": user.phone_numbers,
        "addresses": user.addresses,
        "photos": user.photos,
        "ims": user.ims,
        "entitlements": user.entitlements,
        "roles": user.roles,
        "x509Certificates": user.x509_certificates,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": user.enterprise_user,
    });

    // Update database
    if let Err(e) = sqlx::query(
        r#"
        UPDATE scim_users
        SET user_name = $3, active = $4, external_id = $5, data = $6, updated_at = $7
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .bind(&user.user_name)
    .bind(user.active)
    .bind(&user.external_id)
    .bind(&data)
    .bind(&now)
    .execute(state.db.pool())
    .await
    {
        tracing::error!("Failed to patch user: {}", e);
        return Err(scim_error_response(ApiError::internal()));
    }

    // Update vault user status if changed
    update_vault_user_status(&state, &auth_ctx.tenant_id, &id, user.active)
        .await
        .ok();

    // Fetch and return updated user
    let row = sqlx::query_as::<_, ScimUserRow>(
        "SELECT id, user_name, active, external_id, data, created_at, updated_at FROM scim_users WHERE tenant_id = $1 AND id = $2"
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| scim_error_response(ApiError::internal()))?;

    let updated_user = row_to_scim_user(&state, row, &auth_ctx.tenant_id).await;

    // Log the patch
    log_scim_audit(&state, &auth_ctx, "patch", "User", &id, true, None).await;

    Ok(Json(updated_user))
}

/// DELETE /scim/v2/Users/:id
///
/// Delete a user.
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    let result = sqlx::query("DELETE FROM scim_users WHERE tenant_id = $1 AND id = $2")
        .bind(&auth_ctx.tenant_id)
        .bind(&id)
        .execute(state.db.pool())
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            // Deactivate vault user instead of deleting
            deactivate_vault_user(&state, &auth_ctx.tenant_id, &id)
                .await
                .ok();

            // Log the deletion
            log_scim_audit(&state, &auth_ctx, "delete", "User", &id, true, None).await;

            Ok(StatusCode::NO_CONTENT)
        }
        Ok(_) => Err(scim_error_response(ApiError::NotFound)),
        Err(e) => {
            tracing::error!("Failed to delete user: {}", e);
            Err(scim_error_response(ApiError::internal()))
        }
    }
}

// ============================================================================
// Groups
// ============================================================================

/// Database row for SCIM groups
#[derive(Debug, FromRow)]
struct ScimGroupRow {
    id: String,
    display_name: String,
    external_id: Option<String>,
    data: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// GET /scim/v2/Groups
///
/// Search/Query groups with optional filtering.
pub async fn list_groups(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    let scim_query: ScimQuery = query.into();

    // Get total count
    let total_results: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM scim_groups WHERE tenant_id = $1")
            .bind(&auth_ctx.tenant_id)
            .fetch_one(state.db.pool())
            .await
            .map_err(|_| scim_error_response(ApiError::internal()))?;

    // Execute query with pagination
    let offset = scim_query.start_index - 1;
    let limit = scim_query.count;

    let rows = sqlx::query_as::<_, ScimGroupRow>(
        "SELECT id, display_name, external_id, data, created_at, updated_at FROM scim_groups WHERE tenant_id = $1 ORDER BY display_name LIMIT $2 OFFSET $3"
    )
    .bind(&auth_ctx.tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| scim_error_response(ApiError::internal()))?;

    let groups: Vec<ScimGroup> = rows
        .into_iter()
        .map(|row| row_to_scim_group(row, &auth_ctx.tenant_id))
        .collect();

    let groups_len = groups.len() as i64;
    let response = ListResponse::new(
        groups,
        total_results,
        scim_query.start_index,
        groups_len,
    );

    Ok(Json(response))
}

/// POST /scim/v2/Groups
///
/// Create a new group.
pub async fn create_group(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Json(mut group): Json<ScimGroup>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    // Validate required fields
    if group.display_name.is_empty() {
        return Err(scim_error_response(ApiError::Validation(
            "displayName is required".to_string(),
        )));
    }

    // Check for duplicate displayName
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT id FROM scim_groups WHERE tenant_id = $1 AND display_name = $2")
            .bind(&auth_ctx.tenant_id)
            .bind(&group.display_name)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|_| scim_error_response(ApiError::internal()))?;

    if existing.is_some() {
        return Err(scim_error_response(ApiError::Conflict(format!(
            "Group with displayName '{}' already exists",
            group.display_name
        ))));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    // Build members data
    let members = group.members.clone().unwrap_or_default();

    // Insert into database
    let data = serde_json::json!({
        "members": members,
    });

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO scim_groups (id, tenant_id, display_name, external_id, data, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $6)
        "#
    )
    .bind(&id)
    .bind(&auth_ctx.tenant_id)
    .bind(&group.display_name)
    .bind(&group.external_id)
    .bind(&data)
    .bind(&now)
    .execute(state.db.pool())
    .await {
        tracing::error!("Failed to create group: {}", e);
        return Err(scim_error_response(ApiError::internal()));
    }

    // Sync members
    sync_group_members(&state, &auth_ctx.tenant_id, &id, &members)
        .await
        .ok();

    // Build response
    group.id = id.clone();
    group.schemas = vec![schemas::GROUP.to_string()];
    group.meta = Some(Meta {
        resource_type: "Group".to_string(),
        created: Some(now),
        last_modified: Some(now),
        location: Some(format!("/scim/v2/Groups/{}", id)),
        version: Some(format!("W/\"{}\"", now.timestamp())),
    });

    // Log the creation
    log_scim_audit(&state, &auth_ctx, "create", "Group", &id, true, None).await;

    Ok((StatusCode::CREATED, Json(group)))
}

/// GET /scim/v2/Groups/:id
///
/// Get a group by ID.
pub async fn get_group(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    let row = match sqlx::query_as::<_, ScimGroupRow>(
        "SELECT id, display_name, external_id, data, created_at, updated_at FROM scim_groups WHERE tenant_id = $1 AND id = $2"
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .fetch_optional(state.db.pool())
    .await {
        Ok(Some(row)) => row,
        Ok(None) => return Err(scim_error_response(ApiError::NotFound)),
        Err(e) => {
            tracing::error!("Failed to fetch group: {}", e);
            return Err(scim_error_response(ApiError::internal()));
        }
    };

    let group = row_to_scim_group(row, &auth_ctx.tenant_id);
    Ok(Json(group))
}

/// PUT /scim/v2/Groups/:id
///
/// Full update (replace) of a group.
pub async fn update_group(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Path(id): Path<String>,
    Json(group): Json<ScimGroup>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    // Check if group exists
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT id FROM scim_groups WHERE tenant_id = $1 AND id = $2")
            .bind(&auth_ctx.tenant_id)
            .bind(&id)
            .fetch_optional(state.db.pool())
            .await
            .map_err(|_| scim_error_response(ApiError::internal()))?;

    if existing.is_none() {
        return Err(scim_error_response(ApiError::NotFound));
    }

    let now = Utc::now();
    let members = group.members.clone().unwrap_or_default();

    // Build data
    let data = serde_json::json!({
        "members": members,
    });

    // Update database
    if let Err(e) = sqlx::query(
        r#"
        UPDATE scim_groups
        SET display_name = $3, external_id = $4, data = $5, updated_at = $6
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .bind(&group.display_name)
    .bind(&group.external_id)
    .bind(&data)
    .bind(&now)
    .execute(state.db.pool())
    .await
    {
        tracing::error!("Failed to update group: {}", e);
        return Err(scim_error_response(ApiError::internal()));
    }

    // Sync members
    sync_group_members(&state, &auth_ctx.tenant_id, &id, &members)
        .await
        .ok();

    // Fetch and return updated group
    let row = sqlx::query_as::<_, ScimGroupRow>(
        "SELECT id, display_name, external_id, data, created_at, updated_at FROM scim_groups WHERE tenant_id = $1 AND id = $2"
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| scim_error_response(ApiError::internal()))?;

    let updated_group = row_to_scim_group(row, &auth_ctx.tenant_id);

    // Log the update
    log_scim_audit(&state, &auth_ctx, "update", "Group", &id, true, None).await;

    Ok(Json(updated_group))
}

/// PATCH /scim/v2/Groups/:id
///
/// Partial update of a group.
pub async fn patch_group(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Path(id): Path<String>,
    Json(patch): Json<PatchRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    // Validate schema
    if !patch.schemas.contains(&schemas::PATCH_OP.to_string()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ScimError::invalid_syntax(
                "Missing required schema: urn:ietf:params:scim:api:messages:2.0:PatchOp",
            )),
        ));
    }

    // Fetch current group
    let row = match sqlx::query_as::<_, ScimGroupRow>(
        "SELECT id, display_name, external_id, data, created_at, updated_at FROM scim_groups WHERE tenant_id = $1 AND id = $2"
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .fetch_optional(state.db.pool())
    .await {
        Ok(Some(row)) => row,
        Ok(None) => return Err(scim_error_response(ApiError::NotFound)),
        Err(e) => {
            tracing::error!("Failed to fetch group for patch: {}", e);
            return Err(scim_error_response(ApiError::internal()));
        }
    };

    let mut group = row_to_scim_group(row, &auth_ctx.tenant_id);
    let now = Utc::now();

    // Apply operations
    for op in &patch.operations {
        apply_group_patch_operation(&mut group, op, &state, &auth_ctx.tenant_id, &id).await?;
    }

    // Build data
    let members = group.members.clone().unwrap_or_default();
    let data = serde_json::json!({
        "members": members,
    });

    // Update database
    if let Err(e) = sqlx::query(
        r#"
        UPDATE scim_groups
        SET display_name = $3, external_id = $4, data = $5, updated_at = $6
        WHERE tenant_id = $1 AND id = $2
        "#,
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .bind(&group.display_name)
    .bind(&group.external_id)
    .bind(&data)
    .bind(&now)
    .execute(state.db.pool())
    .await
    {
        tracing::error!("Failed to patch group: {}", e);
        return Err(scim_error_response(ApiError::internal()));
    }

    // Fetch and return updated group
    let row = sqlx::query_as::<_, ScimGroupRow>(
        "SELECT id, display_name, external_id, data, created_at, updated_at FROM scim_groups WHERE tenant_id = $1 AND id = $2"
    )
    .bind(&auth_ctx.tenant_id)
    .bind(&id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| scim_error_response(ApiError::internal()))?;

    let updated_group = row_to_scim_group(row, &auth_ctx.tenant_id);

    // Log the patch
    log_scim_audit(&state, &auth_ctx, "patch", "Group", &id, true, None).await;

    Ok(Json(updated_group))
}

/// DELETE /scim/v2/Groups/:id
///
/// Delete a group.
pub async fn delete_group(
    State(state): State<AppState>,
    Extension(auth_ctx): Extension<ScimAuthContext>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ScimError>)> {
    let result = sqlx::query("DELETE FROM scim_groups WHERE tenant_id = $1 AND id = $2")
        .bind(&auth_ctx.tenant_id)
        .bind(&id)
        .execute(state.db.pool())
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            // Log the deletion
            log_scim_audit(&state, &auth_ctx, "delete", "Group", &id, true, None).await;

            Ok(StatusCode::NO_CONTENT)
        }
        Ok(_) => Err(scim_error_response(ApiError::NotFound)),
        Err(e) => {
            tracing::error!("Failed to delete group: {}", e);
            Err(scim_error_response(ApiError::internal()))
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn row_to_scim_user(state: &AppState, row: ScimUserRow, tenant_id: &str) -> ScimUser {
    let data = row.data;
    let groups = fetch_user_group_memberships(state, tenant_id, &row.id).await;

    ScimUser {
        schemas: vec![schemas::USER.to_string()],
        id: row.id.clone(),
        external_id: row.external_id,
        meta: Some(Meta {
            resource_type: "User".to_string(),
            created: Some(row.created_at),
            last_modified: Some(row.updated_at),
            location: Some(format!("/scim/v2/Users/{}", row.id)),
            version: Some(format!("W/\"{}\"", row.updated_at.timestamp())),
        }),
        user_name: row.user_name,
        name: serde_json::from_value(data.get("name").cloned().unwrap_or(serde_json::Value::Null))
            .ok(),
        display_name: data
            .get("displayName")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        nick_name: data
            .get("nickName")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        profile_url: data
            .get("profileUrl")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        title: data
            .get("title")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        user_type: data
            .get("userType")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        preferred_language: data
            .get("preferredLanguage")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        locale: data
            .get("locale")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        timezone: data
            .get("timezone")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        active: row.active,
        password: None, // Never return password
        emails: serde_json::from_value(
            data.get("emails")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .ok(),
        phone_numbers: serde_json::from_value(
            data.get("phoneNumbers")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .ok(),
        ims: serde_json::from_value(data.get("ims").cloned().unwrap_or(serde_json::Value::Null))
            .ok(),
        photos: serde_json::from_value(
            data.get("photos")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .ok(),
        addresses: serde_json::from_value(
            data.get("addresses")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .ok(),
        groups,
        entitlements: serde_json::from_value(
            data.get("entitlements")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .ok(),
        roles: serde_json::from_value(
            data.get("roles")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .ok(),
        x509_certificates: serde_json::from_value(
            data.get("x509Certificates")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .ok(),
        enterprise_user: serde_json::from_value(
            data.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .ok(),
    }
}

async fn fetch_user_group_memberships(
    state: &AppState,
    tenant_id: &str,
    scim_user_id: &str,
) -> Option<Vec<GroupMembership>> {
    let rows = sqlx::query_as::<_, (String, Option<String>)>(
        r#"
        SELECT gm.external_id, g.display_name
        FROM scim_mappings um
        JOIN organization_members om
          ON om.tenant_id = um.tenant_id
         AND om.user_id = um.local_id
        JOIN scim_mappings gm
          ON gm.tenant_id = um.tenant_id
         AND gm.resource_type = 'Group'
         AND gm.local_id = om.organization_id
        LEFT JOIN scim_groups g
          ON g.tenant_id = gm.tenant_id
         AND g.id = gm.external_id
        WHERE um.tenant_id = $1
          AND um.resource_type = 'User'
          AND um.external_id = $2
        ORDER BY g.display_name ASC
        "#,
    )
    .bind(tenant_id)
    .bind(scim_user_id)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    if rows.is_empty() {
        return None;
    }

    Some(
        rows.into_iter()
            .map(|(group_id, display_name)| GroupMembership {
                value: group_id.clone(),
                display: display_name,
                ref_: Some(format!("/scim/v2/Groups/{}", group_id)),
                type_: Some("direct".to_string()),
            })
            .collect(),
    )
}

fn row_to_scim_group(row: ScimGroupRow, _tenant_id: &str) -> ScimGroup {
    let data = row.data;
    let members: Vec<super::Member> = serde_json::from_value(
        data.get("members")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .unwrap_or_default();

    ScimGroup {
        schemas: vec![schemas::GROUP.to_string()],
        id: row.id.clone(),
        external_id: row.external_id,
        meta: Some(Meta {
            resource_type: "Group".to_string(),
            created: Some(row.created_at),
            last_modified: Some(row.updated_at),
            location: Some(format!("/scim/v2/Groups/{}", row.id)),
            version: Some(format!("W/\"{}\"", row.updated_at.timestamp())),
        }),
        display_name: row.display_name,
        members: if members.is_empty() {
            None
        } else {
            Some(members)
        },
    }
}

/// SQL Query condition with parameters for safe query building
/// 
/// SECURITY: This struct ensures all user input is properly parameterized
/// to prevent SQL injection attacks. Never use string formatting with user input.
#[derive(Debug, Clone)]
struct SqlCondition {
    /// The SQL condition string with $N placeholders
    sql: String,
    /// The parameters to bind to the placeholders
    params: Vec<String>,
    /// Next parameter index
    next_param_idx: usize,
}

impl SqlCondition {
    /// Create a new empty condition
    fn new(starting_idx: usize) -> Self {
        Self {
            sql: String::new(),
            params: Vec::new(),
            next_param_idx: starting_idx,
        }
    }

    /// Add a parameter and return its placeholder
    fn add_param(&mut self, value: String) -> String {
        let idx = self.next_param_idx;
        self.next_param_idx += 1;
        self.params.push(value);
        format!("${}", idx)
    }

    /// Get the next parameter index
    fn next_idx(&self) -> usize {
        self.next_param_idx
    }

    /// Combine another condition into this one
    fn combine(&mut self, other: SqlCondition) {
        self.params.extend(other.params);
        self.next_param_idx = other.next_param_idx;
    }
}

/// Build a user query with proper parameterization
/// 
/// SECURITY: This function uses parameterized queries to prevent SQL injection.
/// All user input (filter values) is passed as parameters, not concatenated.
fn build_user_query(
    tenant_id: &str,
    query: &ScimQuery,
    filter: Option<&Filter>,
) -> (String, Vec<String>) {
    let mut sql = String::from(
        "SELECT id, user_name, active, external_id, data, created_at, updated_at FROM scim_users WHERE tenant_id = $1"
    );
    let mut params = vec![tenant_id.to_string()];
    let mut next_idx = 2; // $1 is tenant_id

    // Apply filter with parameterized queries
    if let Some(f) = filter {
        let condition = filter_to_sql(f, next_idx);
        if !condition.sql.is_empty() {
            sql.push_str(" AND ");
            sql.push_str(&condition.sql);
            params.extend(condition.params);
            next_idx = condition.next_param_idx;
        }
    }

    // Apply sorting
    // SECURITY: sort_col is validated against a whitelist, not user input
    if let Some(ref sort_by) = query.sort_by {
        let sort_col = match sort_by.as_str() {
            "userName" => "user_name",
            "externalId" => "external_id",
            "meta.created" => "created_at",
            "meta.lastModified" => "updated_at",
            _ => "user_name",
        };
        let sort_order = match query.sort_order.as_deref() {
            Some("descending") => "DESC",
            _ => "ASC",
        };
        // sort_col is from a whitelist, sort_order is hardcoded - safe to format
        sql.push_str(&format!(" ORDER BY {} {}", sort_col, sort_order));
    } else {
        sql.push_str(" ORDER BY user_name ASC");
    }

    (sql, params)
}

/// Convert a SCIM filter to a parameterized SQL condition
/// 
/// SECURITY: This function NEVER concatenates user input into SQL strings.
/// All values are passed as parameters ($N) to prevent SQL injection.
fn filter_to_sql(filter: &Filter, starting_idx: usize) -> SqlCondition {
    let mut condition = SqlCondition::new(starting_idx);

    match filter {
        Filter::AttributePresent { attr } => {
            // SECURITY: Validate attribute name against whitelist
            let col = match validate_attribute(attr) {
                Some(c) => c,
                None => {
                    // Invalid attribute - return a condition that matches nothing
                    condition.sql = "1=0".to_string();
                    return condition;
                }
            };
            
            if col == "data" {
                // For JSON data fields, we still need to use the attr name in the JSON path
                // The attr name is validated by validate_attribute, so it's safe
                condition.sql = format!("data->>'{}' IS NOT NULL", attr);
            } else {
                condition.sql = format!("{} IS NOT NULL", col);
            }
        }
        Filter::AttributeComparison { attr, op, value } => {
            // SECURITY: Validate attribute name against whitelist
            let col = match validate_attribute(attr) {
                Some(c) => c,
                None => {
                    // Invalid attribute - return a condition that matches nothing
                    condition.sql = "1=0".to_string();
                    return condition;
                }
            };

            let sql_op = match op {
                super::ComparisonOperator::Eq => "=",
                super::ComparisonOperator::Ne => "!=",
                super::ComparisonOperator::Co => "ILIKE",
                super::ComparisonOperator::Sw => "LIKE",
                super::ComparisonOperator::Ew => "LIKE",
                super::ComparisonOperator::Gt => ">",
                super::ComparisonOperator::Ge => ">=",
                super::ComparisonOperator::Lt => "<",
                super::ComparisonOperator::Le => "<=",
            };

            // SECURITY: Format the value with wildcards but pass as parameter
            let formatted_value = match op {
                super::ComparisonOperator::Co => format!("%{}%", value),
                super::ComparisonOperator::Sw => format!("{}%", value),
                super::ComparisonOperator::Ew => format!("%{}", value),
                _ => value.clone(),
            };

            let param_placeholder = condition.add_param(formatted_value);

            if col == "data" {
                // For JSON data fields, the attr name is validated above
                condition.sql = format!("data->>'{}' {} {}", attr, sql_op, param_placeholder);
            } else {
                condition.sql = format!("{} {} {}", col, sql_op, param_placeholder);
            }
        }
        Filter::And(left, right) => {
            let left_cond = filter_to_sql(left, condition.next_idx());
            let right_cond = filter_to_sql(right, left_cond.next_idx());
            
            condition.sql = format!("({} AND {})", left_cond.sql, right_cond.sql);
            condition.params.extend(left_cond.params);
            condition.params.extend(right_cond.params);
            condition.next_param_idx = right_cond.next_param_idx;
        }
        Filter::Or(left, right) => {
            let left_cond = filter_to_sql(left, condition.next_idx());
            let right_cond = filter_to_sql(right, left_cond.next_idx());
            
            condition.sql = format!("({} OR {})", left_cond.sql, right_cond.sql);
            condition.params.extend(left_cond.params);
            condition.params.extend(right_cond.params);
            condition.next_param_idx = right_cond.next_param_idx;
        }
        Filter::Not(inner) => {
            let inner_cond = filter_to_sql(inner, condition.next_idx());
            condition.sql = format!("NOT ({})", inner_cond.sql);
            condition.params = inner_cond.params;
            condition.next_param_idx = inner_cond.next_param_idx;
        }
    }

    condition
}

/// Whitelist of allowed SCIM attributes for SQL query building
/// 
/// SECURITY: This whitelist prevents SQL injection through attribute names.
/// Only these specific attributes are allowed in filter expressions.
const ALLOWED_ATTRIBUTES: &[&str] = &[
    "userName",
    "externalId",
    "active",
    "id",
    "meta.created",
    "meta.lastModified",
    "name.givenName",
    "name.familyName",
    "name.formatted",
    "displayName",
    "nickName",
    "profileUrl",
    "title",
    "userType",
    "preferredLanguage",
    "locale",
    "timezone",
    "emails.value",
    "emails.type",
    "phoneNumbers.value",
    "phoneNumbers.type",
];

/// Validate an attribute name against the whitelist
/// 
/// Returns the column name if valid, None if not in whitelist
fn validate_attribute(attr: &str) -> Option<&'static str> {
    // Check against whitelist
    if !ALLOWED_ATTRIBUTES.contains(&attr) {
        // Check if it's a simple alphanumeric attribute (for custom data fields)
        // Only allow a-z, A-Z, 0-9, and dots for nested attributes
        if !attr.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '-') {
            return None;
        }
    }

    // Map to column name
    Some(match attr {
        "userName" => "user_name",
        "externalId" => "external_id",
        "active" => "active",
        "id" => "id",
        "meta.created" => "created_at",
        "meta.lastModified" => "updated_at",
        _ => "data",
    })
}

fn apply_patch_operation(
    user: &mut ScimUser,
    op: &PatchOperation,
) -> Result<(), (StatusCode, Json<ScimError>)> {
    match op.op.as_str() {
        "replace" => {
            if let Some(ref path) = op.path {
                apply_replace_by_path(user, path, op.value.clone())?;
            } else {
                // Replace entire resource
                if let Some(ref value) = op.value {
                    if let Ok(new_user) = serde_json::from_value::<ScimUser>(value.clone()) {
                        *user = new_user;
                    }
                }
            }
        }
        "add" => {
            if let Some(ref path) = op.path {
                apply_add_by_path(user, path, op.value.clone())?;
            }
        }
        "remove" => {
            if let Some(ref path) = op.path {
                apply_remove_by_path(user, path)?;
            }
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ScimError::invalid_syntax(&format!(
                    "Unknown operation: {}",
                    op.op
                ))),
            ));
        }
    }
    Ok(())
}

fn apply_replace_by_path(
    user: &mut ScimUser,
    path: &str,
    value: Option<serde_json::Value>,
) -> Result<(), (StatusCode, Json<ScimError>)> {
    match path {
        "userName" => {
            if let Some(v) = value.and_then(|v| v.as_str().map(|s| s.to_string())) {
                user.user_name = v;
            }
        }
        "active" => {
            if let Some(v) = value.and_then(|v| v.as_bool()) {
                user.active = v;
            }
        }
        "externalId" => {
            user.external_id = value.and_then(|v| v.as_str().map(|s| s.to_string()));
        }
        "displayName" => {
            user.display_name = value.and_then(|v| v.as_str().map(|s| s.to_string()));
        }
        "name" => {
            user.name = serde_json::from_value(value.unwrap_or(serde_json::Value::Null)).ok();
        }
        "emails" => {
            user.emails =
                serde_json::from_value(value.unwrap_or(serde_json::Value::Array(vec![]))).ok();
        }
        "entitlements" => {
            user.entitlements =
                serde_json::from_value(value.unwrap_or(serde_json::Value::Array(vec![]))).ok();
        }
        "roles" => {
            user.roles =
                serde_json::from_value(value.unwrap_or(serde_json::Value::Array(vec![]))).ok();
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ScimError::no_target(&format!("Unknown path: {}", path))),
            ));
        }
    }
    Ok(())
}

fn apply_add_by_path(
    user: &mut ScimUser,
    path: &str,
    value: Option<serde_json::Value>,
) -> Result<(), (StatusCode, Json<ScimError>)> {
    // For multi-valued attributes, add to the list
    if path.starts_with("emails") {
        if let Ok(email) =
            serde_json::from_value::<super::Email>(value.unwrap_or(serde_json::Value::Null))
        {
            if user.emails.is_none() {
                user.emails = Some(vec![]);
            }
            if let Some(ref mut emails) = user.emails {
                emails.push(email);
            }
        }
    } else if path.starts_with("roles") {
        if let Ok(role) =
            serde_json::from_value::<super::Role>(value.unwrap_or(serde_json::Value::Null))
        {
            if user.roles.is_none() {
                user.roles = Some(vec![]);
            }
            if let Some(ref mut roles) = user.roles {
                roles.push(role);
            }
        }
    } else {
        // For single-valued attributes, treat as replace
        return apply_replace_by_path(user, path, value);
    }
    Ok(())
}

fn apply_remove_by_path(
    user: &mut ScimUser,
    path: &str,
) -> Result<(), (StatusCode, Json<ScimError>)> {
    if path == "emails" {
        user.emails = None;
    } else if path == "phoneNumbers" {
        user.phone_numbers = None;
    } else if path == "photos" {
        user.photos = None;
    } else if path == "addresses" {
        user.addresses = None;
    } else if path.starts_with("emails[") {
        // RFC7644 filter-style remove: emails[value eq "a@b.com"], emails[type eq "work"]
        let Some((attr, expected)) = parse_remove_filter(path, "emails") else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ScimError::invalid_syntax(
                    "Invalid emails remove filter. Expected emails[value eq \"...\"] or emails[type eq \"...\"]",
                )),
            ));
        };

        if let Some(ref mut emails) = user.emails {
            emails.retain(|email| match attr.as_str() {
                "value" => !email.value.eq_ignore_ascii_case(&expected),
                "type" => email.type_.as_deref().unwrap_or("").to_lowercase() != expected.to_lowercase(),
                _ => true,
            });
            if emails.is_empty() {
                user.emails = None;
            }
        }
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ScimError::no_target(&format!(
                "Cannot remove path: {}",
                path
            ))),
        ));
    }
    Ok(())
}

fn parse_remove_filter(path: &str, attr_name: &str) -> Option<(String, String)> {
    let start = format!("{}[", attr_name);
    if !path.starts_with(&start) || !path.ends_with(']') {
        return None;
    }

    let inner = &path[start.len()..path.len() - 1];
    let (lhs, rhs) = inner.split_once(" eq ")?;
    let value = rhs
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    if value.is_empty() {
        return None;
    }
    Some((lhs.trim().to_string(), value))
}

async fn apply_group_patch_operation(
    group: &mut ScimGroup,
    op: &PatchOperation,
    state: &AppState,
    tenant_id: &str,
    group_id: &str,
) -> Result<(), (StatusCode, Json<ScimError>)> {
    match op.op.as_str() {
        "replace" => {
            if let Some(ref path) = op.path {
                if path == "displayName" {
                    if let Some(v) = op.value.as_ref().and_then(|v| v.as_str()) {
                        group.display_name = v.to_string();
                    }
                } else if path == "externalId" {
                    group.external_id = op
                        .value
                        .as_ref()
                        .and_then(|v| v.as_str().map(|s| s.to_string()));
                } else if path == "members" {
                    group.members = serde_json::from_value(
                        op.value.clone().unwrap_or(serde_json::Value::Array(vec![])),
                    )
                    .ok();
                }
            } else {
                // Replace entire resource
                if let Some(ref value) = op.value {
                    if let Ok(new_group) = serde_json::from_value::<ScimGroup>(value.clone()) {
                        *group = new_group;
                    }
                }
            }
        }
        "add" => {
            if let Some(ref path) = op.path {
                if path == "members" || path.starts_with("members[") {
                    if let Some(ref value) = op.value {
                        // SECURITY: Safe deserialization without unwrap()
                        let members_to_add: Vec<super::Member> = if value.is_array() {
                            serde_json::from_value(value.clone()).unwrap_or_default()
                        } else {
                            // Try to deserialize single member, return empty vec on error
                            match serde_json::from_value::<super::Member>(value.clone()) {
                                Ok(member) => vec![member],
                                Err(e) => {
                                    tracing::warn!(error = %e, "Failed to deserialize member from patch value");
                                    return Err((
                                        StatusCode::BAD_REQUEST,
                                        Json(ScimError::invalid_value(&format!(
                                            "Invalid member data: {}",
                                            e
                                        ))),
                                    ));
                                }
                            }
                        };

                        if group.members.is_none() {
                            group.members = Some(vec![]);
                        }
                        if let Some(ref mut members) = group.members {
                            for member in members_to_add {
                                if !members.iter().any(|m| m.value == member.value) {
                                    members.push(member);
                                }
                            }
                        }

                        // Sync to database
                        if let Some(ref members) = group.members {
                            sync_group_members(state, tenant_id, group_id, members)
                                .await
                                .ok();
                        }
                    }
                }
            }
        }
        "remove" => {
            if let Some(ref path) = op.path {
                if path == "members" {
                    group.members = Some(vec![]);
                } else if path.starts_with("members[") {
                    // Parse value filter like members[value eq "user-id"]
                    if let Some(start) = path.find("value eq \"") {
                        let start = start + 10;
                        if let Some(end) = path[start..].find("\"]") {
                            let member_id = &path[start..start + end];
                            if let Some(ref mut members) = group.members {
                                members.retain(|m| m.value != member_id);
                            }

                            // Sync to database
                            if let Some(ref members) = group.members {
                                sync_group_members(state, tenant_id, group_id, members)
                                    .await
                                    .ok();
                            }
                        }
                    }
                }
            }
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ScimError::invalid_syntax(&format!(
                    "Unknown operation: {}",
                    op.op
                ))),
            ));
        }
    }
    Ok(())
}

// ============================================================================
// Vault User Sync Helpers
// ============================================================================

async fn create_vault_user_from_scim(
    state: &AppState,
    tenant_id: &str,
    scim_user: &ScimUser,
    scim_id: &str,
) -> anyhow::Result<()> {
    // Extract primary email
    let email = scim_user
        .emails
        .as_ref()
        .and_then(|emails| emails.iter().find(|e| e.primary.unwrap_or(false)))
        .map(|e| e.value.clone())
        .or_else(|| {
            scim_user
                .emails
                .as_ref()
                .and_then(|emails| emails.first().map(|e| e.value.clone()))
        })
        .unwrap_or_else(|| format!("{}@scim.local", scim_user.user_name));

    // Create user in the vault users table
    let user_id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO users (id, tenant_id, email, email_verified, status, profile, metadata, created_at, updated_at)
        VALUES ($1, $2, $3, true, $4, $5, $6, NOW(), NOW())
        "#
    )
    .bind(&user_id)
    .bind(tenant_id)
    .bind(&email)
    .bind(if scim_user.active { "active" } else { "suspended" })
    .bind(&serde_json::json!({
        "first_name": scim_user.name.as_ref().and_then(|n| n.given_name.clone()),
        "last_name": scim_user.name.as_ref().and_then(|n| n.family_name.clone()),
        "display_name": scim_user.display_name.clone(),
    }))
    .bind(&serde_json::json!({
        "scim_id": scim_id,
        "scim_user_name": scim_user.user_name,
        "source": "scim",
    }))
    .execute(state.db.pool())
    .await?;

    // Create mapping
    sqlx::query(
        r#"
        INSERT INTO scim_mappings (id, tenant_id, resource_type, external_id, local_id, created_at, updated_at)
        VALUES ($1, $2, 'User', $3, $4, NOW(), NOW())
        "#
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(tenant_id)
    .bind(scim_id)
    .bind(&user_id)
    .execute(state.db.pool())
    .await?;

    Ok(())
}

async fn update_vault_user_from_scim(
    state: &AppState,
    tenant_id: &str,
    scim_user: &ScimUser,
    scim_id: &str,
) -> anyhow::Result<()> {
    // Find the vault user by SCIM mapping
    let mapping: Option<(String,)> = sqlx::query_as(
        "SELECT local_id FROM scim_mappings WHERE tenant_id = $1 AND resource_type = 'User' AND external_id = $2"
    )
    .bind(tenant_id)
    .bind(scim_id)
    .fetch_optional(state.db.pool())
    .await?;

    if let Some((user_id,)) = mapping {
        let email = scim_user
            .emails
            .as_ref()
            .and_then(|emails| emails.iter().find(|e| e.primary.unwrap_or(false)))
            .map(|e| e.value.clone())
            .or_else(|| {
                scim_user
                    .emails
                    .as_ref()
                    .and_then(|emails| emails.first().map(|e| e.value.clone()))
            });

        sqlx::query(
            r#"
            UPDATE users
            SET email = COALESCE($3, email),
                status = $4,
                profile = jsonb_set(
                    jsonb_set(
                        jsonb_set(profile, '{first_name}', COALESCE($5, 'null')::jsonb),
                        '{last_name}', COALESCE($6, 'null')::jsonb
                    ),
                    '{display_name}', COALESCE($7, 'null')::jsonb
                ),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(&user_id)
        .bind(&email)
        .bind(if scim_user.active {
            "active"
        } else {
            "suspended"
        })
        .bind(
            &scim_user
                .name
                .as_ref()
                .and_then(|n| n.given_name.clone())
                .map(|v| serde_json::json!(v)),
        )
        .bind(
            &scim_user
                .name
                .as_ref()
                .and_then(|n| n.family_name.clone())
                .map(|v| serde_json::json!(v)),
        )
        .bind(&scim_user.display_name.clone().map(|v| serde_json::json!(v)))
        .execute(state.db.pool())
        .await?;
    }

    Ok(())
}

async fn update_vault_user_status(
    state: &AppState,
    tenant_id: &str,
    scim_id: &str,
    active: bool,
) -> anyhow::Result<()> {
    let mapping: Option<(String,)> = sqlx::query_as(
        "SELECT local_id FROM scim_mappings WHERE tenant_id = $1 AND resource_type = 'User' AND external_id = $2"
    )
    .bind(tenant_id)
    .bind(scim_id)
    .fetch_optional(state.db.pool())
    .await?;

    if let Some((user_id,)) = mapping {
        sqlx::query(
            "UPDATE users SET status = $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(&user_id)
        .bind(if active { "active" } else { "suspended" })
        .execute(state.db.pool())
        .await?;
    }

    Ok(())
}

async fn deactivate_vault_user(
    state: &AppState,
    tenant_id: &str,
    scim_id: &str,
) -> anyhow::Result<()> {
    update_vault_user_status(state, tenant_id, scim_id, false).await
}

async fn sync_group_members(
    state: &AppState,
    tenant_id: &str,
    group_id: &str,
    members: &[super::Member],
) -> anyhow::Result<()> {
    // Get or create organization for this SCIM group
    // For simplicity, we sync members to organization_members table

    // First, clear existing members
    sqlx::query("DELETE FROM organization_members WHERE organization_id = $1 AND tenant_id = $2")
        .bind(group_id)
        .bind(tenant_id)
        .execute(state.db.pool())
        .await?;

    // Add new members
    for member in members {
        // Find vault user ID from SCIM user ID
        let user_mapping: Option<(String,)> = sqlx::query_as(
            "SELECT local_id FROM scim_mappings WHERE tenant_id = $1 AND resource_type = 'User' AND external_id = $2"
        )
        .bind(tenant_id)
        .bind(&member.value)
        .fetch_optional(state.db.pool())
        .await?;

        if let Some((user_id,)) = user_mapping {
            sqlx::query(
                r#"
                INSERT INTO organization_members (id, tenant_id, organization_id, user_id, role, status, created_at, updated_at)
                VALUES ($1, $2, $3, $4, 'member', 'active', NOW(), NOW())
                ON CONFLICT (organization_id, user_id) DO UPDATE SET status = 'active', updated_at = NOW()
                "#
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(tenant_id)
            .bind(group_id)
            .bind(&user_id)
            .execute(state.db.pool())
            .await?;
        }
    }

    Ok(())
}

// ============================================================================
// Audit Logging
// ============================================================================

async fn log_scim_audit(
    state: &AppState,
    auth_ctx: &ScimAuthContext,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    success: bool,
    error: Option<&str>,
) {
    let _ = sqlx::query(
        r#"
        INSERT INTO scim_audit_logs (id, tenant_id, token_id, action, resource_type, resource_id, 
                                     ip_address, user_agent, success, error, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
        "#,
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&auth_ctx.tenant_id)
    .bind(&auth_ctx.token_id)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(auth_ctx.ip_address.clone())
    .bind(auth_ctx.user_agent.clone())
    .bind(success)
    .bind(error)
    .execute(state.db.pool())
    .await;
}

// ============================================================================
// Schema Attribute (for schema definitions)
// ============================================================================
