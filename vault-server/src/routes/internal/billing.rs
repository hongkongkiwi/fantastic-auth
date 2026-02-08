//! Internal Billing Webhook Routes
//!
//! Stripe webhook endpoint for receiving billing events.
//! These are public routes that Stripe calls directly.

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

use crate::permissions::checker::PermissionChecker;
use crate::state::AppState;
use crate::state::CurrentUser;
use crate::routes::ApiError;

/// Create billing webhook routes
/// These are mounted under /api/v1/internal/billing
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/webhooks/stripe", post(stripe_webhook))
        .route("/invoices", get(list_platform_invoices))
}

/// Handle Stripe webhook events
async fn stripe_webhook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Check if billing is enabled
    if !state.billing_service.is_enabled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Billing is not enabled");
    }

    // Get Stripe signature from headers
    let signature = match headers.get("stripe-signature") {
        Some(sig) => match sig.to_str() {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!("Invalid Stripe signature header encoding");
                return (StatusCode::BAD_REQUEST, "Invalid signature header");
            }
        },
        None => {
            tracing::warn!("Missing Stripe signature header");
            return (StatusCode::BAD_REQUEST, "Missing signature header");
        }
    };

    let payload = match std::str::from_utf8(&body) {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Invalid UTF-8 in body");
        }
    };

    // Process webhook
    match state
        .billing_service
        .handle_webhook(payload, signature)
        .await
    {
        Ok(Some(result)) => {
            tracing::info!(
                event_type = %result.event_type,
                tenant_id = ?result.tenant_id,
                processed = result.processed,
                "Stripe webhook processed"
            );
            (StatusCode::OK, "Webhook processed")
        }
        Ok(None) => {
            // Billing not enabled (shouldn't happen due to check above)
            (StatusCode::SERVICE_UNAVAILABLE, "Billing not enabled")
        }
        Err(e) => {
            tracing::error!("Failed to process Stripe webhook: {}", e);
            (StatusCode::BAD_REQUEST, "Webhook processing failed")
        }
    }
}

/// List invoices across all tenants (superadmin)
async fn list_platform_invoices(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<InvoiceQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_billing_read(&state, &current_user).await?;

    if !state.billing_service.is_enabled() {
        return Ok(Json(serde_json::json!({
            "invoices": [],
            "pagination": {
                "page": 1,
                "perPage": 0,
                "total": 0,
                "totalPages": 0
            }
        })));
    }

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * per_page;

    let filters = InvoiceFilters::from(query)?;

    let mut conn = state.db.acquire().await.map_err(|_| ApiError::Internal)?;
    elevate_to_admin(&mut conn).await?;

    let total = count_invoices(&mut conn, &filters).await?;
    let rows = fetch_invoices(&mut conn, &filters, per_page, offset).await?;

    reset_role(&mut conn).await;

    let mapped: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "tenantId": row.tenant_id,
                "status": row.status,
                "amount": (row.total_cents as f64) / 100.0,
                "currency": row.currency,
                "description": "",
                "createdAt": row.created_at.to_rfc3339(),
                "pdfUrl": row.invoice_pdf_url,
            })
        })
        .collect();

    let total_pages = if total == 0 {
        0
    } else {
        (total as f64 / per_page as f64).ceil() as i64
    };

    Ok(Json(serde_json::json!({
        "invoices": mapped,
        "pagination": {
            "page": page,
            "perPage": per_page,
            "total": total,
            "totalPages": total_pages
        }
    })))
}

#[derive(Debug, Deserialize)]
struct InvoiceQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    #[serde(rename = "tenantId")]
    tenant_id: Option<String>,
    status: Option<String>,
    #[serde(rename = "createdFrom")]
    created_from: Option<String>,
    #[serde(rename = "createdTo")]
    created_to: Option<String>,
}

#[derive(Debug)]
struct InvoiceFilters {
    tenant_id: Option<uuid::Uuid>,
    status: Option<String>,
    created_from: Option<DateTime<Utc>>,
    created_to: Option<DateTime<Utc>>,
}

impl InvoiceFilters {
    fn from(query: InvoiceQuery) -> Result<Self, ApiError> {
        let created_from = match query.created_from {
            Some(value) => Some(parse_datetime(&value)?),
            None => None,
        };
        let created_to = match query.created_to {
            Some(value) => Some(parse_datetime(&value)?),
            None => None,
        };

        let tenant_id = match query.tenant_id {
            Some(value) => Some(
                Uuid::parse_str(&value)
                    .map_err(|_| ApiError::BadRequest("Invalid tenant id".to_string()))?,
            ),
            None => None,
        };

        Ok(Self {
            tenant_id,
            status: query.status,
            created_from,
            created_to,
        })
    }
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ApiError::BadRequest("Invalid date format".to_string()))
}

#[derive(Debug, sqlx::FromRow)]
struct InvoiceRow {
    id: String,
    tenant_id: String,
    status: String,
    total_cents: i32,
    currency: String,
    created_at: DateTime<Utc>,
    invoice_pdf_url: Option<String>,
}

async fn require_billing_read(
    state: &AppState,
    current_user: &CurrentUser,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let checker = PermissionChecker::new(state.db.pool().clone(), state.redis.clone());
    let allowed = checker
        .has_permission(&current_user.user_id, "billing:read")
        .await;
    if !allowed {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn apply_invoice_filters<'a>(
    builder: &mut QueryBuilder<'a, Postgres>,
    filters: &InvoiceFilters,
) {
    if let Some(tenant_id) = &filters.tenant_id {
        builder.push(" AND tenant_id = ").push_bind(tenant_id);
    }
    if let Some(status) = &filters.status {
        builder.push(" AND status = ").push_bind(status);
    }
    if let Some(created_from) = &filters.created_from {
        builder.push(" AND created_at >= ").push_bind(created_from);
    }
    if let Some(created_to) = &filters.created_to {
        builder.push(" AND created_at <= ").push_bind(created_to);
    }
}

async fn count_invoices(
    conn: &mut sqlx::pool::PoolConnection<Postgres>,
    filters: &InvoiceFilters,
) -> Result<i64, ApiError> {
    let mut builder = QueryBuilder::new("SELECT COUNT(*) FROM invoices WHERE 1=1");
    apply_invoice_filters(&mut builder, filters);
    builder
        .build_query_scalar()
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| ApiError::Internal)
}

async fn fetch_invoices(
    conn: &mut sqlx::pool::PoolConnection<Postgres>,
    filters: &InvoiceFilters,
    limit: i64,
    offset: i64,
) -> Result<Vec<InvoiceRow>, ApiError> {
    let mut builder = QueryBuilder::new(
        r#"
        SELECT id::text as id,
               tenant_id::text as tenant_id,
               status,
               total_cents,
               currency,
               created_at,
               invoice_pdf_url
        FROM invoices
        WHERE 1=1
        "#,
    );
    apply_invoice_filters(&mut builder, filters);
    builder.push(" ORDER BY created_at DESC LIMIT ").push_bind(limit);
    builder.push(" OFFSET ").push_bind(offset);

    builder
        .build_query_as::<InvoiceRow>()
        .fetch_all(&mut *conn)
        .await
        .map_err(|_| ApiError::Internal)
}

async fn elevate_to_admin(
    conn: &mut sqlx::pool::PoolConnection<Postgres>,
) -> Result<(), ApiError> {
    sqlx::query("SET ROLE vault_admin")
        .execute(&mut *conn)
        .await
        .map_err(|_| ApiError::Forbidden)?;
    Ok(())
}

async fn reset_role(conn: &mut sqlx::pool::PoolConnection<Postgres>) {
    let _ = sqlx::query("RESET ROLE").execute(&mut *conn).await;
}
