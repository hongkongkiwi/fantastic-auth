//! Admin Security Routes
//!
//! Provides administrative endpoints for managing security settings including:
//! - Geographic restrictions (country allow/block lists)
//! - VPN/proxy detection settings
//! - Geo restriction analytics

use axum::{
    extract::{Query, State},
    routing::{get, put},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::audit::{AuditAction, AuditLogger, ResourceType};
use crate::config::GeoRestrictionPolicy as ConfigGeoRestrictionPolicy;
use crate::routes::ApiError;
use crate::security::geo::common_country_codes;
use crate::security::KmsProviderKind;
use crate::state::{AppState, CurrentUser};

/// Create security admin routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Geographic restriction endpoints
        .route("/security/geo", get(get_geo_policy).put(update_geo_policy))
        .route("/security/geo/analytics", get(get_geo_analytics))
        .route("/security/geo/countries", get(list_countries))
        // VPN/Proxy detection endpoints
        .route("/security/vpn-detection", get(get_vpn_detection_settings))
        .route(
            "/security/vpn-detection",
            put(update_vpn_detection_settings),
        )
        // Geo audit log endpoint
        .route("/security/geo/audit-log", get(get_geo_audit_log))
        // Data encryption provider migration
        .route("/security/data-encryption", get(get_data_encryption_status))
        .route("/security/data-encryption/migrate", put(migrate_data_encryption_provider))
        .route(
            "/security/data-encryption/providers",
            get(list_data_encryption_providers),
        )
}

// ============ Request/Response Types ============

/// Geographic restriction policy response
#[derive(Debug, Serialize)]
pub struct GeoPolicyResponse {
    /// Whether geo restrictions are enabled
    pub enabled: bool,
    /// Policy type: allow_list or block_list
    pub policy: String,
    /// List of country codes (ISO 3166-1 alpha-2)
    pub countries: Vec<String>,
    /// Whether VPN connections are allowed
    #[serde(rename = "allowVpn")]
    pub allow_vpn: bool,
    /// Whether anonymous proxies are blocked
    #[serde(rename = "blockAnonymousProxies")]
    pub block_anonymous_proxies: bool,
    /// Cache TTL in seconds
    #[serde(rename = "cacheTtlSeconds")]
    pub cache_ttl_seconds: u64,
    /// When the policy was last updated
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
    /// Who last updated the policy
    #[serde(rename = "updatedBy")]
    pub updated_by: Option<String>,
}

/// Update geographic restriction policy request
#[derive(Debug, Deserialize)]
pub struct UpdateGeoPolicyRequest {
    /// Whether geo restrictions are enabled
    pub enabled: Option<bool>,
    /// Policy type: allow_list or block_list
    pub policy: Option<String>,
    /// List of country codes (ISO 3166-1 alpha-2)
    pub countries: Option<Vec<String>>,
    /// Whether VPN connections are allowed
    #[serde(rename = "allowVpn")]
    pub allow_vpn: Option<bool>,
    /// Whether anonymous proxies are blocked
    #[serde(rename = "blockAnonymousProxies")]
    pub block_anonymous_proxies: Option<bool>,
    /// Cache TTL in seconds
    #[serde(rename = "cacheTtlSeconds")]
    pub cache_ttl_seconds: Option<u64>,
}

/// Country information
#[derive(Debug, Serialize)]
pub struct CountryInfo {
    /// ISO 3166-1 alpha-2 country code
    pub code: String,
    /// Country name
    pub name: &'static str,
}

/// Geo analytics request query parameters
#[derive(Debug, Deserialize)]
pub struct GeoAnalyticsQuery {
    /// Start date (ISO 8601)
    pub start: Option<DateTime<Utc>>,
    /// End date (ISO 8601)
    pub end: Option<DateTime<Utc>>,
    /// Limit results
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    100
}

fn parse_kms_provider(value: &str) -> Result<KmsProviderKind, ApiError> {
    match value.to_lowercase().as_str() {
        "local" => Ok(KmsProviderKind::Local),
        "aws_kms" | "aws-kms" => Ok(KmsProviderKind::AwsKms),
        "azure_kv" | "azure-kv" | "azure_kms" => Ok(KmsProviderKind::AzureKv),
        "gcp_kms" | "gcp-kms" => Ok(KmsProviderKind::GcpKms),
        "alicloud_kms" | "alicloud-kms" => Ok(KmsProviderKind::AlicloudKms),
        "oracle_kms" | "oracle-kms" => Ok(KmsProviderKind::OracleKms),
        _ => Err(ApiError::BadRequest(format!(
            "Unknown provider: {}",
            value
        ))),
    }
}

/// Geo analytics response
#[derive(Debug, Serialize)]
pub struct GeoAnalyticsResponse {
    /// Total logins in the period
    #[serde(rename = "totalLogins")]
    pub total_logins: i64,
    /// Total blocked attempts
    #[serde(rename = "blockedAttempts")]
    pub blocked_attempts: i64,
    /// Logins by country
    #[serde(rename = "loginsByCountry")]
    pub logins_by_country: Vec<CountryStat>,
    /// Blocked attempts by country
    #[serde(rename = "blockedByCountry")]
    pub blocked_by_country: Vec<CountryStat>,
    /// VPN/proxy usage stats
    #[serde(rename = "vpnStats")]
    pub vpn_stats: VpnStats,
    /// Time series data (login attempts over time)
    #[serde(rename = "timeSeries")]
    pub time_series: Vec<TimeSeriesPoint>,
}

/// Country statistics
#[derive(Debug, Serialize)]
pub struct CountryStat {
    /// Country code
    pub country: String,
    /// Count of events
    pub count: i64,
    /// Percentage of total
    pub percentage: f64,
}

/// VPN usage statistics
#[derive(Debug, Serialize)]
pub struct VpnStats {
    /// Total logins from VPN
    #[serde(rename = "vpnLogins")]
    pub vpn_logins: i64,
    /// Total logins from anonymous proxies
    #[serde(rename = "proxyLogins")]
    pub proxy_logins: i64,
    /// Total blocked VPN attempts
    #[serde(rename = "blockedVpn")]
    pub blocked_vpn: i64,
    /// Total blocked proxy attempts
    #[serde(rename = "blockedProxy")]
    pub blocked_proxy: i64,
}

/// Time series data point
#[derive(Debug, Serialize)]
pub struct TimeSeriesPoint {
    /// Timestamp
    pub timestamp: String,
    /// Number of logins
    pub logins: i64,
    /// Number of blocked attempts
    pub blocked: i64,
}

/// VPN detection settings response
#[derive(Debug, Serialize)]
pub struct VpnDetectionSettingsResponse {
    /// Whether VPN detection is enabled
    pub enabled: bool,
    /// Whether to block VPN connections
    #[serde(rename = "blockVpn")]
    pub block_vpn: bool,
    /// Whether to block anonymous proxies
    #[serde(rename = "blockAnonymousProxies")]
    pub block_anonymous_proxies: bool,
    /// Whether to block hosting providers/datacenters
    #[serde(rename = "blockHostingProviders")]
    pub block_hosting_providers: bool,
    /// Custom VPN ASNs to block
    #[serde(rename = "customVpnAsns")]
    pub custom_vpn_asns: Vec<u32>,
    /// Custom hosting ASNs to block
    #[serde(rename = "customHostingAsns")]
    pub custom_hosting_asns: Vec<u32>,
}

/// Update VPN detection settings request
#[derive(Debug, Deserialize)]
pub struct UpdateVpnDetectionRequest {
    pub enabled: Option<bool>,
    #[serde(rename = "blockVpn")]
    pub block_vpn: Option<bool>,
    #[serde(rename = "blockAnonymousProxies")]
    pub block_anonymous_proxies: Option<bool>,
    #[serde(rename = "blockHostingProviders")]
    pub block_hosting_providers: Option<bool>,
    #[serde(rename = "customVpnAsns")]
    pub custom_vpn_asns: Option<Vec<u32>>,
    #[serde(rename = "customHostingAsns")]
    pub custom_hosting_asns: Option<Vec<u32>>,
}

async fn get_data_encryption_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<DataEncryptionStatusResponse>, ApiError> {
    let tenant_id = current_user.tenant_id.clone();
    let active = state
        .tenant_key_service
        .get_active_key_info(&tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch tenant key info: {}", e);
            ApiError::Internal
        })?;

    let provider = match active.as_ref() {
        Some(info) => match info.provider {
            KmsProviderKind::Local => "local",
            KmsProviderKind::AwsKms => "aws_kms",
            KmsProviderKind::AzureKv => "azure_kv",
            KmsProviderKind::GcpKms => "gcp_kms",
            KmsProviderKind::AlicloudKms => "alicloud_kms",
            KmsProviderKind::OracleKms => "oracle_kms",
        },
        None => match state.config.security.data_encryption.provider {
            crate::config::DataEncryptionProvider::Local => "local",
            crate::config::DataEncryptionProvider::AwsKms => "aws_kms",
            crate::config::DataEncryptionProvider::AzureKv => "azure_kv",
            crate::config::DataEncryptionProvider::GcpKms => "gcp_kms",
            crate::config::DataEncryptionProvider::AlicloudKms => "alicloud_kms",
            crate::config::DataEncryptionProvider::OracleKms => "oracle_kms",
        },
    };

    Ok(Json(DataEncryptionStatusResponse {
        provider: provider.to_string(),
        version: active.as_ref().map(|info| info.version),
        provider_key_id: active.as_ref().and_then(|info| info.provider_key_id.clone()),
        provider_metadata: active.as_ref().map(|info| info.provider_metadata.clone()),
        initialized: active.is_some(),
    }))
}

async fn migrate_data_encryption_provider(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<MigrateDataEncryptionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant_id = current_user.tenant_id.clone();
    let provider = parse_kms_provider(&req.provider)?;

    state
        .tenant_key_service
        .migrate_provider(&tenant_id, provider)
        .await
        .map_err(|e| {
            tracing::error!("Failed to migrate tenant data key: {}", e);
            ApiError::Internal
        })?;

    let audit = state.audit_logger();
    audit
        .log(
            &tenant_id,
            AuditAction::SecurityPolicyUpdated,
            ResourceType::SecurityPolicy,
            "data_encryption_provider",
            Some(current_user.user_id.clone()),
            current_user.session_id.clone(),
            None,
            true,
            None,
            Some(serde_json::json!({
                "provider": req.provider,
            })),
        );

    Ok(Json(serde_json::json!({
        "message": "Data encryption provider migrated",
        "provider": req.provider
    })))
}

async fn list_data_encryption_providers(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let supported: Vec<String> = state
        .tenant_key_service
        .supported_providers()
        .into_iter()
        .map(|provider| match provider {
            KmsProviderKind::Local => "local".to_string(),
            KmsProviderKind::AwsKms => "aws_kms".to_string(),
            KmsProviderKind::AzureKv => "azure_kv".to_string(),
            KmsProviderKind::GcpKms => "gcp_kms".to_string(),
            KmsProviderKind::AlicloudKms => "alicloud_kms".to_string(),
            KmsProviderKind::OracleKms => "oracle_kms".to_string(),
        })
        .collect();

    let default_provider = match state.config.security.data_encryption.provider {
        crate::config::DataEncryptionProvider::Local => "local",
        crate::config::DataEncryptionProvider::AwsKms => "aws_kms",
        crate::config::DataEncryptionProvider::AzureKv => "azure_kv",
        crate::config::DataEncryptionProvider::GcpKms => "gcp_kms",
        crate::config::DataEncryptionProvider::AlicloudKms => "alicloud_kms",
        crate::config::DataEncryptionProvider::OracleKms => "oracle_kms",
    };

    Ok(Json(serde_json::json!({
        "supported": supported,
        "default": default_provider,
        "tenant_id": current_user.tenant_id
    })))
}

#[derive(Debug, Serialize)]
pub struct DataEncryptionStatusResponse {
    pub provider: String,
    pub version: Option<i32>,
    #[serde(rename = "providerKeyId")]
    pub provider_key_id: Option<String>,
    #[serde(rename = "providerMetadata")]
    pub provider_metadata: Option<serde_json::Value>,
    pub initialized: bool,
}

#[derive(Debug, Deserialize)]
pub struct MigrateDataEncryptionRequest {
    pub provider: String,
}

/// Geo audit log entry
#[derive(Debug, Serialize)]
pub struct GeoAuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[serde(rename = "ipAddress")]
    pub ip_address: Option<String>,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
    pub success: bool,
    pub reason: Option<String>,
}

/// Geo audit log response
#[derive(Debug, Serialize)]
pub struct GeoAuditLogResponse {
    pub entries: Vec<GeoAuditLogEntry>,
    pub total: i64,
    pub page: i64,
    #[serde(rename = "perPage")]
    pub per_page: i64,
}

// ============ Route Handlers ============

/// Get current geo restriction policy
async fn get_geo_policy(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<GeoPolicyResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let config = &state.config.security.geo_restriction;

    let response = GeoPolicyResponse {
        enabled: config.enabled,
        policy: match config.policy {
            ConfigGeoRestrictionPolicy::AllowList => "allow_list".to_string(),
            ConfigGeoRestrictionPolicy::BlockList => "block_list".to_string(),
        },
        countries: config.country_list.clone(),
        allow_vpn: config.allow_vpn,
        block_anonymous_proxies: config.block_anonymous_proxies,
        cache_ttl_seconds: config.cache_ttl_seconds,
        updated_at: None, // Would be fetched from tenant config in DB
        updated_by: None,
    };

    Ok(Json(response))
}

/// Update geo restriction policy
async fn update_geo_policy(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<UpdateGeoPolicyRequest>,
) -> Result<Json<GeoPolicyResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Validate country codes
    if let Some(ref countries) = req.countries {
        for code in countries {
            if !crate::security::geo::validate_country_code(code) {
                return Err(ApiError::Validation(format!(
                    "Invalid country code: {}",
                    code
                )));
            }
        }
    }

    // In a real implementation, this would:
    // 1. Save the config to tenant_settings in the database
    // 2. Invalidate any cached config
    // 3. Log the change

    // For now, we'll just return the updated config
    let response = GeoPolicyResponse {
        enabled: req.enabled.unwrap_or(false),
        policy: req.policy.unwrap_or_else(|| "block_list".to_string()),
        countries: req.countries.unwrap_or_default(),
        allow_vpn: req.allow_vpn.unwrap_or(true),
        block_anonymous_proxies: req.block_anonymous_proxies.unwrap_or(false),
        cache_ttl_seconds: req.cache_ttl_seconds.unwrap_or(86400),
        updated_at: Some(Utc::now().to_rfc3339()),
        updated_by: Some(current_user.user_id.clone()),
    };

    // Log the change
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("geo.policy_updated"),
        ResourceType::Admin,
        &current_user.tenant_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "enabled": response.enabled,
            "policy": response.policy,
            "countries": response.countries,
            "allow_vpn": response.allow_vpn,
            "block_anonymous_proxies": response.block_anonymous_proxies,
        })),
    );

    Ok(Json(response))
}

/// List all available countries
async fn list_countries() -> Result<Json<Vec<CountryInfo>>, ApiError> {
    let countries = common_country_codes()
        .into_iter()
        .map(|(code, name)| CountryInfo { code, name })
        .collect();

    Ok(Json(countries))
}

/// Get geo restriction analytics
async fn get_geo_analytics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<GeoAnalyticsQuery>,
) -> Result<Json<GeoAnalyticsResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // In a real implementation, this would query the database for:
    // - Audit logs filtered by geo-related actions
    // - Aggregated statistics by country
    // - Time series data

    // For now, return sample data
    let response = GeoAnalyticsResponse {
        total_logins: 15234,
        blocked_attempts: 456,
        logins_by_country: vec![
            CountryStat {
                country: "US".to_string(),
                count: 5234,
                percentage: 34.4,
            },
            CountryStat {
                country: "GB".to_string(),
                count: 2134,
                percentage: 14.0,
            },
            CountryStat {
                country: "DE".to_string(),
                count: 1892,
                percentage: 12.4,
            },
            CountryStat {
                country: "CA".to_string(),
                count: 1456,
                percentage: 9.6,
            },
            CountryStat {
                country: "FR".to_string(),
                count: 1234,
                percentage: 8.1,
            },
        ],
        blocked_by_country: vec![
            CountryStat {
                country: "CN".to_string(),
                count: 156,
                percentage: 34.2,
            },
            CountryStat {
                country: "RU".to_string(),
                count: 134,
                percentage: 29.4,
            },
            CountryStat {
                country: "KP".to_string(),
                count: 89,
                percentage: 19.5,
            },
        ],
        vpn_stats: VpnStats {
            vpn_logins: 234,
            proxy_logins: 45,
            blocked_vpn: 67,
            blocked_proxy: 23,
        },
        time_series: vec![
            TimeSeriesPoint {
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                logins: 120,
                blocked: 5,
            },
            TimeSeriesPoint {
                timestamp: "2024-01-02T00:00:00Z".to_string(),
                logins: 145,
                blocked: 3,
            },
            TimeSeriesPoint {
                timestamp: "2024-01-03T00:00:00Z".to_string(),
                logins: 132,
                blocked: 8,
            },
        ],
    };

    Ok(Json(response))
}

/// Get VPN detection settings
async fn get_vpn_detection_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<VpnDetectionSettingsResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let config = &state.config.security.geo_restriction;

    let response = VpnDetectionSettingsResponse {
        enabled: config.enabled,
        block_vpn: !config.allow_vpn,
        block_anonymous_proxies: config.block_anonymous_proxies,
        block_hosting_providers: false, // Not yet implemented
        custom_vpn_asns: vec![],
        custom_hosting_asns: vec![],
    };

    Ok(Json(response))
}

/// Update VPN detection settings
async fn update_vpn_detection_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<UpdateVpnDetectionRequest>,
) -> Result<Json<VpnDetectionSettingsResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // In a real implementation, this would save to the database

    let response = VpnDetectionSettingsResponse {
        enabled: req.enabled.unwrap_or(false),
        block_vpn: req.block_vpn.unwrap_or(false),
        block_anonymous_proxies: req.block_anonymous_proxies.unwrap_or(false),
        block_hosting_providers: req.block_hosting_providers.unwrap_or(false),
        custom_vpn_asns: req.custom_vpn_asns.unwrap_or_default(),
        custom_hosting_asns: req.custom_hosting_asns.unwrap_or_default(),
    };

    // Log the change
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("vpn.settings_updated"),
        ResourceType::Admin,
        &current_user.tenant_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "enabled": response.enabled,
            "block_vpn": response.block_vpn,
            "block_anonymous_proxies": response.block_anonymous_proxies,
            "block_hosting_providers": response.block_hosting_providers,
        })),
    );

    Ok(Json(response))
}

/// Get geo audit log
async fn get_geo_audit_log(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<GeoAnalyticsQuery>,
) -> Result<Json<GeoAuditLogResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // In a real implementation, this would query the audit_logs table
    // filtered by geo-related actions

    let entries = vec![
        GeoAuditLogEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            action: "geo.access_denied".to_string(),
            user_id: None,
            ip_address: Some("203.0.113.1".to_string()),
            country_code: Some("CN".to_string()),
            success: false,
            reason: Some("Access from country 'CN' is not permitted".to_string()),
        },
        GeoAuditLogEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            action: "geo.vpn_blocked".to_string(),
            user_id: Some(uuid::Uuid::new_v4().to_string()),
            ip_address: Some("198.51.100.1".to_string()),
            country_code: Some("US".to_string()),
            success: false,
            reason: Some("VPN connections are not allowed".to_string()),
        },
    ];

    Ok(Json(GeoAuditLogResponse {
        entries,
        total: 2,
        page: 1,
        per_page: query.limit,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_policy_response_serialization() {
        let response = GeoPolicyResponse {
            enabled: true,
            policy: "block_list".to_string(),
            countries: vec!["CN".to_string(), "RU".to_string()],
            allow_vpn: false,
            block_anonymous_proxies: true,
            cache_ttl_seconds: 86400,
            updated_at: Some(Utc::now().to_rfc3339()),
            updated_by: Some("admin-123".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("enabled"));
        assert!(json.contains("block_list"));
        assert!(json.contains("CN"));
    }

    #[test]
    fn test_geo_analytics_response() {
        let response = GeoAnalyticsResponse {
            total_logins: 100,
            blocked_attempts: 5,
            logins_by_country: vec![CountryStat {
                country: "US".to_string(),
                count: 50,
                percentage: 50.0,
            }],
            blocked_by_country: vec![],
            vpn_stats: VpnStats {
                vpn_logins: 10,
                proxy_logins: 2,
                blocked_vpn: 1,
                blocked_proxy: 0,
            },
            time_series: vec![],
        };

        assert_eq!(response.total_logins, 100);
    }
}
