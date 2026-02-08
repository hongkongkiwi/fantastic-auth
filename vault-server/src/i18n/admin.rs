//! Admin API endpoints for i18n management

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::i18n::{
    db::{TranslationExport, TranslationRepository},
    with_i18n, Language,
};
use crate::state::AppState;

/// Create admin routes for i18n management
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/languages", get(list_languages))
        .route("/translations/:lang", get(get_translations))
        .route("/translations", put(update_translation))
        .route("/translations/export", post(export_translations))
        .route("/translations/import", post(import_translations))
        .route("/translations/search", get(search_translations))
        .route("/translations/stats", get(get_translation_stats))
}

/// List all supported languages
async fn list_languages() -> impl IntoResponse {
    let languages = crate::i18n::with_i18n(|i18n| i18n.supported_languages());
    
    Json(serde_json::json!({
        "languages": languages,
        "default": "en",
        "count": languages.len()
    }))
}

/// Query params for getting translations
#[derive(Debug, Deserialize)]
struct GetTranslationsQuery {
    #[serde(default)]
    include_system: bool,
}

/// Get translations for a specific language
async fn get_translations(
    State(state): State<AppState>,
    Path(lang): Path<String>,
    Query(_query): Query<GetTranslationsQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let lang = Language::from_code(&lang).ok_or(StatusCode::BAD_REQUEST)?;
    
    let repo = TranslationRepository::new(state.db.pool().clone());
    
    // Get custom translations from database
    let custom = repo
        .get_translations_for_lang(None, lang.code())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let response = serde_json::json!({
        "language": {
            "code": lang.code(),
            "name": lang.english_name(),
            "native_name": lang.native_name(),
            "direction": lang.direction(),
            "is_rtl": lang.is_rtl(),
        },
        "custom_translations": custom.iter().map(|t| serde_json::json!({
            "key": t.key,
            "value": t.value,
            "updated_at": t.updated_at,
        })).collect::<Vec<_>>(),
        "count": custom.len(),
    });
    
    Ok(Json(response))
}

/// Request to update a translation
#[derive(Debug, Deserialize)]
struct UpdateTranslationRequest {
    lang: String,
    key: String,
    value: String,
    #[serde(default)]
    tenant_id: Option<String>,
}

/// Response for updated translation
#[derive(Debug, Serialize)]
struct TranslationResponse {
    lang: String,
    key: String,
    value: String,
    updated_at: String,
}

/// Update or create a translation
async fn update_translation(
    State(state): State<AppState>,
    Json(req): Json<UpdateTranslationRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let lang = Language::from_code(&req.lang).ok_or(StatusCode::BAD_REQUEST)?;
    
    let repo = TranslationRepository::new(state.db.pool().clone());
    
    let tenant_uuid = req.tenant_id.as_ref()
        .and_then(|id| uuid::Uuid::parse_str(id).ok());
    
    let record = repo
        .set_translation(tenant_uuid, lang.code(), &req.key, &req.value)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let response = TranslationResponse {
        lang: record.lang,
        key: record.key,
        value: record.value,
        updated_at: record.updated_at.to_rfc3339(),
    };
    
    Ok((StatusCode::OK, Json(response)))
}

/// Query params for export
#[derive(Debug, Deserialize)]
struct ExportQuery {
    lang: Option<String>,
    #[serde(default)]
    format: ExportFormat,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum ExportFormat {
    #[default]
    Json,
    Ftl,
    Po,
}

/// Export translations
async fn export_translations(
    State(state): State<AppState>,
    Query(query): Query<ExportQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let repo = TranslationRepository::new(state.db.pool().clone());
    
    let export_data = if let Some(lang_code) = query.lang {
        // Export specific language
        let lang = Language::from_code(&lang_code).ok_or(StatusCode::BAD_REQUEST)?;
        let translations = repo
            .get_translations_for_lang(None, lang.code())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
        TranslationExport {
            lang: lang_code,
            translations: translations
                .into_iter()
                .map(|t| crate::i18n::db::TranslationEntry {
                    key: t.key,
                    value: t.value,
                    updated_at: Some(t.updated_at),
                })
                .collect(),
            exported_at: chrono::Utc::now(),
        }
    } else {
        // Export all languages
        return Err(StatusCode::BAD_REQUEST);
    };
    
    // Format based on requested format
    let (content_type, body) = match query.format {
        ExportFormat::Ftl => {
            let ftl_content = export_data
                .translations
                .iter()
                .map(|t| format!("{} = {}", t.key, t.value))
                .collect::<Vec<_>>()
                .join("\n\n");
            ("text/plain", ftl_content)
        }
        _ => {
            let json = serde_json::to_string_pretty(&export_data)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            ("application/json", json)
        }
    };
    
    Ok((
        StatusCode::OK,
        [("Content-Type", content_type)],
        body,
    ))
}

/// Request to import translations
#[derive(Debug, Deserialize)]
struct ImportRequest {
    lang: String,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    format: ImportFormat,
    /// JSON format: object with key-value pairs
    /// FTL format: string content
    data: serde_json::Value,
    #[serde(default)]
    overwrite_existing: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum ImportFormat {
    #[default]
    Json,
    Ftl,
}

#[derive(Debug, Serialize)]
struct ImportResponse {
    imported: usize,
    skipped: usize,
    errors: Vec<String>,
}

/// Import translations
async fn import_translations(
    State(state): State<AppState>,
    Json(req): Json<ImportRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let lang = Language::from_code(&req.lang).ok_or(StatusCode::BAD_REQUEST)?;
    let repo = TranslationRepository::new(state.db.pool().clone());
    
    let tenant_uuid = req.tenant_id.as_ref()
        .and_then(|id| uuid::Uuid::parse_str(id).ok());
    
    let mut imported = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();
    
    match req.format {
        ImportFormat::Json => {
            if let Some(obj) = req.data.as_object() {
                for (key, value) in obj {
                    if let Some(val_str) = value.as_str() {
                        // Check if translation exists and we're not overwriting
                        if !req.overwrite_existing {
                            let exists = repo
                                .get_translation(tenant_uuid, lang.code(), key)
                                .await
                                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                                .is_some();
                            
                            if exists {
                                skipped += 1;
                                continue;
                            }
                        }
                        
                        match repo.set_translation(tenant_uuid, lang.code(), key, val_str).await {
                            Ok(_) => imported += 1,
                            Err(e) => errors.push(format!("{}: {}", key, e)),
                        }
                    }
                }
            }
        }
        ImportFormat::Ftl => {
            // Parse FTL format string
            if let Some(ftl_content) = req.data.as_str() {
                let parsed = parse_ftl_content(ftl_content);
                for (key, value) in parsed {
                    if !req.overwrite_existing {
                        let exists = repo
                            .get_translation(tenant_uuid, lang.code(), &key)
                            .await
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                            .is_some();
                        
                        if exists {
                            skipped += 1;
                            continue;
                        }
                    }
                    
                    match repo.set_translation(tenant_uuid, lang.code(), &key, &value).await {
                        Ok(_) => imported += 1,
                        Err(e) => errors.push(format!("{}: {}", key, e)),
                    }
                }
            }
        }
    }
    
    Ok(Json(ImportResponse {
        imported,
        skipped,
        errors,
    }))
}

/// Parse simple FTL content (key = value format)
fn parse_ftl_content(content: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        if let Some(pos) = line.find('=') {
            let key = line[..pos].trim().to_string();
            let value = line[pos + 1..].trim().to_string();
            if !key.is_empty() {
                result.push((key, value));
            }
        }
    }
    
    result
}

/// Query params for searching translations
#[derive(Debug, Deserialize)]
struct SearchQuery {
    q: String,
    #[serde(default)]
    lang: Option<String>,
}

/// Search translations
async fn search_translations(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let repo = TranslationRepository::new(state.db.pool().clone());
    
    let results = repo
        .search_translations(None, &query.q)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Filter by language if specified
    let filtered: Vec<_> = if let Some(lang) = query.lang {
        results.into_iter()
            .filter(|r| r.lang == lang)
            .collect()
    } else {
        results
    };
    
    Ok(Json(serde_json::json!({
        "results": filtered.iter().map(|r| serde_json::json!({
            "id": r.id,
            "lang": r.lang,
            "key": r.key,
            "value": r.value,
            "updated_at": r.updated_at,
        })).collect::<Vec<_>>(),
        "count": filtered.len(),
    })))
}

/// Get translation statistics
async fn get_translation_stats(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let repo = TranslationRepository::new(state.db.pool().clone());
    
    let stats = repo
        .get_stats(None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let total: i64 = stats.iter().map(|s| s.count).sum();
    
    Ok(Json(serde_json::json!({
        "by_language": stats,
        "total_translations": total,
        "language_count": stats.len(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ftl_content() {
        let ftl = r#"
# This is a comment
hello = Hello World
welcome = Welcome, { $name }!

errors.invalid = Invalid input
"#;

        let parsed = parse_ftl_content(ftl);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].0, "hello");
        assert_eq!(parsed[0].1, "Hello World");
        assert_eq!(parsed[1].0, "welcome");
        assert_eq!(parsed[2].0, "errors.invalid");
    }

    #[test]
    fn test_parse_ftl_empty_lines() {
        let ftl = "key1 = value1\n\nkey2 = value2\n";
        let parsed = parse_ftl_content(ftl);
        assert_eq!(parsed.len(), 2);
    }
}
