//! I18n middleware for language detection and injection

use axum::{
    extract::{Request, State},
    http::header::{HeaderValue, ACCEPT_LANGUAGE},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::i18n::{detect_language, Language};
use crate::state::AppState;

/// Extension key for storing language in request extensions
#[derive(Debug, Clone, Copy)]
pub struct RequestLanguage(pub Language);

/// I18n middleware that detects language and stores it in request extensions
/// 
/// Language detection priority:
/// 1. Query parameter: `?lang=es` or `?locale=fr`
/// 2. Accept-Language header
/// 3. Cookie: `locale=de` or `lang=it`
/// 4. Default: English
pub async fn i18n_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Detect language from request
    let lang = detect_language(&request);
    
    // Store language in request extensions for use by handlers
    request.extensions_mut().insert(RequestLanguage(lang));
    
    // Continue processing
    let mut response = next.run(request).await;
    
    // Add X-Language header to response
    let lang_header = HeaderValue::from_str(lang.code()).unwrap_or_else(|_| {
        HeaderValue::from_static("en")
    });
    response.headers_mut().insert("X-Language", lang_header);
    
    // Add X-Text-Direction header for RTL support
    let direction = if lang.is_rtl() { "rtl" } else { "ltr" };
    response.headers_mut().insert(
        "X-Text-Direction",
        HeaderValue::from_static(direction),
    );
    
    response
}

/// Extract language from request extensions
pub fn extract_language(request: &Request) -> Language {
    request
        .extensions()
        .get::<RequestLanguage>()
        .map(|l| l.0)
        .unwrap_or_default()
}

/// Middleware that sets up language context for error responses
/// This is a lighter version that doesn't require full state
pub async fn language_detection_layer(
    request: Request,
    next: Next,
) -> Response {
    let lang = detect_language(&request);
    
    let mut response = next.run(request).await;
    
    // Add language headers even on error responses
    let lang_header = HeaderValue::from_str(lang.code()).unwrap_or_else(|_| {
        HeaderValue::from_static("en")
    });
    response.headers_mut().insert("X-Language", lang_header);
    
    response
}

/// Helper function to create a localized error response
pub fn localized_error_response(
    status: axum::http::StatusCode,
    error_code: &str,
    message: &str,
    lang: Language,
) -> Response {
    let body = axum::Json(serde_json::json!({
        "error": {
            "code": error_code,
            "message": message,
            "localized": true
        },
        "meta": {
            "language": lang.code(),
            "direction": lang.direction()
        }
    }));

    let mut response = (status, body).into_response();
    
    // Add language headers
    let lang_header = HeaderValue::from_str(lang.code()).unwrap_or_else(|_| {
        HeaderValue::from_static("en")
    });
    response.headers_mut().insert("X-Language", lang_header);
    
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    #[test]
    fn test_extract_language_default() {
        let request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        
        // Without extension, should return default (English)
        let lang = extract_language(&request);
        assert_eq!(lang, Language::English);
    }

    #[test]
    fn test_extract_language_with_extension() {
        let mut request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        
        request.extensions_mut().insert(RequestLanguage(Language::Spanish));
        
        let lang = extract_language(&request);
        assert_eq!(lang, Language::Spanish);
    }

    #[test]
    fn test_detect_language_from_query() {
        let request = Request::builder()
            .uri("/test?lang=es")
            .body(Body::empty())
            .unwrap();
        
        let lang = detect_language(&request);
        assert_eq!(lang, Language::Spanish);
    }

    #[test]
    fn test_detect_language_from_header() {
        let request = Request::builder()
            .uri("/test")
            .header(ACCEPT_LANGUAGE, "fr-FR,fr;q=0.9,en;q=0.8")
            .body(Body::empty())
            .unwrap();
        
        let lang = detect_language(&request);
        assert_eq!(lang, Language::French);
    }

    #[test]
    fn test_detect_language_from_cookie() {
        let request = Request::builder()
            .uri("/test")
            .header("cookie", "locale=de")
            .body(Body::empty())
            .unwrap();
        
        let lang = detect_language(&request);
        assert_eq!(lang, Language::German);
    }

    #[test]
    fn test_language_priority() {
        // Query param should take priority over header
        let request = Request::builder()
            .uri("/test?lang=ja")
            .header(ACCEPT_LANGUAGE, "es-ES,es;q=0.9")
            .body(Body::empty())
            .unwrap();
        
        let lang = detect_language(&request);
        assert_eq!(lang, Language::Japanese);
    }
}
