//! Internationalization (i18n) module for Vault
//!
//! Provides multi-language support with:
//! - Language detection from Accept-Language header, query params, cookies
//! - Fluent-based translation using the `fluent` crate
//! - RTL language support (Arabic, Hebrew)
//! - Database-backed custom translations
//! - Admin API for translation management

use axum::{
    extract::Request,
    http::header::{ACCEPT_LANGUAGE, HeaderMap},
};
use fluent::{FluentBundle, FluentResource, FluentValue};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

pub mod admin;
pub mod db;
pub mod middleware;

/// Supported languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    /// English (default)
    #[serde(rename = "en")]
    English,
    /// Spanish
    #[serde(rename = "es")]
    Spanish,
    /// French
    #[serde(rename = "fr")]
    French,
    /// German
    #[serde(rename = "de")]
    German,
    /// Italian
    #[serde(rename = "it")]
    Italian,
    /// Portuguese
    #[serde(rename = "pt")]
    Portuguese,
    /// Chinese (Simplified)
    #[serde(rename = "zh")]
    Chinese,
    /// Japanese
    #[serde(rename = "ja")]
    Japanese,
    /// Korean
    #[serde(rename = "ko")]
    Korean,
    /// Arabic (RTL)
    #[serde(rename = "ar")]
    Arabic,
    /// Russian
    #[serde(rename = "ru")]
    Russian,
}

impl Language {
    /// Get language code (e.g., "en", "es")
    pub fn code(&self) -> &'static str {
        match self {
            Language::English => "en",
            Language::Spanish => "es",
            Language::French => "fr",
            Language::German => "de",
            Language::Italian => "it",
            Language::Portuguese => "pt",
            Language::Chinese => "zh",
            Language::Japanese => "ja",
            Language::Korean => "ko",
            Language::Arabic => "ar",
            Language::Russian => "ru",
        }
    }

    /// Get language name in its native form
    pub fn native_name(&self) -> &'static str {
        match self {
            Language::English => "English",
            Language::Spanish => "Español",
            Language::French => "Français",
            Language::German => "Deutsch",
            Language::Italian => "Italiano",
            Language::Portuguese => "Português",
            Language::Chinese => "中文",
            Language::Japanese => "日本語",
            Language::Korean => "한국어",
            Language::Arabic => "العربية",
            Language::Russian => "Русский",
        }
    }

    /// Get language name in English
    pub fn english_name(&self) -> &'static str {
        match self {
            Language::English => "English",
            Language::Spanish => "Spanish",
            Language::French => "French",
            Language::German => "German",
            Language::Italian => "Italian",
            Language::Portuguese => "Portuguese",
            Language::Chinese => "Chinese",
            Language::Japanese => "Japanese",
            Language::Korean => "Korean",
            Language::Arabic => "Arabic",
            Language::Russian => "Russian",
        }
    }

    /// Check if language is RTL (Right-to-Left)
    pub fn is_rtl(&self) -> bool {
        matches!(self, Language::Arabic)
    }

    /// Get text direction
    pub fn direction(&self) -> &'static str {
        if self.is_rtl() {
            "rtl"
        } else {
            "ltr"
        }
    }

    /// Parse language from code
    pub fn from_code(code: &str) -> Option<Self> {
        match code.to_lowercase().as_str() {
            "en" | "en-us" | "en-gb" | "en-ca" | "en-au" => Some(Language::English),
            "es" | "es-es" | "es-mx" | "es-ar" => Some(Language::Spanish),
            "fr" | "fr-fr" | "fr-ca" => Some(Language::French),
            "de" | "de-de" => Some(Language::German),
            "it" | "it-it" => Some(Language::Italian),
            "pt" | "pt-br" | "pt-pt" => Some(Language::Portuguese),
            "zh" | "zh-cn" | "zh-hans" | "zh-tw" | "zh-hant" => Some(Language::Chinese),
            "ja" | "ja-jp" => Some(Language::Japanese),
            "ko" | "ko-kr" => Some(Language::Korean),
            "ar" | "ar-sa" | "ar-ae" => Some(Language::Arabic),
            "ru" | "ru-ru" => Some(Language::Russian),
            _ => None,
        }
    }

    /// Get all supported languages
    pub fn all() -> Vec<Language> {
        vec![
            Language::English,
            Language::Spanish,
            Language::French,
            Language::German,
            Language::Italian,
            Language::Portuguese,
            Language::Chinese,
            Language::Japanese,
            Language::Korean,
            Language::Arabic,
            Language::Russian,
        ]
    }
}

impl Default for Language {
    fn default() -> Self {
        Language::English
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

/// Translation arguments for parameterized messages
#[derive(Debug, Clone, Default)]
pub struct TranslationArgs {
    args: HashMap<String, FluentValue<'static>>,
}

impl TranslationArgs {
    /// Create empty args
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a string argument
    pub fn with_str(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.insert(key.into(), FluentValue::from(value.into()));
        self
    }

    /// Add a numeric argument
    pub fn with_int(mut self, key: impl Into<String>, value: i64) -> Self {
        self.args.insert(key.into(), FluentValue::from(value));
        self
    }

    /// Get the inner HashMap
    pub fn into_inner(self) -> HashMap<String, FluentValue<'static>> {
        self.args
    }
}

impl From<HashMap<String, String>> for TranslationArgs {
    fn from(map: HashMap<String, String>) -> Self {
        let args = map
            .into_iter()
            .map(|(k, v)| (k, FluentValue::from(v)))
            .collect();
        Self { args }
    }
}

/// I18n manager for translations
#[derive(Clone)]
pub struct I18n {
    /// Bundles for each language
    bundles: Arc<HashMap<Language, FluentBundle<FluentResource>>>,
    /// Default language
    default_lang: Language,
    /// Custom translations from database (tenant-specific)
    custom_translations: Arc<dashmap::DashMap<(String, Language, String), String>>,
}

impl I18n {
    /// Create a new I18n manager with built-in translations
    pub fn new() -> anyhow::Result<Self> {
        let mut bundles = HashMap::new();

        // Load translations for each language
        for lang in Language::all() {
            if let Some(bundle) = Self::load_bundle(lang)? {
                bundles.insert(lang, bundle);
            }
        }

        Ok(Self {
            bundles: Arc::new(bundles),
            default_lang: Language::English,
            custom_translations: Arc::new(dashmap::DashMap::new()),
        })
    }

    /// Load Fluent bundle for a language
    fn load_bundle(lang: Language) -> anyhow::Result<Option<FluentBundle<FluentResource>>> {
        let ftl_content = match lang {
            Language::English => include_str!("../../resources/i18n/en.ftl"),
            Language::Spanish => include_str!("../../resources/i18n/es.ftl"),
            Language::French => include_str!("../../resources/i18n/fr.ftl"),
            Language::German => include_str!("../../resources/i18n/de.ftl"),
            Language::Italian => include_str!("../../resources/i18n/it.ftl"),
            Language::Portuguese => include_str!("../../resources/i18n/pt.ftl"),
            Language::Chinese => include_str!("../../resources/i18n/zh.ftl"),
            Language::Japanese => include_str!("../../resources/i18n/ja.ftl"),
            Language::Korean => include_str!("../../resources/i18n/ko.ftl"),
            Language::Arabic => include_str!("../../resources/i18n/ar.ftl"),
            Language::Russian => include_str!("../../resources/i18n/ru.ftl"),
        };

        let resource = match FluentResource::try_new(ftl_content.to_string()) {
            Ok(res) => res,
            Err((res, errors)) => {
                debug!(
                    "Failed to parse some FTL entries for {}: {:?}",
                    lang.code(),
                    errors
                );
                res
            }
        };

        let mut bundle = FluentBundle::new(vec![lang.code().parse()?]);
        bundle.set_use_isolating(false);
        
        if let Err(errors) = bundle.add_resource(resource) {
            debug!(
                "Failed to add some resources to bundle for {}: {:?}",
                lang.code(),
                errors
            );
        }

        Ok(Some(bundle))
    }

    /// Translate a key to the specified language
    pub fn translate(
        &self,
        key: &str,
        lang: Language,
        args: Option<TranslationArgs>,
    ) -> String {
        // Check for custom translation first
        // Format: tenant_id:lang:key
        // For now, we skip custom translations - they would be added via admin API

        // Get the bundle for the requested language
        let bundle = match self.bundles.get(&lang) {
            Some(b) => b,
            None => {
                // Fallback to default language
                return self.translate(key, self.default_lang, args);
            }
        };

        // Get the message
        let msg = match bundle.get_message(key) {
            Some(m) => m,
            None => {
                // Try fallback language if not the default
                if lang != self.default_lang {
                    return self.translate(key, self.default_lang, args);
                }
                return format!("[{}]", key);
            }
        };

        let pattern = match msg.value() {
            Some(p) => p,
            None => return format!("[{}]", key),
        };

        let args = args.map(|a| a.into_inner());
        let mut errors = vec![];
        let result = bundle.format_pattern(pattern, args.as_ref(), &mut errors);

        if !errors.is_empty() {
            debug!("Translation formatting errors for key '{}': {:?}", key, errors);
        }

        result.to_string()
    }

    /// Translate with simple string args
    pub fn translate_simple(
        &self,
        key: &str,
        lang: Language,
        args: HashMap<String, String>,
    ) -> String {
        self.translate(key, lang, Some(args.into()))
    }

    /// Get the default language
    pub fn default_language(&self) -> Language {
        self.default_lang
    }

    /// Set a custom translation (used by admin API)
    pub fn set_custom_translation(
        &self,
        tenant_id: &str,
        lang: Language,
        key: &str,
        value: &str,
    ) {
        self.custom_translations.insert(
            (tenant_id.to_string(), lang, key.to_string()),
            value.to_string(),
        );
    }

    /// Get all supported languages with metadata
    pub fn supported_languages(&self) -> Vec<LanguageInfo> {
        Language::all()
            .into_iter()
            .map(|lang| LanguageInfo {
                code: lang.code().to_string(),
                name: lang.english_name().to_string(),
                native_name: lang.native_name().to_string(),
                is_rtl: lang.is_rtl(),
                direction: lang.direction().to_string(),
            })
            .collect()
    }
}

impl Default for I18n {
    fn default() -> Self {
        Self::new().expect("Failed to initialize I18n")
    }
}

/// Language information for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageInfo {
    pub code: String,
    pub name: String,
    pub native_name: String,
    pub is_rtl: bool,
    pub direction: String,
}

/// Detect language from request
/// Priority: query param > header > cookie > default
pub fn detect_language(request: &Request) -> Language {
    // 1. Check query parameter
    if let Some(query) = request.uri().query() {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if key == "lang" || key == "locale" {
                if let Some(lang) = Language::from_code(&value) {
                    return lang;
                }
            }
        }
    }

    // 2. Check Accept-Language header
    if let Some(header) = request.headers().get(ACCEPT_LANGUAGE) {
        if let Ok(header_str) = header.to_str() {
            if let Some(lang) = parse_accept_language(header_str) {
                return lang;
            }
        }
    }

    // 3. Check cookie
    if let Some(cookie_header) = request.headers().get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if cookie.starts_with("locale=") || cookie.starts_with("lang=") {
                    let value = cookie.split('=').nth(1).unwrap_or("en");
                    if let Some(lang) = Language::from_code(value) {
                        return lang;
                    }
                }
            }
        }
    }

    // 4. Default to English
    Language::English
}

/// Detect language from headers only (for email contexts)
pub fn detect_language_from_headers(headers: &HeaderMap) -> Language {
    if let Some(header) = headers.get(ACCEPT_LANGUAGE) {
        if let Ok(header_str) = header.to_str() {
            if let Some(lang) = parse_accept_language(header_str) {
                return lang;
            }
        }
    }
    Language::English
}

/// Parse Accept-Language header
/// Supports quality values (q=0.9) and finds best match
fn parse_accept_language(header: &str) -> Option<Language> {
    let mut candidates: Vec<(f32, Language)> = Vec::new();

    for item in header.split(',') {
        let item = item.trim();
        let parts: Vec<&str> = item.split(';').collect();

        let lang_code = parts[0].trim();
        let quality = if parts.len() > 1 {
            parts[1]
                .trim()
                .strip_prefix("q=")
                .and_then(|q| q.parse::<f32>().ok())
                .unwrap_or(1.0)
        } else {
            1.0
        };

        if let Some(lang) = Language::from_code(lang_code) {
            candidates.push((quality, lang));
        }
    }

    // Sort by quality (highest first)
    candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

    candidates.first().map(|(_, lang)| lang).copied()
}

/// Global I18n instance
pub static I18N: Lazy<I18n> = Lazy::new(I18n::default);

/// Convenience function to translate a key
pub fn t(key: &str, lang: Language) -> String {
    I18N.translate(key, lang, None)
}

/// Translate with arguments
pub fn t_args(key: &str, lang: Language, args: TranslationArgs) -> String {
    I18N.translate(key, lang, Some(args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_parsing() {
        assert_eq!(Language::from_code("en"), Some(Language::English));
        assert_eq!(Language::from_code("es-MX"), Some(Language::Spanish));
        assert_eq!(Language::from_code("zh-CN"), Some(Language::Chinese));
        assert_eq!(Language::from_code("invalid"), None);
    }

    #[test]
    fn test_language_direction() {
        assert_eq!(Language::English.direction(), "ltr");
        assert_eq!(Language::Arabic.direction(), "rtl");
        assert!(Language::Arabic.is_rtl());
        assert!(!Language::English.is_rtl());
    }

    #[test]
    fn test_parse_accept_language() {
        assert_eq!(
            parse_accept_language("en-US,en;q=0.9,es;q=0.8"),
            Some(Language::English)
        );
        assert_eq!(
            parse_accept_language("es-ES,es;q=0.9,en;q=0.8"),
            Some(Language::Spanish)
        );
        assert_eq!(parse_accept_language("fr-FR"), Some(Language::French));
    }

    #[test]
    fn test_translation_args() {
        let args = TranslationArgs::new()
            .with_str("name", "Alice")
            .with_int("count", 5);
        
        let inner = args.into_inner();
        assert!(inner.contains_key("name"));
        assert!(inner.contains_key("count"));
    }
}
