//! I18n middleware re-export
//!
//! Re-exports from the i18n middleware module.

pub use crate::i18n::middleware::{i18n_middleware, language_detection_layer, extract_language, RequestLanguage, localized_error_response};
