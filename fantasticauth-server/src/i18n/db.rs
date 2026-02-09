//! Database operations for i18n translations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Database record for custom translations
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct TranslationRecord {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub lang: String,
    pub key: String,
    pub value: String,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Repository for translation database operations
#[derive(Clone)]
pub struct TranslationRepository {
    pool: PgPool,
}

impl TranslationRepository {
    /// Create a new translation repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a custom translation
    pub async fn get_translation(
        &self,
        tenant_id: Option<Uuid>,
        lang: &str,
        key: &str,
    ) -> anyhow::Result<Option<String>> {
        let result = sqlx::query_scalar::<_, String>(
            r#"
            SELECT value FROM i18n_translations
            WHERE (tenant_id = $1 OR tenant_id IS NULL)
            AND lang = $2
            AND key = $3
            ORDER BY tenant_id NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(lang)
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// Get all translations for a language
    pub async fn get_translations_for_lang(
        &self,
        tenant_id: Option<Uuid>,
        lang: &str,
    ) -> anyhow::Result<Vec<TranslationRecord>> {
        let records = sqlx::query_as::<_, TranslationRecord>(
            r#"
            SELECT * FROM i18n_translations
            WHERE (tenant_id = $1 OR tenant_id IS NULL)
            AND lang = $2
            ORDER BY key
            "#,
        )
        .bind(tenant_id)
        .bind(lang)
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }

    /// Get all translations for a tenant
    pub async fn get_translations_for_tenant(
        &self,
        tenant_id: Option<Uuid>,
    ) -> anyhow::Result<Vec<TranslationRecord>> {
        let records = sqlx::query_as::<_, TranslationRecord>(
            r#"
            SELECT * FROM i18n_translations
            WHERE tenant_id = $1 OR tenant_id IS NULL
            ORDER BY lang, key
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }

    /// Upsert a translation
    pub async fn set_translation(
        &self,
        tenant_id: Option<Uuid>,
        lang: &str,
        key: &str,
        value: &str,
    ) -> anyhow::Result<TranslationRecord> {
        let record = sqlx::query_as::<_, TranslationRecord>(
            r#"
            INSERT INTO i18n_translations (id, tenant_id, lang, key, value, updated_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $6)
            ON CONFLICT (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), lang, key)
            DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
            RETURNING *
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(lang)
        .bind(key)
        .bind(value)
        .bind(Utc::now())
        .fetch_one(&self.pool)
        .await?;

        Ok(record)
    }

    /// Delete a translation
    pub async fn delete_translation(
        &self,
        tenant_id: Option<Uuid>,
        lang: &str,
        key: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM i18n_translations
            WHERE (tenant_id = $1 OR tenant_id IS NULL)
            AND lang = $2
            AND key = $3
            "#,
        )
        .bind(tenant_id)
        .bind(lang)
        .bind(key)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Bulk import translations
    pub async fn bulk_import(
        &self,
        tenant_id: Option<Uuid>,
        lang: &str,
        translations: Vec<(String, String)>,
    ) -> anyhow::Result<usize> {
        let mut count = 0;

        for (key, value) in translations {
            self.set_translation(tenant_id, lang, &key, &value).await?;
            count += 1;
        }

        Ok(count)
    }

    /// Get translation statistics
    pub async fn get_stats(
        &self,
        tenant_id: Option<Uuid>,
    ) -> anyhow::Result<Vec<TranslationStats>> {
        let stats = sqlx::query_as::<_, TranslationStats>(
            r#"
            SELECT 
                lang,
                COUNT(*) as count,
                MAX(updated_at) as last_updated
            FROM i18n_translations
            WHERE tenant_id = $1 OR tenant_id IS NULL
            GROUP BY lang
            ORDER BY lang
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(stats)
    }

    /// Search translations by key pattern
    pub async fn search_translations(
        &self,
        tenant_id: Option<Uuid>,
        pattern: &str,
    ) -> anyhow::Result<Vec<TranslationRecord>> {
        let records = sqlx::query_as::<_, TranslationRecord>(
            r#"
            SELECT * FROM i18n_translations
            WHERE (tenant_id = $1 OR tenant_id IS NULL)
            AND (key ILIKE $2 OR value ILIKE $2)
            ORDER BY lang, key
            "#,
        )
        .bind(tenant_id)
        .bind(format!("%{}%", pattern))
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }
}

/// Translation statistics
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TranslationStats {
    pub lang: String,
    pub count: i64,
    pub last_updated: Option<DateTime<Utc>>,
}

/// Import/Export format for translations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationExport {
    pub lang: String,
    pub translations: Vec<TranslationEntry>,
    pub exported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationEntry {
    pub key: String,
    pub value: String,
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests would require a test database
    // For now, we just verify the struct definitions compile correctly

    #[test]
    fn test_translation_record() {
        let record = TranslationRecord {
            id: Uuid::new_v4(),
            tenant_id: Some(Uuid::new_v4()),
            lang: "en".to_string(),
            key: "errors.invalid_credentials".to_string(),
            value: "Invalid credentials".to_string(),
            updated_at: Utc::now(),
            created_at: Utc::now(),
        };

        assert_eq!(record.lang, "en");
        assert_eq!(record.key, "errors.invalid_credentials");
    }

    #[test]
    fn test_translation_export() {
        let export = TranslationExport {
            lang: "es".to_string(),
            translations: vec![
                TranslationEntry {
                    key: "hello".to_string(),
                    value: "Hola".to_string(),
                    updated_at: Some(Utc::now()),
                },
            ],
            exported_at: Utc::now(),
        };

        assert_eq!(export.lang, "es");
        assert_eq!(export.translations.len(), 1);
    }
}
