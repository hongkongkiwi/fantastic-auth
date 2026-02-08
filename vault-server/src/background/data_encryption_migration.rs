use std::time::Duration;

use crate::db::{set_connection_context, Database};
use crate::security::TenantKeyService;
use crate::state::AppState;
use tracing::{error, info, warn};

pub fn spawn_worker(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = run_once(&state).await {
                error!(error = %err, "Data encryption migration failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

async fn run_once(state: &AppState) -> anyhow::Result<()> {
    let tenant_ids = fetch_all_tenants(&state.db).await?;
    if tenant_ids.is_empty() {
        return Ok(());
    }

    for tenant_id in tenant_ids {
        let tenant_id_str = tenant_id.to_string();
        let tenant_key = state
            .tenant_key_service
            .get_data_key(&tenant_id_str)
            .await?;

        migrate_mfa_methods(state, &tenant_id_str, &tenant_key).await?;
        migrate_mfa_config(state, &tenant_id_str, &tenant_key).await?;
        migrate_webhook_secrets(state, &tenant_id_str, &tenant_key).await?;
        migrate_ldap_passwords(state, &tenant_id_str, &tenant_key).await?;
    }

    Ok(())
}

async fn fetch_all_tenants(db: &Database) -> anyhow::Result<Vec<uuid::Uuid>> {
    let mut conn = db.acquire().await?;
    sqlx::query("SET ROLE vault_service").execute(&mut *conn).await?;
    let rows: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM tenants")
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows)
}

async fn migrate_mfa_methods(
    state: &AppState,
    tenant_id: &str,
    tenant_key: &[u8],
) -> anyhow::Result<()> {
    let mut conn = state.db.acquire().await?;
    set_connection_context(&mut conn, tenant_id).await?;

    let rows: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, secret_encrypted FROM user_mfa_methods WHERE tenant_id = $1::uuid AND secret_encrypted IS NOT NULL",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    for (id, encrypted) in rows {
        let plaintext = match decrypt_with_keys(&encrypted, tenant_key, &state.data_encryption_key) {
            Some(value) => value,
            None => {
                warn!(method_id = %id, tenant_id = tenant_id, "Skipping MFA secret migration: unable to decrypt");
                continue;
            }
        };

        let reencrypted = crate::security::encryption::encrypt_to_base64(tenant_key, &plaintext)?;
        sqlx::query("UPDATE user_mfa_methods SET secret_encrypted = $1 WHERE id = $2")
            .bind(reencrypted)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }

    Ok(())
}

async fn migrate_mfa_config(
    state: &AppState,
    tenant_id: &str,
    tenant_key: &[u8],
) -> anyhow::Result<()> {
    let mut conn = state.db.acquire().await?;
    set_connection_context(&mut conn, tenant_id).await?;

    let rows: Vec<(uuid::Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT id, mfa_config FROM users WHERE tenant_id = $1::uuid",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    for (user_id, mut config) in rows {
        let mut changed = false;
        if let Some(totp) = config.get_mut("totp") {
            if let Some(secret_value) = totp.get("secret").and_then(|v| v.as_str()) {
                if let Some(plaintext) = decrypt_with_keys(secret_value, tenant_key, &state.data_encryption_key) {
                    let reencrypted = crate::security::encryption::encrypt_to_base64(tenant_key, &plaintext)?;
                    if let Some(totp_obj) = totp.as_object_mut() {
                        totp_obj.insert("secret".to_string(), serde_json::Value::String(reencrypted));
                        changed = true;
                    }
                }
            }
        }

        if changed {
            sqlx::query("UPDATE users SET mfa_config = $1 WHERE id = $2 AND tenant_id = $3")
                .bind(&config)
                .bind(user_id)
                .bind(tenant_id)
                .execute(&mut *conn)
                .await?;
        }
    }

    Ok(())
}

async fn migrate_webhook_secrets(
    state: &AppState,
    tenant_id: &str,
    tenant_key: &[u8],
) -> anyhow::Result<()> {
    let mut conn = state.db.acquire().await?;
    set_connection_context(&mut conn, tenant_id).await?;

    let rows: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, secret FROM webhook_endpoints WHERE tenant_id = $1::uuid AND deleted_at IS NULL",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    for (id, secret) in rows {
        let plaintext = decrypt_with_keys(&secret, tenant_key, &state.data_encryption_key)
            .or_else(|| Some(secret.as_bytes().to_vec()));

        let plaintext = match plaintext {
            Some(value) => value,
            None => continue,
        };
        let encrypted = crate::security::encryption::encrypt_to_base64(tenant_key, &plaintext)?;
        sqlx::query("UPDATE webhook_endpoints SET secret = $1 WHERE id = $2")
            .bind(encrypted)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }

    Ok(())
}

async fn migrate_ldap_passwords(
    state: &AppState,
    tenant_id: &str,
    tenant_key: &[u8],
) -> anyhow::Result<()> {
    let mut conn = state.db.acquire().await?;
    set_connection_context(&mut conn, tenant_id).await?;

    let rows: Vec<(uuid::Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, bind_password_encrypted FROM ldap_connections WHERE tenant_id = $1::uuid",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    for (id, maybe_secret) in rows {
        let secret = match maybe_secret {
            Some(value) => value,
            None => continue,
        };

        let plaintext = decrypt_with_keys(&secret, tenant_key, &state.data_encryption_key)
            .or_else(|| Some(secret.as_bytes().to_vec()));

        let plaintext = match plaintext {
            Some(value) => value,
            None => continue,
        };
        let encrypted = crate::security::encryption::encrypt_to_base64(tenant_key, &plaintext)?;
        sqlx::query("UPDATE ldap_connections SET bind_password_encrypted = $1 WHERE id = $2")
            .bind(encrypted)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }

    Ok(())
}

fn decrypt_with_keys(
    value: &str,
    tenant_key: &[u8],
    master_key: &[u8],
) -> Option<Vec<u8>> {
    if let Ok(bytes) = crate::security::encryption::decrypt_from_base64(tenant_key, value) {
        return Some(bytes);
    }
    if let Ok(bytes) = crate::security::encryption::decrypt_from_base64(master_key, value) {
        return Some(bytes);
    }
    None
}
