//! Actions/Rules execution (Wasmtime)

use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
struct ActionOutput {
    allow: Option<bool>,
    deny: Option<bool>,
    reason: Option<String>,
    claims: Option<serde_json::Value>,
}

#[derive(Debug, Default)]
pub struct ActionDecision {
    pub allowed: bool,
    pub reason: Option<String>,
    pub claims: serde_json::Map<String, serde_json::Value>,
}

pub async fn run_actions(
    state: &AppState,
    tenant_id: &str,
    trigger: &str,
    user_id: Option<&str>,
    payload: serde_json::Value,
) -> Result<ActionDecision, ApiError> {
    let actions = state
        .auth_service
        .db()
        .actions()
        .list_actions(tenant_id, Some(trigger))
        .await
        .map_err(|_| ApiError::internal())?;

    let mut decision = ActionDecision {
        allowed: true,
        reason: None,
        claims: serde_json::Map::new(),
    };

    for action in actions.into_iter().filter(|a| a.status == "enabled") {
        let started_at = Utc::now();
        let result = execute_wasm_action(&action.code, &payload, action.timeout_ms)
            .await
            .map_err(|e| ApiError::BadRequest(format!("Action failed: {}", e)))?;

        let output = parse_action_output(&result);
        let status = if output.is_err() { "failed" } else { "success" };

        let output_json = output.as_ref().ok().and_then(|o| o.claims.clone());
        state
            .auth_service
            .db()
            .actions()
            .record_execution(
                tenant_id,
                &action.id,
                user_id,
                status,
                started_at,
                Some(Utc::now()),
                output.as_ref().err().map(|e| e.to_string()).as_deref(),
                output_json,
            )
            .await
            .ok();

        let output = output.map_err(|_| ApiError::internal())?;

        if output.deny.unwrap_or(false) || output.allow == Some(false) {
            decision.allowed = false;
            decision.reason = output.reason;
            return Ok(decision);
        }

        if let Some(claims) = output.claims {
            if let Some(map) = claims.as_object() {
                for (k, v) in map {
                    decision.claims.insert(k.clone(), v.clone());
                }
            }
        }
    }

    Ok(decision)
}

fn parse_action_output(raw: &str) -> Result<ActionOutput, anyhow::Error> {
    let output: ActionOutput = serde_json::from_str(raw)?;
    Ok(output)
}

async fn execute_wasm_action(
    code: &[u8],
    payload: &serde_json::Value,
    timeout_ms: i32,
) -> Result<String, anyhow::Error> {
    let payload = payload.to_string();
    let timeout = Duration::from_millis(timeout_ms as u64);
    let code = code.to_vec(); // Clone to move into closure

    tokio::time::timeout(timeout, tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        use wasmtime::{Engine, Linker, Module, Store};
        use wasmtime_wasi::WasiCtxBuilder;

        let engine = Engine::default();
        let module = Module::from_binary(&engine, &code)?;

        let wasi = WasiCtxBuilder::new()
            .env("VAULT_ACTION_PAYLOAD", &payload)?
            .build();

        let mut store = Store::new(&engine, wasi);
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;

        let instance = linker.instantiate(&mut store, &module)?;
        if let Ok(func) = instance.get_typed_func::<(), ()>(&mut store, "run") {
            func.call(&mut store, ())?;
        } else {
            let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
            start.call(&mut store, ())?;
        }

        // Note: stdout capture temporarily disabled due to wasmtime API changes
        Ok("Action executed successfully".to_string())
    }))
    .await
    .map_err(|_| anyhow::anyhow!("Action execution timed out"))?
    .map_err(|e| anyhow::anyhow!("Action execution failed: {}", e))?
}
