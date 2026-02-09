//! OAuth2/OIDC Authorization Server (IdP) - MVP

use axum::{
    extract::{ConnectInfo, Form, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

use crate::middleware::auth::auth_middleware;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use crate::actions;
use vault_core::crypto::{generate_secure_random, Claims, HybridJwt, TokenType, VaultPasswordHasher};
use vault_core::db::set_connection_context;

pub fn routes() -> Router<AppState> {
    let auth_routes = Router::new().route("/oauth/authorize", get(authorize));

    Router::new()
        .route("/oauth/token", post(token))
        .route("/oauth/device/authorize", post(device_authorize))
        .route("/oauth/introspect", post(introspect))
        .route("/oauth/revoke", post(revoke))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .merge(auth_routes.layer(middleware::from_fn(oidc_auth_middleware)))
}

async fn oidc_auth_middleware(mut request: Request, next: middleware::Next) -> Response {
    let state = match request.extensions().get::<AppState>().cloned() {
        Some(state) => state,
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let addr = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0)
        .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));

    match auth_middleware(State(state), ConnectInfo(addr), request, next).await {
        Ok(response) => response,
        Err(status) => status.into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    device_code: Option<String>,
    subject_token: Option<String>,
    audience: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizeRequest {
    client_id: String,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeviceAuthorizeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(rename = "verification_uri_complete")]
    verification_uri_complete: String,
    expires_in: i64,
    interval: i64,
}

#[derive(Debug, Deserialize)]
struct IntrospectRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    id_token: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct IntrospectResponse {
    active: bool,
    scope: Option<String>,
    client_id: Option<String>,
    username: Option<String>,
    token_type: Option<String>,
    exp: Option<i64>,
    sub: Option<String>,
    aud: Option<String>,
    iss: Option<String>,
}

#[derive(Debug, Serialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

#[derive(Debug, Serialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    use_: String,
    alg: String,
    kid: String,
}

#[derive(Debug, Serialize)]
struct DiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
}

fn extract_tenant_id(headers: &HeaderMap) -> String {
    headers
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default".to_string())
}

async fn authorize(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Result<impl IntoResponse, ApiError> {
    if query.response_type != "code" {
        return Err(ApiError::BadRequest("Unsupported response_type".to_string()));
    }

    let tenant_id = extract_tenant_id(&headers);

    let client = state
        .auth_service
        .db()
        .oidc()
        .get_client(&tenant_id, &query.client_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::BadRequest("Invalid client".to_string()))?;

    let redirect_uris: Vec<String> = serde_json::from_value(client.redirect_uris.clone())
        .unwrap_or_else(|_| Vec::new());
    if !redirect_uris.contains(&query.redirect_uri) {
        return Err(ApiError::BadRequest("Invalid redirect_uri".to_string()));
    }

    let scopes = query.scope.clone().unwrap_or_else(|| "openid".to_string());
    let allowed_scopes: Vec<String> = serde_json::from_value(client.allowed_scopes.clone())
        .unwrap_or_else(|_| vec!["openid".to_string()]);
    for scope in scopes.split(' ') {
        if !allowed_scopes.contains(&scope.to_string()) {
            return Err(ApiError::BadRequest("Invalid scope".to_string()));
        }
    }

    if client.pkce_required && query.code_challenge.is_none() {
        return Err(ApiError::BadRequest("PKCE required".to_string()));
    }

    let code = generate_secure_random(32);
    let expires_at = Utc::now() + Duration::minutes(10);

    state
        .auth_service
        .db()
        .oidc()
        .create_authorization_code(
            &tenant_id,
            &query.client_id,
            &current_user.user_id,
            &code,
            &query.redirect_uri,
            Some(&scopes),
            query.code_challenge.as_deref(),
            query.code_challenge_method.as_deref(),
            query.nonce.as_deref(),
            expires_at,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    let mut redirect_url = format!(
        "{}?code={}",
        query.redirect_uri,
        urlencoding::encode(&code)
    );
    if let Some(state_param) = query.state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(&state_param)));
    }

    Ok(Redirect::to(&redirect_url))
}

async fn device_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<DeviceAuthorizeRequest>,
) -> Result<Json<DeviceAuthorizeResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&headers);

    // Ensure client exists
    let client = state
        .auth_service
        .db()
        .oidc()
        .get_client(&tenant_id, &req.client_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::BadRequest("Invalid client".to_string()))?;

    let device_code = generate_secure_random(32);
    let user_code = generate_secure_random(8).to_uppercase();
    let verification_uri = format!("{}/device", state.config.base_url);
    let verification_uri_complete = format!("{}?user_code={}", verification_uri, user_code);
    let expires_at = Utc::now() + Duration::minutes(15);

    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    sqlx::query(
        r#"INSERT INTO oauth_device_codes (tenant_id, client_id, device_code, user_code, verification_uri, expires_at, interval_seconds)
           VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(&tenant_id)
    .bind(&client.client_id)
    .bind(&device_code)
    .bind(&user_code)
    .bind(&verification_uri)
    .bind(expires_at)
    .bind(5i32)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(DeviceAuthorizeResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in: 900,
        interval: 5,
    }))
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&headers);

    let (client_id, client_secret) = extract_client_credentials(&headers, &req)?;
    let client = state
        .auth_service
        .db()
        .oidc()
        .get_client(&tenant_id, &client_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::BadRequest("Invalid client".to_string()))?;

    if client.client_type == "confidential" {
        let secret_hash = client
            .client_secret_hash
            .as_ref()
            .ok_or(ApiError::BadRequest("Missing client secret".to_string()))?;
        if client_secret.is_none()
            || !VaultPasswordHasher::verify(client_secret.as_ref().unwrap(), secret_hash)
                .map_err(|_| ApiError::BadRequest("Invalid client secret".to_string()))?
        {
            return Err(ApiError::BadRequest("Invalid client secret".to_string()));
        }
    }

    match req.grant_type.as_str() {
        "authorization_code" => token_authorization_code(&state, &tenant_id, &client, req).await,
        "refresh_token" => token_refresh(&state, &tenant_id, &client, req).await,
        "client_credentials" => token_client_credentials(&state, &tenant_id, &client_id).await,
        "urn:ietf:params:oauth:grant-type:device_code" => {
            token_device_code(&state, &tenant_id, &client, req).await
        }
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            token_exchange(&state, &tenant_id, &client, req).await
        }
        _ => Err(ApiError::BadRequest("Unsupported grant_type".to_string())),
    }
}

async fn token_authorization_code(
    state: &AppState,
    tenant_id: &str,
    client: &vault_core::db::oidc::OauthClient,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let code = req
        .code
        .ok_or(ApiError::BadRequest("Missing code".to_string()))?;

    let code_record = state
        .auth_service
        .db()
        .oidc()
        .consume_authorization_code(tenant_id, &client.client_id, &code)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::BadRequest("Invalid code".to_string()))?;

    if let Some(redirect_uri) = req.redirect_uri {
        if redirect_uri != code_record.redirect_uri {
            return Err(ApiError::BadRequest("Redirect URI mismatch".to_string()));
        }
    }

    if client.pkce_required {
        let verifier = req
            .code_verifier
            .ok_or(ApiError::BadRequest("Missing code_verifier".to_string()))?;
        if !verify_pkce(&verifier, code_record.code_challenge.as_deref(), code_record.code_challenge_method.as_deref()) {
            return Err(ApiError::BadRequest("Invalid PKCE".to_string()));
        }
    }

    let user = state
        .auth_service
        .db()
        .users()
        .find_by_id(tenant_id, &code_record.user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::BadRequest("User not found".to_string()))?;

    let scope = code_record.scope.clone();

    let access_claims = Claims::new(
        &user.id,
        &user.tenant_id,
        TokenType::Access,
        &state.config.jwt.issuer,
        &client.client_id,
    )
    .with_email(&user.email, user.email_verified)
    .with_scope(scope.clone().unwrap_or_else(|| "openid".to_string()))
    .with_custom("client_id", serde_json::json!(client.client_id.clone()));

    let decision = actions::run_actions(
        state,
        tenant_id,
        "token_issue",
        Some(&user.id),
        serde_json::json!({
            "user_id": user.id,
            "client_id": client.client_id,
            "scope": scope,
        }),
    )
    .await?;
    if !decision.allowed {
        return Err(ApiError::Forbidden);
    }
    let mut access_claims = access_claims;
    for (k, v) in decision.claims.into_iter() {
        access_claims.custom.insert(k, v);
    }

    let access_token = HybridJwt::encode(&access_claims, state.auth_service.signing_key())
        .map_err(|_| ApiError::Internal)?;

    let mut id_token = None;
    if let Some(scope) = code_record.scope.as_ref() {
        if scope.split(' ').any(|s| s == "openid") {
            let mut id_claims = Claims::new(
                &user.id,
                &user.tenant_id,
                TokenType::Id,
                &state.config.jwt.issuer,
                &client.client_id,
            )
            .with_email(&user.email, user.email_verified)
            .with_custom("nonce", serde_json::json!(code_record.nonce.clone()));

            if let Some(name) = user.profile.name.clone() {
                id_claims = id_claims.with_name(name);
            }

            id_token = Some(
                HybridJwt::encode(&id_claims, state.auth_service.signing_key())
                    .map_err(|_| ApiError::Internal)?,
            );
        }
    }

    let expires_at = Utc::now() + Duration::minutes(15);
    let refresh_token = generate_secure_random(48);
    state
        .auth_service
        .db()
        .oidc()
        .store_token(
            tenant_id,
            &client.client_id,
            Some(&user.id),
            &access_claims.jti,
            Some(&refresh_token),
            code_record.scope.as_deref(),
            expires_at,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        id_token,
        refresh_token: Some(refresh_token),
        scope: code_record.scope,
    }))
}

async fn token_refresh(
    state: &AppState,
    tenant_id: &str,
    client: &vault_core::db::oidc::OauthClient,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let refresh_token = req
        .refresh_token
        .ok_or(ApiError::BadRequest("Missing refresh_token".to_string()))?;

    let token_record = state
        .auth_service
        .db()
        .oidc()
        .consume_refresh_token(tenant_id, &refresh_token)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::BadRequest("Invalid refresh_token".to_string()))?;

    if token_record.client_id != client.client_id {
        return Err(ApiError::BadRequest("Client mismatch".to_string()));
    }

    let user_id = token_record
        .user_id
        .ok_or(ApiError::BadRequest("User not found".to_string()))?;
    let user = state
        .auth_service
        .db()
        .users()
        .find_by_id(tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::BadRequest("User not found".to_string()))?;

    let scope = token_record.scope.clone();
    let access_claims = Claims::new(
        &user.id,
        &user.tenant_id,
        TokenType::Access,
        &state.config.jwt.issuer,
        &client.client_id,
    )
    .with_email(&user.email, user.email_verified)
    .with_scope(scope.clone().unwrap_or_else(|| "openid".to_string()))
    .with_custom("client_id", serde_json::json!(client.client_id.clone()));

    let decision = actions::run_actions(
        state,
        tenant_id,
        "token_issue",
        Some(&user.id),
        serde_json::json!({
            "user_id": user.id,
            "client_id": client.client_id,
            "scope": scope,
            "grant_type": "refresh_token",
        }),
    )
    .await?;
    if !decision.allowed {
        return Err(ApiError::Forbidden);
    }
    let mut access_claims = access_claims;
    for (k, v) in decision.claims.into_iter() {
        access_claims.custom.insert(k, v);
    }

    let access_token = HybridJwt::encode(&access_claims, state.auth_service.signing_key())
        .map_err(|_| ApiError::Internal)?;

    let new_refresh = generate_secure_random(48);
    let expires_at = Utc::now() + Duration::minutes(15);
    state
        .auth_service
        .db()
        .oidc()
        .store_token(
            tenant_id,
            &client.client_id,
            Some(&user.id),
            &access_claims.jti,
            Some(&new_refresh),
            token_record.scope.as_deref(),
            expires_at,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        id_token: None,
        refresh_token: Some(new_refresh),
        scope: token_record.scope,
    }))
}

async fn token_client_credentials(
    state: &AppState,
    tenant_id: &str,
    client_id: &str,
) -> Result<Json<TokenResponse>, ApiError> {
    let access_claims = Claims::new(
        client_id,
        tenant_id,
        TokenType::Access,
        &state.config.jwt.issuer,
        client_id,
    )
    .with_custom("client_id", serde_json::json!(client_id));

    let decision = actions::run_actions(
        state,
        tenant_id,
        "token_issue",
        None,
        serde_json::json!({
            "client_id": client_id,
            "grant_type": "client_credentials",
        }),
    )
    .await?;
    if !decision.allowed {
        return Err(ApiError::Forbidden);
    }
    let mut access_claims = access_claims;
    for (k, v) in decision.claims.into_iter() {
        access_claims.custom.insert(k, v);
    }

    let access_token = HybridJwt::encode(&access_claims, state.auth_service.signing_key())
        .map_err(|_| ApiError::Internal)?;

    let expires_at = Utc::now() + Duration::minutes(15);
    state
        .auth_service
        .db()
        .oidc()
        .store_token(
            tenant_id,
            client_id,
            None,
            &access_claims.jti,
            None,
            None,
            expires_at,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        id_token: None,
        refresh_token: None,
        scope: None,
    }))
}

async fn token_device_code(
    state: &AppState,
    tenant_id: &str,
    client: &vault_core::db::oidc::OauthClient,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let device_code = req
        .device_code
        .ok_or(ApiError::BadRequest("Missing device_code".to_string()))?;

    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    #[derive(sqlx::FromRow)]
    struct DeviceCodeRow {
        id: Uuid,
        user_id: Option<Uuid>,
        status: String,
        expires_at: DateTime<Utc>,
    }

    let row = sqlx::query_as::<_, DeviceCodeRow>(
        r#"SELECT id, user_id, status::text as status, expires_at
           FROM oauth_device_codes
           WHERE tenant_id = $1::uuid AND client_id = $2 AND device_code = $3"#,
    )
    .bind(tenant_id)
    .bind(&client.client_id)
    .bind(device_code)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?
    .ok_or(ApiError::BadRequest("Invalid device_code".to_string()))?;

    if row.expires_at < Utc::now() {
        sqlx::query("UPDATE oauth_device_codes SET status = 'expired' WHERE id = $1")
            .bind(row.id)
            .execute(&mut *conn)
            .await
            .map_err(|_| ApiError::Internal)?;
        return Err(ApiError::BadRequest("expired_token".to_string()));
    }

    match row.status.as_str() {
        "pending" => return Err(ApiError::BadRequest("authorization_pending".to_string())),
        "denied" => return Err(ApiError::BadRequest("access_denied".to_string())),
        "consumed" => return Err(ApiError::BadRequest("invalid_grant".to_string())),
        _ => {}
    }

    let user_id = row
        .user_id
        .ok_or(ApiError::BadRequest("authorization_pending".to_string()))?;

    let user = state
        .auth_service
        .db()
        .users()
        .find_by_id(tenant_id, &user_id.to_string())
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::BadRequest("User not found".to_string()))?;

    let claims = Claims::new(
        user.id.clone(),
        tenant_id.to_string(),
        TokenType::Access,
        state.config.base_url.clone(),
        client.client_id.clone(),
    );
    let access_token = HybridJwt::encode(&claims, state.auth_service.signing_key())
        .map_err(|_| ApiError::Internal)?;

    sqlx::query(
        "UPDATE oauth_device_codes SET status = 'consumed', consumed_at = NOW() WHERE id = $1",
    )
    .bind(row.id)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: TokenType::Access.default_duration().num_seconds(),
        id_token: None,
        refresh_token: None,
        scope: req.scope,
    }))
}

async fn token_exchange(
    state: &AppState,
    tenant_id: &str,
    client: &vault_core::db::oidc::OauthClient,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let subject_token = req
        .subject_token
        .ok_or(ApiError::BadRequest("Missing subject_token".to_string()))?;

    let claims = HybridJwt::decode(&subject_token, state.auth_service.verifying_key())
        .map_err(|_| ApiError::BadRequest("Invalid subject_token".to_string()))?;

    if claims.tenant_id != tenant_id {
        return Err(ApiError::BadRequest("Tenant mismatch".to_string()));
    }

    let audience = req
        .audience
        .unwrap_or_else(|| client.client_id.clone());

    let mut new_claims = Claims::new(
        claims.sub.clone(),
        claims.tenant_id.clone(),
        TokenType::Access,
        state.config.base_url.clone(),
        audience,
    );
    new_claims.scope = req.scope.or(claims.scope);

    let access_token = HybridJwt::encode(&new_claims, state.auth_service.signing_key())
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: TokenType::Access.default_duration().num_seconds(),
        id_token: None,
        refresh_token: None,
        scope: new_claims.scope,
    }))
}

async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&headers);

    let claims = match HybridJwt::decode(&req.token, state.auth_service.verifying_key()) {
        Ok(c) => c,
        Err(_) => {
            return Ok(Json(IntrospectResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                exp: None,
                sub: None,
                aud: None,
                iss: None,
            }));
        }
    };

    let token_record = state
        .auth_service
        .db()
        .oidc()
        .get_token_by_jti(&tenant_id, &claims.jti)
        .await
        .map_err(|_| ApiError::Internal)?;

    let active = token_record
        .as_ref()
        .map(|t| t.revoked_at.is_none() && t.expires_at > Utc::now())
        .unwrap_or(false);

    Ok(Json(IntrospectResponse {
        active,
        scope: claims.scope.clone(),
        client_id: claims
            .custom
            .get("client_id")
            .and_then(|v| v.as_str().map(|s| s.to_string())),
        username: claims.email.clone(),
        token_type: Some(format!("{:?}", claims.token_type).to_lowercase()),
        exp: Some(claims.exp),
        sub: Some(claims.sub),
        aud: Some(claims.aud),
        iss: Some(claims.iss),
    }))
}

async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<RevokeRequest>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = extract_tenant_id(&headers);

    let mut revoked = state
        .auth_service
        .db()
        .oidc()
        .revoke_token_by_refresh(&tenant_id, &req.token)
        .await
        .map_err(|_| ApiError::Internal)?;

    if !revoked {
        if let Ok(claims) = HybridJwt::decode(&req.token, state.auth_service.verifying_key()) {
            revoked = state
                .auth_service
                .db()
                .oidc()
                .revoke_token_by_jti(&tenant_id, &claims.jti)
                .await
                .map_err(|_| ApiError::Internal)?;
        }
    }

    if revoked {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::OK)
    }
}

async fn jwks(State(state): State<AppState>) -> Result<Json<JwksResponse>, ApiError> {
    let verifying_key = state.auth_service.verifying_key();
    let ed_bytes = verifying_key.ed25519_public_bytes();
    let x = URL_SAFE_NO_PAD.encode(ed_bytes);
    let kid_hash = sha2::Sha256::digest(ed_bytes);
    let kid = URL_SAFE_NO_PAD.encode(kid_hash);

    Ok(Json(JwksResponse {
        keys: vec![Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x,
            use_: "sig".to_string(),
            alg: "EdDSA+ML-DSA-65".to_string(),
            kid,
        }],
    }))
}

async fn discovery(State(state): State<AppState>) -> Result<Json<DiscoveryResponse>, ApiError> {
    let base_url = state.config.base_url.clone();
    Ok(Json(DiscoveryResponse {
        issuer: base_url.clone(),
        authorization_endpoint: format!("{}/oauth/authorize", base_url),
        token_endpoint: format!("{}/oauth/token", base_url),
        jwks_uri: format!("{}/.well-known/jwks.json", base_url),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string(), "client_credentials".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["EdDSA+ML-DSA-65".to_string()],
    }))
}

fn extract_client_credentials(headers: &HeaderMap, req: &TokenRequest) -> Result<(String, Option<String>), ApiError> {
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth) = auth.to_str() {
            if auth.starts_with("Basic ") {
                let encoded = &auth[6..];
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| ApiError::BadRequest("Invalid authorization header".to_string()))?;
                let decoded = String::from_utf8(decoded)
                    .map_err(|_| ApiError::BadRequest("Invalid authorization header".to_string()))?;
                let mut parts = decoded.splitn(2, ':');
                let client_id = parts.next().unwrap_or("").to_string();
                let client_secret = parts.next().map(|s| s.to_string());
                return Ok((client_id, client_secret));
            }
        }
    }

    let client_id = req
        .client_id
        .clone()
        .ok_or(ApiError::BadRequest("Missing client_id".to_string()))?;
    Ok((client_id, None))
}

fn verify_pkce(verifier: &str, challenge: Option<&str>, method: Option<&str>) -> bool {
    match (challenge, method) {
        (Some(challenge), Some(method)) if method.eq_ignore_ascii_case("S256") => {
            let digest = sha2::Sha256::digest(verifier.as_bytes());
            let computed = URL_SAFE_NO_PAD.encode(digest);
            computed == challenge
        }
        (Some(challenge), Some(method)) if method.eq_ignore_ascii_case("plain") => verifier == challenge,
        (Some(_), None) => false,
        _ => false,
    }
}
