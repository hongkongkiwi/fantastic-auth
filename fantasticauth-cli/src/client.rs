//! HTTP Client for Vault API

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

/// Vault API Client
pub struct VaultClient {
    client: reqwest::Client,
    base_url: String,
    token: Option<String>,
    tenant_id: Option<String>,
}

impl VaultClient {
    /// Create a new Vault API client
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            base_url: base_url.into(),
            token: None,
            tenant_id: None,
        }
    }

    /// Set authentication token
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Set tenant ID
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Build request with default headers
    fn build_request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}/api/v1{}", self.base_url.trim_end_matches('/'), path);
        let mut request = self.client.request(method, &url);

        request = request.header("Content-Type", "application/json");

        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        if let Some(tenant_id) = &self.tenant_id {
            request = request.header("X-Tenant-ID", tenant_id);
        }

        request
    }

    /// Send GET request
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .build_request(reqwest::Method::GET, path)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    /// Send GET request with query parameters
    pub async fn get_with_params<T: DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        let mut request = self.build_request(reqwest::Method::GET, path);

        for (key, value) in params {
            request = request.query(&[(*key, *value)]);
        }

        let response = request.send().await.context("Failed to send request")?;
        self.handle_response(response).await
    }

    /// Send POST request
    pub async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let response = self
            .build_request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    /// Send PUT request
    pub async fn put<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let response = self
            .build_request(reqwest::Method::PUT, path)
            .json(body)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    /// Send PATCH request
    pub async fn patch<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let response = self
            .build_request(reqwest::Method::PATCH, path)
            .json(body)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    /// Send DELETE request
    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .build_request(reqwest::Method::DELETE, path)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    /// Handle API response
    async fn handle_response<T: DeserializeOwned>(&self, response: reqwest::Response) -> Result<T> {
        let status = response.status();

        if status.is_success() {
            if status == reqwest::StatusCode::NO_CONTENT {
                return serde_json::from_value(serde_json::Value::Null)
                    .context("Failed to parse empty response");
            }

            response
                .json::<T>()
                .await
                .context("Failed to parse response")
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| format!("HTTP {}", status));
            
            // Try to parse as API error
            if let Ok(api_error) = serde_json::from_str::<types::ErrorResponse>(&error_text) {
                anyhow::bail!("API error: {} - {}", api_error.error.code, api_error.error.message);
            }
            
            anyhow::bail!("API error: {}", error_text)
        }
    }
}

/// API Response types
pub mod types {
    use serde::{Deserialize, Serialize};

    /// User representation
    #[derive(Debug, Serialize, Deserialize)]
    pub struct User {
        pub id: String,
        pub email: String,
        #[serde(rename = "emailVerified")]
        pub email_verified: bool,
        pub name: Option<String>,
        pub status: String,
        #[serde(rename = "mfaEnabled")]
        pub mfa_enabled: bool,
        #[serde(rename = "createdAt")]
        pub created_at: String,
    }

    /// User list response
    #[derive(Debug, Serialize, Deserialize)]
    pub struct UserListResponse {
        pub users: Vec<User>,
        pub total: i64,
        pub page: i64,
        pub per_page: i64,
    }

    /// Organization representation
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Organization {
        pub id: String,
        pub name: String,
        pub slug: String,
        #[serde(rename = "memberCount")]
        pub member_count: i64,
        pub status: String,
        #[serde(rename = "createdAt")]
        pub created_at: String,
    }

    /// Organization list response
    #[derive(Debug, Serialize, Deserialize)]
    pub struct OrgList {
        pub data: Vec<Organization>,
        pub pagination: Pagination,
    }

    /// Pagination information
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Pagination {
        pub page: i64,
        #[serde(rename = "perPage")]
        pub per_page: i64,
        pub total: i64,
        #[serde(rename = "totalPages")]
        pub total_pages: i64,
    }

    /// Session representation
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Session {
        pub id: String,
        #[serde(rename = "ipAddress")]
        pub ip_address: Option<String>,
        #[serde(rename = "userAgent")]
        pub user_agent: Option<String>,
        #[serde(rename = "createdAt")]
        pub created_at: String,
        #[serde(rename = "expiresAt")]
        pub expires_at: String,
        pub current: bool,
    }

    /// Authentication response
    #[derive(Debug, Serialize, Deserialize)]
    pub struct AuthResponse {
        #[serde(rename = "accessToken")]
        pub access_token: String,
        #[serde(rename = "refreshToken")]
        pub refresh_token: String,
        pub user: User,
    }

    /// Error response from API
    #[derive(Debug, Deserialize)]
    pub struct ErrorResponse {
        pub error: ApiError,
    }

    /// API error details
    #[derive(Debug, Deserialize)]
    pub struct ApiError {
        pub code: String,
        pub message: String,
    }

    /// Message response (for success messages)
    #[derive(Debug, Deserialize)]
    pub struct MessageResponse {
        pub message: String,
    }
}
