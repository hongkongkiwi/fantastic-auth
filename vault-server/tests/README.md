# Vault Server Integration Tests

This directory contains comprehensive integration tests for the Vault authentication server.

## Test Structure

```
tests/
├── common/
│   └── mod.rs          # Shared test utilities, fixtures, and helpers
├── auth_flow_test.rs   # Authentication flow tests (register, login, logout, etc.)
├── oauth_test.rs       # OAuth 2.0 and OIDC tests
├── mfa_test.rs         # Multi-factor authentication tests (TOTP, backup codes)
├── admin_test.rs       # Admin API tests (user management)
├── security_test.rs    # Security tests (headers, CORS, rate limiting, input validation)
├── api_contract_test.rs # API response format validation
└── middleware_test.rs  # Middleware integration tests
```

## Prerequisites

### Database Setup

Tests require a PostgreSQL database. By default, tests use:

```
TEST_DATABASE_URL=postgres://vault:vault@localhost:5432/vault_test
```

To set up the test database:

```bash
# Create test database
createdb vault_test

# Or use the full URL format
export TEST_DATABASE_URL="postgres://user:password@localhost:5432/vault_test"
```

### Redis (Optional)

Some tests for distributed rate limiting require Redis. If Redis is not available, tests will fall back to in-memory rate limiting.

```bash
export REDIS_URL="redis://localhost:6379"
```

## Running Tests

### Run all tests:

```bash
cd vault-server
cargo test
```

### Run specific test file:

```bash
cargo test --test auth_flow_test
cargo test --test oauth_test
cargo test --test mfa_test
cargo test --test admin_test
cargo test --test security_test
cargo test --test api_contract_test
cargo test --test middleware_test
```

### Run specific test:

```bash
cargo test test_register_login_flow
cargo test test_oauth_redirect_google
cargo test test_totp_enrollment
```

### Run tests that don't require database:

```bash
cargo test -- --skip 'test_db'
```

### Run with output:

```bash
cargo test -- --nocapture
```

### Run ignored tests (requires database):

```bash
cargo test -- --ignored
```

## Test Categories

### 1. Authentication Flow Tests (`auth_flow_test.rs`)

Tests complete user journeys:
- User registration and validation
- Login with credentials
- Token refresh
- Password reset flow
- Email verification
- Magic link authentication
- Logout and session invalidation
- Concurrent sessions
- Rate limiting on auth endpoints

**Key Tests:**
- `test_register_login_flow` - Full registration → login → logout flow
- `test_password_reset_flow` - Password reset via email token
- `test_token_refresh` - Access token refresh using refresh token
- `test_concurrent_sessions` - Multiple device session handling

### 2. OAuth Tests (`oauth_test.rs`)

Tests OAuth 2.0 and OpenID Connect:
- OAuth redirect URL generation
- OAuth callback handling
- State parameter validation (CSRF protection)
- PKCE flow
- SSO redirect
- SAML metadata

**Key Tests:**
- `test_oauth_redirect_google` - Google OAuth redirect generation
- `test_oauth_state_generation` - State parameter uniqueness
- `test_oauth_flow_mocked` - Complete OAuth flow with mocked provider

### 3. MFA Tests (`mfa_test.rs`)

Tests multi-factor authentication:
- TOTP enrollment and QR code generation
- TOTP verification
- Backup codes generation and usage
- WebAuthn registration
- MFA disable flow

**Key Tests:**
- `test_totp_enrollment` - TOTP setup with secret and backup codes
- `test_backup_codes_generation` - Backup codes generation
- `test_webauthn_registration_begin` - WebAuthn challenge generation

### 4. Admin Tests (`admin_test.rs`)

Tests administrative user management:
- User listing with pagination and filters
- User creation
- User updates
- User suspension/activation
- Session revocation

**Key Tests:**
- `test_admin_list_users` - User listing with pagination
- `test_admin_suspend_user` - User suspension
- `test_admin_revoke_all_sessions` - Session revocation

### 5. Security Tests (`security_test.rs`)

Tests security-related functionality:
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- CORS configuration
- Rate limiting
- Input validation
- SQL injection protection
- XSS protection
- Path traversal protection
- JWT tampering detection

**Key Tests:**
- `test_security_headers` - Security headers presence
- `test_cors_preflight` - CORS preflight handling
- `test_sql_injection_protection` - SQL injection attempt handling
- `test_xss_protection` - XSS sanitization

### 6. API Contract Tests (`api_contract_test.rs`)

Tests API response formats:
- Error response format consistency
- Success response format consistency
- Validation error details
- Pagination format

**Key Tests:**
- `test_validation_error_format` - Error response structure
- `test_auth_response_format` - Auth success response structure
- `test_pagination_response_format` - Paginated response structure

### 7. Middleware Tests (`middleware_test.rs`)

Tests middleware functionality:
- Auth middleware
- Rate limiting middleware
- CORS middleware
- Security headers middleware
- Admin/superadmin role checks

**Key Tests:**
- `test_auth_middleware_no_header` - Unauthorized request handling
- `test_rate_limit_exceeded` - Rate limit enforcement
- `test_cors_headers` - CORS headers presence

## Test Utilities (`common/mod.rs`)

The `common` module provides shared utilities:

### TestServer

A test server wrapper that provides convenient methods for making requests:

```rust
let ctx = TestContext::new().await?;
let response = ctx.server.get("/health").await;
let response = ctx.server.post("/api/v1/login", json!({...})).await;
let response = ctx.server.get_with_auth("/api/v1/me", &token).await;
```

### TestContext

A test context that handles setup and provides helper methods:

```rust
let ctx = TestContext::new().await?;
let (user, access_token, refresh_token) = ctx.create_user_and_login().await?;
```

### TestUser

Generates test user credentials:

```rust
let user = TestUser::new();
// user.email - unique test email
// user.password - strong test password
// user.name - test user name
// user.register_json() - JSON for registration
// user.login_json() - JSON for login
```

### WireMock Helpers

For mocking external services:

```rust
use common::wiremock_helpers::*;

let mock_server = mock_oauth_provider().await;
mock_oauth_token(&mock_server).await;
mock_oauth_userinfo(&mock_server, "user@example.com").await;
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TEST_DATABASE_URL` | PostgreSQL connection string | `postgres://vault:vault@localhost:5432/vault_test` |
| `REDIS_URL` | Redis connection string (optional) | None |
| `RUST_LOG` | Log level for tests | `warn` |

## Best Practices

1. **Always use `unique_email()`** to generate unique emails to avoid conflicts between tests
2. **Clean up resources** - Tests should clean up created users when possible
3. **Handle database unavailability** - Tests skip gracefully when database is unavailable
4. **Use test helpers** - Leverage `TestContext` and `TestServer` for common operations
5. **Assert response formats** - Verify both status codes and response body structure

## Troubleshooting

### Tests failing with "database not available"

Ensure PostgreSQL is running and the test database exists:

```bash
# Check PostgreSQL status
pg_isready

# Create test database
createdb vault_test

# Or use custom connection string
export TEST_DATABASE_URL="postgres://user:password@host:5432/vault_test"
```

### Rate limiting tests failing

Rate limiting tests may be flaky depending on timing. They are designed to pass whether or not rate limiting triggers during the test run.

### OAuth tests skipped

OAuth tests require OAuth provider configuration. They will skip if providers are not configured.

## Test Coverage

The test suite covers:

- ✅ Registration and authentication flows
- ✅ Token management (access, refresh)
- ✅ Password reset and email verification
- ✅ OAuth 2.0 / OIDC integration
- ✅ Multi-factor authentication (TOTP, WebAuthn, backup codes)
- ✅ Admin user management
- ✅ Session management
- ✅ Security headers and CORS
- ✅ Rate limiting
- ✅ Input validation and sanitization
- ✅ API response formats

## Adding New Tests

When adding new tests:

1. Place tests in the appropriate file based on category
2. Use `init_tracing()` at the start of each test
3. Check database availability with `test_db_available().await`
4. Use `TestContext` for common setup
5. Clean up any resources created during the test

Example:

```rust
#[tokio::test]
async fn test_new_feature() {
    common::init_tracing();
    
    if !common::test_db_available().await {
        eprintln!("Skipping test: database not available");
        return;
    }
    
    let ctx = TestContext::new().await.expect("Failed to create test context");
    
    // Your test code here
    let response = ctx.server.get("/api/v1/new-endpoint").await;
    assert_eq!(response.status(), StatusCode::OK);
}
```
