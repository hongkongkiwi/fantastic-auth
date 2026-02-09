# Comprehensive Rust API Review

**Date:** 2026-02-09  
**Scope:** Complete codebase review of packages/core/rust and packages/apps/server  
**Lines of Code:** ~60,000+ lines across 350+ Rust files

---

## Executive Summary

The FantasticAuth codebase is a well-architected, security-focused authentication system with quantum-resistant cryptography (Ed25519 + ML-DSA-65). The code demonstrates strong security practices including:
- Hybrid post-quantum signatures
- Argon2id password hashing
- Constant-time token comparison
- Comprehensive audit logging
- RLS-based tenant isolation

However, several issues ranging from **critical** to **low** severity have been identified that should be addressed.

---

## Critical Issues 🔴

### 1. Session Binding - Fail-Open Security (CRITICAL)
**Location:** `packages/apps/server/src/middleware/auth.rs:607`

```rust
// Allow on error (fail open for availability)
Ok(BindingAction::Allow)
```

**Issue:** When session binding check encounters an error (e.g., database failure), it defaults to allowing the request. This is a fail-open security posture.

**Impact:** Session hijacking attacks could succeed during database outages or connection issues.

**Recommendation:** Change to fail-closed:
```rust
Err(e) => {
    tracing::error!("Session binding check error: {}", e);
    return Err(StatusCode::UNAUTHORIZED); // Fail closed
}
```

---

### 2. Missing Token Rotation on Refresh (CRITICAL)
**Location:** `packages/core/rust/src/auth/mod.rs:442-511`

**Issue:** The `refresh_token` method validates and returns new tokens but doesn't invalidate the old refresh token. This allows refresh token replay attacks.

**Impact:** Stolen refresh tokens can be used indefinitely until expiry, even after the legitimate user refreshes.

**Recommendation:** Implement refresh token rotation with family tracking:
```rust
// After validating old refresh token, mark it as rotated/revoked
self.token_store.revoke_token(&claims.jti).await?;
// Issue new token pair with same family
```

---

### 3. Insecure JWT Secret Key Loading (CRITICAL)
**Location:** `packages/apps/server/src/state.rs:671-712`

**Issue:** If no encryption key is configured, the system generates an ephemeral key that is lost on restart, invalidating all existing sessions/tokens.

```rust
tracing::warn!("No data encryption key configured; generating ephemeral key for this process");
Ok(vault_core::crypto::generate_random_bytes(32))
```

**Impact:**
- All sessions invalidated on server restart
- Encrypted data becomes unrecoverable
- Potential data loss in production

**Recommendation:** Require explicit key configuration in production; fail to start if key is missing.

---

## High Severity Issues 🟠

### 4. Timing Attack in OAuth Redirect URL Construction (HIGH)
**Location:** Various OAuth provider handlers

**Issue:** OAuth state parameter generation and validation doesn't use constant-time comparison in all paths, potentially leaking state through timing.

**Recommendation:** Ensure all secret comparisons use `subtle::ConstantTimeEq`.

---

### 5. Insufficient Password Hash Verification Error Handling (HIGH)
**Location:** `packages/core/rust/src/crypto/mod.rs:300-315`

**Issue:** Password verification errors are distinguishable from invalid password responses:

```rust
Err(argon2::password_hash::Error::Password) => Ok(false),
Err(e) => Err(VaultError::crypto(format!(...)))
```

**Impact:** Attackers can distinguish between "user not found" and "invalid password" through error responses.

**Recommendation:** Always return identical error responses regardless of failure reason.

---

### 6. Race Condition in Session Limit Check (HIGH)
**Location:** `packages/apps/server/src/state.rs:545-634`

**Issue:** Session limits are checked and then sessions are created in separate, non-atomic operations. Concurrent requests can bypass limits.

**Impact:** Users can exceed session limits through race conditions.

**Recommendation:** Use database-level constraints or atomic operations:
```sql
-- Use advisory locks or serializable transactions
SELECT pg_advisory_xact_lock(hashtext('session_limit:' || user_id));
```

---

### 7. Unvalidated Redirect URLs in OAuth (HIGH)
**Location:** OAuth callback handlers

**Issue:** Redirect URLs from OAuth providers aren't always validated against allowlists, potentially enabling open redirect vulnerabilities.

**Recommendation:** Strictly validate all redirect URLs against pre-registered allowlists.

---

## Medium Severity Issues 🟡

### 8. Missing Request Body Size Limits on Specific Routes (MEDIUM)
**Location:** Various admin routes

**Issue:** While global body limits are configured (10MB), some bulk import/export routes need specific limits but don't have them.

**Recommendation:** Apply per-route body limits for bulk operations:
```rust
.route("/bulk/import", post(import_handler).layer(RequestBodyLimitLayer::new(MAX_IMPORT_SIZE)))
```

---

### 9. Insecure Error Message Information Leakage (MEDIUM)
**Location:** Various locations

**Issue:** Some error messages reveal implementation details:
- Database error types in some edge cases
- File paths in certain error conditions
- Internal service names

**Recommendation:** Implement centralized error sanitization:
```rust
// Never expose internal details
ApiError::Internal => "An error occurred".to_string()
```

---

### 10. Weak MFA TOTP Secret Generation (MEDIUM)
**Location:** `packages/apps/server/src/mfa/totp.rs`

**Issue:** TOTP secrets may not use sufficient entropy in some generation paths.

**Recommendation:** Ensure all TOTP secrets use `generate_secure_random(32)` minimum.

---

### 11. Missing CSRF Protection on State-Changing GET Requests (MEDIUM)
**Location:** Various routes

**Issue:** Some GET endpoints perform state changes (logout, email verification) without CSRF protection.

**Recommendation:** 
- Change state-changing operations to POST
- Implement double-submit cookie pattern or CSRF tokens

---

### 12. Redis Connection Without TLS (MEDIUM)
**Location:** `packages/apps/server/src/state.rs:99-104`

**Issue:** Redis connections don't enforce TLS by default.

```rust
let client = redis::Client::open(redis_url.as_str())?;
```

**Recommendation:** Add TLS requirement option:
```rust
let client = if config.redis_require_tls {
    redis::Client::open(format!("rediss://{}", redis_url))?
} else {
    redis::Client::open(redis_url.as_str())?
};
```

---

### 13. Insufficient Audit Log Protection (MEDIUM)
**Location:** `packages/apps/server/src/db/mod.rs:160-194`

**Issue:** Audit logs can be deleted by administrators, violating compliance requirements (PCI-DSS, SOC2).

**Recommendation:** Implement append-only audit logs with separate storage and retention policies.

---

### 14. Webhook Signature Verification Bypass (MEDIUM)
**Location:** `packages/core/rust/src/webhooks/signatures.rs`

**Issue:** Webhook signature verification may accept weak signatures in some edge cases.

**Recommendation:** Enforce minimum signature algorithm requirements (HMAC-SHA256 minimum).

---

## Low Severity Issues 🟢

### 15. Unused Features and Dead Code (LOW)
**Locations:**
- `packages/core/rust/src/zk/` - Zero-knowledge module largely unimplemented
- Various `#[cfg(feature = "...")]` blocks for features not in Cargo.toml

**Issue:** 
```rust
#[cfg(feature = "axum")]  // Warning: feature axum not defined
pub mod axum;
```

**Recommendation:** Remove dead code or complete implementations.

---

### 16. Test-Only Code in Production Builds (LOW)
**Location:** `packages/core/rust/src/crypto/jwt.rs:611-626`

```rust
#[cfg(debug_assertions)]
pub fn decode_unverified(token: &str) -> Result<Claims>
```

**Issue:** Debug-only functions exist in production code paths.

**Recommendation:** Move to test-only modules or feature-gate with `#[cfg(test)]`.

---

### 17. Inefficient Database Query Patterns (LOW)
**Location:** `packages/core/rust/src/db/users.rs:488-555`

**Issue:** Dynamic query construction with downcasting:
```rust
for param in &params {
    count_q = count_q.bind(param.downcast_ref::<String>().unwrap());
}
```

**Impact:** Unnecessary overhead; potential runtime panics.

**Recommendation:** Use strongly-typed query builders or sqlx's compile-time checked queries.

---

### 18. Missing Pagination Limits (LOW)
**Location:** Various list endpoints

**Issue:** Some list endpoints don't enforce maximum pagination limits, allowing DoS through `?per_page=1000000`.

**Recommendation:** Enforce server-side maximums:
```rust
const MAX_PER_PAGE: i64 = 100;
let per_page = req.per_page.min(MAX_PER_PAGE);
```

---

### 19. Unnecessary `unwrap()` and `expect()` Usage (LOW)
**Count:** 
- Server: ~150 instances
- Core: ~120 instances

**Issue:** Potential panics in production code.

**Recommendation:** Replace with proper error handling using `?` or `match`.

---

### 20. TODO/FIXME Comments (LOW)
**Count:** 15 unresolved TODOs

**Key TODOs:**
- SAML session service routing
- Audit log rotation implementation gaps
- LDAP attribute parsing
- Notification service integration

---

## Security Best Practices (Non-Issues)

These are correctly implemented and should be maintained:

✅ **Constant-Time JWT Token Extraction** - Uses `subtle::ConstantTimeEq`  
✅ **Argon2id Password Hashing** - Proper memory-hard parameters  
✅ **Hybrid Post-Quantum Signatures** - Ed25519 + ML-DSA-65  
✅ **Secure Random Generation** - Uses `OsRng` throughout  
✅ **HSTS Headers** (production)  
✅ **Content Security Policy** headers  
✅ **Rate Limiting** with Redis fallback  
✅ **RLS (Row-Level Security)** for tenant isolation  
✅ **Password Strength Validation** with entropy checking  
✅ **HIBP Breach Checking** for compromised passwords  

---

## Architecture Concerns

### 1. Session Storage Architecture
**Current:** Sessions stored in PostgreSQL with Redis for caching  
**Concern:** Doesn't horizontally scale well for very high traffic  
**Recommendation:** Consider Redis as primary session store for high-traffic deployments

### 2. Key Rotation
**Current:** Keys generated at startup and persisted  
**Concern:** No automated key rotation mechanism  
**Recommendation:** Implement automated key rotation with grace periods

### 3. Plugin WASM Sandbox
**Current:** Uses Wasmtime with WASI  
**Concern:** Memory limits and execution timeouts need verification  
**Recommendation:** Add explicit resource limits and timeouts

---

## Recommendations Summary

| Priority | Action |
|----------|--------|
| **P0** | Fix fail-open session binding |
| **P0** | Implement refresh token rotation |
| **P0** | Require explicit encryption keys in production |
| **P1** | Add database-level session limit constraints |
| **P1** | Standardize error handling to prevent info leakage |
| **P1** | Add CSRF protection to state-changing GET requests |
| **P2** | Remove dead code and complete TODOs |
| **P2** | Add comprehensive request size limits |
| **P2** | Enforce TLS for all external connections |
| **P3** | Replace `unwrap()` calls with proper error handling |
| **P3** | Add pagination limits to all list endpoints |

---

## Testing Recommendations

1. **Add Fuzzing Tests:** For JWT parsing, token validation, and all input parsers
2. **Race Condition Tests:** For session limit enforcement
3. **Security Regression Tests:** For all security-critical paths
4. **Load Tests:** Verify behavior under high concurrent load
5. **Chaos Engineering:** Test behavior during Redis/DB outages

---

*End of Review*
