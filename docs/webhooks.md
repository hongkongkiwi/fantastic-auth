# Webhook System

The Vault webhook system provides real-time event notifications to tenant-configured endpoints. When events occur (user login, user created, etc.), the system delivers signed HTTP POST requests to subscribed endpoints.

## Architecture

### Components

1. **Webhook Service** (`vault-server/src/webhooks/mod.rs`)
   - Manages webhook endpoints (CRUD operations)
   - Triggers events and creates delivery records
   - Handles HTTP delivery with HMAC-SHA256 signing

2. **Background Worker** (`vault-server/src/background/webhooks.rs`)
   - Polls database for pending deliveries
   - Executes HTTP requests with retry logic
   - Implements exponential backoff (1s, 2s, 4s, 8s, 16s, 32s)

3. **Database Repository** (`vault-server/src/db/webhooks.rs`)
   - Stores webhook endpoints and deliveries
   - Implements retry scheduling with exponential backoff
   - Tracks delivery status and attempts

4. **Audit Integration** (`vault-server/src/audit.rs`)
   - Triggers webhooks when audit events occur
   - Events: user.created, user.updated, user.deleted, user.login, user.logout, session.revoked

## Database Schema

### webhook_endpoints

```sql
CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events JSONB NOT NULL DEFAULT '[]',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT,
    headers JSONB DEFAULT '{}',
    max_retries INTEGER NOT NULL DEFAULT 3,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
```

### webhook_deliveries

```sql
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(255) NOT NULL,
    payload JSONB NOT NULL,
    payload_size INTEGER NOT NULL,
    attempt_number INTEGER NOT NULL DEFAULT 1,
    status VARCHAR(50) NOT NULL, -- pending, delivered, failed
    http_status_code INTEGER,
    response_body TEXT,
    response_headers JSONB,
    error_message TEXT,
    duration_ms INTEGER,
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## Configuration

```rust
pub struct WebhookConfig {
    pub retry_attempts: u32,                  // Default: 5
    pub retry_schedule_seconds: Vec<u64>,     // Default: [60, 300, 900, 3600]
    pub retry_jitter: f32,                    // Default: 0.2
    pub overload_penalty_seconds: u64,        // Default: 60
    pub timeout_seconds: u64,                 // Default: 30
    pub batch_size: usize,                    // Default: 100
    pub worker_poll_interval_seconds: u64,    // Default: 30
    pub max_payload_size: usize,              // Default: 1MB
    pub max_response_body_bytes: usize,       // Default: 20KB
    pub in_progress_timeout_seconds: u64,     // Default: 300
    pub enabled: bool,                        // Default: true
}
```

Environment variables:
- `VAULT_WEBHOOK_ENABLED=true` - Enable webhook worker

## Event Types

### User Events
- `user.created` - User account created
- `user.updated` - User account updated
- `user.deleted` - User account deleted
- `user.login` - User logged in
- `user.logout` - User logged out

### Session Events
- `session.revoked` - Session revoked

## Payload Signature

Webhooks are signed using HMAC-SHA256 for security verification.

### Headers

```
X-Webhook-ID: <delivery_id>
X-Webhook-Timestamp: <unix_timestamp>
X-Webhook-Signature: v1=<hex_signature>
X-Webhook-Event: <event_type>
X-Webhook-Attempt: <attempt_number>
Content-Type: application/json
User-Agent: Vault-Webhook/1.0
```

### Signature Verification

```rust
// Signature payload format: "timestamp.body"
let payload = format!("{}.{}", timestamp, body);

// Compute HMAC-SHA256
let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
mac.update(payload.as_bytes());
let signature = hex::encode(mac.finalize().into_bytes());

// Expected signature header: "v1=<signature>"
```

### Example Verification (Python)

```python
import hmac
import hashlib

def verify_signature(payload_body, secret, signature_header, timestamp):
    # Extract signature
    sig_parts = signature_header.split('=')
    if len(sig_parts) != 2 or sig_parts[0] != 'v1':
        return False
    
    expected_sig = sig_parts[1]
    
    # Build signed payload
    signed_payload = f"{timestamp}.{payload_body}"
    
    # Compute signature
    computed = hmac.new(
        secret.encode(),
        signed_payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Constant-time comparison
    return hmac.compare_digest(expected_sig, computed)
```

## Retry Logic

The system implements exponential backoff for failed deliveries:

| Attempt | Delay |
|---------|-------|
| 1       | 1s    |
| 2       | 2s    |
| 3       | 4s    |
| 4       | 8s    |
| 5       | 16s   |
| 6       | 32s   |

- Maximum 6 attempts over ~60 seconds
- 2xx responses are considered successful
- 4xx/5xx responses trigger retry
- Network timeouts trigger retry

## Usage

### Creating an Audit Logger with Webhooks

```rust
// In your handler
let audit = state.audit_logger();

// Log events will automatically trigger webhooks
audit.log_login_success(
    tenant_id,
    user_id,
    Some(session_id),
    email,
    context,
    "password",
);
```

### Manual Webhook Trigger

```rust
use crate::webhooks::WebhookService;

let service = WebhookService::new(db);

// Create endpoint
let endpoint = service
    .create_endpoint(
        tenant_id,
        "My Webhook",
        "https://example.com/webhook",
        vec!["user.created".to_string(), "user.login".to_string()],
        None, // auto-generate secret
        Some("Description".to_string()),
        None, // no custom headers
    )
    .await?;

// Trigger event
let deliveries = service
    .trigger_event(tenant_id, "user.created", json!({
        "id": user_id,
        "email": email,
    }))
    .await?;
```

## Security Considerations

1. **HTTPS Only**: Webhook URLs must use HTTPS in production
2. **Secret Management**: Store webhook secrets securely; they are only shown once on creation
3. **Signature Verification**: Always verify the HMAC-SHA256 signature
4. **Idempotency**: Use the `X-Webhook-ID` header for idempotency
5. **Timestamp Validation**: Validate the timestamp to prevent replay attacks

## Monitoring

Check webhook delivery stats:

```rust
let worker = spawn_worker(db);
let stats = worker.get_stats().await?;

println!("Pending: {}", stats.pending);
println!("Delivered: {}", stats.delivered);
println!("Failed: {}", stats.failed);
```

## Testing

Run webhook tests:

```bash
cargo test -p vault-server webhooks
```
