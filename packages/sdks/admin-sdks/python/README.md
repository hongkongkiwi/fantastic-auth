# Vault Auth Python SDK

Official Python SDK for Vault authentication and user management.

## Installation

```bash
pip install vault-auth
```

With framework extras:

```bash
pip install vault-auth[flask]
pip install vault-auth[django]
pip install vault-auth[fastapi]
```

## Quick Start

```python
from vault_auth import VaultAuth

# Initialize client
vault = VaultAuth(
    api_key="vault_m2m_your_key_here",
    base_url="https://api.vault.dev"
)

# Verify a JWT token
user = vault.verify_token("eyJhbGciOiJSUzI1NiIs...")
print(user.email)

# Get user by ID
user = vault.users.get("user_123")

# Create a new user
new_user = vault.users.create(
    email="user@example.com",
    password="secure_password",
    first_name="John",
    last_name="Doe"
)
```

## Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `api_key` | Your Vault M2M API key | Required |
| `base_url` | Vault API base URL | `https://api.vault.dev` |
| `timeout` | Request timeout (seconds) | `30.0` |
| `max_retries` | Max retries on 5xx | `3` |
| `retry_delay` | Base retry delay (seconds) | `1.0` |
| `request_id` | Request ID for tracing | `None` |
| `jwks_cache_ttl` | JWKS cache TTL (seconds) | `3600` |

## User Management

```python
# List users
users_page = vault.users.list(page=1, per_page=20)
for user in users_page.data:
    print(user.email)

# Get user by email
user = vault.users.get_by_email("user@example.com")

# Update user
vault.users.update(
    user_id="user_123",
    first_name="Jane",
    last_name="Smith"
)

# Delete user
vault.users.delete("user_123")

# Get user's organizations
memberships = vault.users.get_organizations("user_123")
for membership in memberships:
    print(f"{membership.organization.name} - {membership.role}")

# Get user's sessions
sessions = vault.users.get_sessions("user_123")
```

## Organization Management

```python
# Create organization
org = vault.organizations.create(
    name="Acme Corp",
    slug="acme-corp"
)

# Get organization
org = vault.organizations.get("org_123")

# Update organization
vault.organizations.update(
    org_id="org_123",
    name="Acme Corporation"
)

# Delete organization
vault.organizations.delete("org_123")

# Manage members
vault.organizations.add_member("org_123", "user_123", role="admin")
vault.organizations.update_member_role("org_123", "user_123", "owner")
vault.organizations.remove_member("org_123", "user_123")

# Get members
members = vault.organizations.get_members("org_123")
```

## Session Management

```python
# Get session
session = vault.sessions.get("session_123")

# Revoke session
vault.sessions.revoke("session_123")

# Revoke all user sessions
vault.sessions.revoke_all_user_sessions("user_123")
```

## Flask Integration

```python
from flask import Flask, g, jsonify
from vault_auth.middleware.flask import VaultAuthMiddleware, require_auth

app = Flask(__name__)

# Initialize middleware
vault_auth = VaultAuthMiddleware(
    app=app,
    api_key="vault_m2m_your_key_here",
    excluded_paths=["/health", "/public"]
)

@app.route('/protected')
@require_auth()
def protected():
    return jsonify({"email": g.vault_user.email})

@app.route('/admin')
@require_auth(roles=["admin", "owner"])
def admin_only():
    return jsonify({"message": "Admin area"})

if __name__ == '__main__':
    app.run()
```

## Django Integration

```python
# settings.py
MIDDLEWARE = [
    # ... other middleware
    'vault_auth.middleware.django.VaultAuthMiddleware',
]

VAULT_API_KEY = "vault_m2m_your_key_here"
VAULT_BASE_URL = "https://api.vault.dev"
VAULT_EXCLUDED_PATHS = ['/health', '/admin/']
```

```python
# views.py
from django.http import JsonResponse
from vault_auth.middleware.django import require_auth

@require_auth()
def protected_view(request):
    return JsonResponse({"email": request.vault_user.email})

@require_auth(roles=['admin'])
def admin_view(request):
    return JsonResponse({"message": "Admin only"})
```

### Django REST Framework

```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'vault_auth.middleware.django.VaultAuthentication',
    ],
}
```

## FastAPI Integration

```python
from fastapi import FastAPI, Depends
from vault_auth.middleware.fastapi import (
    VaultAuthMiddleware,
    get_current_user,
    get_current_token_payload,
    RequireAuth,
)
from vault_auth.types import User, TokenPayload

app = FastAPI()

# Add middleware
app.add_middleware(
    VaultAuthMiddleware,
    api_key="vault_m2m_your_key_here",
    excluded_paths=["/health", "/docs"]
)

# Or use dependencies
@app.get("/protected")
async def protected(user: User = Depends(get_current_user)):
    return {"email": user.email}

@app.get("/token-info")
async def token_info(payload: TokenPayload = Depends(get_current_token_payload)):
    return {"user_id": payload.sub, "org_id": payload.org_id}

# Class-based with roles
require_auth = RequireAuth(api_key="vault_m2m_your_key_here")

@app.get("/admin")
async def admin_only(user: User = Depends(require_auth(roles=["admin", "owner"]))):
    return {"message": "Admin area"}
```

## Error Handling

```python
from vault_auth import VaultAuth
from vault_auth.errors import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)

vault = VaultAuth(api_key="vault_m2m_...")

try:
    user = vault.verify_token("invalid_token")
except AuthenticationError as e:
    print(f"Auth failed: {e.message}")
except NotFoundError as e:
    print(f"Not found: {e.resource_type} {e.resource_id}")
except RateLimitError as e:
    print(f"Rate limited, retry after: {e.retry_after}s")
except ServerError as e:
    print(f"Server error: {e.status_code}")
except VaultAuthError as e:
    print(f"Vault error: {e.message} (code: {e.error_code})")
```

## Token Verification

```python
# Verify token and get user
user = vault.verify_token("eyJhbGc...")

# Decode token without verification
payload = vault.decode_token("eyJhbGc...")
print(payload.sub)  # User ID
print(payload.org_id)  # Organization ID
print(payload.org_role)  # Organization role

# Get JWKS for manual verification
jwks = vault.get_jwks()
for key in jwks.keys:
    print(f"Key ID: {key.kid}, Algorithm: {key.alg}")
```

## Advanced Usage

### Custom HTTP Client Settings

```python
vault = VaultAuth(
    api_key="vault_m2m_...",
    base_url="https://api.vault.dev",
    timeout=60.0,
    max_retries=5,
    retry_delay=2.0,
    request_id="trace-123",
)
```

### Request ID Tracing

```python
# Pass request ID for distributed tracing
vault = VaultAuth(
    api_key="vault_m2m_...",
    request_id="x-request-id-from-header"
)
```

## License

MIT License - see LICENSE file for details.
