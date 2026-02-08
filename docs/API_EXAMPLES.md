# Vault API Examples

Complete examples for using the Vault API.

## Base URL

```
http://localhost:3000/api/v1
```

## Authentication

Most endpoints require a Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

---

## Authentication Endpoints

### Register

Create a new user account.

```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "name": "John Doe"
  }'
```

**Response (201 Created):**
```json
{
  "user": {
    "id": "usr_abc123",
    "email": "user@example.com",
    "emailVerified": false,
    "status": "pending",
    "profile": {
      "name": "John Doe",
      "preferred_username": "john_doe"
    },
    "mfaEnabled": false,
    "createdAt": "2024-01-15T10:30:00Z"
  },
  "session": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIs...",
    "expiresIn": 900
  }
}
```

---

### Login

Authenticate with email and password.

```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

**Response (200 OK):**
```json
{
  "user": {
    "id": "usr_abc123",
    "email": "user@example.com",
    "emailVerified": true,
    "status": "active"
  },
  "session": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJSUzI1NiIs...",
    "expiresIn": 900
  },
  "mfaRequired": false
}
```

**MFA Required Response:**
```json
{
  "mfaRequired": true,
  "challenge": {
    "method": "totp",
    "expiresAt": "2024-01-15T10:35:00Z"
  }
}
```

---

### Refresh Token

Get a new access token using a refresh token.

```bash
curl -X POST http://localhost:3000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "refreshToken": "eyJhbGciOiJSUzI1NiIs..."
  }'
```

**Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIs...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIs...",
  "expiresIn": 900
}
```

---

### Logout

Revoke the current session.

```bash
curl -X POST http://localhost:3000/api/v1/auth/logout \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default" \
  -d '{
    "allSessions": false
  }'
```

**Response (204 No Content)**

---

### Magic Link

Request a magic link for passwordless login.

```bash
# Request magic link
curl -X POST http://localhost:3000/api/v1/auth/magic-link \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "email": "user@example.com"
  }'
```

**Response (200 OK)**

```bash
# Verify magic link
curl -X POST http://localhost:3000/api/v1/auth/magic-link/verify \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "token": "magic_link_token_from_email"
  }'
```

---

### Password Reset

Request and complete password reset.

```bash
# Request reset
curl -X POST http://localhost:3000/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "email": "user@example.com"
  }'
```

**Response (200 OK)**

```bash
# Reset password
curl -X POST http://localhost:3000/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "token": "reset_token_from_email",
    "newPassword": "NewSecurePass123!"
  }'
```

**Response (200 OK)**

---

### Email Verification

Verify email address.

```bash
curl -X POST http://localhost:3000/api/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "token": "verification_token_from_email"
  }'
```

**Response (200 OK):**
```json
{
  "id": "usr_abc123",
  "email": "user@example.com",
  "emailVerified": true,
  "status": "active"
}
```

---

## User Endpoints

### Get Current User

```bash
curl -X GET http://localhost:3000/api/v1/users/me \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default"
```

**Response (200 OK):**
```json
{
  "id": "usr_abc123",
  "email": "user@example.com",
  "emailVerified": true,
  "status": "active",
  "profile": {
    "name": "John Doe",
    "givenName": "John",
    "familyName": "Doe",
    "picture": "https://..."
  },
  "mfaEnabled": true,
  "mfaMethods": ["totp"],
  "lastLoginAt": "2024-01-15T10:30:00Z",
  "createdAt": "2024-01-01T00:00:00Z"
}
```

---

### Update Profile

```bash
curl -X PATCH http://localhost:3000/api/v1/users/me \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "profile": {
      "name": "John Updated",
      "phoneNumber": "+1234567890"
    }
  }'
```

---

### Change Password

```bash
curl -X PATCH http://localhost:3000/api/v1/users/me/password \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "currentPassword": "OldPass123!",
    "newPassword": "NewSecurePass123!"
  }'
```

---

### List Sessions

```bash
curl -X GET http://localhost:3000/api/v1/users/me/sessions \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default"
```

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "sess_abc123",
      "ipAddress": "192.168.1.1",
      "userAgent": "Mozilla/5.0...",
      "createdAt": "2024-01-15T10:30:00Z",
      "lastActivityAt": "2024-01-15T11:00:00Z",
      "current": true
    }
  ],
  "total": 3
}
```

---

### Revoke Session

```bash
curl -X DELETE http://localhost:3000/api/v1/users/me/sessions/sess_abc123 \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default"
```

---

## Organization Endpoints

### List Organizations

```bash
curl -X GET http://localhost:3000/api/v1/organizations \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default"
```

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "org_abc123",
      "name": "Acme Corp",
      "slug": "acme-corp",
      "role": "owner",
      "memberCount": 5,
      "createdAt": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

---

### Create Organization

```bash
curl -X POST http://localhost:3000/api/v1/organizations \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "name": "My Team",
    "slug": "my-team"
  }'
```

**Response (201 Created):**
```json
{
  "id": "org_xyz789",
  "name": "My Team",
  "slug": "my-team",
  "role": "owner",
  "createdAt": "2024-01-15T10:30:00Z"
}
```

---

### Get Organization

```bash
curl -X GET http://localhost:3000/api/v1/organizations/org_xyz789 \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default"
```

---

### List Members

```bash
curl -X GET http://localhost:3000/api/v1/organizations/org_xyz789/members \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default"
```

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "mem_abc123",
      "userId": "usr_abc123",
      "email": "user@example.com",
      "name": "John Doe",
      "role": "owner",
      "status": "active",
      "joinedAt": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 5
}
```

---

### Invite Member

```bash
curl -X POST http://localhost:3000/api/v1/organizations/org_xyz789/members \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "email": "newmember@example.com",
    "role": "member"
  }'
```

---

### Leave Organization

```bash
curl -X POST http://localhost:3000/api/v1/organizations/org_xyz789/leave \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default"
```

---

## MFA Endpoints

### Get MFA Status

```bash
curl -X GET http://localhost:3000/api/v1/users/me/mfa \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default"
```

---

### Enable TOTP

```bash
# Start enrollment
curl -X POST http://localhost:3000/api/v1/users/me/mfa/totp \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default"
```

**Response (200 OK):**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qrCodeUrl": "otpauth://totp/Vault:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Vault",
  "backupCodes": ["12345678", "87654321", "..."]
}
```

```bash
# Verify and enable
curl -X POST http://localhost:3000/api/v1/users/me/mfa/totp/verify \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "code": "123456"
  }'
```

---

### Disable MFA

```bash
curl -X DELETE http://localhost:3000/api/v1/users/me/mfa \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "password": "SecurePass123!"
  }'
```

---

## WebAuthn / Passkeys

### Begin Registration

```bash
curl -X POST http://localhost:3000/api/v1/webauthn/register/begin \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: default"
```

**Response (200 OK):**
```json
{
  "challenge": "base64url-encoded-challenge",
  "rp": {
    "id": "localhost",
    "name": "Vault"
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "displayName": "John Doe",
    "name": "john_doe"
  },
  "pubKeyCredParams": [
    { "alg": -7, "type": "public-key" }
  ],
  "authenticatorSelection": {
    "residentKey": "preferred",
    "userVerification": "preferred"
  }
}
```

---

### Finish Registration

```bash
curl -X POST http://localhost:3000/api/v1/webauthn/register/finish \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: default" \
  -d '{
    "id": "credential-id",
    "rawId": "base64url-encoded-raw-id",
    "response": {
      "clientDataJSON": "base64url-encoded-client-data",
      "attestationObject": "base64url-encoded-attestation"
    },
    "type": "public-key"
  }'
```

---

## Error Responses

### 400 Bad Request
```json
{
  "error": "Validation failed",
  "code": "validation_error",
  "details": {
    "email": "Invalid email format",
    "password": "Password must be at least 12 characters"
  }
}
```

### 401 Unauthorized
```json
{
  "error": "Invalid credentials",
  "code": "authentication_failed"
}
```

### 403 Forbidden
```json
{
  "error": "Insufficient permissions",
  "code": "forbidden"
}
```

### 404 Not Found
```json
{
  "error": "User not found",
  "code": "not_found"
}
```

### 409 Conflict
```json
{
  "error": "User with email user@example.com already exists",
  "code": "conflict"
}
```

### 429 Too Many Requests
```json
{
  "error": "Rate limit exceeded. Try again in 60 seconds.",
  "code": "rate_limited",
  "retryAfter": 60
}
```

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| POST /auth/login | 5 requests / minute |
| POST /auth/register | 5 requests / minute |
| POST /auth/magic-link | 3 requests / minute |
| POST /auth/forgot-password | 3 requests / hour |
| All other endpoints | 100 requests / minute |

---

## SDK Usage

### JavaScript/React

```javascript
import { VaultProvider, useAuth, SignIn } from '@vault/sdk';

function App() {
  return (
    <VaultProvider 
      apiUrl="http://localhost:3000"
      tenantId="default"
    >
      <AuthContent />
    </VaultProvider>
  );
}

function AuthContent() {
  const { isSignedIn, user, signOut } = useAuth();
  
  if (!isSignedIn) {
    return <SignIn oauthProviders={['google', 'github']} />;
  }
  
  return (
    <div>
      <p>Welcome, {user.email}!</p>
      <button onClick={signOut}>Sign Out</button>
    </div>
  );
}
```

### cURL with Variables

```bash
# Set variables
BASE_URL="http://localhost:3000/api/v1"
TENANT_ID="default"

# Register
RESPONSE=$(curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }')

# Extract token
TOKEN=$(echo $RESPONSE | jq -r '.session.accessToken')

# Use token
curl -X GET "$BASE_URL/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID"
```
