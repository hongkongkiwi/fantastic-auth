# Security Documentation

## Overview

This document outlines the security measures implemented in the Vault Tenant Admin UI.

## Authentication

### Cookie-Based Authentication
- Uses httpOnly cookies (not localStorage)
- Cookies automatically sent with requests
- Protected against XSS attacks
- Secure flag in production
- SameSite=Strict

### CSRF Protection
- CSRF tokens required for mutating requests
- Tokens fetched from `/auth/csrf` endpoint
- Stored in memory (not localStorage)
- Automatic retry on CSRF expiration

## API Security

### Request Configuration
```typescript
{
  withCredentials: true,  // Send cookies
  timeout: 30000,        // 30s timeout
  headers: {
    'X-CSRF-Token': token  // For mutations
  }
}
```

### Error Handling
- 401 responses trigger redirect to login
- 403 CSRF errors trigger token refresh
- Session expiration handled gracefully

## Content Security Policy

Meta tag CSP in index.html:
```
default-src 'self'
script-src 'self' 'unsafe-inline'
style-src 'self' 'unsafe-inline'
img-src 'self' data: https:
connect-src 'self' {API_URL}
```

## Input Validation

Zod schemas for all forms:
- Login: Email + password (min 8 chars)
- User creation: Email, name, role
- Password change: Current + new (min 12 chars)
- Webhooks: HTTPS URL validation

## Security Headers

Configured via meta tags:
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- X-Frame-Options: DENY

## Environment Variables

```
VITE_API_URL (backend API URL)
```

Note: All sensitive config is server-side only.

## Security Best Practices

1. **No Token Storage**: Tokens never stored in localStorage
2. **CSRF Protection**: All mutations require valid CSRF token
3. **HTTPS Only**: All API communication over HTTPS
4. **Session Verification**: Periodic session validation
5. **Auto Logout**: On 401 responses
6. **Error Boundaries**: Prevent stack trace leakage
