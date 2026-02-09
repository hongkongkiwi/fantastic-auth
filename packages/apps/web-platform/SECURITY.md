# Security Documentation

## Overview

This document outlines the security measures implemented in the Vault Platform Admin UI.

## Authentication & Session Management

### Session Storage
- Sessions are stored in Redis (not in-memory)
- Sessions persist across server restarts
- Supports horizontal scaling
- Session TTL: 8 hours with sliding window

### Cookie Security
- `HttpOnly`: Prevents XSS access to session cookie
- `Secure`: Only sent over HTTPS in production
- `SameSite=Strict`: Prevents CSRF via cross-site requests
- `Max-Age`: 8 hours

### CSRF Protection
- CSRF tokens generated per session
- Validated on all mutating requests (POST, PUT, DELETE, PATCH)
- Tokens rotate periodically
- 403 response on CSRF validation failure

## Rate Limiting

### Login Endpoint
- 5 attempts per 5 minutes per IP
- Returns 429 status when exceeded
- Uses Upstash Redis for distributed rate limiting

### API Endpoints
- 100 requests per minute per IP
- Analytics enabled for monitoring

## Content Security Policy

### Default Policy
```
default-src 'self'
script-src 'self' 'nonce-{nonce}' 'strict-dynamic'
style-src 'self' 'unsafe-inline'
img-src 'self' data: https:
connect-src 'self' {API_BASE_URL}
font-src 'self'
object-src 'none'
base-uri 'self'
form-action 'self'
frame-ancestors 'none'
upgrade-insecure-requests
```

## Security Headers

All responses include:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Strict-Transport-Security` (HSTS in production)

## Input Validation

All server function inputs validated using Zod schemas:
- Email format validation
- Password strength requirements
- String length limits
- Enum validation
- Custom refinements

## Error Handling

- Generic error messages for auth failures
- Detailed errors only in development mode
- All errors logged to server
- Sentry integration for error tracking

## Environment Variables

Required security-related env vars:
```
INTERNAL_UI_PASSWORD (min 12 chars)
REDIS_URL
UPSTASH_REDIS_REST_URL (optional, for rate limiting)
UPSTASH_REDIS_REST_TOKEN
NODE_ENV
```

## Security Checklist

- [x] No secrets in client-side code
- [x] HttpOnly cookies for session
- [x] CSRF protection enabled
- [x] Rate limiting configured
- [x] CSP headers set
- [x] Security headers configured
- [x] Input validation on all endpoints
- [x] Error boundaries prevent data leaks
- [x] XSS protection via CSP
- [x] Clickjacking protection via X-Frame-Options
