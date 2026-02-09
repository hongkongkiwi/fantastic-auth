# Security Documentation

## Overview

This document outlines the security measures in the Vault User Portal.

## Authentication

### Cookie-Based Sessions
- httpOnly cookies for session tokens
- Automatic cookie sending with `credentials: 'include'`
- No JavaScript access to tokens
- Protected against XSS

### CSRF Protection
- Tokens fetched from `/auth/csrf`
- Added to mutating requests via `X-CSRF-Token` header
- Automatic refresh on expiration
- Memory-only storage (cleared on page reload)

## Privacy & GDPR

### Data Export
- User can request full data export
- Export includes: profile, sessions, devices, consents
- Secure download links (time-limited)
- JSON and CSV formats

### Account Deletion
- Confirmation text required: "DELETE MY ACCOUNT"
- 30-day grace period
- Email notification on request
- Complete data purging after grace period

### Consent Management
- Granular consent preferences
- Marketing, analytics, third-party options
- Withdrawal tracking
- Versioned consent records

## Session Management

### Active Sessions
- View all active sessions
- Revoke individual sessions
- "Log out all others" functionality
- Device and location information

### Device Trust
- Device trust scores
- Trust/untrust devices
- Auto-revocation policy
- Location mismatch detection

## API Security

### Request Headers
```
Content-Type: application/json
X-CSRF-Token: {token}
```

### Error Handling
- 401: Redirect to login
- 403: Clear CSRF, retry or show error
- All errors show user-friendly message

## Content Security Policy

Configured in root route:
```
default-src 'self'
script-src 'self'
style-src 'self' 'unsafe-inline'
img-src 'self' data: https:
connect-src 'self' {API_URL}
```

## Input Validation

- Profile updates: Name length limits
- Password changes: Strength requirements
- MFA setup: Code format validation
- Export requests: Format validation

## Security Features

- XSS Protection via CSP
- CSRF Protection on all mutations
- Session hijacking detection
- Suspicious activity alerts
- Automatic session timeout
- Secure password requirements
