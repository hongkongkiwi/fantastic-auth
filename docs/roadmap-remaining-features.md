# Remaining Feature Roadmap (Post-Alignment)

## 1) IdP / OAuth Authorization Server
- Implement OIDC authorization code + PKCE flows, token endpoint, JWKS endpoint.
- Add client app registration and secrets management (admin API + DB table).
- Support scopes, consent screens, and refresh token rotation policies.
- Add UI admin screens for app clients and consent.

Dependencies
- New DB tables: oauth_clients, oauth_consents, oauth_tokens, oauth_codes.
- JWT signing key rotation policy and JWKS hosting.

## 2) Actions/Rules Extensibility
- Define action hooks (pre-login, post-login, pre-register, token-issue).
- Provide JS/Wasmtime sandbox execution with timeout and resource limits.
- Add admin API to manage action scripts and enable/disable by tenant.

Dependencies
- Secure sandbox runtime selection (Wasmtime preferred).
- Audit logging for action execution outcomes.

## 3) Log Streaming (SIEM/Analytics)
- Add streaming destinations (HTTP, S3, Webhook, Datadog, Splunk).
- Allow filtering by event types and severity.
- Retry/backoff with dead-letter queue and delivery status.

Dependencies
- New DB tables: log_streams, log_stream_deliveries.
- Background worker for delivery.

## 4) MFA Hardening + Email OTP
- Replace base64 secret storage with AES-256-GCM using KMS-managed keys.
- Replace backup code hashing with Argon2id.
- Implement Email OTP factor using existing email service.

Dependencies
- KMS or master key configuration for encryption.
- Update MFA storage schema and migration.

## 5) SCIM Admin Config Completion
- Persist SCIM admin config in DB and expose update routes.
- Add admin UI pages for SCIM tokens + config.

Dependencies
- DB table for scim_config (per-tenant).

## 6) Internal API Auth
- Add API key or super-admin JWT middleware to `/api/v1/internal/*`.
- Enforce tenant isolation overrides only for platform roles.

Dependencies
- Internal auth key storage and rotation.

## 7) Spec/SDK Hardening
- Keep OpenAPI spec synced with route changes.
- Regenerate SDKs as part of CI.
