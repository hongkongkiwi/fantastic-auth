# Vault vs Competitors: Feature Matrix and Gaps

Generated from OpenAPI specs with code-path validation notes.

## Status Legend
- Implemented: Code path appears to exist and no known stubs for this endpoint.
- Partial: Endpoint exists but has security or persistence TODOs.
- Stub: Endpoint returns generated/static data or is wired to stubbed services.
- Spec mismatch: Spec path does not match mounted route or location.
- Missing: No matching route found in code.

## API Matrix

### Auth
| Feature (Tag) | Method | Endpoint (Spec) | Spec File | Vault Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Authentication | POST | `/auth/register` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/login` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/logout` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/refresh` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/magic-link` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/magic-link/verify` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/forgot-password` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/reset-password` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/verify-email` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | GET | `/auth/me` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). Response name field is TODO (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/oauth/{provider}` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | GET | `/auth/oauth/{provider}/callback` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | GET | `/auth/sso/redirect` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/sso/callback` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | GET | `/auth/sso/metadata` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| MFA | GET | `/users/me/mfa` | `vault-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | POST | `/users/me/mfa` | `vault-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | DELETE | `/users/me/mfa` | `vault-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | POST | `/users/me/mfa/webauthn/register/begin` | `vault-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | POST | `/users/me/mfa/webauthn/register/finish` | `vault-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | POST | `/users/me/mfa/backup-codes` | `vault-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | POST | `/users/me/mfa/backup-codes/verify` | `vault-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| Authentication | POST | `/auth/register` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/login` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/logout` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/refresh` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/magic-link` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/magic-link/verify` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/forgot-password` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/reset-password` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/verify-email` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/oauth/{provider}` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | GET | `/auth/oauth/{provider}/callback` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | GET | `/auth/sso/redirect` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | POST | `/auth/sso/callback` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| Authentication | GET | `/auth/sso/metadata` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/* without /auth prefix (vault-server/src/routes/client/auth.rs). |
| MFA | GET | `/users/me/mfa` | `vault-client-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | POST | `/users/me/mfa` | `vault-client-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | DELETE | `/users/me/mfa` | `vault-client-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | POST | `/users/me/mfa/webauthn/register/begin` | `vault-client-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | POST | `/users/me/mfa/webauthn/register/finish` | `vault-client-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | POST | `/users/me/mfa/backup-codes` | `vault-client-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| MFA | POST | `/users/me/mfa/backup-codes/verify` | `vault-client-api.yaml` | Implemented | MFA secrets are encrypted at rest and backup codes are hashed. |
| SSO | GET | `/sso/saml/connections` | `vault-admin-api.yaml` | Implemented |  |
| SSO | POST | `/sso/saml/connections` | `vault-admin-api.yaml` | Implemented |  |
| SSO | GET | `/sso/saml/connections/{connectionId}` | `vault-admin-api.yaml` | Implemented |  |
| SSO | PATCH | `/sso/saml/connections/{connectionId}` | `vault-admin-api.yaml` | Implemented |  |
| SSO | DELETE | `/sso/saml/connections/{connectionId}` | `vault-admin-api.yaml` | Implemented |  |
| SSO | GET | `/sso/oidc/connections` | `vault-admin-api.yaml` | Implemented |  |
| SSO | POST | `/sso/oidc/connections` | `vault-admin-api.yaml` | Implemented |  |
| SSO | GET | `/sso/oidc/connections/{connectionId}` | `vault-admin-api.yaml` | Implemented |  |
| SSO | PATCH | `/sso/oidc/connections/{connectionId}` | `vault-admin-api.yaml` | Implemented |  |
| SSO | DELETE | `/sso/oidc/connections/{connectionId}` | `vault-admin-api.yaml` | Implemented |  |
| SSO | PATCH | `/organizations/{orgId}/sso` | `vault-admin-api.yaml` | Implemented |  |

### User Mgmt
| Feature (Tag) | Method | Endpoint (Spec) | Spec File | Vault Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Users | GET | `/users/me` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| Users | PATCH | `/users/me` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| Users | DELETE | `/users/me` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| Users | PATCH | `/users/me/password` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| User Profile | GET | `/users/me` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| User Profile | PATCH | `/users/me` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| User Profile | DELETE | `/users/me` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| User Profile | PATCH | `/users/me/password` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| User Management | GET | `/users` | `vault-admin-api.yaml` | Implemented |  |
| User Management | POST | `/users` | `vault-admin-api.yaml` | Implemented |  |
| User Management | GET | `/users/{userId}` | `vault-admin-api.yaml` | Implemented |  |
| User Management | PATCH | `/users/{userId}` | `vault-admin-api.yaml` | Implemented |  |
| User Management | DELETE | `/users/{userId}` | `vault-admin-api.yaml` | Implemented |  |
| User Management | POST | `/users/{userId}/suspend` | `vault-admin-api.yaml` | Implemented |  |
| User Management | POST | `/users/{userId}/activate` | `vault-admin-api.yaml` | Implemented |  |
| User Management | GET | `/users/{userId}/sessions` | `vault-admin-api.yaml` | Implemented |  |
| User Management | DELETE | `/users/{userId}/sessions` | `vault-admin-api.yaml` | Implemented |  |

### Orgs
| Feature (Tag) | Method | Endpoint (Spec) | Spec File | Vault Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Organizations | GET | `/organizations` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/ and /api/v1/:id without /organizations prefix (vault-server/src/routes/client/organizations.rs). |
| Organizations | POST | `/organizations` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/ and /api/v1/:id without /organizations prefix (vault-server/src/routes/client/organizations.rs). |
| Organizations | GET | `/organizations/{orgId}` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/ and /api/v1/:id without /organizations prefix (vault-server/src/routes/client/organizations.rs). |
| Organizations | PATCH | `/organizations/{orgId}` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/ and /api/v1/:id without /organizations prefix (vault-server/src/routes/client/organizations.rs). |
| Organizations | DELETE | `/organizations/{orgId}` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/ and /api/v1/:id without /organizations prefix (vault-server/src/routes/client/organizations.rs). |
| Organizations | GET | `/organizations/{orgId}/members` | `vault-api.yaml` | Missing | No client organization member/invitation routes implemented in vault-server/src/routes/client/organizations.rs. |
| Organizations | POST | `/organizations/{orgId}/members` | `vault-api.yaml` | Missing | No client organization member/invitation routes implemented in vault-server/src/routes/client/organizations.rs. |
| Organizations | PATCH | `/organizations/{orgId}/members/{userId}` | `vault-api.yaml` | Missing | No client organization member/invitation routes implemented in vault-server/src/routes/client/organizations.rs. |
| Organizations | DELETE | `/organizations/{orgId}/members/{userId}` | `vault-api.yaml` | Missing | No client organization member/invitation routes implemented in vault-server/src/routes/client/organizations.rs. |
| Organizations | GET | `/organizations/{orgId}/invitations` | `vault-api.yaml` | Missing | No client organization member/invitation routes implemented in vault-server/src/routes/client/organizations.rs. |
| Organizations | POST | `/organizations/invitations/{token}/accept` | `vault-api.yaml` | Missing | No client organization member/invitation routes implemented in vault-server/src/routes/client/organizations.rs. |
| Organizations | GET | `/organizations` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/ and /api/v1/:id without /organizations prefix (vault-server/src/routes/client/organizations.rs). |
| Organizations | POST | `/organizations` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/ and /api/v1/:id without /organizations prefix (vault-server/src/routes/client/organizations.rs). |
| Organizations | GET | `/organizations/{orgId}` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/ and /api/v1/:id without /organizations prefix (vault-server/src/routes/client/organizations.rs). |
| Organizations | GET | `/organizations/{orgId}/members` | `vault-client-api.yaml` | Missing | No client organization member/invitation routes implemented in vault-server/src/routes/client/organizations.rs. |
| Organizations | POST | `/organizations/{orgId}/leave` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/ and /api/v1/:id without /organizations prefix (vault-server/src/routes/client/organizations.rs). |
| Organization Management | GET | `/organizations` | `vault-admin-api.yaml` | Implemented |  |
| Organization Management | GET | `/organizations/{orgId}` | `vault-admin-api.yaml` | Implemented |  |
| Organization Management | PATCH | `/organizations/{orgId}` | `vault-admin-api.yaml` | Implemented |  |
| Organization Management | DELETE | `/organizations/{orgId}` | `vault-admin-api.yaml` | Implemented |  |
| Organization Management | GET | `/organizations/{orgId}/members` | `vault-admin-api.yaml` | Implemented |  |
| Organization Management | PATCH | `/organizations/{orgId}/members/{userId}` | `vault-admin-api.yaml` | Implemented |  |
| Organization Management | DELETE | `/organizations/{orgId}/members/{userId}` | `vault-admin-api.yaml` | Implemented |  |
| Organization Management | GET | `/organizations/{orgId}/invitations` | `vault-admin-api.yaml` | Implemented |  |
| Organization Management | DELETE | `/organizations/{orgId}/invitations/{invitationId}` | `vault-admin-api.yaml` | Implemented |  |
| Domains | GET | `/organizations/{orgId}/domains` | `vault-admin-api.yaml` | Implemented |  |
| Domains | POST | `/organizations/{orgId}/domains` | `vault-admin-api.yaml` | Implemented |  |
| Domains | POST | `/organizations/{orgId}/domains/{domainId}/verify` | `vault-admin-api.yaml` | Implemented |  |
| Domains | DELETE | `/organizations/{orgId}/domains/{domainId}` | `vault-admin-api.yaml` | Implemented |  |
| Roles & Permissions | GET | `/organizations/{orgId}/roles` | `vault-admin-api.yaml` | Stub | Role CRUD returns generated data; no persistence (vault-server/src/routes/admin/roles.rs). |
| Roles & Permissions | POST | `/organizations/{orgId}/roles` | `vault-admin-api.yaml` | Stub | Role CRUD returns generated data; no persistence (vault-server/src/routes/admin/roles.rs). |
| Roles & Permissions | PATCH | `/organizations/{orgId}/roles/{roleId}` | `vault-admin-api.yaml` | Stub | Role CRUD returns generated data; no persistence (vault-server/src/routes/admin/roles.rs). |
| Roles & Permissions | DELETE | `/organizations/{orgId}/roles/{roleId}` | `vault-admin-api.yaml` | Stub | Role CRUD returns generated data; no persistence (vault-server/src/routes/admin/roles.rs). |
| Directory | GET | `/directory/ldap/connections` | `vault-admin-api.yaml` | Implemented | LDAP bind_password is encrypted at rest and never returned in responses. |
| Directory | POST | `/directory/ldap/connections` | `vault-admin-api.yaml` | Implemented | LDAP bind_password is encrypted at rest and never returned in responses. |
| Directory | PATCH | `/directory/ldap/connections/{connectionId}` | `vault-admin-api.yaml` | Implemented | LDAP bind_password is encrypted at rest and never returned in responses. |
| Directory | DELETE | `/directory/ldap/connections/{connectionId}` | `vault-admin-api.yaml` | Implemented | LDAP bind_password is encrypted at rest and never returned in responses. |

### Tokens
| Feature (Tag) | Method | Endpoint (Spec) | Spec File | Vault Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Sessions | GET | `/users/me/sessions` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| Sessions | DELETE | `/users/me/sessions` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| Sessions | DELETE | `/users/me/sessions/{sessionId}` | `vault-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| Sessions | GET | `/users/me/sessions` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| Sessions | DELETE | `/users/me/sessions` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |
| Sessions | DELETE | `/users/me/sessions/{sessionId}` | `vault-client-api.yaml` | Spec mismatch | Routes mounted at /api/v1/me... without /users prefix (vault-server/src/routes/client/users.rs). |

### Compliance
| Feature (Tag) | Method | Endpoint (Spec) | Spec File | Vault Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Security Policies | POST | `/security/policies` | `vault-admin-api.yaml` | Stub | Returns generated responses; no persistence (vault-server/src/routes/admin/security_policies.rs). |
| Security Policies | PATCH | `/security/policies/{policyId}` | `vault-admin-api.yaml` | Stub | Returns generated responses; no persistence (vault-server/src/routes/admin/security_policies.rs). |
| Audit Exports | POST | `/audit-logs/exports` | `vault-admin-api.yaml` | Implemented |  |
| Audit Exports | GET | `/audit-logs/exports` | `vault-admin-api.yaml` | Implemented |  |
| Audit Exports | POST | `/audit-logs/webhooks` | `vault-admin-api.yaml` | Implemented |  |
| Audit Exports | GET | `/audit-logs/webhooks` | `vault-admin-api.yaml` | Implemented |  |
| Audit Exports | DELETE | `/audit-logs/webhooks/{webhookId}` | `vault-admin-api.yaml` | Implemented |  |
| Audit Logs | GET | `/audit-logs` | `vault-admin-api.yaml` | Implemented |  |

### Ops
| Feature (Tag) | Method | Endpoint (Spec) | Spec File | Vault Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Health | GET | `/health` | `vault-api.yaml` | Implemented |  |
| Health | GET | `/health` | `vault-client-api.yaml` | Implemented |  |
| SCIM | GET | `/scim/v2/Users` | `vault-admin-api.yaml` | Spec mismatch | SCIM protocol routes are mounted at /scim/v2 (top-level), not under /api/v1/admin. |
| SCIM | POST | `/scim/v2/Users` | `vault-admin-api.yaml` | Spec mismatch | SCIM protocol routes are mounted at /scim/v2 (top-level), not under /api/v1/admin. |
| SCIM | GET | `/scim/v2/Users/{userId}` | `vault-admin-api.yaml` | Spec mismatch | SCIM protocol routes are mounted at /scim/v2 (top-level), not under /api/v1/admin. |
| SCIM | PATCH | `/scim/v2/Users/{userId}` | `vault-admin-api.yaml` | Spec mismatch | SCIM protocol routes are mounted at /scim/v2 (top-level), not under /api/v1/admin. |
| SCIM | DELETE | `/scim/v2/Users/{userId}` | `vault-admin-api.yaml` | Spec mismatch | SCIM protocol routes are mounted at /scim/v2 (top-level), not under /api/v1/admin. |
| SCIM | GET | `/scim/v2/Groups` | `vault-admin-api.yaml` | Spec mismatch | SCIM protocol routes are mounted at /scim/v2 (top-level), not under /api/v1/admin. |
| SCIM | POST | `/scim/v2/Groups` | `vault-admin-api.yaml` | Spec mismatch | SCIM protocol routes are mounted at /scim/v2 (top-level), not under /api/v1/admin. |
| SCIM | GET | `/scim/v2/Groups/{groupId}` | `vault-admin-api.yaml` | Spec mismatch | SCIM protocol routes are mounted at /scim/v2 (top-level), not under /api/v1/admin. |
| SCIM | PATCH | `/scim/v2/Groups/{groupId}` | `vault-admin-api.yaml` | Spec mismatch | SCIM protocol routes are mounted at /scim/v2 (top-level), not under /api/v1/admin. |
| SCIM | DELETE | `/scim/v2/Groups/{groupId}` | `vault-admin-api.yaml` | Spec mismatch | SCIM protocol routes are mounted at /scim/v2 (top-level), not under /api/v1/admin. |
| Tenant Settings | GET | `/settings` | `vault-admin-api.yaml` | Implemented |  |
| Tenant Settings | PATCH | `/settings` | `vault-admin-api.yaml` | Implemented |  |
| Tenant Settings | PATCH | `/settings/mfa` | `vault-admin-api.yaml` | Implemented |  |
| System | GET | `/system/health` | `vault-admin-api.yaml` | Spec mismatch | Implemented at /api/v1/admin/health (vault-server/src/routes/admin/system.rs). |
| Tenant Management | GET | `/tenants` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Tenant Management | POST | `/tenants` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Tenant Management | GET | `/tenants/{tenantId}` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Tenant Management | PATCH | `/tenants/{tenantId}` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Tenant Management | DELETE | `/tenants/{tenantId}` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Tenant Management | POST | `/tenants/{tenantId}/suspend` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Tenant Management | POST | `/tenants/{tenantId}/activate` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Tenant Management | POST | `/tenants/{tenantId}/migrate` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Platform Users | GET | `/users` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Platform Users | GET | `/users/{userId}` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Platform Users | POST | `/users/{userId}/impersonate` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Billing | GET | `/billing/subscriptions` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Billing | GET | `/billing/tenants/{tenantId}/subscription` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Billing | PATCH | `/billing/tenants/{tenantId}/subscription` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Billing | POST | `/billing/tenants/{tenantId}/invoice` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Billing | POST | `/billing/webhook` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Platform Analytics | GET | `/analytics/overview` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Platform Analytics | GET | `/analytics/tenants` | `vault-internal-api.yaml` | Missing | No matching route; internal analytics only exposes /overview and /growth. |
| Platform Analytics | GET | `/analytics/usage` | `vault-internal-api.yaml` | Missing | No matching route; internal analytics only exposes /overview and /growth. |
| System Configuration | GET | `/config/features` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| System Configuration | POST | `/config/features` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| System Configuration | PATCH | `/config/features/{flagId}` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| System Configuration | GET | `/config/oauth-providers` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| System Configuration | POST | `/config/oauth-providers` | `vault-internal-api.yaml` | Stub (spec mismatch) | Internal routes are mounted at /api/v1/internal with no sub-prefix (e.g. /features, /overview, /webhooks/stripe). Internal handlers return stubbed data in tenants, platform_users, analytics, config, maintenance, and billing modules. |
| Maintenance | POST | `/maintenance/migrations` | `vault-internal-api.yaml` | Missing | No matching route; internal maintenance exposes /status, /enable, /disable, /health. |
| Maintenance | POST | `/maintenance/backup` | `vault-internal-api.yaml` | Missing | No matching route; internal maintenance exposes /status, /enable, /disable, /health. |

### UI
| Feature (Tag) | Method | Endpoint (Spec) | Spec File | Vault Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Dashboard | GET | `/dashboard` | `vault-admin-api.yaml` | Implemented |  |
| Dashboard | GET | `/dashboard/metrics` | `vault-admin-api.yaml` | Missing | No matching route; admin dashboard only exposes /dashboard. |
| Branding | GET | `/branding` | `vault-admin-api.yaml` | Stub | Branding/theme endpoints return defaults; no persistence (vault-server/src/routes/admin/branding.rs). |
| Branding | PATCH | `/branding` | `vault-admin-api.yaml` | Stub | Branding/theme endpoints return defaults; no persistence (vault-server/src/routes/admin/branding.rs). |
| Branding | GET | `/themes` | `vault-admin-api.yaml` | Stub | Branding/theme endpoints return defaults; no persistence (vault-server/src/routes/admin/branding.rs). |
| Branding | PATCH | `/themes` | `vault-admin-api.yaml` | Stub | Branding/theme endpoints return defaults; no persistence (vault-server/src/routes/admin/branding.rs). |

## Spec Gaps (Endpoints Implemented But Missing in Specs)
- Client auth: `/captcha-site-key`, `/webauthn/*`, `/step-up`, `/webauthn/credentials/*` in `vault-server/src/routes/client/auth.rs`.
- Client users: `/me/linked-accounts*` in `vault-server/src/routes/client/users.rs`.
- Admin SCIM management: `/api/v1/admin/scim/*` (tokens/config/audit/stats) in `vault-server/src/routes/admin/scim.rs`.
- Admin billing: `/api/v1/admin/billing/*` in `vault-server/src/routes/admin/billing.rs`.
- Internal maintenance: `/api/v1/internal/status`, `/enable`, `/disable`, `/health` in `vault-server/src/routes/internal/maintenance.rs`.

## Known Implementation Gaps Not Captured in OpenAPI
- MFA secret encryption and backup-code hashing are placeholders.
- Internal API lacks auth/superadmin middleware (`vault-server/src/routes/internal/mod.rs`).
- Billing uses a stubbed Stripe service (`vault-server/src/billing/stripe.rs`).

## Competitor Feature Highlights (Source-Backed)

### Clerk
- Organizations with role sets and custom permissions, including predefined `admin`/`member` roles and permission management. citeturn0search2
- Enterprise SSO (SAML/OIDC) and ability to act as an IdP for third-party applications. citeturn0search4
- MFA options include SMS and TOTP plus backup codes. citeturn2search9
- Webhooks for user/session/org events. citeturn3search0

### Auth0
- Organizations for B2B tenancy boundaries. citeturn1search0
- Actions for extensibility in auth flows. citeturn1search1
- Log Streams for exporting logs to external systems. citeturn2search2
- SCIM provisioning support. citeturn1search9

### SuperTokens
- Multi-tenancy support in core product design. citeturn3search0
- MFA support for TOTP, SMS, and Email OTP. citeturn3search2
- Step-up authentication support. citeturn3search1

### FusionAuth
- WebAuthn passkeys. citeturn2search1
- SAML-based SSO. citeturn3search3
- SCIM provisioning. citeturn3search9

## Features Competitors Have That Vault Should Implement (or Finish)

1. OIDC/OAuth authorization server (IdP) for third-party apps, not just social login as a client. Clerk exposes IdP functionality; Auth0’s platform centers around IdP workflows. citeturn0search4
2. Persistent, enforceable org roles/permissions with role sets and permission management (current role endpoints are stubbed). Clerk documents role sets and permissions. citeturn0search2
3. MFA via SMS and Email OTP in addition to TOTP/WebAuthn, plus secure secret storage and backup-code hashing (current encryption is placeholder). Clerk and SuperTokens support SMS/Email OTP and TOTP. citeturn2search9turn3search2
4. Extensibility hooks for auth flows (Actions/Rules-like). Auth0 provides Actions. citeturn1search1
5. Log streaming with destinations and filters for SIEM/analytics (beyond current export/webhook). Auth0 Log Streams provides this capability. citeturn2search2
6. SCIM admin UX and configuration endpoints that are fully implemented and documented (Vault has SCIM protocol routes but admin config/update is incomplete). Auth0 and FusionAuth provide SCIM provisioning. citeturn1search9turn3search9
7. Tenant-level auth configuration and multi-tenancy tooling as a first-class surface (self-serve per-tenant login methods, limits, and policies). SuperTokens highlights multi-tenancy as a core capability. citeturn3search0
8. Step-up authentication productization (policy configuration + SDK/UI) to match SuperTokens’ step-up model; Vault has a route but no public spec/UI. citeturn3search1

## Non-Competitor Gaps That Block Adoption
- Client API routing is out of sync with OpenAPI for auth/users/orgs (spec mismatch). Fixing this is required to make SDKs and docs trustworthy.
- Client org membership/invitation endpoints are specified but not implemented.
- Internal API is stubbed and lacks auth middleware.
- Branding and roles endpoints are stubbed (no persistence).
