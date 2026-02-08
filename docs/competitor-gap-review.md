# Vault vs Competitors: Feature Gaps & Recommendations (2026-02-08)

This document summarizes competitor capabilities (Clerk, Auth0, SuperTokens, FusionAuth) and highlights Vault feature gaps to consider. It complements `docs/competitor-feature-matrix.md`, which is the endpoint-level inventory.

## Legend
- Vault status: Implemented | Partial | Missing
- Competitor column: Yes | Partial | Unknown (based on publicly documented features)
- Vault spec: OpenAPI spec file and path, when applicable

## Feature Matrix (Competitor Coverage vs Vault)

### Auth
| Feature | Clerk | Auth0 | SuperTokens | FusionAuth | Vault status | Vault spec / notes |
| --- | --- | --- | --- | --- | --- | --- |
| Social login (OAuth) | Yes | Yes | Yes | Yes | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/auth/oauth/{provider}` |
| Magic link / passwordless | Yes | Yes | Yes | Yes | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/auth/magic-link`, `/auth/magic-link/verify` |
| Email OTP sign-in | Yes | Yes | Yes | Yes | Partial | No passwordless email OTP endpoints (distinct from MFA email OTP) |
| SMS OTP sign-in | Yes | Yes | Unknown | Unknown | Missing | No SMS OTP login endpoints |
| Enterprise SSO (SAML, OIDC) inbound | Yes | Yes | Yes | Yes | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/auth/sso/*` and admin SAML/OIDC connections |
| IdP / OAuth2 Authorization Server | Yes | Yes | Yes | Unknown | Missing | No OAuth2/OIDC authorization server endpoints |
| M2M / Client Credentials Flow | Yes | Yes | Yes | Unknown | Missing | No client credentials endpoints |
| MFA: TOTP | Yes | Yes | Yes | Yes | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/users/me/mfa` |
| MFA: WebAuthn / Passkeys | Yes | Yes | Unknown | Yes | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/users/me/mfa/webauthn/*` |
| MFA: Backup codes | Yes | Yes | Unknown | Unknown | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/users/me/mfa/backup-codes` |
| MFA: SMS | Unknown | Yes | Yes | Yes | Partial | Routes exist but core verification isn’t integrated |
| MFA: Email OTP | Unknown | Yes | Yes | Yes | Missing | Core verification exists but issuance/flows missing |
| MFA: Push / Voice | Unknown | Yes | Unknown | Unknown | Missing | Not implemented |
| Adaptive / risk-based MFA | Unknown | Yes | Unknown | Unknown | Missing | No risk engine or adaptive policy layer |
| Step-up auth | Yes | Yes | Yes | Yes | Partial | Step-up routes exist but no global policy engine |

### User Management
| Feature | Clerk | Auth0 | SuperTokens | FusionAuth | Vault status | Vault spec / notes |
| --- | --- | --- | --- | --- | --- | --- |
| Admin user CRUD | Yes | Yes | Yes | Yes | Implemented | `vault-admin-api.yaml` `/users` |
| Self-service profile | Yes | Yes | Yes | Yes | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/users/me` |
| User sessions & revoke | Yes | Yes | Yes | Yes | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/users/me/sessions` |
| Impersonation | Unknown | Yes | Unknown | Unknown | Implemented | `vault-admin-api.yaml` `/users/{userId}/impersonate` |
| Account linking | Unknown | Unknown | Yes | Unknown | Missing | No account-linking flows or APIs |
| Self-serve account portal | Yes | Yes | Yes | Yes | Partial | `vault-web` exists; no hosted/embedded widgets or tenant theming |

### Organizations (B2B)
| Feature | Clerk | Auth0 | SuperTokens | FusionAuth | Vault status | Vault spec / notes |
| --- | --- | --- | --- | --- | --- | --- |
| Orgs CRUD | Yes | Yes | Yes | Unknown | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/organizations` |
| Org members & invitations | Yes | Yes | Yes | Unknown | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/organizations/{orgId}/members`, `/invitations` |
| Org roles & permissions | Yes | Unknown | Unknown | Unknown | Implemented | `vault-admin-api.yaml` `/organizations/{orgId}/roles` + admin permissions APIs |
| Org domains & verification | Yes | Unknown | Unknown | Unknown | Implemented | `vault-admin-api.yaml` `/organizations/{orgId}/domains` |
| Domain-based auto-join / JIT membership | Yes | Yes | Yes | Unknown | Missing | No matching endpoints or policy engine |
| Org-level SSO connections | Yes | Yes | Yes | Unknown | Partial | Admin `PATCH /organizations/{orgId}/sso` exists but lacks policy surface |

### Tokens & Sessions
| Feature | Clerk | Auth0 | SuperTokens | FusionAuth | Vault status | Vault spec / notes |
| --- | --- | --- | --- | --- | --- | --- |
| Access/refresh tokens | Yes | Yes | Yes | Yes | Implemented | `vault-core` auth tokens + session tables |
| Session rotation / revoke | Yes | Yes | Yes | Yes | Implemented | `vault-api.yaml` + `vault-client-api.yaml` `/users/me/sessions` |
| Token introspection / revocation (RFC 7662/7009) | Unknown | Yes | Unknown | Unknown | Missing | No OAuth2 introspection or revocation endpoints |
| JWKS / key rotation endpoint | Yes | Yes | Yes | Unknown | Partial | JWTs exist; no JWKS publishing endpoint |

### Ops & Security
| Feature | Clerk | Auth0 | SuperTokens | FusionAuth | Vault status | Vault spec / notes |
| --- | --- | --- | --- | --- | --- | --- |
| Audit logs | Unknown | Yes | Unknown | Unknown | Implemented | `vault-admin-api.yaml` `/audit-logs` |
| Webhooks | Yes | Yes | Unknown | Yes | Implemented | `vault-admin-api.yaml` `/audit-logs/webhooks` |
| Log streaming to SIEM / Kafka | Unknown | Yes | Unknown | Yes | Missing | No log streaming destinations or stream health |
| Rate limiting | Unknown | Yes | Unknown | Unknown | Implemented | Redis-backed sliding window |
| Bot protection | Unknown | Unknown | Unknown | Unknown | Implemented | Turnstile/hCaptcha |
| Brute force protection | Unknown | Unknown | Yes | Unknown | Implemented | Account lockout policies |
| Breached password detection | Unknown | Unknown | Unknown | Unknown | Implemented | HaveIBeenPwned |

### DX (Developer Experience)
| Feature | Clerk | Auth0 | SuperTokens | FusionAuth | Vault status | Vault spec / notes |
| --- | --- | --- | --- | --- | --- | --- |
| SDKs (web, mobile) | Yes | Yes | Yes | Unknown | Implemented | `vault-sdk-*` packages (JS, React, Next.js, RN, Svelte, Vue) |
| Prebuilt UI components | Unknown | Unknown | Yes | Unknown | Missing | No embeddable auth widgets/components packages |
| Extensibility hooks/actions | Unknown | Yes | Yes | Unknown | Missing | No actions/rules pipeline |
| Admin dashboard | Yes | Yes | Yes | Yes | Partial | `vault-web` lacks tenant branding + analytics completeness |

### UI / Product Surface
| Feature | Clerk | Auth0 | SuperTokens | FusionAuth | Vault status | Vault spec / notes |
| --- | --- | --- | --- | --- | --- | --- |
| Hosted login pages | Yes | Yes | Yes | Yes | Partial | `vault-web` exists but not multi-tenant hosted login |
| Theme customization | Unknown | Yes | Yes | Unknown | Missing | No theming/branding APIs |
| Account portal (profile/MFA/sessions) | Yes | Yes | Yes | Yes | Partial | `vault-web` has settings UI; missing embed + theming |
| Admin analytics dashboards | Yes | Yes | Partial | Yes | Partial | Internal analytics endpoints are stubbed |

## Recommended Additions (Competitor-Driven)

### Highest impact gaps
1. OAuth2/OIDC Authorization Server (IdP) with app registration, JWKS, token introspection, revocation, and client credentials flow.
2. Email OTP & SMS MFA (first-class), plus optional push factors; include policies, templates, and self-serve enrollments.
3. Log streaming with connectors (Splunk/Datadog/etc.), filters, PII obfuscation, delivery health, and retries.
4. Actions/Rules pipeline (pre/post login, pre-register, token issuance) with isolation and audit logs.
5. Domain-based org auto-join / JIT membership, plus per-org branding/login customization.

### Medium impact gaps
1. Account linking / identity merge across providers.
2. OAuth device flow and service-to-service/M2M authorization model.
3. Hosted/embeddable UI components + theming API.
4. SCIM admin config persistence and UI.
5. Internal API auth + audit coverage for internal endpoints.

## Notes on Vault Status
- Endpoint-level statuses are tracked in `docs/competitor-feature-matrix.md`.
- Remaining roadmap items are tracked in `docs/roadmap-remaining-features.md`.
