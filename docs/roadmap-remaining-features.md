# Remaining Feature Roadmap (After Admin Stabilization)

Updated: 2026-02-09

## Completed in this pass
- Admin canonical route mounts stabilized for:
  - `/api/v1/admin/dashboard`
  - `/api/v1/admin/organizations`
  - `/api/v1/admin/audit-logs`
- Web admin API client aligned to backend paths with typed endpoint map:
  - `/oidc/clients`
  - `/sso/saml/connections`
  - `/settings/v2/*`
  - `/audit-logs/exports`
- Password policy updates now persist via tenant settings service.
- OIDC usage stats/isActive placeholders replaced with DB-backed values.
- Consent export generation now writes real JSON export artifacts and exposes download:
  - `/api/v1/consents/export/:export_id/download`
- Bulk import lifecycle improved:
  - Job status transitions persisted (`pending -> processing -> completed/failed`)
  - `update_existing` implemented for imported users
  - Optional welcome email delivery implemented (best-effort when email service is configured)
- SCIM operational gaps addressed:
  - User group memberships now populated in SCIM user responses
  - PATCH remove filter semantics added for emails (`emails[value eq "..."]`, `emails[type eq "..."]`)
  - SCIM audit logs now capture IP and User-Agent
- SAML SLO GET now supports user-initiated flow (no `NotImplemented` response path).
- Push MFA route surface no longer advertises a 501 websocket contract path.
- Admin backlog test ledger no longer relies on ignored placeholders for touched areas.

## Remaining High-Priority Work
1. Admin route namespace cleanup outside canonical trio
- Some admin modules are still mounted as flat roots and should be explicitly namespaced to avoid future ambiguity.

2. OpenAPI source-of-truth alignment
- `packages/specs/openapi/vault-admin-api.yaml` still needs route/shape synchronization for the newly stabilized and corrected admin paths.
- SDK generation currently succeeds, but reflects the current OpenAPI spec, not guaranteed runtime parity.

3. SDK and UI contract harmonization
- Continue normalizing response payload shapes between backend and `fantasticauth-web-admin` to reduce per-endpoint adaptation logic.

4. CI enforcement
- Add CI checks for:
  - admin route map generation + uniqueness assertions
  - OpenAPI drift detection
  - SDK regeneration drift detection
