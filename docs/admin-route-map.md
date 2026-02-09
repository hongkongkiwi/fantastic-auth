# Admin Route Map (Canonical Surface)

Generated on 2026-02-09 from:
- `fantasticauth-server/src/routes/admin/mod.rs`
- `fantasticauth-server/src/routes/admin/dashboard.rs`
- `fantasticauth-server/src/routes/admin/organizations.rs`
- `fantasticauth-server/src/routes/admin/audit_logs.rs`

## Canonical Mounts
- `/api/v1/admin/dashboard` -> `dashboard::routes()`
- `/api/v1/admin/organizations` -> `organizations::routes()`
- `/api/v1/admin/audit-logs` -> `audit_logs::routes()`

## Mounted Endpoints
- `GET /api/v1/admin/dashboard`
- `GET /api/v1/admin/organizations`
- `GET /api/v1/admin/organizations/:org_id`
- `PATCH /api/v1/admin/organizations/:org_id`
- `DELETE /api/v1/admin/organizations/:org_id`
- `GET /api/v1/admin/organizations/:org_id/members`
- `POST /api/v1/admin/organizations/:org_id/members`
- `PATCH /api/v1/admin/organizations/:org_id/members/:user_id`
- `DELETE /api/v1/admin/organizations/:org_id/members/:user_id`
- `GET /api/v1/admin/organizations/:org_id/invitations`
- `DELETE /api/v1/admin/organizations/:org_id/invitations/:invitation_id`
- `GET /api/v1/admin/audit-logs`

## Uniqueness Check
- Scope checked: canonical admin mounts above.
- Result: no method+path collisions in canonical mounted endpoints.
