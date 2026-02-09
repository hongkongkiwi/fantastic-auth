# Vault Web (TanStack Start)

Internal web console for Vault. This UI only talks to the Rust internal API; it does not access the database directly.

## Requirements

- Node.js 18+
- pnpm

## Development

```bash
pnpm install
pnpm dev
```

The app runs at `http://localhost:3000`.

## Configuration

Server-side environment variables:

- `INTERNAL_API_BASE_URL` (default: `http://localhost:3000/api/v1/internal`)
- `INTERNAL_API_KEY` (required for internal endpoints)
- `INTERNAL_UI_TOKEN` (optional, enforces a UI access token)
- `INTERNAL_UI_PASSWORD` (optional, enables session-based UI access)
- `INTERNAL_UI_AUDIT_STORAGE` (optional, default: `file`)
- `LOG_LEVEL` (optional, `trace|debug|info|warn|error|fatal`)

Client-side environment variables:

- `VITE_INTERNAL_API_BASE_URL` (optional, overrides the default internal API base URL)
- `VITE_INTERNAL_UI_TOKEN` (optional, provides a default UI token in the client)
- `VITE_SENTRY_DSN` (optional, enables Sentry error reporting)
- `VITE_SENTRY_ENVIRONMENT` (optional, sets Sentry environment)
- `VITE_SENTRY_TRACES_SAMPLE_RATE` (optional, 0.0 - 1.0)
- `VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH` (optional, overrides for matched routes)
- `VITE_SENTRY_TRACES_SAMPLE_RATE_HIGH_ROUTES` (optional, comma-separated route prefixes)
- `VITE_SENTRY_TRACES_SAMPLE_RATE_LOW` (optional, overrides for matched routes)
- `VITE_SENTRY_TRACES_SAMPLE_RATE_LOW_ROUTES` (optional, comma-separated route prefixes)

Client-side stored values:

- `vault_internal_api_base_url`
- `vault_internal_ui_token`
- `vault_internal_ui_session` (session storage)

Sentry build-time variables (optional, for source map uploads):

- `SENTRY_AUTH_TOKEN`
- `SENTRY_ORG`
- `SENTRY_PROJECT`
- `SENTRY_RELEASE` (optional)

## OpenAPI SDK (TypeScript)

The internal SDK is generated from `openapi/vault-internal-api.yaml`.

```bash
pnpm generate:sdk
```

Generated output: `src/sdk/internal.ts`.

## Features

- Access panel for base URL + optional UI token + UI session login
- Platform overview (cached server-side for 30s)
- List tenants (cached server-side for 30s)
- Tenant detail view
- Create tenants
- Update tenants (plan, limits, settings)
- Suspend / activate tenants
- Delete tenants
- Migrate tenants
- Platform user search + detail
- List billing subscriptions (cached server-side for 30s)
- Subscription detail
- Update subscriptions
- Generate invoices
- Local audit log with CSV export + filtering + sorting
- Server audit log (persisted) with time-range filtering, pagination, sorting, and CSV export (streaming for large logs, gzip fallback)
- CSV export for tenants, subscriptions, users, and invoices
