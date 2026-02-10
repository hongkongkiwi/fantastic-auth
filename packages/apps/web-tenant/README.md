# Tenant Admin Web App (`web-tenant`)

Web admin dashboard for tenant-level operations.

## Stack

- React + TypeScript
- Vite
- Tailwind CSS
- TanStack Query/Table/Form
- Vitest

## Commands

Run inside `packages/apps/web-tenant`:

```bash
pnpm install
pnpm dev
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm preview
```

## Environment

```env
VITE_API_URL=http://localhost:8080/api/v1/admin
```

## SDK Generation

```bash
pnpm generate:sdk
```

Generates `src/types/generated-admin-api.ts` from `../../specs/openapi/vault-admin-api.yaml`.

## Related Docs

- Docs index: `../../../docs/README.md`
- Admin route map: `../../../docs/admin-route-map.md`
- OpenAPI package: `../../specs/openapi/README.md`
