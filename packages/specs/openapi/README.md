# OpenAPI Specs and SDK Generation

This package stores Fantasticauth OpenAPI specs and generation tooling.

## Specs

- `vault-api.yaml`: main public API
- `vault-client-api.yaml`: client-facing API surface
- `vault-admin-api.yaml`: admin API surface
- `vault-internal-api.yaml`: internal platform API surface

## Generation

- Script: `generate.sh`
- Generator config: `openapitools.json`
- Generated TypeScript SDK output: `../../../generated/typescript`

Run from this directory:

```bash
./generate.sh
```

## Related SDK Packages

- React/App SDK: `../../sdks/app-sdks/js/README.md`
- Next.js SDK: `../../sdks/app-sdks/nextjs/README.md`
- Internal JS SDK: `../../sdks/internal-sdks/js/README.md`
- Tenant JS SDK: `../../sdks/tenant-sdks/js/README.md`

## Related Docs

- API examples: `../../../docs/API_EXAMPLES.md`
- Package index: `../../README.md`
