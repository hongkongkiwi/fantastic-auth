# FantasticAuth Monorepo

Authentication platform with Rust backend services, web apps, SDKs, OpenAPI specs, plugins, and infrastructure definitions.

## Documentation

- Docs index: [`docs/README.md`](docs/README.md)
- Package index: [`packages/README.md`](packages/README.md)
- OpenAPI specs: [`packages/specs/openapi/README.md`](packages/specs/openapi/README.md)

## Repository Layout

- Apps: [`packages/apps/README.md`](packages/apps/README.md)
- Core libraries: [`packages/core/README.md`](packages/core/README.md)
- Database: [`packages/database/README.md`](packages/database/README.md)
- Plugins: [`packages/plugins/README.md`](packages/plugins/README.md)
- SDKs: [`packages/sdks/README.md`](packages/sdks/README.md)
- Infrastructure: [`packages/infrastructure/README.md`](packages/infrastructure/README.md)
- Specs: [`packages/specs/README.md`](packages/specs/README.md)

## Quick Start

### Rust services

```bash
cargo check
cargo test
```

### Web apps (run inside each app directory)

```bash
pnpm install
pnpm dev
```

Web apps:
- [`packages/apps/web-platform`](packages/apps/web-platform)
- [`packages/apps/web-tenant`](packages/apps/web-tenant)
- [`packages/apps/web-user`](packages/apps/web-user)
