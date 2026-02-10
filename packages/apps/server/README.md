# Fantasticauth Server (`fantasticauth-server`)

Rust backend service for auth, organizations, sessions, MFA, OAuth/SSO, SCIM, admin APIs, and internal APIs.

## Source

- Library entry: [`src/lib.rs`](src/lib.rs)
- Binary entry: [`src/main.rs`](src/main.rs)
- Tests: [`tests/`](tests/)

## Run and Test

```bash
cargo run -p fantasticauth-server
cargo test -p fantasticauth-server
```

## Related Docs

- API examples: [`../../../docs/API_EXAMPLES.md`](../../../docs/API_EXAMPLES.md)
- OAuth providers: [`../../../docs/OAUTH_PROVIDERS.md`](../../../docs/OAUTH_PROVIDERS.md)
- Plugin system: [`../../../docs/PLUGIN_SYSTEM.md`](../../../docs/PLUGIN_SYSTEM.md)
- OpenAPI specs: [`../../specs/openapi/README.md`](../../specs/openapi/README.md)
