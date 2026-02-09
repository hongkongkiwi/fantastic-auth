# Fly.io

Set secrets:
```bash
fly secrets set VAULT_DATABASE_URL=... VAULT_REDIS_URL=... VAULT_JWT_SECRET=...
```
See `ops/deployments/RECOMMENDATIONS.md` for DB/Redis/HA guidance.

## Provider Notes
- Postgres: Fly Postgres or external managed Postgres.
- Redis: Upstash Redis or external managed Redis.
