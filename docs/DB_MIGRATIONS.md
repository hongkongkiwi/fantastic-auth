# Database Migrations

We use **dbmate** for migrations. It supports SQL-first workflows and explicit rollbacks via `.down.sql` files.

## Structure
- Up migrations: `migrations/<version>_<name>.sql`
- Down migrations: `migrations/<version>_<name>.down.sql`

Example:
```
20260210120000_add_projects.sql
20260210120000_add_projects.down.sql
```

## Run Locally
```bash
export DATABASE_URL=postgres://user:pass@localhost:5432/vault
scripts/migrations/up.sh
scripts/migrations/status.sh
scripts/migrations/down.sh 1
```

If `dbmate` isn’t installed, the scripts fall back to the Docker image.

## CI Guard
CI enforces:
- Every new migration has a `.down.sql` rollback file.
- Every new `CREATE TABLE` enables RLS (unless explicitly allowlisted).

See `scripts/ci/migration_guard.py`.
