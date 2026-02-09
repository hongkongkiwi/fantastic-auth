# Deployment Recommendations

These apply across platforms:
- Use a managed Postgres with PITR (point-in-time recovery) and automated backups.
- Use managed Redis with persistence (AOF or snapshots) and multi-AZ where available.
- Run at least 2 application instances behind a load balancer.
- Store `VAULT_JWT_SECRET` and any encryption keys in a managed secret store.
- Run migrations as a one-off job/task before rolling out new app versions.

## Postgres
- Enable TLS to the database.
- Prefer read replicas for analytics/reporting.

## Redis
- Enable authentication and TLS.
- Use cluster/sentinel where available.

## Observability
- Scrape `/metrics` from port `9090`.
- Ship logs to a centralized logging system.
