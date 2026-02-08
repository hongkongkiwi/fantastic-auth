# GCP Cloud Run

Use `service.yaml` and set secrets in Secret Manager or as environment variables.
See `ops/deployments/RECOMMENDATIONS.md` for DB/Redis/HA guidance.

## Provider Notes
- Postgres: Cloud SQL for PostgreSQL (HA + PITR).
- Redis: Memorystore for Redis (AUTH + TLS where available).
