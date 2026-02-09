# GCP GKE

Use the Kubernetes templates in `ops/kubernetes/`.
See `ops/deployments/RECOMMENDATIONS.md` for DB/Redis/HA guidance.

## Provider Notes
- Postgres: Cloud SQL for PostgreSQL (HA + PITR).
- Redis: Memorystore for Redis (AUTH + TLS where available).
