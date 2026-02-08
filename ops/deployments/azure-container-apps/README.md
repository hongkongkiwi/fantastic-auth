# Azure Container Apps

Use `containerapp.yaml` as a template. Replace secrets and managed environment ID.
See `ops/deployments/RECOMMENDATIONS.md` for DB/Redis/HA guidance.

## Provider Notes
- Postgres: Azure Database for PostgreSQL (Flexible Server) with HA.
- Redis: Azure Cache for Redis (AUTH + TLS).
