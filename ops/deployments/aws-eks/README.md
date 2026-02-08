# AWS EKS

Use the Kubernetes templates in `ops/kubernetes/`.
See `ops/deployments/RECOMMENDATIONS.md` for DB/Redis/HA guidance.

## Provider Notes
- Postgres: Amazon RDS or Aurora PostgreSQL (Multi-AZ, PITR enabled).
- Redis: ElastiCache Redis (Multi-AZ, AUTH + TLS).
