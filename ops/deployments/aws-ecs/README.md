# AWS ECS/Fargate

Templates:
- `task-definition.json`
- `service.json`

Notes:
- Use SSM Parameter Store or Secrets Manager for secrets.
- Run migrations using a one-off task with `dbmate`.
- See `ops/deployments/RECOMMENDATIONS.md` for DB/Redis/HA guidance.

## Provider Notes
- Postgres: Amazon RDS or Aurora PostgreSQL (Multi-AZ, PITR enabled).
- Redis: ElastiCache Redis (Multi-AZ, AUTH + TLS).
