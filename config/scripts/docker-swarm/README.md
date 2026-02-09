# Docker Swarm

Deploy:
```bash
docker stack deploy -c ops/deployments/docker-swarm/stack.yml vault
```
See `ops/deployments/RECOMMENDATIONS.md` for DB/Redis/HA guidance.

## Provider Notes
- Postgres: use managed Postgres (e.g., RDS/Cloud SQL/Azure PG) or self-managed with PITR.
- Redis: managed Redis (e.g., ElastiCache/Memorystore/Azure Cache).
