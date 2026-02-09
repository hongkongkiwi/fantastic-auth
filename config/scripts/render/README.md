# Render

Set secrets in the Render dashboard for the env vars marked `sync: false`.
See `ops/deployments/RECOMMENDATIONS.md` for DB/Redis/HA guidance.

## Provider Notes
- Postgres: Render Postgres (HA plan recommended).
- Redis: Render Redis or external managed Redis.
