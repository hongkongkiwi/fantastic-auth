# Deployment Templates

This folder provides **templates only** for popular hosting platforms. None of these are wired into CI/CD.

Each template assumes the same runtime contract:
- `VAULT_DATABASE_URL` and `VAULT_REDIS_URL` set
- `VAULT_JWT_SECRET` set
- HTTP port `3000`, metrics `9090`

General recommendations: see `ops/deployments/RECOMMENDATIONS.md`.

## Contents
- AWS ECS/Fargate: `ops/deployments/aws-ecs/`
- AWS EKS (K8s): `ops/deployments/aws-eks/` (points to k8s templates)
- GCP Cloud Run: `ops/deployments/gcp-cloud-run/`
- GCP GKE (K8s): `ops/deployments/gcp-gke/`
- Azure Container Apps: `ops/deployments/azure-container-apps/`
- Azure AKS (K8s): `ops/deployments/azure-aks/`
- Fly.io: `ops/deployments/fly/`
- Render: `ops/deployments/render/`
- Railway: `ops/deployments/railway/`
- DigitalOcean App Platform: `ops/deployments/digitalocean/`
- Nomad: `ops/deployments/nomad/`
- Docker Swarm: `ops/deployments/docker-swarm/`
