# Kubernetes Deployment

This folder provides a Kustomize base to run Vault in a highly-available setup.

## Highlights
- Stateless API pods (scale horizontally)
- Readiness/liveness probes
- Pod anti-affinity + spread constraints
- HPA + PDB
- Separate migration Job

## Usage
```bash
kubectl apply -k ops/kubernetes/base
```

Update image and secrets before apply:
- `ops/kubernetes/base/deployment.yaml` and `job-migrate.yaml`
- `ops/kubernetes/base/secret.yaml`

Note: These are templates only. We are not wiring Kubernetes into CI/CD right now.

## Production Overlay
```bash
kubectl apply -k ops/kubernetes/overlays/prod
```

Overlay files:
- `ops/kubernetes/overlays/prod/kustomization.yaml`
- `ops/kubernetes/overlays/prod/deployment-patch.yaml`
- `ops/kubernetes/overlays/prod/ingress-patch.yaml`
- `ops/kubernetes/overlays/prod/secret-patch.yaml`

## Staging Overlay
```bash
kubectl apply -k ops/kubernetes/overlays/staging
```

Overlay files:
- `ops/kubernetes/overlays/staging/kustomization.yaml`
- `ops/kubernetes/overlays/staging/ingress-patch.yaml`
- `ops/kubernetes/overlays/staging/secret-patch.yaml`

## DR Overlay
```bash
kubectl apply -k ops/kubernetes/overlays/dr
```

Overlay files:
- `ops/kubernetes/overlays/dr/kustomization.yaml`
- `ops/kubernetes/overlays/dr/deployment-patch.yaml`
- `ops/kubernetes/overlays/dr/ingress-patch.yaml`
- `ops/kubernetes/overlays/dr/secret-patch.yaml`

## DR / HA Guidance
- Use a managed Postgres with PITR and read replicas.
- Use Redis with persistence and clustering/sentinel.
- Run at least 3 replicas across nodes.
- Keep JWT secrets and encryption keys in a secure secret manager.

## Helm
If you prefer Helm, see `ops/helm/vault/README.md`.
