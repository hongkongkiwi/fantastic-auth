# Production Overlay

Apply:
```bash
kubectl apply -k ops/kubernetes/overlays/prod
```

Update before use:
- `ops/kubernetes/overlays/prod/kustomization.yaml` image tag
- `ops/kubernetes/overlays/prod/secret-patch.yaml` (use real secrets)
- `ops/kubernetes/overlays/prod/ingress-patch.yaml` host + TLS secret

Migrations are run via `vault-migrate` Job. In CI, see `.github/workflows/deploy-staging.yml`.
