# DR Overlay

Apply:
```bash
kubectl apply -k ops/kubernetes/overlays/dr
```

Update before use:
- `ops/kubernetes/overlays/dr/kustomization.yaml` image tag
- `ops/kubernetes/overlays/dr/secret-patch.yaml` (point to DR Postgres/Redis)
- `ops/kubernetes/overlays/dr/ingress-patch.yaml` host
