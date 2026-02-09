# Staging Overlay

Apply:
```bash
kubectl apply -k ops/kubernetes/overlays/staging
```

Update before use:
- `ops/kubernetes/overlays/staging/kustomization.yaml` image tag
- `ops/kubernetes/overlays/staging/secret-patch.yaml` (use real secrets)
- `ops/kubernetes/overlays/staging/ingress-patch.yaml` host
