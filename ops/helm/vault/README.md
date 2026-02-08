# Helm Chart

Install:
```bash
helm upgrade --install vault ops/helm/vault \
  --namespace vault --create-namespace
```

Configure values in `ops/helm/vault/values.yaml`.

Migrations are run via a Job when `migrations.enabled=true`.
