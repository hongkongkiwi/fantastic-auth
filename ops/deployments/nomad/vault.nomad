job "vault" {
  datacenters = ["dc1"]
  type = "service"

  group "vault" {
    count = 2

    network {
      port "http" {
        to = 3000
      }
      port "metrics" {
        to = 9090
      }
    }

    task "vault" {
      driver = "docker"

      config {
        image = "ghcr.io/your-org/vault-server:latest"
        ports = ["http", "metrics"]
      }

      env {
        VAULT_HOST = "0.0.0.0"
        VAULT_PORT = "3000"
        VAULT_METRICS_PORT = "9090"
        VAULT_LOG_LEVEL = "info"
      }

      template {
        data = <<EOH
VAULT_DATABASE_URL={{ with secret "secret/data/vault" }}{{ .Data.data.database_url }}{{ end }}
VAULT_REDIS_URL={{ with secret "secret/data/vault" }}{{ .Data.data.redis_url }}{{ end }}
VAULT_JWT_SECRET={{ with secret "secret/data/vault" }}{{ .Data.data.jwt_secret }}{{ end }}
EOH
        destination = "secrets/env"
        env = true
      }

      resources {
        cpu    = 500
        memory = 1024
      }

      service {
        name = "vault"
        port = "http"
        check {
          type     = "http"
          path     = "/health"
          interval = "10s"
          timeout  = "2s"
        }
      }
    }
  }
}
