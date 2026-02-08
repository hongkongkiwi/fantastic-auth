# Terraform Provider for Vault

A Terraform provider for managing Vault resources. This provider allows you to manage users, organizations, OAuth clients, SAML connections, webhooks, and roles through infrastructure-as-code.

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.21 (for building the provider)

## Building the Provider

```bash
# Clone the repository
git clone https://github.com/vault-auth/terraform-provider-vault
cd terraform-provider-vault

# Build the provider
make build

# Or install locally for testing
make install
```

## Using the Provider

### Provider Configuration

```hcl
terraform {
  required_providers {
    vault = {
      source  = "vault-auth/vault"
      version = "~> 1.0"
    }
  }
}

provider "vault" {
  api_key   = var.vault_api_key
  base_url  = "https://vault.example.com"
  tenant_id = var.vault_tenant_id
}
```

### Environment Variables

The provider can also be configured using environment variables:

- `VAULT_API_KEY` - The API key for Vault authentication
- `VAULT_BASE_URL` - The base URL of the Vault server
- `VAULT_TENANT_ID` - The tenant ID for Vault

### Resources

#### vault_user

```hcl
resource "vault_user" "example" {
  email    = "user@example.com"
  password = "secure_password_123"
  
  first_name = "John"
  last_name  = "Doe"
  
  email_verified = true
  
  metadata = {
    department = "Engineering"
    role       = "Senior Developer"
  }
}
```

#### vault_organization

```hcl
resource "vault_organization" "engineering" {
  name        = "Engineering Team"
  slug        = "engineering"
  description = "Engineering department"
  
  settings = {
    allow_signup = "false"
    require_mfa  = "true"
  }
}
```

#### vault_organization_member

```hcl
resource "vault_organization_member" "john_engineering" {
  organization_id = vault_organization.engineering.id
  user_id         = vault_user.example.id
  role            = "admin"
}
```

#### vault_oauth_client

```hcl
resource "vault_oauth_client" "web_app" {
  name        = "Web Application"
  description = "Main web app OAuth client"
  
  redirect_uris = [
    "https://app.example.com/callback",
    "https://app.example.com/silent"
  ]
  
  allowed_scopes = ["openid", "profile", "email"]
  allowed_grants = ["authorization_code", "refresh_token"]
  
  is_confidential = true
}
```

#### vault_saml_connection

```hcl
resource "vault_saml_connection" "okta" {
  name = "Okta SSO"
  
  idp_metadata_xml = file("okta-metadata.xml")
  
  name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  
  attribute_mappings = {
    email      = "user.email"
    first_name = "user.firstName"
    last_name  = "user.lastName"
    groups     = "groups"
  }
  
  jit_provisioning_enabled = true
}
```

#### vault_webhook

```hcl
resource "vault_webhook" "user_events" {
  name   = "User Events Webhook"
  url    = "https://api.example.com/webhooks/vault"
  events = ["user.created", "user.updated", "user.deleted"]
  
  secret = "webhook_signing_secret_123"
  
  headers = {
    "X-Custom-Header" = "custom-value"
  }
}
```

#### vault_role

```hcl
resource "vault_role" "custom_admin" {
  name        = "custom_admin"
  description = "Custom administrator role"
  
  permissions = [
    "users:read",
    "users:write",
    "organizations:read",
    "organizations:write",
  ]
}
```

### Data Sources

#### vault_user

```hcl
data "vault_user" "existing" {
  email = "admin@example.com"
}
```

#### vault_organization

```hcl
data "vault_organization" "engineering" {
  slug = "engineering"
}
```

#### vault_tenant

```hcl
data "vault_tenant" "current" {}
```

## Development

### Requirements

- Go >= 1.21
- Terraform >= 1.0

### Building

```bash
# Build the provider
make build

# Install locally for testing
make install

# Run tests
make test

# Run acceptance tests
make testacc
```

### Project Structure

```
terraform-provider-vault/
├── main.go                      # Entry point
├── internal/
│   ├── provider/
│   │   ├── provider.go          # Provider schema and configuration
│   │   ├── config.go            # Configuration structs
│   │   └── client.go            # HTTP client for Vault API
│   ├── resources/
│   │   ├── resource_user.go
│   │   ├── resource_organization.go
│   │   ├── resource_organization_member.go
│   │   ├── resource_oauth_client.go
│   │   ├── resource_saml_connection.go
│   │   ├── resource_webhook.go
│   │   └── resource_role.go
│   └── data_sources/
│       ├── data_source_user.go
│       ├── data_source_organization.go
│       └── data_source_tenant.go
├── examples/
│   └── main.tf                  # Example usage
├── Makefile
├── go.mod
└── README.md
```

## Testing

### Unit Tests

```bash
make test
```

### Acceptance Tests

Acceptance tests require a running Vault server:

```bash
export VAULT_API_KEY="your-api-key"
export VAULT_BASE_URL="https://vault.example.com"
export VAULT_TENANT_ID="your-tenant-id"
make testacc
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT License

## Support

For support, please open an issue on GitHub or contact the maintainers.
