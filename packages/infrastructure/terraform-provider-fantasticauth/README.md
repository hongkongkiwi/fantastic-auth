# Terraform Provider for Fantasticauth

A Terraform provider for managing Fantasticauth resources. This provider allows you to manage users, organizations, OAuth clients, SAML connections, webhooks, and roles through infrastructure-as-code.

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.21 (for building the provider)

## Building the Provider

```bash
# Clone the repository
git clone https://github.com/fantasticauth/terraform-provider-fantasticauth
cd terraform-provider-fantasticauth

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
    fantasticauth = {
      source  = "fantasticauth/fantasticauth"
      version = "~> 1.0"
    }
  }
}

provider "fantasticauth" {
  api_key   = var.fantasticauth_api_key
  base_url  = "https://api.fantasticauth.com"
  tenant_id = var.fantasticauth_tenant_id
}
```

### Environment Variables

The provider can also be configured using environment variables:

- `FANTASTICAUTH_API_KEY` - The API key for Fantasticauth authentication
- `FANTASTICAUTH_BASE_URL` - The base URL of the Fantasticauth server
- `FANTASTICAUTH_TENANT_ID` - The tenant ID for Fantasticauth

### Resources

#### fantasticauth_user

```hcl
resource "fantasticauth_user" "example" {
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

#### fantasticauth_organization

```hcl
resource "fantasticauth_organization" "engineering" {
  name        = "Engineering Team"
  slug        = "engineering"
  description = "Engineering department"
  
  settings = {
    allow_signup = "false"
    require_mfa  = "true"
  }
}
```

#### fantasticauth_organization_member

```hcl
resource "fantasticauth_organization_member" "john_engineering" {
  organization_id = fantasticauth_organization.engineering.id
  user_id         = fantasticauth_user.example.id
  role            = "admin"
}
```

#### fantasticauth_oauth_client

```hcl
resource "fantasticauth_oauth_client" "web_app" {
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

#### fantasticauth_saml_connection

```hcl
resource "fantasticauth_saml_connection" "okta" {
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

#### fantasticauth_webhook

```hcl
resource "fantasticauth_webhook" "user_events" {
  name   = "User Events Webhook"
  url    = "https://api.example.com/webhooks/vault"
  events = ["user.created", "user.updated", "user.deleted"]
  
  secret = "webhook_signing_secret_123"
  
  headers = {
    "X-Custom-Header" = "custom-value"
  }
}
```

#### fantasticauth_role

```hcl
resource "fantasticauth_role" "custom_admin" {
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

#### fantasticauth_user

```hcl
data "fantasticauth_user" "existing" {
  email = "admin@example.com"
}
```

#### fantasticauth_organization

```hcl
data "fantasticauth_organization" "engineering" {
  slug = "engineering"
}
```

#### fantasticauth_tenant

```hcl
data "fantasticauth_tenant" "current" {}
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
terraform-provider-fantasticauth/
├── main.go                      # Entry point
├── internal/
│   ├── provider/
│   │   └── provider.go          # Provider schema and configuration
│   ├── tenantclient/
│   │   ├── config.go            # Configuration structs
│   │   └── client.go            # HTTP client for Fantasticauth API
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

Acceptance tests require a running Fantasticauth server:

```bash
export FANTASTICAUTH_API_KEY="your-api-key"
export FANTASTICAUTH_BASE_URL="https://api.fantasticauth.com"
export FANTASTICAUTH_TENANT_ID="your-tenant-id"
make testacc
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT License

## Support

For support, please open an issue on GitHub or contact the maintainers.
