terraform {
  required_providers {
    vault = {
      source  = "vault-auth/vault"
      version = "~> 1.0"
    }
  }
}

variable "vault_api_key" {
  description = "Vault API Key"
  type        = string
  sensitive   = true
}

variable "vault_base_url" {
  description = "Vault Base URL"
  type        = string
  default     = "https://vault.example.com"
}

variable "vault_tenant_id" {
  description = "Vault Tenant ID"
  type        = string
}

provider "vault" {
  api_key   = var.vault_api_key
  base_url  = var.vault_base_url
  tenant_id = var.vault_tenant_id
}

# Create a user
resource "vault_user" "example" {
  email    = "user@example.com"
  password = random_password.user_password.result

  first_name = "John"
  last_name  = "Doe"

  email_verified = true

  metadata = {
    department = "Engineering"
    role       = "Senior Developer"
  }
}

# Generate a secure password
resource "random_password" "user_password" {
  length  = 16
  special = true
}

# Create an organization
resource "vault_organization" "engineering" {
  name        = "Engineering Team"
  slug        = "engineering"
  description = "Engineering department"

  settings = {
    allow_signup = "false"
    require_mfa  = "true"
  }
}

# Add user to organization
resource "vault_organization_member" "john_engineering" {
  organization_id = vault_organization.engineering.id
  user_id         = vault_user.example.id
  role            = "admin"
}

# Create OAuth client
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

# Create SAML connection
resource "vault_saml_connection" "okta" {
  name = "Okta SSO"

  idp_metadata_xml = file("${path.module}/okta-metadata.xml")

  name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

  attribute_mappings = {
    email      = "user.email"
    first_name = "user.firstName"
    last_name  = "user.lastName"
    groups     = "groups"
  }

  jit_provisioning_enabled = true
}

# Create webhook
resource "vault_webhook" "user_events" {
  name   = "User Events Webhook"
  url    = "https://api.example.com/webhooks/vault"
  events = ["user.created", "user.updated", "user.deleted"]

  secret = var.webhook_secret

  headers = {
    "X-Custom-Header" = "custom-value"
  }
}

variable "webhook_secret" {
  description = "Webhook signing secret"
  type        = string
  sensitive   = true
}

# Create custom role
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

# Data sources
data "vault_user" "existing" {
  email = "admin@example.com"
}

data "vault_organization" "engineering_data" {
  slug = "engineering"
}

data "vault_tenant" "current" {}

# Outputs
output "user_id" {
  value = vault_user.example.id
}

output "organization_id" {
  value = vault_organization.engineering.id
}

output "oauth_client_id" {
  value = vault_oauth_client.web_app.client_id
}

output "oauth_client_secret" {
  value     = vault_oauth_client.web_app.client_secret
  sensitive = true
}

output "existing_user_id" {
  value = data.vault_user.existing.id
}

output "current_tenant_name" {
  value = data.vault_tenant.current.name
}
