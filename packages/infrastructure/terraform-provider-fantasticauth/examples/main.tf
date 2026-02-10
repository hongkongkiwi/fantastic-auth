terraform {
  required_providers {
    fantasticauth = {
      source  = "fantasticauth/fantasticauth"
      version = "~> 1.0"
    }
  }
}

variable "fantasticauth_api_key" {
  description = "Fantasticauth API Key"
  type        = string
  sensitive   = true
}

variable "fantasticauth_base_url" {
  description = "Fantasticauth Base URL"
  type        = string
  default     = "https://api.fantasticauth.com"
}

variable "fantasticauth_tenant_id" {
  description = "Fantasticauth Tenant ID"
  type        = string
}

provider "fantasticauth" {
  api_key   = var.fantasticauth_api_key
  base_url  = var.fantasticauth_base_url
  tenant_id = var.fantasticauth_tenant_id
}

# Create a user
resource "fantasticauth_user" "example" {
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
resource "fantasticauth_organization" "engineering" {
  name        = "Engineering Team"
  slug        = "engineering"
  description = "Engineering department"

  settings = {
    allow_signup = "false"
    require_mfa  = "true"
  }
}

# Add user to organization
resource "fantasticauth_organization_member" "john_engineering" {
  organization_id = fantasticauth_organization.engineering.id
  user_id         = fantasticauth_user.example.id
  role            = "admin"
}

# Create OAuth client
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

# Create SAML connection
resource "fantasticauth_saml_connection" "okta" {
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
resource "fantasticauth_webhook" "user_events" {
  name   = "User Events Webhook"
  url    = "https://api.example.com/webhooks/fantasticauth"
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

# Data sources
data "fantasticauth_user" "existing" {
  email = "admin@example.com"
}

data "fantasticauth_organization" "engineering_data" {
  slug = "engineering"
}

data "fantasticauth_tenant" "current" {}

# Outputs
output "user_id" {
  value = fantasticauth_user.example.id
}

output "organization_id" {
  value = fantasticauth_organization.engineering.id
}

output "oauth_client_id" {
  value = fantasticauth_oauth_client.web_app.client_id
}

output "oauth_client_secret" {
  value     = fantasticauth_oauth_client.web_app.client_secret
  sensitive = true
}

output "existing_user_id" {
  value = data.fantasticauth_user.existing.id
}

output "current_tenant_name" {
  value = data.fantasticauth_tenant.current.name
}
