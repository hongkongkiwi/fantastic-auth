# Custom Domains (White-Label) Setup Guide

This guide explains how to set up and use custom domains for Vault, allowing tenants to use their own domains (e.g., `auth.company.com`) for authentication pages.

## Overview

Custom domains enable tenants to:
- Use their own domain for authentication pages (e.g., `auth.company.com` instead of `vault.example.com`)
- Apply custom branding (logo, colors, page title)
- Provide a seamless white-label experience for their users

## Architecture

```
User Request → DNS → Reverse Proxy (nginx/traefik) → Vault Server
                    ↓
              SSL Termination (Let's Encrypt or Custom)
                    ↓
              Tenant Resolution by Host Header
```

## Setup Options

### Option 1: Simplified Setup (Reverse Proxy Handles SSL)

In this setup, your reverse proxy handles SSL termination and the Vault app just validates domain ownership.

#### 1. Configure Environment Variables

```bash
# Base domain for CNAME targets
VAULT_CUSTOM_DOMAINS_BASE_DOMAIN=vault.example.com

# Disable SSL management (reverse proxy handles it)
VAULT_CUSTOM_DOMAINS_ENABLE_SSL=false

# Optional: Storage path for certificates (if using custom SSL)
VAULT_CUSTOM_DOMAINS_CERT_STORAGE_PATH=/etc/vault/certs
```

#### 2. Configure nginx

Create a server block for wildcard/custom domains:

```nginx
# /etc/nginx/sites-available/vault-custom-domains
server {
    listen 80;
    server_name ~^(?<subdomain>.+)\.vault\.example\.com$;
    
    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ~^(?<subdomain>.+)\.vault\.example\.com$;
    
    # SSL Certificate (Let's Encrypt wildcard or individual)
    ssl_certificate /etc/letsencrypt/live/vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault.example.com/privkey.pem;
    
    # Or use individual certificates per domain
    # ssl_certificate /etc/vault/certs/$ssl_server_name-cert.pem;
    # ssl_certificate_key /etc/vault/certs/$ssl_server_name-key.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Enable WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# Wildcard SSL with Let's Encrypt
server {
    listen 443 ssl http2;
    server_name *.vault.example.com;
    
    ssl_certificate /etc/letsencrypt/live/vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault.example.com/privkey.pem;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the configuration:
```bash
sudo ln -s /etc/nginx/sites-available/vault-custom-domains /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Option 2: Using Traefik (Automatic SSL)

If you're using Docker/Kubernetes with Traefik:

```yaml
# docker-compose.yml
version: '3'
services:
  vault:
    image: vault:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.vault.rule=Host(`vault.example.com`) || HostRegexp(`{subdomain:[a-z0-9-]+}.vault.example.com`)"
      - "traefik.http.routers.vault.tls=true"
      - "traefik.http.routers.vault.tls.certresolver=letsencrypt"
```

## API Usage

### 1. Add a Custom Domain

```bash
curl -X POST https://vault.example.com/api/v1/admin/custom-domains \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "auth.company.com"
  }'
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "tenantId": "tenant-123",
  "domain": "auth.company.com",
  "status": "pending",
  "sslProvider": "lets_encrypt",
  "autoSsl": true,
  "forceHttps": true,
  "createdAt": "2024-01-15T10:30:00Z",
  "updatedAt": "2024-01-15T10:30:00Z"
}
```

### 2. Get DNS Instructions

```bash
curl https://vault.example.com/api/v1/admin/custom-domains/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "domain": "auth.company.com",
  "status": "pending",
  "verificationToken": "abc123xyz",
  "targetCname": "vault.example.com",
  ...
}
```

### 3. Configure DNS

Add a CNAME record pointing to your base domain:

| Type | Name | Value |
|------|------|-------|
| CNAME | auth.company.com | vault.example.com |

Or use A/AAAA records pointing to your server's IP.

### 4. Verify DNS

```bash
curl -X POST https://vault.example.com/api/v1/admin/custom-domains/550e8400-e29b-41d4-a716-446655440000/verify \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Response:
```json
{
  "success": true,
  "cnameRecord": "vault.example.com",
  "aRecords": [],
  "aaaaRecords": [],
  "checkedAt": "2024-01-15T10:35:00Z"
}
```

### 5. Update Branding

```bash
curl -X PATCH https://vault.example.com/api/v1/admin/custom-domains/550e8400-e29b-41d4-a716-446655440000/branding \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "logoUrl": "https://company.com/logo.png",
    "primaryColor": "#FF5733",
    "pageTitle": "Company Login",
    "faviconUrl": "https://company.com/favicon.ico"
  }'
```

### 6. Check SSL Status

```bash
curl https://vault.example.com/api/v1/admin/custom-domains/550e8400-e29b-41d4-a716-446655440000/status \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Domain Status Flow

```
Pending → Active (after DNS verification)
   ↓
Error (if DNS verification fails)
   ↓
Active → SSL Pending → Active (if auto-SSL is enabled)
   ↓
SSL Failed (if SSL provisioning fails)
```

## Certificate Renewal

If using Let's Encrypt auto-SSL, certificates are automatically renewed 30 days before expiry.

For manual renewal or custom certificates:

```bash
curl -X POST https://vault.example.com/api/v1/admin/custom-domains/550e8400-e29b-41d4-a716-446655440000/regenerate-ssl \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Security Considerations

1. **SSL/TLS**: Always use HTTPS in production. The `forceHttps` option redirects HTTP to HTTPS.

2. **Domain Validation**: Domains must be verified via DNS before they become active.

3. **Rate Limiting**: Certificate generation is rate-limited by Let's Encrypt (50 per week per domain).

4. **CORS**: Ensure your CORS settings allow requests from custom domains:
   ```bash
   VAULT_CORS_ORIGINS=https://auth.company.com,https://login.partner.org
   ```

## Troubleshooting

### Domain verification fails

1. Check DNS propagation:
   ```bash
   dig auth.company.com CNAME
   nslookup auth.company.com
   ```

2. Verify CNAME points to correct target:
   ```bash
   dig auth.company.com CNAME +short
   # Should return: vault.example.com
   ```

3. Wait for DNS propagation (can take up to 48 hours, usually 5-30 minutes)

### SSL certificate issues

1. Check domain is active:
   ```bash
   curl https://vault.example.com/api/v1/admin/custom-domains/$DOMAIN_ID \
     -H "Authorization: Bearer $TOKEN"
   ```

2. Regenerate certificate:
   ```bash
   curl -X POST https://vault.example.com/api/v1/admin/custom-domains/$DOMAIN_ID/regenerate-ssl \
     -H "Authorization: Bearer $TOKEN"
   ```

3. Check Let's Encrypt rate limits: https://letsencrypt.org/docs/rate-limits/

### Custom domain not routing

1. Verify Host header is passed by reverse proxy:
   ```bash
   curl -H "Host: auth.company.com" http://localhost:3000/api/v1/health
   ```

2. Check tenant resolution:
   ```bash
   curl https://auth.company.com/api/v1/health -v
   # Look for X-Tenant-ID header in response
   ```

## API Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/custom-domains` | List all custom domains |
| POST | `/api/v1/admin/custom-domains` | Add new custom domain |
| GET | `/api/v1/admin/custom-domains/:id` | Get domain details |
| DELETE | `/api/v1/admin/custom-domains/:id` | Remove custom domain |
| POST | `/api/v1/admin/custom-domains/:id/verify` | Verify DNS configuration |
| GET | `/api/v1/admin/custom-domains/:id/status` | Check DNS and SSL status |
| POST | `/api/v1/admin/custom-domains/:id/regenerate-ssl` | Regenerate SSL certificate |
| PATCH | `/api/v1/admin/custom-domains/:id/branding` | Update branding |
| PATCH | `/api/v1/admin/custom-domains/:id/ssl` | Update SSL settings |

## Configuration Reference

```yaml
# config.yaml
custom_domains:
  enabled: true
  base_domain: "vault.example.com"
  cert_storage_path: "/etc/vault/certs"
  auto_verify_dns: false
  enable_ssl: false  # Set to true for built-in SSL management
  ssl_provider: "lets_encrypt"  # or "custom" or "none"
  force_https: true
  acme_directory_url: "https://acme-v02.api.letsencrypt.org/directory"
  acme_contact_email: "admin@example.com"
  cert_renewal_interval_hours: 24
```

Or using environment variables:

```bash
VAULT_CUSTOM_DOMAINS_ENABLED=true
VAULT_CUSTOM_DOMAINS_BASE_DOMAIN=vault.example.com
VAULT_CUSTOM_DOMAINS_CERT_STORAGE_PATH=/etc/vault/certs
VAULT_CUSTOM_DOMAINS_AUTO_VERIFY_DNS=false
VAULT_CUSTOM_DOMAINS_ENABLE_SSL=false
VAULT_CUSTOM_DOMAINS_SSL_PROVIDER=lets_encrypt
VAULT_CUSTOM_DOMAINS_FORCE_HTTPS=true
VAULT_CUSTOM_DOMAINS_ACME_CONTACT_EMAIL=admin@example.com
```
