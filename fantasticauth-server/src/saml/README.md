# SAML 2.0 Implementation for Fantastic Auth

## Overview

This module provides complete SAML 2.0 Service Provider (SP) support for Fantastic Auth, enabling enterprise Single Sign-On (SSO) with identity providers like Okta, Azure AD, OneLogin, Auth0, and more.

## Features

### Core SAML Features
- **SP-initiated SSO** - Standard SAML flow initiated from Fantastic Auth
- **IdP-initiated SSO** - Login initiated from the Identity Provider
- **Single Logout (SLO)** - Synchronous logout across IdP and SP
- **Signed Requests** - RSA-SHA256 signing of authentication requests
- **Signed Assertions** - Validation of signed SAML assertions
- **Encrypted Assertions** - Support for encrypted assertions (infrastructure ready)
- **Multiple Bindings** - HTTP-Redirect and HTTP-POST bindings

### Security Features
- **XML Signature Validation** - Full XML-DSig validation using OpenSSL
- **X509 Certificate Management** - Certificate parsing, validation, and chain verification
- **Time Validation** - Strict NotBefore/NotOnOrAfter checking with configurable clock skew
- **Audience Restriction** - Validation of audience restrictions
- **Replay Attack Prevention** - Request/response ID tracking with Redis
- **Destination Validation** - Verification of ACS and SLO URLs

### Enterprise Features
- **JIT Provisioning** - Automatic user creation from SAML attributes
- **Attribute Mapping** - Flexible mapping of SAML attributes to user profiles
- **Group/Role Mapping** - Map SAML groups to Fantastic Auth roles
- **Multiple Connections** - Multiple SAML IdPs per tenant
- **Metadata Management** - Automatic SP metadata generation and IdP metadata parsing
- **Certificate Rotation** - Automated certificate generation and rotation

## Module Structure

```
fantasticauth-server/src/saml/
├── mod.rs           # Core types (SamlRequest, SamlResponse, SamlAssertion, etc.)
├── crypto.rs        # X509 certificates, XML signatures, RSA operations
├── metadata.rs      # SP metadata generation, IdP metadata parsing
├── handlers.rs      # HTTP endpoints (login, ACS, SLO, metadata)
├── validation.rs    # Assertion/response validation
└── README.md        # This file
```

## API Endpoints

### Public Endpoints (No Authentication)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/login` | GET | Initiate SAML SSO - redirects to IdP |
| `/saml/acs` | POST | Assertion Consumer Service - receives SAML Response |
| `/saml/slo` | GET | Single Logout (HTTP-Redirect binding) |
| `/saml/slo` | POST | Single Logout (HTTP-POST binding) |
| `/saml/metadata` | GET | Service Provider metadata XML |

### Admin Endpoints (Authentication Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/admin/sso/saml/connections` | GET | List SAML connections |
| `/api/v1/admin/sso/saml/connections` | POST | Create SAML connection |
| `/api/v1/admin/sso/saml/connections/:id` | GET | Get connection details |
| `/api/v1/admin/sso/saml/connections/:id` | PATCH | Update connection |
| `/api/v1/admin/sso/saml/connections/:id` | DELETE | Delete connection |
| `/api/v1/admin/sso/saml/connections/:id/metadata` | GET | Download SP metadata |
| `/api/v1/admin/sso/saml/connections/:id/metadata` | POST | Upload IdP metadata XML |
| `/api/v1/admin/sso/saml/connections/:id/certificates` | GET | List certificates |
| `/api/v1/admin/sso/saml/connections/:id/certificates` | POST | Generate new certificate |
| `/api/v1/admin/sso/saml/connections/:id/certificates/rotate` | POST | Rotate certificate |
| `/api/v1/admin/sso/saml/connections/:id/test` | POST | Test connection |
| `/api/v1/admin/sso/saml/connections/:id/attribute-mappings` | GET | Get attribute mappings |
| `/api/v1/admin/sso/saml/connections/:id/attribute-mappings` | PUT | Update attribute mappings |

## SAML Flow

### SP-Initiated SSO

```
1. User clicks "Login with SAML"
   ↓
2. GET /saml/login
   ↓
3. Fantastic Auth generates AuthnRequest (signed if configured)
   ↓
4. Redirect to IdP SSO URL with SAMLRequest parameter
   ↓
5. User authenticates at IdP
   ↓
6. IdP POSTs SAML Response to /saml/acs
   ↓
7. Fantastic Auth validates signature, extracts attributes
   ↓
8. Find or create user (JIT provisioning)
   ↓
9. Create session, issue JWT tokens
   ↓
10. Redirect to success URL with tokens
```

### IdP-Initiated SSO

```
1. User logs into IdP portal
   ↓
2. User clicks Fantastic Auth application
   ↓
3. IdP POSTs SAML Response directly to /saml/acs
   ↓
4-10. Same as SP-initiated flow
```

## Database Schema

### saml_connections Table

```sql
CREATE TABLE saml_connections (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,

    -- IdP Configuration
    idp_entity_id VARCHAR(500),
    idp_sso_url VARCHAR(500),
    idp_slo_url VARCHAR(500),
    idp_certificate TEXT,

    -- SP Configuration
    sp_entity_id VARCHAR(500) NOT NULL,
    sp_acs_url VARCHAR(500) NOT NULL,
    sp_slo_url VARCHAR(500),
    sp_certificate TEXT,
    sp_private_key TEXT,

    -- Settings
    name_id_format VARCHAR(100) DEFAULT 'email_address',
    want_authn_requests_signed BOOLEAN DEFAULT false,
    want_assertions_signed BOOLEAN DEFAULT true,
    want_assertions_encrypted BOOLEAN DEFAULT false,

    -- Attribute Mappings & JIT
    attribute_mappings JSONB,
    jit_provisioning_enabled BOOLEAN DEFAULT true,
    jit_default_role VARCHAR(50),

    -- Status
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
```

## Configuration Example

### Creating a SAML Connection

```bash
POST /api/v1/admin/sso/saml/connections
{
    "name": "Okta SSO",
    "idp_entity_id": "http://www.okta.com/exk1234567890",
    "idp_sso_url": "https://your-domain.okta.com/app/fantasticauth/exk1234567890/sso/saml",
    "idp_slo_url": "https://your-domain.okta.com/app/fantasticauth/exk1234567890/slo/saml",
    "idp_certificate": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
    "want_authn_requests_signed": true,
    "want_assertions_signed": true,
    "jit_provisioning_enabled": true,
    "attribute_mappings": {
        "email": "email",
        "firstName": "profile.first_name",
        "lastName": "profile.last_name",
        "displayName": "profile.name",
        "groups": "metadata.groups"
    }
}
```

### Uploading IdP Metadata

```bash
POST /api/v1/admin/sso/saml/connections/:id/metadata
Content-Type: multipart/form-data

metadata: [metadata.xml file]
```

## Attribute Mapping

Default attribute mappings:

| SAML Attribute | Fantastic Auth Field | Required |
|---------------|-------------|----------|
| `email` | `email` | Yes |
| `firstName` | `profile.first_name` | No |
| `lastName` | `profile.last_name` | No |
| `displayName` | `profile.name` | No |
| `groups` | `metadata.groups` | No |

Custom mappings can be configured per connection.

## Security Considerations

1. **Private Key Storage**: SP private keys are stored encrypted at the application level
2. **Certificate Validation**: IdP certificates are validated for expiration and chain trust
3. **Clock Skew**: Default 60 seconds clock skew allowance for time validation
4. **Replay Prevention**: 24-hour message log retention with Redis
5. **Signature Validation**: All assertions must be signed when `want_assertions_signed` is true

## Testing

### Test SAML Connection

```bash
POST /api/v1/admin/sso/saml/connections/:id/test
```

Response:
```json
{
    "success": true,
    "message": "SAML connection configuration is valid",
    "details": {
        "idp_entity_id_configured": true,
        "idp_sso_url_configured": true,
        "idp_certificate_configured": true,
        "sp_certificate_configured": true
    }
}
```

## Dependencies

- `openssl` - X509 certificates and RSA operations
- `quick-xml` - XML parsing for SAML messages
- `flate2` - Deflate compression for redirect binding
- `base64` - Encoding/decoding
- `urlencoding` - URL-safe encoding

## Future Enhancements

- [ ] Artifact binding support
- [ ] Encrypted assertion decryption
- [ ] Multiple ACS endpoints
- [ ] IdP discovery service
- [ ] SAML attribute query
- [ ] Enhanced metadata support (Organization, ContactPerson)
- [ ] SAML attribute authority
