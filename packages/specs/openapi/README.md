# Vault OpenAPI & SDK

This directory contains the OpenAPI specification and SDK generation setup for the Vault API.

## Structure

```
openapi/
├── vault-api.yaml       # OpenAPI 3.0 specification
├── generate.sh          # SDK generation script
└── README.md            # This file

vault-sdk-js/            # React SDK (uses generated client)
├── src/
│   ├── context/         # VaultProvider React context
│   ├── hooks/           # React hooks (useAuth, useUser, etc.)
│   ├── components/      # UI components (SignIn, SignUp, etc.)
│   └── index.ts         # Main exports
typescript/              # Generated TypeScript client
├── src/                 # Auto-generated API client code
└── package.json         # Generated package config
```

## OpenAPI Specification

The `vault-api.yaml` file contains the complete API specification including:

- **Authentication**: Register, login, OAuth, magic links, password reset
- **Users**: Profile management, MFA, sessions
- **Organizations**: Team management, invitations, roles
- **Security**: JWT Bearer auth, rate limiting headers

### View Documentation

You can view the API documentation using Swagger UI:

```bash
# Using Docker
docker run -p 8080:8080 -e SWAGGER_JSON=/api/vault-api.yaml -v $(pwd)/vault-api.yaml:/api/vault-api.yaml swaggerapi/swagger-ui

# Or using the Swagger Editor online
# Go to https://editor.swagger.io/ and paste the YAML content
```

## Generating SDKs

### Prerequisites

```bash
# Install OpenAPI Generator CLI
npm install -g @openapitools/openapi-generator-cli
```

### Generate TypeScript Client

```bash
cd openapi
./generate.sh
```

This will generate the TypeScript client in `../generated/typescript/`.

### Available Generators

| Language | Generator Name | Status |
|----------|---------------|--------|
| TypeScript | `typescript-fetch` | ✅ Ready |
| Python | `python` | ⏳ Planned |
| Go | `go` | ⏳ Planned |
| Rust | `rust` | ⏳ Planned |
| Java | `java` | ⏳ Planned |

### Generate Other Languages

Uncomment the sections in `generate.sh` or run manually:

```bash
# Python
openapi-generator generate \
    -i vault-api.yaml \
    -g python \
    -o ../generated/python \
    --additional-properties=packageName=vault_sdk

# Go
openapi-generator generate \
    -i vault-api.yaml \
    -g go \
    -o ../generated/go \
    --additional-properties=packageName=vaultsdk
```

## React SDK

The React SDK (`vault-sdk-js`) provides a high-level interface built on top of the generated TypeScript client.

### Installation

```bash
# After generating the TypeScript client
cd vault-sdk-js
npm install
npm run build
```

### Usage

```tsx
import { VaultProvider, SignIn, UserButton, SignedIn, SignedOut } from '@vault/react';

function App() {
  return (
    <VaultProvider apiUrl="https://api.vault.dev/api/v1" tenantId="my-tenant">
      <SignedOut>
        <SignIn onSuccess={() => console.log('Signed in!')} />
      </SignedOut>
      <SignedIn>
        <UserButton />
      </SignedIn>
    </VaultProvider>
  );
}
```

### Components

| Component | Description |
|-----------|-------------|
| `VaultProvider` | Context provider for auth state |
| `SignIn` | Email/password + OAuth sign-in form |
| `SignUp` | Registration form |
| `UserButton` | User menu with avatar and sign-out |
| `OrganizationSwitcher` | Switch between orgs |
| `SignedIn` | Render children only when signed in |
| `SignedOut` | Render children only when signed out |

### Hooks

| Hook | Description |
|------|-------------|
| `useAuth()` | Auth state and actions |
| `useUser()` | Current user data |
| `useOrganization()` | Active organization |
| `useSession()` | Session management |
| `useVault()` | Full context access |

## API Client Usage (Direct)

If you need lower-level access, use the generated client directly:

```typescript
import { Configuration, DefaultApi } from '@vault/sdk';

const api = new DefaultApi(
  new Configuration({
    basePath: 'https://api.vault.dev/api/v1',
    headers: { 'X-Tenant-ID': 'my-tenant' },
  })
);

// Login
const auth = await api.login({
  email: 'user@example.com',
  password: 'password123',
});

// Use the access token for authenticated requests
const config = new Configuration({
  basePath: 'https://api.vault.dev/api/v1',
  headers: {
    'Authorization': `Bearer ${auth.accessToken}`,
    'X-Tenant-ID': 'my-tenant',
  },
});

const authenticatedApi = new DefaultApi(config);
const user = await authenticatedApi.getMe();
```

## Updating the API

1. Edit `openapi/vault-api.yaml` to add/modify endpoints
2. Run `./openapi/generate.sh` to regenerate clients
3. Update React SDK components/hooks if needed
4. Rebuild the SDK: `cd vault-sdk-js && npm run build`

## Best Practices

1. **Always use the React SDK** for frontend applications - it handles token management, caching, and UI state
2. **Use the generated client directly** only for:
   - Server-side code (Node.js backends)
   - Mobile apps (React Native, etc.)
   - Non-React web apps
3. **Keep the OpenAPI spec in sync** with the backend implementation
4. **Version the generated SDKs** alongside the API

## Contributing

When adding new API endpoints:

1. Add to `vault-api.yaml` first
2. Generate the TypeScript client
3. Update React SDK if user-facing
4. Write tests for new functionality
5. Update this README
