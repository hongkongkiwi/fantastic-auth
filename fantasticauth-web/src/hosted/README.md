# Vault Hosted UI

Pre-built hosted authentication pages with tenant branding support, similar to Auth0's Universal Login or Clerk's hosted pages.

## Overview

Users can redirect to `https://auth.vault.dev/hosted/sign-in` instead of building their own UI. This is useful for:

- **Quick prototyping** - Get started without building custom auth UI
- **Mobile apps** - Handle authentication without web views
- **OAuth redirects** - Simplified OAuth callback handling
- **Branded login** - Organizations can customize the look and feel

## Available Pages

| Page | URL | Description |
|------|-----|-------------|
| Sign In | `/hosted/sign-in?tenant_id=xxx` | Email/password, OAuth, magic link |
| Sign Up | `/hosted/sign-up?tenant_id=xxx` | Account registration |
| Forgot Password | `/hosted/forgot-password?tenant_id=xxx` | Password reset request |
| Verify Email | `/hosted/verify-email?token=xxx&tenant_id=xxx` | Email verification |
| OAuth Callback | `/hosted/oauth-callback` | OAuth provider callback |
| MFA Challenge | `/hosted/mfa?tenant_id=xxx&mfa_token=xxx` | Multi-factor authentication |
| Create Organization | `/hosted/organization/create?tenant_id=xxx` | Create new organization |
| Switch Organization | `/hosted/organization/switch?tenant_id=xxx` | Switch between organizations |

## Query Parameters

All hosted pages support these query parameters:

- `tenant_id` (required) - The tenant identifier
- `redirect_url` - Where to redirect after successful authentication
- `organization_id` - Pre-select an organization

## Configuration

Hosted pages are configured per-tenant via the API:

```typescript
interface HostedUIConfig {
  // Branding
  logoUrl?: string;
  faviconUrl?: string;
  primaryColor?: string;
  backgroundColor?: string;
  
  // Content
  companyName: string;
  signInTitle?: string;
  signUpTitle?: string;
  
  // Features
  oauthProviders: ('google' | 'github' | 'apple' | 'microsoft' | 'slack' | 'discord')[];
  showMagicLink: boolean;
  showWebAuthn: boolean;
  requireEmailVerification: boolean;
  allowSignUp: boolean;
  
  // URLs
  afterSignInUrl: string;
  afterSignUpUrl: string;
  afterSignOutUrl: string;
  
  // Legal
  termsUrl?: string;
  privacyUrl?: string;
  
  // Advanced
  customCss?: string;
  customJs?: string;
  
  // Security
  allowedRedirectUrls: string[];
}
```

## Usage Examples

### Basic Sign-In Link

```html
<a href="https://auth.vault.dev/hosted/sign-in?tenant_id=acme-corp">
  Sign In
</a>
```

### With Redirect After Login

```html
<a href="https://auth.vault.dev/hosted/sign-in?tenant_id=acme-corp&redirect_url=https://app.acme.com/dashboard">
  Sign In
</a>
```

### Programmatic Redirect

```javascript
// After detecting user is not authenticated
window.location.href = `https://auth.vault.dev/hosted/sign-in?tenant_id=${TENANT_ID}&redirect_url=${encodeURIComponent(window.location.href)}`;
```

### React Component

```tsx
import { Link } from '@tanstack/react-router';

function SignInButton() {
  return (
    <Link
      to="https://auth.vault.dev/hosted/sign-in"
      search={{ tenant_id: 'acme-corp', redirect_url: '/dashboard' }}
    >
      Sign In
    </Link>
  );
}
```

## Theming

Tenants can customize the appearance of hosted pages:

### Brand Colors

Set `primaryColor` to your brand color (hex format):

```json
{
  "primaryColor": "#4f46e5",
  "backgroundColor": "#f8fafc"
}
```

### Custom Logo

Provide URLs to your logo and favicon:

```json
{
  "logoUrl": "https://cdn.example.com/logo.png",
  "faviconUrl": "https://cdn.example.com/favicon.ico"
}
```

### Custom CSS

Inject custom CSS for advanced styling:

```json
{
  "customCss": `
    .hosted-card {
      border-radius: 16px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .hosted-button {
      text-transform: uppercase;
      font-weight: 600;
    }
  `
}
```

### Custom JavaScript

Add custom JavaScript for analytics or tracking:

```json
{
  "customJs": `
    console.log('Hosted page loaded');
    // Initialize analytics
    analytics.track('Page Viewed', { page: 'sign-in' });
  `
}
```

## Security Considerations

### Redirect URL Validation

All `redirect_url` parameters are validated against the tenant's `allowedRedirectUrls` allowlist. This prevents open redirect vulnerabilities.

### CSRF Protection

OAuth flows include state parameter validation to prevent CSRF attacks.

### Session Management

Hosted pages use secure, HTTP-only cookies for session management with appropriate SameSite settings.

### Rate Limiting

Authentication endpoints are rate-limited to prevent brute force attacks.

## API Endpoints

The hosted UI uses these backend endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/hosted/api/config` | GET | Get tenant configuration |
| `/hosted/api/auth/signin` | POST | Sign in with credentials |
| `/hosted/api/auth/signup` | POST | Create new account |
| `/hosted/api/auth/oauth/start` | POST | Start OAuth flow |
| `/hosted/api/auth/oauth/callback` | POST | Handle OAuth callback |
| `/hosted/api/auth/password-reset` | POST | Request password reset |

## Self-Hosting

To self-host the hosted UI pages:

1. Build the vault-web application:
   ```bash
   cd vault-web
   npm run build
   ```

2. Deploy to your hosting platform (Vercel, Netlify, etc.)

3. Configure environment variables:
   ```
   VITE_API_BASE_URL=https://api.your-domain.com
   ```

4. Update DNS to point `auth.your-domain.com` to your deployment

## Development

To run the hosted UI locally:

```bash
cd vault-web
npm run dev
```

Access the hosted pages at:
- `http://localhost:3000/hosted/sign-in?tenant_id=test`

## File Structure

```
vault-web/src/
├── hosted/
│   ├── index.ts              # Module exports
│   ├── types.ts              # TypeScript types
│   ├── api.ts                # Server API functions
│   ├── useHostedConfig.tsx   # Configuration hook
│   └── HostedLayout.tsx      # Shared layout component
├── routes/hosted/
│   ├── index.tsx             # /hosted (redirects to sign-in)
│   ├── sign-in.tsx           # /hosted/sign-in
│   ├── sign-up.tsx           # /hosted/sign-up
│   ├── forgot-password.tsx   # /hosted/forgot-password
│   ├── verify-email.tsx      # /hosted/verify-email
│   ├── oauth-callback.tsx    # /hosted/oauth-callback
│   ├── mfa.tsx               # /hosted/mfa
│   └── organization/
│       ├── create.tsx        # /hosted/organization/create
│       └── switch.tsx        # /hosted/organization/switch
```

## Future Enhancements

- [ ] SAML/Enterprise SSO support
- [ ] Custom domain support (auth.yourdomain.com)
- [ ] Localization/i18n support
- [ ] Advanced theming (CSS variables)
- [ ] Analytics integration
- [ ] Bot protection (CAPTCHA)
- [ ] Remember device functionality
