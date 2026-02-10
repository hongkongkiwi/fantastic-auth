# OAuth Providers Guide

Vault now supports **30+ OAuth providers** matching Auth0's extensive provider list, enabling your users to sign in with their favorite identity providers.

## Supported Providers

### Social/Consumer (10 providers)

| Provider | ID | PKCE | Notes |
|----------|-----|------|-------|
| Google | `google` | No | Standard OAuth 2.0 + OpenID Connect |
| Facebook | `facebook` | No | Facebook Login v18.0 |
| X (Twitter) | `twitter` | Yes | OAuth 2.0 (requires PKCE) |
| Instagram | `instagram` | No | Instagram Basic Display API |
| TikTok | `tiktok` | Yes | TikTok for Developers |
| Snapchat | `snapchat` | Yes | Snap Kit Login |
| Pinterest | `pinterest` | Yes | Pinterest OAuth 2.0 |
| Reddit | `reddit` | Yes | OAuth 2.0 with duration=permanent |
| Twitch | `twitch` | Yes | Twitch OAuth 2.0 |
| Spotify | `spotify` | Yes | Spotify OAuth 2.0 |

### Professional (3 providers)

| Provider | ID | PKCE | Notes |
|----------|-----|------|-------|
| Microsoft | `microsoft` | No | Microsoft Identity Platform |
| Apple | `apple` | Yes | Sign in with Apple (requires JWT client secret) |
| LinkedIn | `linkedin` | Yes | LinkedIn OAuth 2.0 + OIDC |

### Developer/Tech (7 providers)

| Provider | ID | PKCE | Notes |
|----------|-----|------|-------|
| GitHub | `github` | No | GitHub OAuth Apps |
| GitLab | `gitlab` | No | GitLab OAuth 2.0 |
| Bitbucket | `bitbucket` | No | Atlassian Bitbucket OAuth |
| DigitalOcean | `digitalocean` | No | DigitalOcean OAuth |
| Heroku | `heroku` | No | Heroku OAuth |
| Vercel | `vercel` | Yes | Vercel OAuth 2.0 |
| Netlify | `netlify` | No | Netlify OAuth |
| Cloudflare | `cloudflare` | No | Cloudflare OAuth |

### Enterprise (8 providers)

| Provider | ID | PKCE | Notes |
|----------|-----|------|-------|
| Salesforce | `salesforce` | Yes | Salesforce OAuth 2.0 |
| HubSpot | `hubspot` | No | HubSpot OAuth |
| Zendesk | `zendesk` | No | Requires subdomain configuration |
| Notion | `notion` | Yes | Notion OAuth |
| Figma | `figma` | No | Figma OAuth 2.0 |
| Linear | `linear` | Yes | Linear OAuth |
| Atlassian | `atlassian` | Yes | Atlassian OAuth 2.0 |
| Okta | `okta` | Yes | Okta OAuth 2.0 (requires domain) |

### Regional (5 providers)

| Provider | ID | PKCE | Notes |
|----------|-----|------|-------|
| WeChat | `wechat` | No | 微信登录 (QR code login) |
| LINE | `line` | Yes | LINE Login |
| KakaoTalk | `kakaotalk` | No | 카카오톡 로그인 |
| VKontakte | `vkontakte` | No | VK OAuth |
| Yandex | `yandex` | Yes | Yandex OAuth 2.0 |

### Communication

| Provider | ID | PKCE | Notes |
|----------|-----|------|-------|
| Discord | `discord` | No | Discord OAuth2 |
| Slack | `slack` | No | Slack OAuth 2.0 |

## Configuration

### Environment Variables

Each provider requires environment variables for client credentials:

```bash
# Standard OAuth providers
OAUTH_<PROVIDER>_CLIENT_ID=your-client-id
OAUTH_<PROVIDER>_CLIENT_SECRET=your-client-secret
OAUTH_<PROVIDER>_REDIRECT_URI=https://yourapp.com/oauth/callback

# Special configurations
OAUTH_ZENDESK_SUBDOMAIN=your-subdomain
OAUTH_OKTA_DOMAIN=your-domain.okta.com
OAUTH_WECHAT_APP_ID=your-app-id
OAUTH_WECHAT_USE_QR_LOGIN=true
```

### Server Configuration

```rust
// vault-server/src/config.rs
pub struct OAuthConfigs {
    // Social/Consumer
    pub google: Option<OAuthProviderConfig>,
    pub facebook: Option<OAuthProviderConfig>,
    pub twitter: Option<OAuthProviderConfig>,
    // ... etc
    
    // Special configs
    pub zendesk: Option<ZendeskOAuthConfig>,
    pub okta: Option<OktaOAuthConfig>,
    pub wechat: Option<WeChatOAuthConfig>,
}
```

### SDK Configuration (React/JavaScript)

```typescript
import { VaultProvider } from '@vault/react';

<VaultProvider
  config={{
    apiUrl: "https://api.vault.dev",
    tenantId: "my-tenant",
    oauth: {
      // Social
      google: { clientId: "..." },
      facebook: { clientId: "..." },
      twitter: { clientId: "..." },
      
      // Professional
      linkedin: { clientId: "..." },
      
      // Developer
      github: { clientId: "..." },
      gitlab: { clientId: "..." },
      
      // Enterprise
      salesforce: { clientId: "..." },
      okta: { clientId: "...", domain: "..." },
      
      // Regional
      line: { clientId: "..." },
    }
  }}
>
  <App />
</VaultProvider>
```

## Usage

### Sign In Component

```tsx
import { SignIn } from '@vault/react';

// Enable specific providers
<SignIn 
  oauthProviders={['google', 'github', 'linkedin', 'twitter']}
/>

// Enable all social providers
<SignIn 
  oauthProviders={['google', 'facebook', 'twitter', 'instagram', 'tiktok']}
/>

// Enable developer-focused providers
<SignIn 
  oauthProviders={['github', 'gitlab', 'bitbucket', 'vercel']}
/>
```

### Programmatic OAuth Sign In

```typescript
import { useSignIn } from '@vault/react';

const { signInWithOAuth } = useSignIn();

// Sign in with any provider
await signInWithOAuth({ 
  provider: 'linkedin',
  redirectUrl: '/dashboard'
});
```

### Using OAuth Utilities

```typescript
import { 
  getAllOAuthProviders,
  getOAuthProvidersByCategory,
  getOAuthProviderMetadata,
  getRecommendedOAuthProviders,
  isPkceEnabled
} from '@vault/react';

// Get all providers
const allProviders = getAllOAuthProviders();
// ['google', 'github', 'microsoft', 'facebook', ...]

// Get by category
const socialProviders = getOAuthProvidersByCategory('social');
const enterpriseProviders = getOAuthProvidersByCategory('enterprise');

// Get provider metadata
const metadata = getOAuthProviderMetadata('twitter');
// { id: 'twitter', displayName: 'X (Twitter)', pkceEnabled: true, ... }

// Get recommended for use case
const b2bProviders = getRecommendedOAuthProviders('b2b');
const devProviders = getRecommendedOAuthProviders('developer');
```

## Provider-Specific Notes

### Apple Sign-In

Apple requires a JWT as the client secret instead of a static secret:

```bash
OAUTH_APPLE_CLIENT_ID=com.yourapp.signin
OAUTH_APPLE_TEAM_ID=ABCD123456
OAUTH_APPLE_KEY_ID=DEF123GHIJ
OAUTH_APPLE_PRIVATE_KEY="-----BEGIN EC PRIVATE KEY-----
...
-----END EC PRIVATE KEY-----"
```

### Okta

Okta requires your organization's domain:

```bash
OAUTH_OKTA_DOMAIN=dev-123456.okta.com
OAUTH_OKTA_CLIENT_ID=your-client-id
OAUTH_OKTA_CLIENT_SECRET=your-client-secret
```

### Zendesk

Zendesk uses subdomain-based endpoints:

```bash
OAUTH_ZENDESK_SUBDOMAIN=your-company
OAUTH_ZENDESK_CLIENT_ID=your-client-id
OAUTH_ZENDESK_CLIENT_SECRET=your-client-secret
```

### WeChat

WeChat uses different flows for web vs mobile:

```bash
OAUTH_WECHAT_APP_ID=your-app-id
OAUTH_WECHAT_APP_SECRET=your-app-secret
OAUTH_WECHAT_USE_QR_LOGIN=true  # For web
```

## PKCE Support

Providers marked with PKCE use Proof Key for Code Exchange (RFC 7636) for enhanced security:

| Provider | PKCE Required |
|----------|---------------|
| Apple | Required |
| Twitter/X | Required |
| LinkedIn | Required |
| Spotify | Required |
| Okta | Recommended |
| Notion | Required |
| Linear | Required |
| Atlassian | Required |

Vault automatically generates PKCE code verifiers and challenges for these providers.

## User Info Normalization

All providers return normalized user info:

```rust
pub struct OAuthUserInfo {
    pub id: String,              // Provider's unique user ID
    pub email: Option<String>,   // User's email
    pub email_verified: bool,    // Whether email is verified
    pub name: Option<String>,    // Full name
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>, // Profile picture URL
    pub username: Option<String>,
    pub locale: Option<String>,
    pub provider: Option<OAuthProvider>,
    pub raw: serde_json::Value,  // Raw provider response
}
```

## Testing

Run the OAuth provider tests:

```bash
cargo test -p vault-core oauth
```

Test specific provider:

```bash
cargo test -p vault-core test_parse_google_user_info
```

## Adding a New Provider

To add a new OAuth provider:

1. Add the provider to the `OAuthProvider` enum in `vault-core/src/auth/oauth.rs`
2. Add endpoints (auth, token, userinfo) to the match statements
3. Add default scopes
4. Add user info parser function
5. Add configuration to `vault-server/src/config.rs`
6. Add environment variables to `.env.example`
7. Add TypeScript types to `packages/sdks/app-sdks/js/src/types/index.ts`
8. Add icon and button to `SocialButton.tsx`
9. Add metadata to `packages/sdks/app-sdks/js/src/utils/oauth.ts`

## Security Considerations

1. **PKCE**: Always enable PKCE for providers that support it
2. **State Parameter**: Vault automatically generates state for CSRF protection
3. **Email Verification**: Most social providers return verified emails
4. **Profile Pictures**: URLs are passed through; implement proxy for sizing
5. **Scopes**: Request minimum required scopes for your use case

## Troubleshooting

### Provider returns "invalid_client"
- Check client ID and secret
- Ensure redirect URI matches exactly (including protocol)

### "redirect_uri_mismatch"
- Add your redirect URI to the provider's app settings
- Check for trailing slashes

### Apple Sign-In fails
- Verify private key format (PEM)
- Check Team ID and Key ID
- Ensure client secret JWT is valid (expires every 6 months)

### Okta/Zendesk subdomain errors
- Verify subdomain format (no `.zendesk.com` suffix)
- Check domain is accessible

## References

- [OAuth 2.0 Specification](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect](https://openid.net/connect/)
- [Apple Sign-In](https://developer.apple.com/sign-in-with-apple/)
- [Auth0 Identity Providers](https://auth0.com/docs/connections/identity-providers-social)
