# Vault Svelte SDK

A comprehensive Svelte SDK for Vault authentication and user management. Supports both **Svelte 4** (stores) and **Svelte 5** (runes).

## Features

- 🔐 **Authentication** - Sign in/up with email/password, OAuth, magic links, and WebAuthn/passkeys
- 👤 **User Management** - Profile updates, password changes, account deletion
- 🏢 **Organizations** - Multi-tenant support with organization switching
- 🛡️ **Security** - MFA, session management, secure token handling
- ⚡ **Svelte 5 Ready** - Full support for runes (`$state`, `$derived`, `$effect`)
- 🔧 **Svelte 4 Compatible** - Works with traditional stores
- 🚀 **SvelteKit Integration** - Server-side auth, form actions, and hooks
- 🎨 **Pre-built Components** - SignIn, SignUp, UserButton, OrganizationSwitcher, and more

## Installation

```bash
npm install @fantasticauth/svelte
# or
yarn add @fantasticauth/svelte
# or
pnpm add @fantasticauth/svelte
```

## Quick Start

### 1. Setup the Provider

```svelte
<!-- +layout.svelte -->
<script>
  import { VaultProvider } from '@fantasticauth/svelte';
</script>

<VaultProvider 
  config={{
    apiUrl: 'https://api.vault.dev',
    tenantId: 'my-tenant'
  }}
>
  <slot />
</VaultProvider>
```

### 2. Use Authentication (Svelte 5 - Runes)

```svelte
<!-- +page.svelte -->
<script>
  import { useAuth, SignIn, UserButton } from '@fantasticauth/svelte';
  
  const { isSignedIn, user, signOut } = useAuth();
</script>

{#if isSignedIn}
  <div class="user-nav">
    <p>Welcome, {user?.profile?.name || user?.email}</p>
    <UserButton />
  </div>
{:else}
  <SignIn />
{/if}
```

### 3. Use Authentication (Svelte 4 - Stores)

```svelte
<script>
  import { authStore, userStore, SignIn, UserButton } from '@fantasticauth/svelte';
</script>

{#if $authStore.isSignedIn}
  <div class="user-nav">
    <p>Welcome, {$userStore.user?.profile?.name || $userStore.user?.email}</p>
    <UserButton />
  </div>
{:else}
  <SignIn />
{/if}
```

## Svelte 5 Runes

The SDK provides modern Svelte 5 runes for reactive state management:

### `useAuth()`

```svelte
<script>
  import { useAuth } from '@fantasticauth/svelte';
  
  const { 
    isLoaded, 
    isSignedIn, 
    user, 
    session, 
    organization,
    signIn, 
    signOut, 
    signUp,
    signInWithMagicLink,
    signInWithOAuth 
  } = useAuth();
</script>
```

### `useSignIn()`

```svelte
<script>
  import { useSignIn } from '@fantasticauth/svelte';
  
  const { signIn, isLoading, error, resetError } = useSignIn();
  
  let email = $state('');
  let password = $state('');
  
  async function handleSubmit() {
    try {
      await signIn({ email, password });
    } catch (e) {
      // Error is available in `error`
    }
  }
</script>

<form onsubmit={handleSubmit}>
  <input bind:value={email} type="email" />
  <input bind:value={password} type="password" />
  <button disabled={isLoading}>
    {isLoading ? 'Signing in...' : 'Sign In'}
  </button>
</form>

{#if error}
  <p class="error">{error.message}</p>
{/if}
```

### `useUser()`

```svelte
<script>
  import { useUser } from '@fantasticauth/svelte';
  
  const { user, update, reload, changePassword, deleteAccount } = useUser();
</script>
```

### `useOrganization()`

```svelte
<script>
  import { useOrganization } from '@fantasticauth/svelte';
  
  const { 
    organization, 
    organizations, 
    setActive, 
    create, 
    leave,
    refresh 
  } = useOrganization();
</script>
```

## Components

### SignIn

```svelte
<script>
  import { SignIn } from '@fantasticauth/svelte';
</script>

<SignIn
  redirectUrl="/dashboard"
  oauthProviders={['google', 'github', 'microsoft']}
  showMagicLink={true}
  showForgotPassword={true}
  onSignIn={() => console.log('Signed in!')}
  onError={(error) => console.error(error)}
/>
```

### SignUp

```svelte
<script>
  import { SignUp } from '@fantasticauth/svelte';
</script>

<SignUp
  redirectUrl="/dashboard"
  oauthProviders={['google', 'github']}
  requireName={true}
  onSignUp={() => console.log('Signed up!')}
/>
```

### UserButton

```svelte
<script>
  import { UserButton } from '@fantasticauth/svelte';
</script>

<UserButton
  showName={true}
  showManageAccount={true}
  onSignOut={() => console.log('Signed out')}
  menuItems={[
    { label: 'Settings', onClick: () => goto('/settings') }
  ]}
/>
```

### UserProfile

```svelte
<script>
  import { UserProfile } from '@fantasticauth/svelte';
</script>

<UserProfile 
  onUpdate={(user) => console.log('Updated:', user)}
/>
```

### OrganizationSwitcher

```svelte
<script>
  import { OrganizationSwitcher } from '@fantasticauth/svelte';
</script>

<OrganizationSwitcher
  hidePersonal={false}
  onSwitch={(org) => console.log('Switched to:', org)}
/>
```

### Conditional Rendering

```svelte
<script>
  import { SignedIn, SignedOut, Protect } from '@fantasticauth/svelte';
</script>

<SignedIn>
  <UserNav />
</SignedIn>

<SignedOut>
  <LoginButton />
</SignedOut>

<Protect role="admin">
  <AdminPanel />
  
  {#snippet fallback()}
    <p>Admin access required</p>
  {/snippet}
</Protect>
```

### WebAuthn/Passkey Button

```svelte
<script>
  import { WebAuthnButton } from '@fantasticauth/svelte';
</script>

<WebAuthnButton
  mode="signin"
  label="Sign in with passkey"
  onSuccess={() => console.log('Authenticated with passkey')}
/>
```

## SvelteKit Server Integration

### Handle Hook

```typescript
// hooks.server.ts
import { vaultAuth } from '@fantasticauth/svelte/server';

export const handle = vaultAuth({
  publicRoutes: ['/sign-in', '/sign-up', '/api/webhook'],
  apiUrl: 'https://api.vault.dev',
  tenantId: 'my-tenant',
  signInUrl: '/sign-in'
});
```

### Server Load Functions

```typescript
// +page.server.ts
import { requireAuth, optionalAuth } from '@fantasticauth/svelte/server';

// Require authentication
export const load = requireAuth(async ({ locals }) => {
  // locals.user is guaranteed to be set
  return {
    user: locals.user
  };
});

// Optional authentication
export const load = optionalAuth(async ({ locals }) => {
  return {
    user: locals.user // may be null
  };
});
```

### Form Actions

```typescript
// +page.server.ts
import { vaultActions } from '@fantasticauth/svelte/server';

const config = {
  apiUrl: 'https://api.vault.dev',
  tenantId: 'my-tenant',
  signInRedirect: '/dashboard',
  signOutRedirect: '/sign-in'
};

export const actions = vaultActions(config);
```

```svelte
<!-- +page.svelte -->
<form method="POST" action="?/signIn">
  <input name="email" type="email" required />
  <input name="password" type="password" required />
  <input type="hidden" name="redirect" value="/dashboard" />
  <button type="submit">Sign In</button>
</form>
```

## Actions

Use the `protect` action for DOM-based protection:

```svelte
<script>
  import { protect } from '@fantasticauth/svelte';
</script>

<div use:protect>
  Only visible to authenticated users
</div>

<div use:protect={{ role: 'admin' }}>
  Only visible to admins
</div>

<div use:protect={{ 
  role: 'member',
  mode: 'hide',
  fallback: '<p>Members only</p>'
}}>
  Protected content
</div>
```

## TypeScript

The SDK includes full TypeScript support:

```typescript
import type { 
  User, 
  Session, 
  Organization,
  VaultConfig,
  SignInOptions,
  UseAuthReturn 
} from '@fantasticauth/svelte';
```

## Configuration

```typescript
interface VaultConfig {
  apiUrl: string;           // Vault API URL
  tenantId: string;         // Your tenant ID
  debug?: boolean;          // Enable debug logging
  sessionToken?: string;    // Initial token (for SSR)
  fetch?: typeof fetch;     // Custom fetch implementation
  turnstileSiteKey?: string; // Turnstile site key
  oauth?: {
    google?: { clientId: string };
    github?: { clientId: string };
    microsoft?: { clientId: string };
  };
}
```

## License

MIT
