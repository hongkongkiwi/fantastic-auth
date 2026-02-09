# @fantasticauth/vue

Vue 3 SDK for Vault - Secure user management with Composition API support.

## Features

- 🎨 **Vue 3 Composition API** - Built with `<script setup>` and modern Vue patterns
- 🔒 **Authentication** - Sign in/up with email/password, OAuth, Magic Links, and WebAuthn
- 🏢 **Organizations** - Multi-tenant support with organization switching
- 🛡️ **Route Guards** - Vue Router navigation guards for protected routes
- 📦 **Pinia Integration** - Optional Pinia store for state management
- 🎭 **Pre-built Components** - Ready-to-use Vue components
- 🔐 **MFA Support** - TOTP and WebAuthn multi-factor authentication
- 📱 **SSR Ready** - Server-side rendering support

## Installation

```bash
npm install @fantasticauth/vue
# or
yarn add @fantasticauth/vue
# or
pnpm add @fantasticauth/vue
```

## Quick Start

### 1. Setup the Plugin

```typescript
// main.ts
import { createApp } from 'vue';
import { createVault } from '@fantasticauth/vue';
import App from './App.vue';

const vault = createVault({
  config: {
    apiUrl: 'https://api.vault.dev',
    tenantId: 'my-tenant',
  },
});

const app = createApp(App);
app.use(vault);
app.mount('#app');
```

### 2. Use in Your Components

```vue
<script setup lang="ts">
import { useAuth, useUser } from '@fantasticauth/vue';

const { isSignedIn, signOut } = useAuth();
const { user } = useUser();
</script>

<template>
  <div v-if="isSignedIn">
    <p>Welcome {{ user?.name }}</p>
    <button @click="signOut">Sign Out</button>
  </div>
  <div v-else>
    <VaultSignIn />
  </div>
</template>
```

## Composables

### `useAuth()`

Main composable for authentication state and methods.

```vue
<script setup lang="ts">
import { useAuth } from '@fantasticauth/vue';

const {
  isLoaded,      // Ref<boolean> - Auth state has been loaded
  isSignedIn,    // Ref<boolean> - User is authenticated
  user,          // Ref<User | null> - Current user
  session,       // Ref<Session | null> - Current session
  organization,  // Ref<Organization | null> - Active organization
  signIn,        // (options: SignInOptions) => Promise<void>
  signUp,        // (options: SignUpOptions) => Promise<void>
  signOut,       // () => Promise<void>
} = useAuth();
</script>
```

### `useSignIn()`

Sign in with loading and error states.

```vue
<script setup lang="ts">
import { ref } from 'vue';
import { useSignIn } from '@fantasticauth/vue';

const email = ref('');
const password = ref('');

const { signIn, isLoading, error, resetError } = useSignIn();

const handleSubmit = async () => {
  try {
    await signIn({ email: email.value, password: password.value });
  } catch (e) {
    // error.value contains the error details
  }
};
</script>
```

### `useUser()`

Access and manage user data.

```vue
<script setup lang="ts">
import { useUser, useUpdateUser } from '@fantasticauth/vue';

const user = useUser();
const { updateUser, isLoading, error } = useUpdateUser();
</script>
```

### `useOrganization()`

Organization management.

```vue
<script setup lang="ts">
import { useOrganization } from '@fantasticauth/vue';

const {
  organization,       // Current active organization
  organizations,      // List of all organizations
  setActive,          // Switch organization
  create,             // Create new organization
  isLoading,
} = useOrganization();
</script>
```

### `usePermissions()`

Permission and role checking.

```vue
<script setup lang="ts">
import { usePermissions } from '@fantasticauth/vue';

const { has, hasRole, hasAnyRole } = usePermissions();

// Check permission
const canWrite = has('org:write');

// Check role
const isAdmin = hasRole('admin');

// Check any role
const isManager = hasAnyRole(['admin', 'owner']);
</script>
```

### `useWebAuthn()`

WebAuthn/Passkey authentication.

```vue
<script setup lang="ts">
import { useWebAuthn } from '@fantasticauth/vue';

const { isSupported, register, authenticate, isLoading } = useWebAuthn();
</script>

<template>
  <button v-if="isSupported" @click="authenticate" :disabled="isLoading">
    Sign in with Passkey
  </button>
</template>
```

## Components

### SignIn

Pre-built sign-in form with multiple authentication methods.

```vue
<template>
  <VaultSignIn
    :oauth-providers="['google', 'github']"
    :show-magic-link="true"
    :show-web-authn="true"
    redirect-url="/dashboard"
    @success="onSignIn"
    @error="onError"
  />
</template>
```

### SignUp

User registration form.

```vue
<template>
  <VaultSignUp
    :require-name="true"
    :oauth-providers="['google']"
    redirect-url="/welcome"
  />
</template>
```

### UserButton

User menu with avatar and dropdown.

```vue
<template>
  <VaultUserButton
    :show-name="true"
    :show-manage-account="true"
    :menu-items="[
      { label: 'Settings', onClick: goToSettings },
      { label: 'Billing', onClick: goToBilling },
    ]"
    @sign-out="onSignOut"
  />
</template>
```

### Protect

Route protection wrapper component.

```vue
<template>
  <VaultProtect role="admin">
    <AdminPanel />
    <template #fallback>
      <p>You don't have access to this page.</p>
    </template>
  </VaultProtect>
</template>
```

### OrganizationSwitcher

Organization selection dropdown.

```vue
<template>
  <VaultOrganizationSwitcher
    :hide-personal="false"
    @switch="onOrgSwitch"
  />
</template>
```

## Vue Router Integration

### Navigation Guards

```typescript
// router/index.ts
import { createRouter, createWebHistory } from 'vue-router';
import { requireAuth, requireRole, createAuthGuard } from '@fantasticauth/vue/router';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/dashboard',
      component: Dashboard,
      beforeEnter: requireAuth,
    },
    {
      path: '/admin',
      component: AdminPanel,
      beforeEnter: requireRole('admin'),
    },
    {
      path: '/sign-in',
      component: SignIn,
      meta: { guestOnly: true },
    },
  ],
});

// Or use the meta-based guard globally
router.beforeEach(createAuthGuard());

export default router;
```

### Route Meta Fields

```typescript
{
  path: '/protected',
  component: ProtectedPage,
  meta: {
    requiresAuth: true,           // Require authentication
    requiresRole: 'admin',        // Require specific role
    requiresPermission: 'org:write', // Require permission
    guestOnly: false,             // Only for non-authenticated users
  },
}
```

## Pinia Integration

### Using with Pinia Store

```typescript
// stores/auth.ts
import { defineStore } from 'pinia';
import { useVault } from '@fantasticauth/vue';

export const useAuthStore = defineStore('auth', () => {
  const vault = useVault();

  return {
    // State
    isLoaded: vault.isLoaded,
    isSignedIn: vault.isSignedIn,
    user: vault.user,
    session: vault.session,
    organization: vault.organization,
    organizations: vault.organizations,

    // Actions
    signIn: vault.signIn,
    signUp: vault.signUp,
    signOut: vault.signOut,
    setActiveOrganization: vault.setActiveOrganization,
  };
});
```

### Usage in Components

```vue
<script setup lang="ts">
import { useAuthStore } from '@/stores/auth';
import { storeToRefs } from 'pinia';

const auth = useAuthStore();
const { isSignedIn, user } = storeToRefs(auth);
</script>
```

## TypeScript Support

All composables and components are fully typed. Import types from the package:

```typescript
import type {
  User,
  Session,
  Organization,
  SignInOptions,
  UseAuthReturn,
} from '@fantasticauth/vue';
```

## Configuration Options

```typescript
interface VaultConfig {
  apiUrl: string;              // Vault API URL
  tenantId: string;            // Your tenant ID
  debug?: boolean;             // Enable debug logging
  sessionToken?: string;       // Initial session token (SSR)
  fetch?: typeof fetch;        // Custom fetch implementation
  turnstileSiteKey?: string;   // Turnstile site key for bot protection
  oauth?: {
    google?: { clientId: string };
    github?: { clientId: string };
    microsoft?: { clientId: string };
  };
}
```

## Server-Side Rendering (SSR)

For SSR applications, pass initial data to the plugin:

```typescript
// server.ts - serialize user data
const vault = createVault({
  config: { apiUrl, tenantId },
  initialUser: serverUserData,       // User from server
  initialSessionToken: serverToken,  // Session token from server
});

// The SDK will use this data instead of loading from localStorage
```

## Examples

### Complete App Layout

```vue
<!-- App.vue -->
<script setup lang="ts">
import { useAuth } from '@fantasticauth/vue';

const { isLoaded, isSignedIn } = useAuth();
</script>

<template>
  <div v-if="!isLoaded" class="loading">
    Loading...
  </div>
  <div v-else-if="isSignedIn" class="app">
    <nav>
      <VaultUserButton />
      <VaultOrganizationSwitcher />
    </nav>
    <main>
      <router-view />
    </main>
  </div>
  <div v-else class="auth">
    <router-view />
  </div>
</template>
```

### Protected Route Component

```vue
<!-- Dashboard.vue -->
<script setup lang="ts">
import { useAuth, useOrganization } from '@fantasticauth/vue';

const { user } = useAuth();
const { organization } = useOrganization();
</script>

<template>
  <VaultProtect>
    <h1>Dashboard</h1>
    <p>Welcome, {{ user?.name }}</p>
    <p v-if="organization">
      Organization: {{ organization.name }}
    </p>
  </VaultProtect>
</template>
```

## License

MIT
