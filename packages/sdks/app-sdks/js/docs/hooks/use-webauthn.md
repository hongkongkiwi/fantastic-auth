# useWebAuthn Hook

The `useWebAuthn` hook provides functionality for WebAuthn/passkey authentication.

## Overview

The `useWebAuthn` hooks include:
- `useWebAuthn()` - WebAuthn operations
- `useIsWebAuthnSupported()` - Check browser support

## useWebAuthn

Register and authenticate with passkeys/WebAuthn.

### Basic Usage

```tsx
import { useWebAuthn } from '@fantasticauth/react';

function PasskeyButtons() {
  const { isSupported, register, authenticate, isLoading, error } = useWebAuthn();

  if (!isSupported) {
    return <p>Passkeys are not supported on this device</p>;
  }

  return (
    <div>
      <button onClick={() => register()} disabled={isLoading}>
        Register Passkey
      </button>
      <button onClick={() => authenticate()} disabled={isLoading}>
        Sign in with Passkey
      </button>
      {error && <p>{error.message}</p>}
    </div>
  );
}
```

### Return Value

```tsx
interface UseWebAuthnReturn {
  isSupported: boolean;
  isLoading: boolean;
  error: ApiError | null;
  register: (name?: string) => Promise<void>;
  authenticate: () => Promise<Session | null>;
  resetError: () => void;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `isSupported` | `boolean` | Whether WebAuthn is supported |
| `isLoading` | `boolean` | Whether an operation is in progress |
| `error` | `ApiError \| null` | Last error, if any |
| `register` | `(name?) => Promise<void>` | Register a new passkey |
| `authenticate` | `() => Promise<Session>` | Authenticate with passkey |
| `resetError` | `() => void` | Clear error state |

### Examples

#### Register Passkey

```tsx
import { useWebAuthn } from '@fantasticauth/react';

function RegisterPasskey() {
  const { register, isLoading, error, isSupported } = useWebAuthn();

  if (!isSupported) {
    return <p>Your device doesn't support passkeys</p>;
  }

  const handleRegister = async () => {
    try {
      await register('My Device');
      alert('Passkey registered successfully!');
    } catch {
      // Error handled by error state
    }
  };

  return (
    <button onClick={handleRegister} disabled={isLoading}>
      {isLoading ? 'Registering...' : 'Register Passkey'}
    </button>
  );
}
```

#### Sign In with Passkey

```tsx
import { useWebAuthn } from '@fantasticauth/react';
import { useRouter } from 'next/router';

function PasskeySignIn() {
  const { authenticate, isLoading, error, isSupported } = useWebAuthn();
  const router = useRouter();

  if (!isSupported) {
    return null; // Don't show on unsupported devices
  }

  const handleAuthenticate = async () => {
    try {
      await authenticate();
      router.push('/dashboard');
    } catch {
      // Error handled by error state
    }
  };

  return (
    <div>
      <button onClick={handleAuthenticate} disabled={isLoading}>
        🔐 Sign in with Passkey
      </button>
      {error && <p>{error.message}</p>}
    </div>
  );
}
```

## useIsWebAuthnSupported

Simple hook to check WebAuthn support.

### Usage

```tsx
import { useIsWebAuthnSupported } from '@fantasticauth/react';

function Component() {
  const isSupported = useIsWebAuthnSupported();

  return (
    <div>
      {isSupported ? (
        <p>✅ Passkeys supported</p>
      ) : (
        <p>❌ Passkeys not supported</p>
      )}
    </div>
  );
}
```

### Return Value

```tsx
boolean
```

## Error Codes

| Code | Description |
|------|-------------|
| `user_cancelled` | User cancelled the operation |
| `webauthn_error` | General WebAuthn error |
| `not_supported` | WebAuthn not supported on device |
| `registration_failed` | Passkey registration failed |
| `authentication_failed` | Passkey authentication failed |

## Browser Support

WebAuthn is supported in:
- Chrome 67+
- Firefox 60+
- Safari 13+
- Edge 79+

## See Also

- [WebAuthnButton Component](../components/webauthn-button.md) - Pre-built button
- [SignIn Component](../components/sign-in.md) - Sign-in with passkey option
