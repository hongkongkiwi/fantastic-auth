# WebAuthnButton Component

The `WebAuthnButton` component provides a button for passkey/WebAuthn authentication.

## Basic Usage

```tsx
import { WebAuthnButton } from '@vault/react';

function SignInOptions() {
  return (
    <div>
      <WebAuthnButton
        mode="signin"
        label="Sign in with Passkey"
        onSuccess={() => console.log('Signed in!')}
      />
    </div>
  );
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `mode` | `'signin' \| 'signup' \| 'link'` | `'signin'` | Button mode |
| `label` | `string` | - | Custom button label |
| `onSuccess` | `() => void` | - | Callback on success |
| `onError` | `(error: ApiError) => void` | - | Callback on error |
| `appearance` | `Appearance` | - | Custom styling |
| `className` | `string` | - | CSS class names |

## Examples

### Sign In Mode

```tsx
<WebAuthnButton
  mode="signin"
  onSuccess={() => router.push('/dashboard')}
/>
```

### Sign Up Mode

```tsx
<WebAuthnButton
  mode="signup"
  label="Register Passkey"
  onSuccess={() => alert('Passkey registered!')}
/>
```

## See Also

- [useWebAuthn Hook](../hooks/use-webauthn.md)
