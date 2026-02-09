# VerifyEmail Component

The `VerifyEmail` component handles email verification flow.

## Basic Usage

```tsx
import { VerifyEmail } from '@fantasticauth/react';

function VerifyEmailPage() {
  return (
    <VerifyEmail
      onVerified={() => {
        console.log('Email verified!');
        window.location.href = '/dashboard';
      }}
    />
  );
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `token` | `string` | - | Verification token from URL |
| `onVerified` | `() => void` | - | Callback after verification |
| `onError` | `(error: ApiError) => void` | - | Callback on error |
| `redirectUrl` | `string` | - | Redirect after verification |
| `appearance` | `Appearance` | - | Custom styling |
| `className` | `string` | - | CSS class names |

## See Also

- [UserProfile Component](./user-profile.md)
