# ResetPassword Component

The `ResetPassword` component provides a password reset form.

## Basic Usage

```tsx
import { ResetPassword } from '@vault/react';

function ResetPasswordPage() {
  return (
    <ResetPassword
      onSuccess={() => {
        console.log('Password reset!');
        window.location.href = '/sign-in';
      }}
    />
  );
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `token` | `string` | - | Reset token from URL |
| `onSuccess` | `() => void` | - | Callback after successful reset |
| `onError` | `(error: ApiError) => void` | - | Callback on error |
| `redirectUrl` | `string` | - | Redirect after reset |
| `appearance` | `Appearance` | - | Custom styling |
| `className` | `string` | - | CSS class names |

## See Also

- [SignIn Component](./sign-in.md)
