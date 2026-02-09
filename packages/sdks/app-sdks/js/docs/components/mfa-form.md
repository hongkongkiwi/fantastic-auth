# MFAForm Component

The `MFAForm` component provides a complete multi-factor authentication verification form.

## Overview

The MFAForm component handles:
- TOTP code verification (6-digit)
- Backup code verification
- Auto-advancing input fields
- Pasting codes from clipboard
- Error handling and validation

## Basic Usage

```tsx
import { MFAForm } from '@fantasticauth/react';

function SignInPage() {
  return (
    <MFAForm
      onVerify={() => {
        console.log('MFA verified!');
        window.location.href = '/dashboard';
      }}
    />
  );
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `challenge` | `MfaChallenge` | - | MFA challenge from auth context |
| `onVerify` | `() => void` | - | Callback after successful verification |
| `onError` | `(error: ApiError) => void` | - | Callback on verification error |
| `allowBackupCode` | `boolean` | `true` | Allow backup code fallback |
| `appearance` | `Appearance` | - | Custom styling configuration |
| `className` | `string` | - | Additional CSS class names |

## Examples

### Basic MFA Verification

```tsx
<MFAForm
  onVerify={() => {
    window.location.href = '/dashboard';
  }}
/>
```

### With Error Handling

```tsx
<MFAForm
  onVerify={() => {
    console.log('MFA verified!');
  }}
  onError={(error) => {
    console.error('MFA failed:', error);
  }}
  allowBackupCode={true}
/>
```

### With Custom Styling

```tsx
<MFAForm
  onVerify={() => window.location.href = '/dashboard'}
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '8px',
    },
  }}
/>
```

### Complete Sign In Flow with MFA

```tsx
import { SignIn, MFAForm, useAuth } from '@fantasticauth/react';

function SignInPage() {
  const { authState } = useAuth();

  // Check if MFA is required
  if (authState.status === 'mfa_required') {
    return (
      <MFAForm
        onVerify={() => {
          window.location.href = '/dashboard';
        }}
        allowBackupCode={true}
      />
    );
  }

  return <SignIn redirectUrl="/dashboard" />;
}
```

## Input Features

The MFAForm includes:

1. **6-digit input fields** - One field per digit
2. **Auto-advance** - Automatically moves to next field
3. **Backspace support** - Goes to previous field when empty
4. **Paste support** - Can paste entire code from clipboard
5. **Numeric only** - Only accepts numbers
6. **Keyboard navigation** - Full keyboard support

## Backup Codes

When `allowBackupCode` is true:

1. User sees "Use backup code instead" link
2. Clicking switches to single input field
3. User enters one of their saved backup codes
4. Code verifies and signs user in

```tsx
<MFAForm
  allowBackupCode={true}
  onVerify={() => console.log('Signed in with backup code')}
/>
```

## Customization

### CSS Classes

```tsx
<MFAForm className="custom-mfa" />
```

### Appearance Variables

```tsx
<MFAForm
  appearance={{
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '8px',
    },
    elements: {
      digitInput: {
        width: '56px',
        height: '64px',
      },
    },
  }}
/>
```

## Testing

```tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { MFAForm } from '@fantasticauth/react';

test('renders 6 input fields', () => {
  render(<MFAForm />);
  
  const inputs = screen.getAllByRole('textbox');
  expect(inputs).toHaveLength(6);
});

test('accepts numeric input', () => {
  render(<MFAForm />);
  
  const input = screen.getAllByRole('textbox')[0];
  fireEvent.change(input, { target: { value: '1' } });
  
  expect(input).toHaveValue('1');
});
```

## See Also

- [useMfa Hook](../hooks/use-mfa.md) - MFA management
- [SignIn Component](./sign-in.md) - Sign-in with MFA support
