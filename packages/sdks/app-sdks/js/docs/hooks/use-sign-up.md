# useSignUp Hook

The `useSignUp` hook provides sign-up functionality with loading states and error handling.

## Basic Usage

```tsx
import { useSignUp } from '@fantasticauth/react';
import { useState } from 'react';

function SignUpForm() {
  const { signUp, signUpWithOAuth, isLoading, error, resetError } = useSignUp();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      await signUp({ email, password, name });
      // Sign-up successful
    } catch {
      // Error available in error state
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="Name"
        disabled={isLoading}
      />
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
        disabled={isLoading}
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
        disabled={isLoading}
      />
      {error && <p>{error.message}</p>}
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Creating account...' : 'Sign Up'}
      </button>
    </form>
  );
}
```

## Return Value

```tsx
interface UseSignUpReturn {
  isLoading: boolean;
  error: ApiError | null;
  signUp: (options: SignUpOptions) => Promise<void>;
  signUpWithOAuth: (options: OAuthOptions) => Promise<void>;
  resetError: () => void;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `isLoading` | `boolean` | Whether sign-up is in progress |
| `error` | `ApiError \| null` | Last error, if any |
| `signUp` | `(options) => Promise<void>` | Sign up with email/password |
| `signUpWithOAuth` | `(options) => Promise<void>` | Sign up with OAuth |
| `resetError` | `() => void` | Clear error state |

## SignUpOptions

```tsx
interface SignUpOptions {
  email: string;
  password: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  turnstileToken?: string;
}
```

## Examples

### OAuth Sign Up

```tsx
const { signUpWithOAuth } = useSignUp();

<button onClick={() => signUpWithOAuth({ provider: 'google' })}>
  Sign up with Google
</button>
```

## See Also

- [SignUp Component](../components/sign-up.md)
- [useSignIn Hook](./use-sign-in.md)
