# Waitlist

Guide for implementing a waitlist for your application.

## Overview

A waitlist allows you to:
- Collect interested users before launch
- Manage access to your application
- Send invitations

## Implementation

While Vault doesn't provide a built-in waitlist component, you can implement one using the SDK:

```tsx
import { useSignUp } from '@vault/react';

function WaitlistForm() {
  const { signUp, isLoading } = useSignUp();
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Store in waitlist
    await fetch('/api/waitlist', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
    
    setSubmitted(true);
  };

  if (submitted) {
    return <p>Thanks for joining the waitlist!</p>;
  }

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Enter your email"
      />
      <button type="submit" disabled={isLoading}>
        Join Waitlist
      </button>
    </form>
  );
}
```

## See Also

- [SignUp Component](./sign-up.md)
