# useMfa Hook

The `useMfa` hook provides functionality for multi-factor authentication management and verification.

## Overview

The `useMfa` hooks include:
- `useMfa()` - MFA setup and management
- `useMfaChallenge()` - Verify MFA during sign-in

## useMfa

Set up and manage multi-factor authentication.

### Basic Usage

```tsx
import { useMfa } from '@fantasticauth/react';
import { useState } from 'react';

function MfaSetup() {
  const { setupTotp, verifyTotp, isLoading, error } = useMfa();
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [step, setStep] = useState<'setup' | 'verify' | 'complete'>('setup');

  const handleSetup = async () => {
    const setup = await setupTotp();
    if (setup) {
      setQrCode(setup.qrCode);
      setBackupCodes(setup.backupCodes);
      setStep('verify');
    }
  };

  const handleVerify = async (code: string) => {
    await verifyTotp(code);
    setStep('complete');
  };

  return (
    <div>
      {step === 'setup' && (
        <button onClick={handleSetup} disabled={isLoading}>
          Setup Two-Factor Authentication
        </button>
      )}
      
      {step === 'verify' && qrCode && (
        <div>
          <img src={qrCode} alt="Scan with authenticator app" />
          <p>Scan the QR code with your authenticator app</p>
          <VerificationForm onSubmit={handleVerify} isLoading={isLoading} />
        </div>
      )}
      
      {step === 'complete' && (
        <div>
          <h3>Setup Complete!</h3>
          <p>Save these backup codes:</p>
          <ul>
            {backupCodes.map((code) => (
              <li key={code}>{code}</li>
            ))}
          </ul>
        </div>
      )}
      
      {error && <p>{error.message}</p>}
    </div>
  );
}
```

### Return Value

```tsx
interface UseMfaReturn {
  isLoading: boolean;
  error: ApiError | null;
  setupTotp: () => Promise<TotpSetup | null>;
  verifyTotp: (code: string) => Promise<void>;
  enableMfa: (method: MfaMethod) => Promise<void>;
  disableMfa: (method: MfaMethod) => Promise<void>;
  generateBackupCodes: () => Promise<string[]>;
  resetError: () => void;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `isLoading` | `boolean` | Whether an operation is in progress |
| `error` | `ApiError \| null` | Last error, if any |
| `setupTotp` | `() => Promise<TotpSetup>` | Start TOTP setup |
| `verifyTotp` | `(code) => Promise<void>` | Verify TOTP code during setup |
| `enableMfa` | `(method) => Promise<void>` | Enable an MFA method |
| `disableMfa` | `(method) => Promise<void>` | Disable an MFA method |
| `generateBackupCodes` | `() => Promise<string[]>` | Generate new backup codes |
| `resetError` | `() => void` | Clear error state |

### TotpSetup

```tsx
interface TotpSetup {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}
```

## useMfaChallenge

Verify MFA during the sign-in flow.

### Basic Usage

```tsx
import { useMfaChallenge, useAuth } from '@fantasticauth/react';
import { useState } from 'react';

function MfaVerification() {
  const { challenge, isRequired, verify, isLoading, error } = useMfaChallenge();
  const { authState } = useAuth();
  const [code, setCode] = useState('');

  // Only show if MFA is required
  if (!isRequired && !challenge) {
    return null;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await verify(code, challenge?.method || 'totp');
    // Verification successful - user is now authenticated
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Two-Factor Authentication</h2>
      <p>Enter the code from your authenticator app</p>
      
      <input
        type="text"
        value={code}
        onChange={(e) => setCode(e.target.value)}
        placeholder="000000"
        maxLength={6}
        disabled={isLoading}
      />
      
      {error && <p>{error.message}</p>}
      
      <button type="submit" disabled={isLoading || code.length !== 6}>
        {isLoading ? 'Verifying...' : 'Verify'}
      </button>
    </form>
  );
}
```

### Return Value

```tsx
interface UseMfaChallengeReturn {
  challenge: MfaChallenge | null;
  isRequired: boolean;
  verify: (code: string, method: MfaMethod) => Promise<void>;
  isLoading: boolean;
  error: ApiError | null;
}
```

| Property | Type | Description |
|----------|------|-------------|
| `challenge` | `MfaChallenge \| null` | Current MFA challenge |
| `isRequired` | `boolean` | Whether MFA verification is required |
| `verify` | `(code, method) => Promise<void>` | Verify MFA code |
| `isLoading` | `boolean` | Whether verification is in progress |
| `error` | `ApiError \| null` | Error state |

### MfaChallenge

```tsx
interface MfaChallenge {
  method: MfaMethod;
  expiresAt: string;
}

type MfaMethod = 'totp' | 'email' | 'sms' | 'webauthn' | 'backup_codes';
```

## Examples

### Complete MFA Setup Flow

```tsx
import { useMfa, useUser } from '@fantasticauth/react';
import { useState } from 'react';

function MfaSetupFlow() {
  const user = useUser();
  const { setupTotp, verifyTotp, disableMfa, isLoading, error } = useMfa();
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [secret, setSecret] = useState<string>('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verificationCode, setVerificationCode] = useState('');
  const [step, setStep] = useState<'intro' | 'scan' | 'verify' | 'complete'>('intro');

  const handleStartSetup = async () => {
    const setup = await setupTotp();
    if (setup) {
      setQrCode(setup.qrCode);
      setSecret(setup.secret);
      setBackupCodes(setup.backupCodes);
      setStep('scan');
    }
  };

  const handleVerify = async () => {
    await verifyTotp(verificationCode);
    setStep('complete');
  };

  const handleDisable = async () => {
    if (window.confirm('Disable two-factor authentication?')) {
      await disableMfa('totp');
    }
  };

  // User already has MFA enabled
  if (user?.mfaEnabled) {
    return (
      <div>
        <h2>Two-Factor Authentication</h2>
        <p>Status: Enabled</p>
        <button onClick={handleDisable} disabled={isLoading}>
          Disable 2FA
        </button>
      </div>
    );
  }

  return (
    <div>
      <h2>Two-Factor Authentication</h2>
      
      {step === 'intro' && (
        <div>
          <p>Protect your account with two-factor authentication</p>
          <button onClick={handleStartSetup} disabled={isLoading}>
            Setup 2FA
          </button>
        </div>
      )}

      {step === 'scan' && qrCode && (
        <div>
          <p>1. Scan this QR code with your authenticator app:</p>
          <img src={qrCode} alt="2FA QR Code" />
          <p>Or enter this code manually: {secret}</p>
          
          <p>2. Enter the 6-digit code from your app:</p>
          <input
            type="text"
            value={verificationCode}
            onChange={(e) => setVerificationCode(e.target.value)}
            maxLength={6}
            placeholder="000000"
          />
          <button onClick={handleVerify} disabled={isLoading}>
            Verify
          </button>
        </div>
      )}

      {step === 'complete' && (
        <div>
          <h3>✓ Two-Factor Authentication Enabled</h3>
          <p>Save these backup codes in a safe place:</p>
          <div className="backup-codes">
            {backupCodes.map((code) => (
              <code key={code}>{code}</code>
            ))}
          </div>
          <p>You can use these codes if you lose access to your authenticator app.</p>
        </div>
      )}

      {error && <p className="error">{error.message}</p>}
    </div>
  );
}
```

### Sign In with MFA

```tsx
import { useAuth, useMfaChallenge } from '@fantasticauth/react';
import { SignIn, MFAForm } from '@fantasticauth/react';

function SignInPage() {
  const { authState } = useAuth();
  const { isRequired } = useMfaChallenge();

  // Check if MFA is required
  if (authState.status === 'mfa_required' || isRequired) {
    return (
      <MFAForm
        onVerify={() => {
          window.location.href = '/dashboard';
        }}
        onError={(error) => {
          console.error('MFA verification failed:', error);
        }}
      />
    );
  }

  return (
    <SignIn
      redirectUrl="/dashboard"
      onError={(error) => {
        if (error.code === 'mfa_required') {
          // MFA will be handled by authState change
        }
      }}
    />
  );
}
```

### Backup Codes Management

```tsx
import { useMfa, useUser } from '@fantasticauth/react';
import { useState } from 'react';

function BackupCodesManager() {
  const user = useUser();
  const { generateBackupCodes, isLoading } = useMfa();
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [showCodes, setShowCodes] = useState(false);

  const handleGenerate = async () => {
    const codes = await generateBackupCodes();
    setBackupCodes(codes);
    setShowCodes(true);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(backupCodes.join('\n'));
    alert('Backup codes copied to clipboard');
  };

  if (!user?.mfaEnabled) {
    return <p>Enable two-factor authentication to use backup codes</p>;
  }

  return (
    <div>
      <h3>Backup Codes</h3>
      
      {!showCodes ? (
        <div>
          <p>Generate new backup codes in case you lose access to your authenticator app.</p>
          <p className="warning">Generating new codes will invalidate your existing codes.</p>
          <button onClick={handleGenerate} disabled={isLoading}>
            {isLoading ? 'Generating...' : 'Generate New Codes'}
          </button>
        </div>
      ) : (
        <div>
          <p>Save these codes in a safe place:</p>
          <div className="backup-codes-list">
            {backupCodes.map((code) => (
              <code key={code}>{code}</code>
            ))}
          </div>
          <button onClick={handleCopy}>Copy to Clipboard</button>
          <button onClick={() => setShowCodes(false)}>Done</button>
        </div>
      )}
    </div>
  );
}
```

### Disable MFA

```tsx
import { useMfa, useUser } from '@fantasticauth/react';
import { useState } from 'react';

function DisableMfa() {
  const user = useUser();
  const { disableMfa, isLoading, error } = useMfa();
  const [password, setPassword] = useState('');
  const [showConfirm, setShowConfirm] = useState(false);

  const handleDisable = async () => {
    await disableMfa('totp');
    setShowConfirm(false);
    setPassword('');
  };

  if (!user?.mfaEnabled) {
    return null;
  }

  return (
    <div className="danger-zone">
      <h3>Disable Two-Factor Authentication</h3>
      
      {!showConfirm ? (
        <button
          onClick={() => setShowConfirm(true)}
          className="danger"
        >
          Disable 2FA
        </button>
      ) : (
        <div>
          <p className="warning">
            Warning: This will make your account less secure
          </p>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password to confirm"
          />
          <button onClick={handleDisable} disabled={isLoading || !password}>
            {isLoading ? 'Disabling...' : 'Confirm Disable'}
          </button>
          <button onClick={() => setShowConfirm(false)}>Cancel</button>
          {error && <p className="error">{error.message}</p>}
        </div>
      )}
    </div>
  );
}
```

## Testing

Test MFA hooks:

```tsx
import { renderHook, act } from '@testing-library/react';
import { useMfa, VaultProvider } from '@fantasticauth/react';

const wrapper = ({ children }) => (
  <VaultProvider config={{ apiUrl: 'https://test', tenantId: 'test' }}>
    {children}
  </VaultProvider>
);

test('useMfa returns correct initial state', () => {
  const { result } = renderHook(() => useMfa(), { wrapper });

  expect(result.current.isLoading).toBe(false);
  expect(result.current.error).toBeNull();
});
```

## Best Practices

1. **Always show backup codes** after TOTP setup
2. **Warn users** before disabling MFA
3. **Copy to clipboard** button for backup codes
4. **Show clear instructions** for scanning QR codes
5. **Handle loading states** during MFA operations

## See Also

- [MFAForm Component](../components/mfa-form.md) - Pre-built MFA verification
- [useAuth Hook](./use-auth.md) - Authentication state
- [SignIn Component](../components/sign-in.md) - Sign-in with MFA support
