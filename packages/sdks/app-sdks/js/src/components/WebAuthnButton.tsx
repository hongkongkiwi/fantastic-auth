/**
 * WebAuthnButton Component
 * 
 * Button for WebAuthn/Passkey authentication.
 * 
 * @example
 * ```tsx
 * // Sign in with passkey
 * <WebAuthnButton mode="signin" label="Sign in with Passkey" />
 * 
 * // Register new passkey
 * <WebAuthnButton mode="signup" label="Register Passkey" />
 * 
 * // Link passkey to existing account
 * <WebAuthnButton mode="link" label="Add Passkey" />
 * ```
 */

import React, { useState, useCallback } from 'react';
import { useWebAuthn } from '../hooks/useWebAuthn';
import { useVault } from '../context/VaultContext';
import { WebAuthnButtonProps, ApiError } from '../types';

export type { WebAuthnButtonProps };

export function WebAuthnButton({
  mode = 'signin',
  label,
  onSuccess,
  onError,
  appearance,
  className,
}: WebAuthnButtonProps) {
  const { isSupported, isLoading, error, register, authenticate, resetError } = useWebAuthn();
  const [localError, setLocalError] = useState<string | null>(null);
  const [showNameInput, setShowNameInput] = useState(false);
  const [passkeyName, setPasskeyName] = useState('');

  const handleClick = useCallback(async () => {
    resetError();
    setLocalError(null);

    if (!isSupported) {
      const err: ApiError = {
        code: 'webauthn_not_supported',
        message: 'Passkeys are not supported on this device',
      };
      setLocalError(err.message);
      onError?.(err);
      return;
    }

    try {
      if (mode === 'signup' || mode === 'link') {
        if (!showNameInput) {
          setShowNameInput(true);
          return;
        }
        await register(passkeyName || undefined);
        setShowNameInput(false);
        setPasskeyName('');
      } else {
        await authenticate();
      }
      onSuccess?.();
    } catch (err: any) {
      setLocalError(err.message || 'Passkey operation failed');
      onError?.(err as ApiError);
    }
  }, [mode, isSupported, register, authenticate, onSuccess, onError, resetError, showNameInput, passkeyName]);

  const handleCancel = useCallback(() => {
    setShowNameInput(false);
    setPasskeyName('');
  }, []);

  if (!isSupported) {
    return (
      <div style={applyAppearance(styles.unsupported, appearance)} className={className}>
        <span style={styles.unsupportedText}>
          Passkeys not supported on this device
        </span>
      </div>
    );
  }

  const displayError = localError || error?.message;

  // Get default label based on mode
  const getDefaultLabel = () => {
    switch (mode) {
      case 'signin':
        return 'Sign in with Passkey';
      case 'signup':
        return 'Register Passkey';
      case 'link':
        return 'Add Passkey';
      default:
        return 'Continue with Passkey';
    }
  };

  const buttonLabel = label || getDefaultLabel();

  if (showNameInput) {
    return (
      <div style={applyAppearance(styles.container, appearance)} className={className}>
        <div style={styles.inputGroup}>
          <input
            type="text"
            value={passkeyName}
            onChange={(e) => setPasskeyName(e.target.value)}
            placeholder="Name your passkey (optional)"
            style={applyAppearance(styles.input, appearance)}
            disabled={isLoading}
            autoFocus
          />
          <button
            onClick={handleClick}
            disabled={isLoading}
            style={applyAppearance(styles.button, appearance)}
          >
            {isLoading ? 'Registering...' : 'Register'}
          </button>
          <button
            onClick={handleCancel}
            disabled={isLoading}
            style={applyAppearance(styles.cancelButton, appearance)}
          >
            Cancel
          </button>
        </div>
        {displayError && (
          <div style={applyAppearance(styles.error, appearance)} role="alert">
            {displayError}
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={applyAppearance(styles.container, appearance)} className={className}>
      <button
        onClick={handleClick}
        disabled={isLoading}
        style={applyAppearance(styles.button, appearance)}
      >
        <PasskeyIcon />
        <span>{isLoading ? 'Please wait...' : buttonLabel}</span>
      </button>
      {displayError && (
        <div style={applyAppearance(styles.error, appearance)} role="alert">
          {displayError}
        </div>
      )}
    </div>
  );
}

// Passkey Icon Component
function PasskeyIcon() {
  return (
    <svg
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="8" r="4" />
      <path d="M12 12v8" />
      <path d="M9 16h6" />
      <path d="M8 20h8" />
      <rect x="4" y="2" width="16" height="20" rx="2" />
    </svg>
  );
}

// Apply appearance variables
function applyAppearance(
  baseStyle: React.CSSProperties,
  appearance?: { theme?: string; variables?: Record<string, string>; elements?: Record<string, React.CSSProperties> }
): React.CSSProperties {
  if (!appearance) return baseStyle;

  const variables = appearance.variables || {};
  let style = { ...baseStyle };

  if (variables['colorPrimary']) {
    if (baseStyle.backgroundColor === '#0066cc' || baseStyle.borderColor === '#0066cc') {
      style = { ...style, backgroundColor: variables['colorPrimary'], borderColor: variables['colorPrimary'] };
    }
  }

  if (variables['borderRadius'] && baseStyle.borderRadius) {
    style = { ...style, borderRadius: variables['borderRadius'] };
  }

  return style;
}

// Styles
const styles: Record<string, React.CSSProperties> = {
  container: {
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  button: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    width: '100%',
    padding: '12px 16px',
    fontSize: '16px',
    fontWeight: 500,
    color: '#374151',
    backgroundColor: '#f3f4f6',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'all 0.15s ease-in-out',
  },
  inputGroup: {
    display: 'flex',
    gap: '8px',
    marginBottom: '8px',
  },
  input: {
    flex: 1,
    padding: '10px 12px',
    fontSize: '15px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    outline: 'none',
  },
  cancelButton: {
    padding: '10px 16px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#6b7280',
    backgroundColor: '#f3f4f6',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    cursor: 'pointer',
  },
  error: {
    marginTop: '8px',
    padding: '8px 12px',
    fontSize: '13px',
    color: '#dc2626',
    backgroundColor: '#fee2e2',
    borderRadius: '6px',
  },
  unsupported: {
    padding: '12px',
    textAlign: 'center',
    backgroundColor: '#f3f4f6',
    borderRadius: '6px',
  },
  unsupportedText: {
    fontSize: '14px',
    color: '#6b7280',
  },
};
