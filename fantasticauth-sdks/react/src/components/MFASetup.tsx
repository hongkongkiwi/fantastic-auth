/**
 * MFASetup Component
 * 
 * Pre-built multi-factor authentication setup component.
 */

import React, { useState, useCallback, useEffect } from 'react';
import { useMfa } from '@vault/react';
import type { MFASetupProps, AuthError } from '../types';
import { Button, Input, Alert, Spinner } from './ui';
import { classNames, getThemeClass } from '../styles';

type SetupView = 'select' | 'totp-setup' | 'totp-verify' | 'backup-codes' | 'success';

interface TotpSetupData {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

/**
 * Pre-built MFA setup component
 * 
 * @example
 * ```tsx
 * <MFASetup 
 *   methods={['totp', 'sms']}
 *   onSuccess={() => console.log('MFA enabled')}
 *   onCancel={() => console.log('Cancelled')}
 * />
 * ```
 */
export const MFASetup: React.FC<MFASetupProps> = ({
  methods = ['totp'],
  onSuccess,
  onError,
  onCancel,
  theme = 'light',
  className,
  style,
}) => {
  const { setupTotp, verifyTotp, enableMfa, isLoading, error: hookError, resetError } = useMfa();
  
  const [view, setView] = useState<SetupView>('select');
  const [selectedMethod, setSelectedMethod] = useState<string>('');
  const [totpData, setTotpData] = useState<TotpSetupData | null>(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [localError, setLocalError] = useState<AuthError | null>(null);
  const [copiedCodes, setCopiedCodes] = useState(false);

  const error = localError || (hookError ? {
    code: hookError.code || 'mfa_error',
    message: hookError.message,
  } : null);

  const handleSetupTotp = useCallback(async () => {
    try {
      setLocalError(null);
      resetError();
      const data = await setupTotp();
      if (data) {
        setTotpData(data as TotpSetupData);
        setView('totp-setup');
      }
    } catch (err) {
      const authError: AuthError = {
        code: 'totp_setup_failed',
        message: err instanceof Error ? err.message : 'Failed to setup TOTP.',
      };
      setLocalError(authError);
      onError?.(authError);
    }
  }, [setupTotp, resetError, onError]);

  const handleVerifyTotp = useCallback(async () => {
    if (!verificationCode || verificationCode.length !== 6) {
      setLocalError({
        code: 'invalid_code',
        message: 'Please enter a valid 6-digit code.',
      });
      return;
    }

    try {
      setLocalError(null);
      resetError();
      await verifyTotp(verificationCode);
      setView('backup-codes');
    } catch (err) {
      const authError: AuthError = {
        code: 'verification_failed',
        message: err instanceof Error ? err.message : 'Invalid verification code.',
      };
      setLocalError(authError);
      onError?.(authError);
    }
  }, [verificationCode, verifyTotp, resetError, onError]);

  const handleComplete = useCallback(() => {
    setView('success');
    onSuccess?.();
  }, [onSuccess]);

  const copyBackupCodes = useCallback(() => {
    if (totpData?.backupCodes) {
      navigator.clipboard.writeText(totpData.backupCodes.join('\n'));
      setCopiedCodes(true);
      setTimeout(() => setCopiedCodes(false), 2000);
    }
  }, [totpData]);

  const themeClass = getThemeClass(theme);

  // Select method view
  if (view === 'select') {
    return (
      <div className={classNames('vault-mfa-setup', themeClass, className)} style={style}>
        <div className="vault-mfa-header">
          <h2 className="vault-mfa-title">Set up two-factor authentication</h2>
          <p className="vault-mfa-subtitle">
            Add an extra layer of security to your account.
          </p>
        </div>

        {error && (
          <Alert variant="error" className="vault-mb-4">
            {error.message}
          </Alert>
        )}

        <div className="vault-mfa-methods">
          {methods.includes('totp') && (
            <button
              type="button"
              className={classNames(
                'vault-mfa-method',
                selectedMethod === 'totp' && 'vault-mfa-method-selected'
              )}
              onClick={() => {
                setSelectedMethod('totp');
                handleSetupTotp();
              }}
              disabled={isLoading}
            >
              <div className="vault-mfa-method-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              </div>
              <div className="vault-mfa-method-content">
                <div className="vault-mfa-method-title">Authenticator App</div>
                <div className="vault-mfa-method-description">
                  Use Google Authenticator, Authy, or similar
                </div>
              </div>
              <div className="vault-mfa-method-arrow">→</div>
            </button>
          )}

          {methods.includes('sms') && (
            <button
              type="button"
              className={classNames(
                'vault-mfa-method',
                selectedMethod === 'sms' && 'vault-mfa-method-selected'
              )}
              onClick={() => setSelectedMethod('sms')}
              disabled={isLoading}
            >
              <div className="vault-mfa-method-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z" />
                </svg>
              </div>
              <div className="vault-mfa-method-content">
                <div className="vault-mfa-method-title">SMS</div>
                <div className="vault-mfa-method-description">
                  Receive codes via text message
                </div>
              </div>
              <div className="vault-mfa-method-arrow">→</div>
            </button>
          )}

          {methods.includes('email') && (
            <button
              type="button"
              className={classNames(
                'vault-mfa-method',
                selectedMethod === 'email' && 'vault-mfa-method-selected'
              )}
              onClick={() => setSelectedMethod('email')}
              disabled={isLoading}
            >
              <div className="vault-mfa-method-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                  <polyline points="22,6 12,13 2,6" />
                </svg>
              </div>
              <div className="vault-mfa-method-content">
                <div className="vault-mfa-method-title">Email</div>
                <div className="vault-mfa-method-description">
                  Receive codes via email
                </div>
              </div>
              <div className="vault-mfa-method-arrow">→</div>
            </button>
          )}
        </div>

        {onCancel && (
          <Button
            variant="ghost"
            fullWidth
            onClick={onCancel}
            className="vault-mt-4"
          >
            Cancel
          </Button>
        )}
      </div>
    );
  }

  // TOTP Setup view
  if (view === 'totp-setup' && totpData) {
    return (
      <div className={classNames('vault-mfa-setup', themeClass, className)} style={style}>
        <div className="vault-mfa-header">
          <h2 className="vault-mfa-title">Scan QR code</h2>
          <p className="vault-mfa-subtitle">
            Scan this QR code with your authenticator app.
          </p>
        </div>

        {error && (
          <Alert variant="error" className="vault-mb-4">
            {error.message}
          </Alert>
        )}

        <div className="vault-totp-setup">
          <div className="vault-totp-qr">
            <img 
              src={totpData.qrCode} 
              alt="QR Code for authenticator app"
              className="vault-totp-qr-image"
            />
          </div>

          <div className="vault-totp-secret">
            <p>Can't scan? Enter this code manually:</p>
            <code className="vault-totp-secret-code">{totpData.secret}</code>
          </div>

          <Button
            variant="primary"
            fullWidth
            onClick={() => setView('totp-verify')}
            className="vault-mt-4"
          >
            Next
          </Button>

          <Button
            variant="ghost"
            fullWidth
            onClick={() => setView('select')}
            className="vault-mt-2"
          >
            Back
          </Button>
        </div>
      </div>
    );
  }

  // TOTP Verification view
  if (view === 'totp-verify') {
    return (
      <div className={classNames('vault-mfa-setup', themeClass, className)} style={style}>
        <div className="vault-mfa-header">
          <h2 className="vault-mfa-title">Verify setup</h2>
          <p className="vault-mfa-subtitle">
            Enter the 6-digit code from your authenticator app.
          </p>
        </div>

        {error && (
          <Alert variant="error" className="vault-mb-4">
            {error.message}
          </Alert>
        )}

        <div className="vault-totp-verify">
          <Input
            type="text"
            label="Verification code"
            placeholder="000000"
            value={verificationCode}
            onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            maxLength={6}
            disabled={isLoading}
            required
          />

          <Button
            type="button"
            variant="primary"
            fullWidth
            isLoading={isLoading}
            onClick={handleVerifyTotp}
            className="vault-mt-4"
          >
            Verify
          </Button>

          <Button
            variant="ghost"
            fullWidth
            onClick={() => setView('totp-setup')}
            className="vault-mt-2"
          >
            Back
          </Button>
        </div>
      </div>
    );
  }

  // Backup codes view
  if (view === 'backup-codes' && totpData) {
    return (
      <div className={classNames('vault-mfa-setup', themeClass, className)} style={style}>
        <div className="vault-mfa-header">
          <h2 className="vault-mfa-title">Save backup codes</h2>
          <p className="vault-mfa-subtitle">
            Save these backup codes in a safe place. You can use them to sign in if you lose access to your authenticator app.
          </p>
        </div>

        <div className="vault-backup-codes">
          <div className="vault-backup-codes-list">
            {totpData.backupCodes.map((code, index) => (
              <code key={index} className="vault-backup-code">{code}</code>
            ))}
          </div>

          <Button
            variant="secondary"
            fullWidth
            onClick={copyBackupCodes}
            className="vault-mt-4"
          >
            {copiedCodes ? 'Copied!' : 'Copy backup codes'}
          </Button>

          <Button
            variant="primary"
            fullWidth
            onClick={handleComplete}
            className="vault-mt-2"
          >
            I've saved my backup codes
          </Button>
        </div>
      </div>
    );
  }

  // Success view
  if (view === 'success') {
    return (
      <div className={classNames('vault-mfa-setup', themeClass, className)} style={style}>
        <Alert variant="success" title="Two-factor authentication enabled">
          Your account is now more secure. You'll be asked for a verification code when you sign in.
        </Alert>
      </div>
    );
  }

  return null;
};
