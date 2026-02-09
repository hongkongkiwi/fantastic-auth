/**
 * UserProfile Component
 * 
 * Pre-built user profile management component.
 */

import React, { useState, useCallback, useEffect } from 'react';
import { useUser, useUserProfile } from '../hooks/useUser';
import type { UserProfileProps, AuthError } from '../types';
import { Button, Input, Alert } from './ui';
import { classNames, getThemeClass } from '../styles';

type ProfileView = 'profile' | 'password' | 'danger';

/**
 * Pre-built user profile component
 * 
 * @example
 * ```tsx
 * <UserProfile 
 *   onUpdate={(user) => console.log('Updated:', user)}
 *   showChangePassword
 *   showDeleteAccount
 * />
 * ```
 */
export const UserProfile: React.FC<UserProfileProps> = ({
  onUpdate,
  onError,
  showDeleteAccount = false,
  showChangePassword = true,
  theme = 'light',
  className,
  style,
}) => {
  const { user, isLoading: userLoading, update, changePassword, deleteAccount, error: userError } = useUser();
  const { profile, reload } = useUserProfile();
  
  const [view, setView] = useState<ProfileView>('profile');
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
  });
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [isUpdating, setIsUpdating] = useState(false);
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [localError, setLocalError] = useState<AuthError | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  // Initialize form data when user loads
  useEffect(() => {
    if (user) {
      setFormData({
        name: user.profile?.name || '',
        email: user.email || '',
        phone: user.profile?.phoneNumber || '',
      });
    }
  }, [user]);

  const error = localError || (userError ? {
    code: userError.code || 'profile_error',
    message: userError.message,
  } : null);

  const clearMessages = useCallback(() => {
    setLocalError(null);
    setSuccessMessage(null);
  }, []);

  const handleProfileUpdate = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();

    try {
      setIsUpdating(true);
      await update({
        profile: {
          ...user?.profile,
          name: formData.name,
          phoneNumber: formData.phone,
        },
      });
      await reload();
      setSuccessMessage('Profile updated successfully');
      onUpdate?.(user!);
    } catch (err) {
      const authError: AuthError = {
        code: 'update_failed',
        message: err instanceof Error ? err.message : 'Failed to update profile.',
      };
      setLocalError(authError);
      onError?.(authError);
    } finally {
      setIsUpdating(false);
    }
  }, [formData, user, update, reload, onUpdate, onError, clearMessages]);

  const validatePasswordForm = useCallback((): boolean => {
    const errors: Record<string, string> = {};

    if (!passwordData.currentPassword) {
      errors.currentPassword = 'Current password is required';
    }

    if (!passwordData.newPassword) {
      errors.newPassword = 'New password is required';
    } else if (passwordData.newPassword.length < 8) {
      errors.newPassword = 'Password must be at least 8 characters';
    }

    if (passwordData.newPassword !== passwordData.confirmPassword) {
      errors.confirmPassword = 'Passwords do not match';
    }

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  }, [passwordData]);

  const handlePasswordChange = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    clearMessages();

    if (!validatePasswordForm()) return;

    try {
      setIsChangingPassword(true);
      await changePassword(passwordData.currentPassword, passwordData.newPassword);
      setSuccessMessage('Password changed successfully');
      setPasswordData({
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
      });
    } catch (err) {
      const authError: AuthError = {
        code: 'password_change_failed',
        message: err instanceof Error ? err.message : 'Failed to change password.',
      };
      setLocalError(authError);
      onError?.(authError);
    } finally {
      setIsChangingPassword(false);
    }
  }, [passwordData, validatePasswordForm, changePassword, onError, clearMessages]);

  const handleDeleteAccount = useCallback(async () => {
    if (!window.confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
      return;
    }

    try {
      await deleteAccount();
    } catch (err) {
      const authError: AuthError = {
        code: 'delete_failed',
        message: err instanceof Error ? err.message : 'Failed to delete account.',
      };
      setLocalError(authError);
      onError?.(authError);
    }
  }, [deleteAccount, onError]);

  const themeClass = getThemeClass(theme);

  if (userLoading) {
    return (
      <div className={classNames('vault-user-profile', themeClass, className)} style={style}>
        <div className="vault-loading">Loading profile...</div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className={classNames('vault-user-profile', themeClass, className)} style={style}>
        <Alert variant="error">
          Please sign in to view your profile.
        </Alert>
      </div>
    );
  }

  return (
    <div className={classNames('vault-user-profile', themeClass, className)} style={style}>
      {/* Navigation */}
      <div className="vault-profile-nav">
        <button
          type="button"
          className={classNames('vault-profile-nav-item', view === 'profile' && 'vault-profile-nav-active')}
          onClick={() => setView('profile')}
        >
          Profile
        </button>
        {showChangePassword && (
          <button
            type="button"
            className={classNames('vault-profile-nav-item', view === 'password' && 'vault-profile-nav-active')}
            onClick={() => setView('password')}
          >
            Password
          </button>
        )}
        {showDeleteAccount && (
          <button
            type="button"
            className={classNames('vault-profile-nav-item', view === 'danger' && 'vault-profile-nav-active')}
            onClick={() => setView('danger')}
          >
            Danger Zone
          </button>
        )}
      </div>

      {/* Messages */}
      {error && (
        <Alert variant="error" className="vault-mb-4" onDismiss={clearMessages}>
          {error.message}
        </Alert>
      )}
      {successMessage && (
        <Alert variant="success" className="vault-mb-4" onDismiss={clearMessages}>
          {successMessage}
        </Alert>
      )}

      {/* Profile View */}
      {view === 'profile' && (
        <form onSubmit={handleProfileUpdate} className="vault-profile-form">
          <div className="vault-profile-avatar">
            {user.profile?.picture ? (
              <img 
                src={user.profile.picture} 
                alt="Profile" 
                className="vault-profile-avatar-image"
              />
            ) : (
              <div className="vault-profile-avatar-placeholder">
                {formData.name?.charAt(0)?.toUpperCase() || user.email?.charAt(0)?.toUpperCase()}
              </div>
            )}
          </div>

          <Input
            type="text"
            label="Full name"
            value={formData.name}
            onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
            disabled={isUpdating}
          />

          <Input
            type="email"
            label="Email"
            value={formData.email}
            disabled
            helperText="Email cannot be changed"
          />

          <Input
            type="tel"
            label="Phone number"
            value={formData.phone}
            onChange={(e) => setFormData(prev => ({ ...prev, phone: e.target.value }))}
            disabled={isUpdating}
          />

          <div className="vault-profile-info">
            <div className="vault-profile-info-item">
              <span className="vault-profile-info-label">Member since</span>
              <span className="vault-profile-info-value">
                {new Date(user.createdAt).toLocaleDateString()}
              </span>
            </div>
            <div className="vault-profile-info-item">
              <span className="vault-profile-info-label">Email verified</span>
              <span className={classNames('vault-profile-info-value', user.emailVerified ? 'vault-text-success' : 'vault-text-warning')}>
                {user.emailVerified ? 'Yes' : 'No'}
              </span>
            </div>
            <div className="vault-profile-info-item">
              <span className="vault-profile-info-label">MFA enabled</span>
              <span className={classNames('vault-profile-info-value', user.mfaEnabled ? 'vault-text-success' : 'vault-text-muted')}>
                {user.mfaEnabled ? 'Yes' : 'No'}
              </span>
            </div>
          </div>

          <Button
            type="submit"
            variant="primary"
            isLoading={isUpdating}
            className="vault-mt-4"
          >
            Save changes
          </Button>
        </form>
      )}

      {/* Password View */}
      {view === 'password' && (
        <form onSubmit={handlePasswordChange} className="vault-password-form">
          <Input
            type="password"
            label="Current password"
            value={passwordData.currentPassword}
            onChange={(e) => {
              setPasswordData(prev => ({ ...prev, currentPassword: e.target.value }));
              if (fieldErrors.currentPassword) {
                setFieldErrors(prev => ({ ...prev, currentPassword: '' }));
              }
            }}
            error={fieldErrors.currentPassword}
            disabled={isChangingPassword}
            required
          />

          <Input
            type="password"
            label="New password"
            value={passwordData.newPassword}
            onChange={(e) => {
              setPasswordData(prev => ({ ...prev, newPassword: e.target.value }));
              if (fieldErrors.newPassword) {
                setFieldErrors(prev => ({ ...prev, newPassword: '' }));
              }
            }}
            error={fieldErrors.newPassword}
            disabled={isChangingPassword}
            required
          />

          <Input
            type="password"
            label="Confirm new password"
            value={passwordData.confirmPassword}
            onChange={(e) => {
              setPasswordData(prev => ({ ...prev, confirmPassword: e.target.value }));
              if (fieldErrors.confirmPassword) {
                setFieldErrors(prev => ({ ...prev, confirmPassword: '' }));
              }
            }}
            error={fieldErrors.confirmPassword}
            disabled={isChangingPassword}
            required
          />

          <Button
            type="submit"
            variant="primary"
            isLoading={isChangingPassword}
            className="vault-mt-4"
          >
            Change password
          </Button>
        </form>
      )}

      {/* Danger Zone View */}
      {view === 'danger' && (
        <div className="vault-danger-zone">
          <div className="vault-danger-item">
            <div className="vault-danger-content">
              <h3 className="vault-danger-title">Delete account</h3>
              <p className="vault-danger-description">
                Permanently delete your account and all associated data. This action cannot be undone.
              </p>
            </div>
            <Button
              variant="danger"
              onClick={handleDeleteAccount}
            >
              Delete account
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};
