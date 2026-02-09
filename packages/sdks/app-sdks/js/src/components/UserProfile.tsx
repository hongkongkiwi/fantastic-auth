/**
 * UserProfile Component
 * 
 * Profile management page component for viewing and editing user profile.
 * 
 * @example
 * ```tsx
 * <UserProfile 
 *   onUpdate={(user) => console.log('Updated:', user)}
 * />
 * ```
 */

import React, { useState, useCallback } from 'react';
import { useUserManager } from '../hooks/useUser';
import { UserProfileProps, User, ApiError } from '../types';

export type { UserProfileProps };

export function UserProfile({
  onUpdate,
  appearance,
  className,
}: UserProfileProps) {
  const { user, isLoading, error, update, changePassword, deleteUser } = useUserManager();
  
  const [activeTab, setActiveTab] = useState<'profile' | 'security' | 'danger'>('profile');
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    givenName: '',
    familyName: '',
    phoneNumber: '',
  });
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [localError, setLocalError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Initialize form data when user loads
  React.useEffect(() => {
    if (user) {
      setFormData({
        name: user.profile?.name || '',
        givenName: user.profile?.givenName || '',
        familyName: user.profile?.familyName || '',
        phoneNumber: user.profile?.phoneNumber || '',
      });
    }
  }, [user]);

  const handleInputChange = useCallback((field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setLocalError(null);
    setSuccessMessage(null);
  }, []);

  const handleSaveProfile = useCallback(async () => {
    setLocalError(null);
    setSuccessMessage(null);

    try {
      await update({
        profile: {
          ...user?.profile,
          ...formData,
        },
      });
      setIsEditing(false);
      setSuccessMessage('Profile updated successfully');
      onUpdate?.(user as User);
    } catch (err) {
      setLocalError((err as ApiError).message || 'Failed to update profile');
    }
  }, [formData, user, update, onUpdate]);

  const handleChangePassword = useCallback(async () => {
    setLocalError(null);
    setSuccessMessage(null);

    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setLocalError('Passwords do not match');
      return;
    }

    if (passwordData.newPassword.length < 12) {
      setLocalError('Password must be at least 12 characters');
      return;
    }

    try {
      await changePassword(passwordData.currentPassword, passwordData.newPassword);
      setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
      setSuccessMessage('Password changed successfully');
    } catch (err) {
      setLocalError((err as ApiError).message || 'Failed to change password');
    }
  }, [passwordData, changePassword]);

  const handleDeleteAccount = useCallback(async () => {
    if (window.confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
      try {
        await deleteUser();
      } catch (err) {
        setLocalError((err as ApiError).message || 'Failed to delete account');
      }
    }
  }, [deleteUser]);

  if (!user) {
    return (
      <div style={applyAppearance(styles.container, appearance)} className={className}>
        <div style={styles.loading}>Loading profile...</div>
      </div>
    );
  }

  const displayError = localError || error?.message;

  return (
    <div style={applyAppearance(styles.container, appearance)} className={className}>
      <h1 style={applyAppearance(styles.heading, appearance)}>Profile</h1>

      {/* Tabs */}
      <div style={styles.tabs}>
        <TabButton
          label="Profile"
          isActive={activeTab === 'profile'}
          onClick={() => setActiveTab('profile')}
          appearance={appearance}
        />
        <TabButton
          label="Security"
          isActive={activeTab === 'security'}
          onClick={() => setActiveTab('security')}
          appearance={appearance}
        />
        <TabButton
          label="Danger Zone"
          isActive={activeTab === 'danger'}
          onClick={() => setActiveTab('danger')}
          appearance={appearance}
          isDanger
        />
      </div>

      {/* Messages */}
      {displayError && (
        <div style={applyAppearance(styles.error, appearance)} role="alert">
          {displayError}
        </div>
      )}
      {successMessage && (
        <div style={applyAppearance(styles.success, appearance)} role="status">
          {successMessage}
        </div>
      )}

      {/* Profile Tab */}
      {activeTab === 'profile' && (
        <div style={styles.section}>
          <div style={styles.sectionHeader}>
            <h2 style={styles.sectionTitle}>Personal Information</h2>
            {!isEditing && (
              <button
                onClick={() => setIsEditing(true)}
                style={applyAppearance(styles.editButton, appearance)}
              >
                Edit
              </button>
            )}
          </div>

          <div style={styles.fieldGroup}>
            <div style={styles.field}>
              <label style={applyAppearance(styles.label, appearance)}>Email</label>
              <input
                type="email"
                value={user.email}
                disabled
                style={{ ...applyAppearance(styles.input, appearance), backgroundColor: '#f3f4f6' }}
              />
              {user.emailVerified ? (
                <span style={styles.verifiedBadge}>✓ Verified</span>
              ) : (
                <span style={styles.unverifiedBadge}>Unverified</span>
              )}
            </div>

            <div style={styles.field}>
              <label style={applyAppearance(styles.label, appearance)}>Full Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => handleInputChange('name', e.target.value)}
                disabled={!isEditing || isLoading}
                style={applyAppearance(styles.input, appearance)}
                placeholder="Your full name"
              />
            </div>

            <div style={styles.row}>
              <div style={{ ...styles.field, flex: 1 }}>
                <label style={applyAppearance(styles.label, appearance)}>First Name</label>
                <input
                  type="text"
                  value={formData.givenName}
                  onChange={(e) => handleInputChange('givenName', e.target.value)}
                  disabled={!isEditing || isLoading}
                  style={applyAppearance(styles.input, appearance)}
                  placeholder="First"
                />
              </div>
              <div style={{ ...styles.field, flex: 1 }}>
                <label style={applyAppearance(styles.label, appearance)}>Last Name</label>
                <input
                  type="text"
                  value={formData.familyName}
                  onChange={(e) => handleInputChange('familyName', e.target.value)}
                  disabled={!isEditing || isLoading}
                  style={applyAppearance(styles.input, appearance)}
                  placeholder="Last"
                />
              </div>
            </div>

            <div style={styles.field}>
              <label style={applyAppearance(styles.label, appearance)}>Phone Number</label>
              <input
                type="tel"
                value={formData.phoneNumber}
                onChange={(e) => handleInputChange('phoneNumber', e.target.value)}
                disabled={!isEditing || isLoading}
                style={applyAppearance(styles.input, appearance)}
                placeholder="+1 (555) 123-4567"
              />
            </div>
          </div>

          {isEditing && (
            <div style={styles.buttonGroup}>
              <button
                onClick={handleSaveProfile}
                disabled={isLoading}
                style={applyAppearance(styles.primaryButton, appearance)}
              >
                {isLoading ? 'Saving...' : 'Save Changes'}
              </button>
              <button
                onClick={() => {
                  setIsEditing(false);
                  setFormData({
                    name: user.profile?.name || '',
                    givenName: user.profile?.givenName || '',
                    familyName: user.profile?.familyName || '',
                    phoneNumber: user.profile?.phoneNumber || '',
                  });
                }}
                disabled={isLoading}
                style={applyAppearance(styles.secondaryButton, appearance)}
              >
                Cancel
              </button>
            </div>
          )}
        </div>
      )}

      {/* Security Tab */}
      {activeTab === 'security' && (
        <div style={styles.section}>
          <h2 style={styles.sectionTitle}>Change Password</h2>
          
          <div style={styles.fieldGroup}>
            <div style={styles.field}>
              <label style={applyAppearance(styles.label, appearance)}>Current Password</label>
              <input
                type="password"
                value={passwordData.currentPassword}
                onChange={(e) => setPasswordData(prev => ({ ...prev, currentPassword: e.target.value }))}
                style={applyAppearance(styles.input, appearance)}
                placeholder="Enter current password"
              />
            </div>

            <div style={styles.field}>
              <label style={applyAppearance(styles.label, appearance)}>New Password</label>
              <input
                type="password"
                value={passwordData.newPassword}
                onChange={(e) => setPasswordData(prev => ({ ...prev, newPassword: e.target.value }))}
                style={applyAppearance(styles.input, appearance)}
                placeholder="Min 12 characters"
              />
            </div>

            <div style={styles.field}>
              <label style={applyAppearance(styles.label, appearance)}>Confirm New Password</label>
              <input
                type="password"
                value={passwordData.confirmPassword}
                onChange={(e) => setPasswordData(prev => ({ ...prev, confirmPassword: e.target.value }))}
                style={applyAppearance(styles.input, appearance)}
                placeholder="Re-enter new password"
              />
            </div>
          </div>

          <button
            onClick={handleChangePassword}
            disabled={isLoading || !passwordData.currentPassword || !passwordData.newPassword}
            style={applyAppearance(styles.primaryButton, appearance)}
          >
            {isLoading ? 'Changing...' : 'Change Password'}
          </button>

          <div style={styles.infoBox}>
            <h3 style={styles.infoTitle}>Account Information</h3>
            <div style={styles.infoRow}>
              <span style={styles.infoLabel}>Account ID:</span>
              <code style={styles.code}>{user.id}</code>
            </div>
            <div style={styles.infoRow}>
              <span style={styles.infoLabel}>Created:</span>
              <span>{new Date(user.createdAt).toLocaleDateString()}</span>
            </div>
            <div style={styles.infoRow}>
              <span style={styles.infoLabel}>Last Login:</span>
              <span>{user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleDateString() : 'Never'}</span>
            </div>
          </div>
        </div>
      )}

      {/* Danger Zone Tab */}
      {activeTab === 'danger' && (
        <div style={styles.section}>
          <h2 style={{ ...styles.sectionTitle, color: '#dc2626' }}>Danger Zone</h2>
          
          <div style={styles.dangerBox}>
            <h3 style={styles.dangerTitle}>Delete Account</h3>
            <p style={styles.dangerText}>
              Once you delete your account, there is no going back. Please be certain.
            </p>
            <button
              onClick={handleDeleteAccount}
              disabled={isLoading}
              style={applyAppearance(styles.dangerButton, appearance)}
            >
              Delete Account
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// Tab Button Component
function TabButton({
  label,
  isActive,
  onClick,
  appearance,
  isDanger,
}: {
  label: string;
  isActive: boolean;
  onClick: () => void;
  appearance?: { theme?: string; variables?: Record<string, string> };
  isDanger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        ...styles.tabButton,
        ...(isActive && styles.tabButtonActive),
        ...(isActive && appearance?.variables?.['colorPrimary'] && {
          borderBottomColor: appearance.variables['colorPrimary'],
          color: appearance.variables['colorPrimary'],
        }),
        ...(isDanger && { color: isActive ? '#dc2626' : '#6b7280' }),
        ...(isDanger && isActive && { borderBottomColor: '#dc2626' }),
      }}
    >
      {label}
    </button>
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
    maxWidth: '600px',
    margin: '0 auto',
    padding: '24px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  loading: {
    textAlign: 'center',
    padding: '48px',
    color: '#6b7280',
  },
  heading: {
    fontSize: '28px',
    fontWeight: 600,
    margin: '0 0 24px',
    color: '#1f2937',
  },
  tabs: {
    display: 'flex',
    borderBottom: '1px solid #e5e7eb',
    marginBottom: '24px',
  },
  tabButton: {
    padding: '12px 16px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#6b7280',
    background: 'transparent',
    border: 'none',
    borderBottom: '2px solid transparent',
    cursor: 'pointer',
    transition: 'all 0.15s ease-in-out',
  },
  tabButtonActive: {
    color: '#0066cc',
    borderBottomColor: '#0066cc',
  },
  error: {
    padding: '12px 16px',
    marginBottom: '16px',
    color: '#dc2626',
    backgroundColor: '#fee2e2',
    borderRadius: '6px',
    fontSize: '14px',
  },
  success: {
    padding: '12px 16px',
    marginBottom: '16px',
    color: '#059669',
    backgroundColor: '#d1fae5',
    borderRadius: '6px',
    fontSize: '14px',
  },
  section: {
    backgroundColor: '#fff',
    border: '1px solid #e5e7eb',
    borderRadius: '8px',
    padding: '24px',
  },
  sectionHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '20px',
  },
  sectionTitle: {
    fontSize: '18px',
    fontWeight: 600,
    margin: 0,
    color: '#1f2937',
  },
  editButton: {
    padding: '6px 12px',
    fontSize: '14px',
    color: '#0066cc',
    backgroundColor: 'transparent',
    border: '1px solid #0066cc',
    borderRadius: '6px',
    cursor: 'pointer',
  },
  fieldGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
    marginBottom: '24px',
  },
  field: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
  },
  row: {
    display: 'flex',
    gap: '16px',
  },
  label: {
    fontSize: '14px',
    fontWeight: 500,
    color: '#374151',
  },
  input: {
    padding: '10px 12px',
    fontSize: '15px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    outline: 'none',
    transition: 'border-color 0.15s ease-in-out',
  },
  verifiedBadge: {
    fontSize: '12px',
    color: '#059669',
    marginTop: '4px',
  },
  unverifiedBadge: {
    fontSize: '12px',
    color: '#d97706',
    marginTop: '4px',
  },
  buttonGroup: {
    display: 'flex',
    gap: '12px',
  },
  primaryButton: {
    padding: '10px 20px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#fff',
    backgroundColor: '#0066cc',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  secondaryButton: {
    padding: '10px 20px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#374151',
    backgroundColor: '#f3f4f6',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  infoBox: {
    marginTop: '24px',
    padding: '16px',
    backgroundColor: '#f9fafb',
    borderRadius: '6px',
  },
  infoTitle: {
    fontSize: '14px',
    fontWeight: 600,
    margin: '0 0 12px',
    color: '#374151',
  },
  infoRow: {
    display: 'flex',
    gap: '8px',
    marginBottom: '8px',
    fontSize: '14px',
  },
  infoLabel: {
    color: '#6b7280',
    minWidth: '100px',
  },
  code: {
    fontFamily: 'monospace',
    fontSize: '12px',
    color: '#6b7280',
  },
  dangerBox: {
    padding: '16px',
    border: '1px solid #fecaca',
    borderRadius: '6px',
    backgroundColor: '#fef2f2',
  },
  dangerTitle: {
    fontSize: '16px',
    fontWeight: 600,
    margin: '0 0 8px',
    color: '#dc2626',
  },
  dangerText: {
    fontSize: '14px',
    color: '#7f1d1d',
    margin: '0 0 16px',
  },
  dangerButton: {
    padding: '10px 20px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#fff',
    backgroundColor: '#dc2626',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
};
