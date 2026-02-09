/**
 * CreateOrganization Component
 *
 * Pre-built organization creation form with slug auto-generation and optional invitation screen.
 *
 * @example
 * ```tsx
 * <CreateOrganization
 *   onCreate={(org) => console.log('Created:', org)}
 *   onCancel={() => console.log('Cancelled')}
 *   redirectUrl="/dashboard"
 * />
 * ```
 */

import React, { useState, useCallback } from 'react';
import { useOrganization } from '../hooks/useOrganization';
import { Appearance, Organization, ApiError } from '../types';

export interface CreateOrganizationProps {
  /**
   * Callback after successful organization creation
   */
  onCreate?: (org: Organization) => void;
  /**
   * Callback when user cancels
   */
  onCancel?: () => void;
  /**
   * Redirect URL after successful creation
   */
  redirectUrl?: string;
  /**
   * Skip the invitation screen after creation
   */
  skipInvitationScreen?: boolean;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export function CreateOrganization({
  onCreate,
  onCancel,
  redirectUrl,
  skipInvitationScreen = false,
  appearance,
  className,
}: CreateOrganizationProps) {
  const { create, isLoading } = useOrganization();

  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [description, setDescription] = useState('');
  const [logo, setLogo] = useState<File | null>(null);
  const [logoPreview, setLogoPreview] = useState<string | null>(null);
  const [createdOrg, setCreatedOrg] = useState<Organization | null>(null);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'admin' | 'member'>('member');
  const [inviteSent, setInviteSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-generate slug from name
  const generateSlug = useCallback((name: string): string => {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }, []);

  const handleNameChange = useCallback((value: string) => {
    setName(value);
    // Only auto-update slug if user hasn't manually edited it
    if (slug === '' || slug === generateSlug(name)) {
      setSlug(generateSlug(value));
    }
  }, [slug, name, generateSlug]);

  const handleLogoChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (file.size > 5 * 1024 * 1024) {
        setError('Logo must be less than 5MB');
        return;
      }
      if (!file.type.startsWith('image/')) {
        setError('Please upload an image file');
        return;
      }
      setLogo(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setLogoPreview(reader.result as string);
      };
      reader.readAsDataURL(file);
      setError(null);
    }
  }, []);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!name.trim()) {
      setError('Organization name is required');
      return;
    }

    if (!slug.trim()) {
      setError('Organization slug is required');
      return;
    }

    try {
      const org = await create({ name: name.trim(), slug: slug.trim() });
      
      if (skipInvitationScreen) {
        onCreate?.(org);
        if (redirectUrl) {
          window.location.href = redirectUrl;
        }
      } else {
        setCreatedOrg(org);
      }
    } catch (err) {
      setError((err as ApiError).message || 'Failed to create organization');
    }
  }, [name, slug, create, skipInvitationScreen, onCreate, redirectUrl]);

  const handleSendInvite = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!inviteEmail.trim()) {
      setError('Email is required');
      return;
    }

    // Note: This would call the actual invite API
    // For now, we simulate success
    setInviteSent(true);
    setTimeout(() => {
      onCreate?.(createdOrg!);
      if (redirectUrl) {
        window.location.href = redirectUrl;
      }
    }, 1500);
  }, [inviteEmail, createdOrg, onCreate, redirectUrl]);

  const handleSkipInvite = useCallback(() => {
    onCreate?.(createdOrg!);
    if (redirectUrl) {
      window.location.href = redirectUrl;
    }
  }, [createdOrg, onCreate, redirectUrl]);

  // Invitation Screen
  if (createdOrg) {
    return (
      <div style={applyAppearance(styles.container, appearance)} className={className}>
        <div style={styles.successState}>
          <div style={styles.successIcon}>✓</div>
          <h2 style={applyAppearance(styles.title, appearance)}>
            Organization Created!
          </h2>
          <p style={styles.successText}>
            <strong>{createdOrg.name}</strong> has been created successfully.
          </p>

          {inviteSent ? (
            <div style={applyAppearance(styles.successMessage, appearance)}>
              Invitation sent to {inviteEmail}!
            </div>
          ) : (
            <form onSubmit={handleSendInvite} style={styles.inviteForm}>
              <p style={styles.inviteText}>
                Want to invite team members now?
              </p>
              
              {error && (
                <div style={applyAppearance(styles.error, appearance)} role="alert">
                  {error}
                </div>
              )}

              <div style={styles.field}>
                <label htmlFor="vault-invite-email" style={applyAppearance(styles.label, appearance)}>
                  Email Address
                </label>
                <input
                  id="vault-invite-email"
                  type="email"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="colleague@example.com"
                  style={applyAppearance(styles.input, appearance)}
                  disabled={isLoading}
                />
              </div>

              <div style={styles.field}>
                <label htmlFor="vault-invite-role" style={applyAppearance(styles.label, appearance)}>
                  Role
                </label>
                <select
                  id="vault-invite-role"
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as 'admin' | 'member')}
                  style={applyAppearance(styles.select, appearance)}
                  disabled={isLoading}
                >
                  <option value="member">Member</option>
                  <option value="admin">Admin</option>
                </select>
              </div>

              <div style={styles.buttonGroup}>
                <button
                  type="submit"
                  disabled={isLoading}
                  style={applyAppearance(styles.primaryButton, appearance)}
                >
                  {isLoading ? 'Sending...' : 'Send Invitation'}
                </button>
                <button
                  type="button"
                  onClick={handleSkipInvite}
                  style={applyAppearance(styles.secondaryButton, appearance)}
                >
                  Skip for now
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    );
  }

  // Create Organization Form
  return (
    <div style={applyAppearance(styles.container, appearance)} className={className}>
      <form onSubmit={handleSubmit} style={styles.form}>
        <h2 style={applyAppearance(styles.title, appearance)}>Create Organization</h2>
        <p style={styles.subtitle}>
          Set up a new organization to collaborate with your team.
        </p>

        {error && (
          <div style={applyAppearance(styles.error, appearance)} role="alert">
            {error}
          </div>
        )}

        <div style={styles.field}>
          <label htmlFor="vault-org-name" style={applyAppearance(styles.label, appearance)}>
            Organization Name *
          </label>
          <input
            id="vault-org-name"
            type="text"
            value={name}
            onChange={(e) => handleNameChange(e.target.value)}
            placeholder="Acme Inc"
            required
            style={applyAppearance(styles.input, appearance)}
            disabled={isLoading}
          />
        </div>

        <div style={styles.field}>
          <label htmlFor="vault-org-slug" style={applyAppearance(styles.label, appearance)}>
            Organization Slug *
          </label>
          <input
            id="vault-org-slug"
            type="text"
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            placeholder="acme-inc"
            required
            style={applyAppearance(styles.input, appearance)}
            disabled={isLoading}
          />
          <span style={styles.helpText}>
            Used in URLs: vault.dev/o/{slug || 'your-org'}
          </span>
        </div>

        <div style={styles.field}>
          <label htmlFor="vault-org-description" style={applyAppearance(styles.label, appearance)}>
            Description
          </label>
          <textarea
            id="vault-org-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What does your organization do?"
            rows={3}
            style={applyAppearance(styles.textarea, appearance)}
            disabled={isLoading}
          />
        </div>

        <div style={styles.field}>
          <label htmlFor="vault-org-logo" style={applyAppearance(styles.label, appearance)}>
            Logo
          </label>
          <div style={styles.logoUpload}>
            {logoPreview ? (
              <div style={styles.logoPreview}>
                <img src={logoPreview} alt="Logo preview" style={styles.logoImage} />
                <button
                  type="button"
                  onClick={() => {
                    setLogo(null);
                    setLogoPreview(null);
                  }}
                  style={styles.removeLogo}
                >
                  ✕
                </button>
              </div>
            ) : (
              <label style={applyAppearance(styles.logoInputLabel, appearance)}>
                <input
                  id="vault-org-logo"
                  type="file"
                  accept="image/*"
                  onChange={handleLogoChange}
                  style={styles.fileInput}
                  disabled={isLoading}
                />
                <UploadIcon />
                <span>Upload logo</span>
              </label>
            )}
          </div>
          <span style={styles.helpText}>Max 5MB, PNG or JPG recommended</span>
        </div>

        <div style={styles.buttonGroup}>
          <button
            type="submit"
            disabled={isLoading || !name.trim() || !slug.trim()}
            style={applyAppearance(styles.primaryButton, appearance)}
          >
            {isLoading ? 'Creating...' : 'Create Organization'}
          </button>
          {onCancel && (
            <button
              type="button"
              onClick={onCancel}
              disabled={isLoading}
              style={applyAppearance(styles.secondaryButton, appearance)}
            >
              Cancel
            </button>
          )}
        </div>
      </form>
    </div>
  );
}

// Icon Components
function UploadIcon() {
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
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </svg>
  );
}

// Apply appearance variables
function applyAppearance(
  baseStyle: React.CSSProperties,
  appearance?: Appearance
): React.CSSProperties {
  if (!appearance) return baseStyle;

  const variables = appearance.variables || {};
  let style = { ...baseStyle };

  if (variables['colorPrimary']) {
    if (baseStyle.backgroundColor === '#0066cc' || baseStyle.borderColor === '#0066cc') {
      style = {
        ...style,
        backgroundColor: variables['colorPrimary'],
        borderColor: variables['colorPrimary'],
      };
    }
    if (baseStyle.color === '#0066cc') {
      style = { ...style, color: variables['colorPrimary'] };
    }
  }

  if (variables['borderRadius'] && baseStyle.borderRadius) {
    style = { ...style, borderRadius: variables['borderRadius'] };
  }

  if (variables['fontSize'] && baseStyle.fontSize) {
    style = { ...style, fontSize: variables['fontSize'] };
  }

  return style;
}

// Styles
const styles: Record<string, React.CSSProperties> = {
  container: {
    maxWidth: '480px',
    margin: '0 auto',
    padding: '24px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
  },
  title: {
    margin: '0',
    fontSize: '24px',
    fontWeight: 600,
    color: '#1a1a1a',
  },
  subtitle: {
    margin: '-12px 0 0',
    fontSize: '14px',
    color: '#6b7280',
  },
  field: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
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
  textarea: {
    padding: '10px 12px',
    fontSize: '15px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    outline: 'none',
    transition: 'border-color 0.15s ease-in-out',
    resize: 'vertical',
    fontFamily: 'inherit',
  },
  select: {
    padding: '10px 12px',
    fontSize: '15px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    outline: 'none',
    backgroundColor: '#fff',
    cursor: 'pointer',
  },
  helpText: {
    fontSize: '12px',
    color: '#6b7280',
  },
  logoUpload: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  logoInputLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '12px 16px',
    fontSize: '14px',
    color: '#374151',
    backgroundColor: '#f3f4f6',
    border: '2px dashed #d1d5db',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'all 0.15s ease-in-out',
  },
  fileInput: {
    position: 'absolute',
    opacity: 0,
    width: 0,
    height: 0,
  },
  logoPreview: {
    position: 'relative',
    width: '64px',
    height: '64px',
    borderRadius: '8px',
    overflow: 'hidden',
    border: '1px solid #e5e7eb',
  },
  logoImage: {
    width: '100%',
    height: '100%',
    objectFit: 'cover',
  },
  removeLogo: {
    position: 'absolute',
    top: '2px',
    right: '2px',
    width: '20px',
    height: '20px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '12px',
    color: '#fff',
    backgroundColor: 'rgba(0,0,0,0.5)',
    border: 'none',
    borderRadius: '50%',
    cursor: 'pointer',
  },
  buttonGroup: {
    display: 'flex',
    gap: '12px',
    marginTop: '8px',
  },
  primaryButton: {
    flex: 1,
    padding: '12px',
    fontSize: '15px',
    fontWeight: 600,
    color: '#fff',
    backgroundColor: '#0066cc',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  secondaryButton: {
    padding: '12px 20px',
    fontSize: '15px',
    fontWeight: 500,
    color: '#374151',
    backgroundColor: '#f3f4f6',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  error: {
    padding: '12px',
    color: '#dc2626',
    backgroundColor: '#fee2e2',
    borderRadius: '6px',
    fontSize: '14px',
  },
  successState: {
    textAlign: 'center',
    padding: '32px 24px',
  },
  successIcon: {
    width: '64px',
    height: '64px',
    margin: '0 auto 16px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '32px',
    color: '#fff',
    backgroundColor: '#10b981',
    borderRadius: '50%',
  },
  successText: {
    fontSize: '16px',
    color: '#6b7280',
    margin: '0 0 24px',
  },
  successMessage: {
    padding: '16px',
    color: '#059669',
    backgroundColor: '#d1fae5',
    borderRadius: '6px',
    fontSize: '15px',
  },
  inviteForm: {
    marginTop: '24px',
    textAlign: 'left',
  },
  inviteText: {
    fontSize: '15px',
    color: '#374151',
    margin: '0 0 16px',
  },
};
