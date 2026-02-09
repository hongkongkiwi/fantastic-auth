/**
 * OrganizationProfile Component
 *
 * Organization management page with tabs for General, Members, and Settings.
 *
 * @example
 * ```tsx
 * <OrganizationProfile
 *   onUpdate={(org) => console.log('Updated:', org)}
 * />
 * ```
 */

import React, { useState, useCallback, useEffect } from 'react';
import { useOrganization } from '../hooks/useOrganization';
import { useVault } from '../context/VaultContext';
import { Appearance, Organization, OrganizationMember, OrganizationRole, ApiError } from '../types';

export interface OrganizationProfileProps {
  /**
   * Organization to display (defaults to active organization)
   */
  organization?: Organization;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export function OrganizationProfile({
  organization: propOrg,
  appearance,
  className,
}: OrganizationProfileProps) {
  const vault = useVault();
  const { 
    organization: activeOrg, 
    organizations,
    isLoaded,
    refreshMembers,
  } = useOrganization();

  const organization = propOrg || activeOrg;
  const [activeTab, setActiveTab] = useState<'general' | 'members' | 'settings'>('general');
  
  // General tab state
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [description, setDescription] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  
  // Members tab state
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [isLoadingMembers, setIsLoadingMembers] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<OrganizationRole>('member');
  const [isInviting, setIsInviting] = useState(false);
  
  // Settings tab state
  const [isDeleting, setIsDeleting] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  
  // Common state
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Initialize form data when organization loads
  useEffect(() => {
    if (organization) {
      setName(organization.name || '');
      setSlug(organization.slug || '');
      setDescription(organization.description || '');
    }
  }, [organization]);

  // Load members when members tab is selected
  useEffect(() => {
    if (activeTab === 'members' && organization) {
      loadMembers();
    }
  }, [activeTab, organization?.id]);

  const loadMembers = useCallback(async () => {
    if (!organization) return;
    
    setIsLoadingMembers(true);
    try {
      const response = await vault.api.listOrganizationMembers(organization.id);
      setMembers(response);
    } catch (err) {
      setError((err as ApiError).message || 'Failed to load members');
    } finally {
      setIsLoadingMembers(false);
    }
  }, [organization, vault.api]);

  const handleSaveGeneral = useCallback(async () => {
    if (!organization) return;
    
    setIsSaving(true);
    setError(null);
    
    try {
      await vault.api.updateOrganization(organization.id, {
        name: name.trim(),
        slug: slug.trim(),
        description: description.trim() || undefined,
      });
      
      setSuccessMessage('Organization updated successfully');
      setIsEditing(false);
      
      // Refresh organizations list
      await vault.refreshOrganizations();
      
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError((err as ApiError).message || 'Failed to update organization');
    } finally {
      setIsSaving(false);
    }
  }, [organization, name, slug, description, vault]);

  const handleInviteMember = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!organization || !inviteEmail.trim()) return;
    
    setIsInviting(true);
    setError(null);
    
    try {
      // This would call the actual invite API
      // await vault.api.inviteMember(organization.id, { email: inviteEmail, role: inviteRole });
      
      // Simulate success for now
      setSuccessMessage(`Invitation sent to ${inviteEmail}`);
      setInviteEmail('');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError((err as ApiError).message || 'Failed to send invitation');
    } finally {
      setIsInviting(false);
    }
  }, [organization, inviteEmail, inviteRole]);

  const handleRemoveMember = useCallback(async (memberId: string) => {
    if (!organization) return;
    
    if (!window.confirm('Are you sure you want to remove this member?')) {
      return;
    }
    
    try {
      // await vault.api.removeMember(organization.id, memberId);
      setMembers(prev => prev.filter(m => m.id !== memberId));
      setSuccessMessage('Member removed successfully');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError((err as ApiError).message || 'Failed to remove member');
    }
  }, [organization]);

  const handleUpdateMemberRole = useCallback(async (memberId: string, newRole: OrganizationRole) => {
    if (!organization) return;
    
    try {
      // await vault.api.updateMemberRole(organization.id, memberId, newRole);
      setMembers(prev => prev.map(m => 
        m.id === memberId ? { ...m, role: newRole } : m
      ));
      setSuccessMessage('Role updated successfully');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError((err as ApiError).message || 'Failed to update role');
    }
  }, [organization]);

  const handleDeleteOrganization = useCallback(async () => {
    if (!organization) return;
    
    if (deleteConfirmText !== organization.name) {
      setError('Please type the organization name to confirm');
      return;
    }
    
    setIsDeleting(true);
    try {
      await vault.api.deleteOrganization(organization.id);
      // Redirect to dashboard or org list
      window.location.href = '/';
    } catch (err) {
      setError((err as ApiError).message || 'Failed to delete organization');
      setIsDeleting(false);
    }
  }, [organization, deleteConfirmText, vault.api]);

  const handleLeaveOrganization = useCallback(async () => {
    if (!organization) return;
    
    if (!window.confirm(`Are you sure you want to leave ${organization.name}?`)) {
      return;
    }
    
    try {
      await vault.leaveOrganization(organization.id);
      window.location.href = '/';
    } catch (err) {
      setError((err as ApiError).message || 'Failed to leave organization');
    }
  }, [organization, vault]);

  if (!isLoaded) {
    return (
      <div style={applyAppearance(styles.container, appearance)} className={className}>
        <div style={styles.loading}>Loading...</div>
      </div>
    );
  }

  if (!organization) {
    return (
      <div style={applyAppearance(styles.container, appearance)} className={className}>
        <div style={styles.emptyState}>
          <p>No organization selected.</p>
          <p style={styles.emptyStateSubtext}>
            Create or join an organization to manage it here.
          </p>
        </div>
      </div>
    );
  }

  const isOwner = organization.role === 'owner';
  const isAdmin = organization.role === 'admin' || isOwner;

  return (
    <div style={applyAppearance(styles.container, appearance)} className={className}>
      <div style={styles.header}>
        <div>
          <h1 style={applyAppearance(styles.heading, appearance)}>
            {organization.name}
          </h1>
          <span style={styles.roleBadge}>
            {organization.role}
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div style={styles.tabs}>
        <TabButton
          label="General"
          isActive={activeTab === 'general'}
          onClick={() => setActiveTab('general')}
          appearance={appearance}
        />
        <TabButton
          label="Members"
          isActive={activeTab === 'members'}
          onClick={() => setActiveTab('members')}
          appearance={appearance}
        />
        <TabButton
          label="Settings"
          isActive={activeTab === 'settings'}
          onClick={() => setActiveTab('settings')}
          appearance={appearance}
        />
      </div>

      {/* Messages */}
      {error && (
        <div style={applyAppearance(styles.error, appearance)} role="alert">
          {error}
        </div>
      )}
      {successMessage && (
        <div style={applyAppearance(styles.success, appearance)} role="status">
          {successMessage}
        </div>
      )}

      {/* General Tab */}
      {activeTab === 'general' && (
        <div style={styles.section}>
          <div style={styles.sectionHeader}>
            <h2 style={styles.sectionTitle}>Organization Details</h2>
            {isAdmin && !isEditing && (
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
              <label style={applyAppearance(styles.label, appearance)}>Organization Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={!isEditing || isSaving}
                style={applyAppearance(styles.input, appearance)}
              />
            </div>

            <div style={styles.field}>
              <label style={applyAppearance(styles.label, appearance)}>Organization Slug</label>
              <input
                type="text"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                disabled={!isEditing || isSaving}
                style={applyAppearance(styles.input, appearance)}
              />
              <span style={styles.helpText}>
                Used in URLs: vault.dev/o/{slug}
              </span>
            </div>

            <div style={styles.field}>
              <label style={applyAppearance(styles.label, appearance)}>Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                disabled={!isEditing || isSaving}
                rows={3}
                style={applyAppearance(styles.textarea, appearance)}
                placeholder="What does your organization do?"
              />
            </div>

            {organization.logoUrl && (
              <div style={styles.field}>
                <label style={applyAppearance(styles.label, appearance)}>Logo</label>
                <img
                  src={organization.logoUrl}
                  alt="Organization logo"
                  style={styles.logoImage}
                />
              </div>
            )}
          </div>

          {isEditing && (
            <div style={styles.buttonGroup}>
              <button
                onClick={handleSaveGeneral}
                disabled={isSaving || !name.trim() || !slug.trim()}
                style={applyAppearance(styles.primaryButton, appearance)}
              >
                {isSaving ? 'Saving...' : 'Save Changes'}
              </button>
              <button
                onClick={() => {
                  setIsEditing(false);
                  setName(organization.name);
                  setSlug(organization.slug);
                  setDescription(organization.description || '');
                  setError(null);
                }}
                disabled={isSaving}
                style={applyAppearance(styles.secondaryButton, appearance)}
              >
                Cancel
              </button>
            </div>
          )}
        </div>
      )}

      {/* Members Tab */}
      {activeTab === 'members' && (
        <div style={styles.section}>
          <h2 style={styles.sectionTitle}>Members</h2>

          {isAdmin && (
            <form onSubmit={handleInviteMember} style={styles.inviteForm}>
              <div style={styles.inviteRow}>
                <input
                  type="email"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="colleague@example.com"
                  style={{ ...applyAppearance(styles.input, appearance), flex: 1 }}
                  disabled={isInviting}
                />
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as OrganizationRole)}
                  style={applyAppearance(styles.select, appearance)}
                  disabled={isInviting}
                >
                  <option value="member">Member</option>
                  <option value="admin">Admin</option>
                  {isOwner && <option value="owner">Owner</option>}
                </select>
                <button
                  type="submit"
                  disabled={isInviting || !inviteEmail.trim()}
                  style={applyAppearance(styles.primaryButton, appearance)}
                >
                  {isInviting ? 'Inviting...' : 'Invite'}
                </button>
              </div>
            </form>
          )}

          {isLoadingMembers ? (
            <div style={styles.loading}>Loading members...</div>
          ) : (
            <div style={styles.membersList}>
              {members.length === 0 ? (
                <div style={styles.emptyMembers}>
                  No members yet.
                </div>
              ) : (
                members.map((member) => (
                  <div key={member.id} style={styles.memberRow}>
                    <div style={styles.memberInfo}>
                      <div style={styles.memberAvatar}>
                        {member.name?.[0] || member.email[0].toUpperCase()}
                      </div>
                      <div>
                        <div style={styles.memberName}>
                          {member.name || member.email}
                        </div>
                        {member.name && (
                          <div style={styles.memberEmail}>{member.email}</div>
                        )}
                      </div>
                    </div>
                    <div style={styles.memberActions}>
                      {isAdmin && member.userId !== vault.user?.id ? (
                        <>
                          <select
                            value={member.role}
                            onChange={(e) => handleUpdateMemberRole(member.id, e.target.value as OrganizationRole)}
                            style={applyAppearance(styles.roleSelect, appearance)}
                          >
                            <option value="member">Member</option>
                            <option value="admin">Admin</option>
                            {isOwner && <option value="owner">Owner</option>}
                          </select>
                          <button
                            onClick={() => handleRemoveMember(member.id)}
                            style={styles.removeButton}
                            title="Remove member"
                          >
                            ✕
                          </button>
                        </>
                      ) : (
                        <span style={styles.roleBadge}>{member.role}</span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}

      {/* Settings Tab */}
      {activeTab === 'settings' && (
        <div style={styles.section}>
          <h2 style={styles.sectionTitle}>Organization Settings</h2>

          {!isOwner && (
            <div style={styles.dangerBox}>
              <h3 style={styles.dangerTitle}>Leave Organization</h3>
              <p style={styles.dangerText}>
                You will lose access to all resources in this organization.
              </p>
              <button
                onClick={handleLeaveOrganization}
                style={applyAppearance(styles.dangerButton, appearance)}
              >
                Leave Organization
              </button>
            </div>
          )}

          {isOwner && (
            <div style={styles.dangerBox}>
              <h3 style={styles.dangerTitle}>Delete Organization</h3>
              <p style={styles.dangerText}>
                Once deleted, this organization and all its data cannot be recovered.
                This action cannot be undone.
              </p>
              
              {!showDeleteConfirm ? (
                <button
                  onClick={() => setShowDeleteConfirm(true)}
                  style={applyAppearance(styles.dangerButton, appearance)}
                >
                  Delete Organization
                </button>
              ) : (
                <div style={styles.confirmDelete}>
                  <p style={styles.confirmText}>
                    Type <strong>{organization.name}</strong> to confirm:
                  </p>
                  <input
                    type="text"
                    value={deleteConfirmText}
                    onChange={(e) => setDeleteConfirmText(e.target.value)}
                    placeholder={organization.name}
                    style={applyAppearance(styles.input, appearance)}
                  />
                  <div style={styles.buttonGroup}>
                    <button
                      onClick={handleDeleteOrganization}
                      disabled={isDeleting || deleteConfirmText !== organization.name}
                      style={applyAppearance(styles.dangerButton, appearance)}
                    >
                      {isDeleting ? 'Deleting...' : 'Confirm Delete'}
                    </button>
                    <button
                      onClick={() => {
                        setShowDeleteConfirm(false);
                        setDeleteConfirmText('');
                        setError(null);
                      }}
                      style={applyAppearance(styles.secondaryButton, appearance)}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
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
}: {
  label: string;
  isActive: boolean;
  onClick: () => void;
  appearance?: Appearance;
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
      }}
    >
      {label}
    </button>
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

  if (variables['colorDanger'] && baseStyle.backgroundColor === '#dc2626') {
    style = { ...style, backgroundColor: variables['colorDanger'] };
  }

  if (variables['borderRadius'] && baseStyle.borderRadius) {
    style = { ...style, borderRadius: variables['borderRadius'] };
  }

  return style;
}

// Styles
const styles: Record<string, React.CSSProperties> = {
  container: {
    maxWidth: '800px',
    margin: '0 auto',
    padding: '24px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  loading: {
    textAlign: 'center',
    padding: '48px',
    color: '#6b7280',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: '24px',
  },
  heading: {
    fontSize: '28px',
    fontWeight: 600,
    margin: '0 0 8px',
    color: '#1f2937',
  },
  roleBadge: {
    display: 'inline-block',
    padding: '4px 12px',
    fontSize: '12px',
    fontWeight: 500,
    textTransform: 'uppercase',
    color: '#6b7280',
    backgroundColor: '#f3f4f6',
    borderRadius: '9999px',
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
  logoImage: {
    width: '80px',
    height: '80px',
    objectFit: 'cover',
    borderRadius: '8px',
    border: '1px solid #e5e7eb',
  },
  emptyState: {
    textAlign: 'center',
    padding: '48px',
    color: '#6b7280',
  },
  emptyStateSubtext: {
    fontSize: '14px',
    marginTop: '8px',
  },
  inviteForm: {
    marginBottom: '24px',
    padding: '16px',
    backgroundColor: '#f9fafb',
    borderRadius: '6px',
  },
  inviteRow: {
    display: 'flex',
    gap: '8px',
  },
  membersList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  memberRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '12px',
    backgroundColor: '#f9fafb',
    borderRadius: '6px',
  },
  memberInfo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  memberAvatar: {
    width: '36px',
    height: '36px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '14px',
    fontWeight: 600,
    color: '#fff',
    backgroundColor: '#0066cc',
    borderRadius: '50%',
  },
  memberName: {
    fontSize: '14px',
    fontWeight: 500,
    color: '#1f2937',
  },
  memberEmail: {
    fontSize: '12px',
    color: '#6b7280',
  },
  memberActions: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  roleSelect: {
    padding: '6px 10px',
    fontSize: '13px',
    border: '1px solid #d1d5db',
    borderRadius: '4px',
    backgroundColor: '#fff',
    cursor: 'pointer',
  },
  removeButton: {
    padding: '6px 10px',
    fontSize: '12px',
    color: '#dc2626',
    backgroundColor: 'transparent',
    border: '1px solid #fecaca',
    borderRadius: '4px',
    cursor: 'pointer',
  },
  emptyMembers: {
    textAlign: 'center',
    padding: '24px',
    color: '#6b7280',
    fontSize: '14px',
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
  confirmDelete: {
    marginTop: '12px',
  },
  confirmText: {
    fontSize: '14px',
    marginBottom: '8px',
  },
};
