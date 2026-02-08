/**
 * OrganizationList Component
 *
 * List all user's organizations with active state and organization switching.
 *
 * @example
 * ```tsx
 * <OrganizationList
 *   onSelect={(org) => console.log('Selected:', org)}
 *   hideCreateButton={false}
 * />
 * ```
 */

import React, { useState, useCallback } from 'react';
import { useOrganization } from '../hooks/useOrganization';
import { useAuth } from '../hooks/useAuth';
import { Appearance, Organization } from '../types';

export interface OrganizationListProps {
  /**
   * Callback when an organization is selected
   */
  onSelect?: (org: Organization) => void;
  /**
   * Hide the create organization button
   */
  hideCreateButton?: boolean;
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export function OrganizationList({
  onSelect,
  hideCreateButton = false,
  appearance,
  className,
}: OrganizationListProps) {
  const { 
    organizations, 
    organization: activeOrg, 
    isLoaded, 
    setActive,
    create,
  } = useOrganization();
  const { user } = useAuth();

  const [isCreating, setIsCreating] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handleSelectOrg = useCallback((org: Organization) => {
    setActive(org.id);
    onSelect?.(org);
  }, [setActive, onSelect]);

  const handleCreateOrg = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgName.trim()) return;

    setIsLoading(true);
    setError(null);

    try {
      const newOrg = await create({ name: newOrgName.trim() });
      setSuccessMessage(`Organization "${newOrg.name}" created successfully`);
      setNewOrgName('');
      setIsCreating(false);
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to create organization');
    } finally {
      setIsLoading(false);
    }
  }, [newOrgName, create]);

  if (!isLoaded) {
    return (
      <div style={applyAppearance(styles.container, appearance)} className={className}>
        <div style={styles.loading}>Loading organizations...</div>
      </div>
    );
  }

  const hasOrganizations = organizations.length > 0;

  return (
    <div style={applyAppearance(styles.container, appearance)} className={className}>
      <div style={styles.header}>
        <h2 style={applyAppearance(styles.title, appearance)}>Your Organizations</h2>
        {!hideCreateButton && !isCreating && (
          <button
            onClick={() => setIsCreating(true)}
            style={applyAppearance(styles.createButton, appearance)}
          >
            <PlusIcon />
            <span>New</span>
          </button>
        )}
      </div>

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

      {isCreating && (
        <form onSubmit={handleCreateOrg} style={styles.createForm}>
          <input
            type="text"
            value={newOrgName}
            onChange={(e) => setNewOrgName(e.target.value)}
            placeholder="Organization name"
            autoFocus
            style={applyAppearance(styles.createInput, appearance)}
            disabled={isLoading}
          />
          <div style={styles.createActions}>
            <button
              type="submit"
              disabled={isLoading || !newOrgName.trim()}
              style={applyAppearance(styles.primaryButton, appearance)}
            >
              {isLoading ? 'Creating...' : 'Create'}
            </button>
            <button
              type="button"
              onClick={() => {
                setIsCreating(false);
                setNewOrgName('');
                setError(null);
              }}
              disabled={isLoading}
              style={applyAppearance(styles.secondaryButton, appearance)}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <div style={styles.list}>
        {/* Personal Account */}
        <OrganizationItem
          name={user?.profile?.name || user?.email || 'Personal Account'}
          email={user?.email}
          isActive={!activeOrg}
          onClick={() => {
            setActive(null);
            onSelect?.(null as any);
          }}
          isPersonal
          appearance={appearance}
        />

        {/* Organizations */}
        {organizations.map((org) => (
          <OrganizationItem
            key={org.id}
            name={org.name}
            role={org.role}
            isActive={activeOrg?.id === org.id}
            onClick={() => handleSelectOrg(org)}
            appearance={appearance}
          />
        ))}

        {!hasOrganizations && !isCreating && (
          <div style={styles.emptyState}>
            <div style={styles.emptyIcon}>
              <BuildingIcon />
            </div>
            <p style={styles.emptyTitle}>No organizations yet</p>
            <p style={styles.emptyText}>
              Create an organization to collaborate with your team.
            </p>
            {!hideCreateButton && (
              <button
                onClick={() => setIsCreating(true)}
                style={applyAppearance(styles.emptyCreateButton, appearance)}
              >
                Create Organization
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// Organization Item Component
interface OrganizationItemProps {
  name: string;
  email?: string;
  role?: string;
  isActive: boolean;
  onClick: () => void;
  isPersonal?: boolean;
  appearance?: Appearance;
}

function OrganizationItem({
  name,
  email,
  role,
  isActive,
  onClick,
  isPersonal = false,
  appearance,
}: OrganizationItemProps) {
  return (
    <button
      onClick={onClick}
      style={{
        ...styles.item,
        ...(isActive && styles.itemActive),
        ...(isActive && appearance?.variables?.['colorPrimary'] && {
          borderColor: appearance.variables['colorPrimary'],
          backgroundColor: `${appearance.variables['colorPrimary']}10`,
        }),
      }}
    >
      <div style={styles.itemIcon}>
        {isPersonal ? <UserIcon /> : <BuildingIcon small />}
      </div>
      <div style={styles.itemContent}>
        <div style={styles.itemName}>{name}</div>
        {email && <div style={styles.itemEmail}>{email}</div>}
        {role && !isPersonal && (
          <span style={styles.itemRole}>{role}</span>
        )}
      </div>
      {isActive && (
        <div 
          style={{
            ...styles.activeBadge,
            ...(appearance?.variables?.['colorPrimary'] && {
              backgroundColor: appearance.variables['colorPrimary'],
            }),
          }}
        >
          Active
        </div>
      )}
    </button>
  );
}

// Icon Components
function BuildingIcon({ small }: { small?: boolean }) {
  return (
    <svg
      width={small ? 20 : 24}
      height={small ? 20 : 24}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z" />
      <path d="M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2" />
      <path d="M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2" />
      <path d="M10 6h4" />
      <path d="M10 10h4" />
      <path d="M10 14h4" />
      <path d="M10 18h4" />
    </svg>
  );
}

function UserIcon() {
  return (
    <svg
      width={20}
      height={20}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  );
}

function PlusIcon() {
  return (
    <svg
      width={16}
      height={16}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M5 12h14" />
      <path d="M12 5v14" />
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
  loading: {
    textAlign: 'center',
    padding: '48px',
    color: '#6b7280',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '20px',
  },
  title: {
    margin: '0',
    fontSize: '20px',
    fontWeight: 600,
    color: '#1a1a1a',
  },
  createButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '8px 12px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#0066cc',
    backgroundColor: '#eff6ff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  error: {
    padding: '12px',
    marginBottom: '16px',
    color: '#dc2626',
    backgroundColor: '#fee2e2',
    borderRadius: '6px',
    fontSize: '14px',
  },
  success: {
    padding: '12px',
    marginBottom: '16px',
    color: '#059669',
    backgroundColor: '#d1fae5',
    borderRadius: '6px',
    fontSize: '14px',
  },
  createForm: {
    marginBottom: '16px',
    padding: '16px',
    backgroundColor: '#f9fafb',
    borderRadius: '8px',
  },
  createInput: {
    width: '100%',
    padding: '10px 12px',
    fontSize: '15px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    marginBottom: '12px',
    outline: 'none',
    boxSizing: 'border-box',
  },
  createActions: {
    display: 'flex',
    gap: '8px',
  },
  primaryButton: {
    flex: 1,
    padding: '10px',
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
    padding: '10px 16px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#6b7280',
    backgroundColor: '#fff',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  list: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  item: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '16px',
    backgroundColor: '#fff',
    border: '1px solid #e5e7eb',
    borderRadius: '8px',
    cursor: 'pointer',
    transition: 'all 0.15s ease-in-out',
    textAlign: 'left',
    width: '100%',
  },
  itemActive: {
    borderColor: '#0066cc',
    backgroundColor: '#eff6ff',
  },
  itemIcon: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '40px',
    height: '40px',
    color: '#6b7280',
    backgroundColor: '#f3f4f6',
    borderRadius: '8px',
    flexShrink: 0,
  },
  itemContent: {
    flex: 1,
    minWidth: 0,
  },
  itemName: {
    fontSize: '15px',
    fontWeight: 500,
    color: '#1f2937',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  itemEmail: {
    fontSize: '13px',
    color: '#6b7280',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  itemRole: {
    display: 'inline-block',
    marginTop: '4px',
    padding: '2px 8px',
    fontSize: '11px',
    fontWeight: 500,
    textTransform: 'uppercase',
    color: '#6b7280',
    backgroundColor: '#f3f4f6',
    borderRadius: '9999px',
  },
  activeBadge: {
    padding: '4px 10px',
    fontSize: '12px',
    fontWeight: 500,
    color: '#fff',
    backgroundColor: '#0066cc',
    borderRadius: '9999px',
    flexShrink: 0,
  },
  emptyState: {
    textAlign: 'center',
    padding: '48px 24px',
    border: '2px dashed #e5e7eb',
    borderRadius: '8px',
  },
  emptyIcon: {
    display: 'flex',
    justifyContent: 'center',
    marginBottom: '16px',
    color: '#d1d5db',
  },
  emptyTitle: {
    margin: '0 0 8px',
    fontSize: '16px',
    fontWeight: 500,
    color: '#374151',
  },
  emptyText: {
    margin: '0 0 20px',
    fontSize: '14px',
    color: '#6b7280',
  },
  emptyCreateButton: {
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
};
