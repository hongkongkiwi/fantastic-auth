/**
 * OrganizationSwitcher Component
 *
 * Organization switching dropdown component with search, pagination, and creation.
 *
 * @example
 * ```tsx
 * <OrganizationSwitcher
 *   hidePersonal={false}
 *   onSwitch={(org) => console.log('Switched to:', org?.name)}
 *   showSearch={true}
 * />
 * ```
 */

import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { useOrganization } from '../hooks/useOrganization';
import { useAuth } from '../hooks/useAuth';
import { OrganizationSwitcherProps, Organization } from '../types';

// Extended props interface for new features
export interface OrganizationSwitcherExtendedProps extends OrganizationSwitcherProps {
  /**
   * Show search input to filter organizations
   */
  showSearch?: boolean;
  /**
   * Maximum number of organizations to show before pagination
   */
  pageSize?: number;
}

export type { OrganizationSwitcherProps };

const DEFAULT_PAGE_SIZE = 10;

export function OrganizationSwitcher({
  hidePersonal = false,
  onSwitch,
  appearance,
  className,
  showSearch = true,
  pageSize = DEFAULT_PAGE_SIZE,
}: OrganizationSwitcherExtendedProps) {
  const { 
    organization: activeOrg, 
    organizations, 
    isLoaded, 
    setActive,
    create,
  } = useOrganization();
  const { user } = useAuth();

  const [isOpen, setIsOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Filter organizations based on search query
  const filteredOrganizations = useMemo(() => {
    if (!searchQuery.trim()) return organizations;
    
    const query = searchQuery.toLowerCase();
    return organizations.filter(org =>
      org.name.toLowerCase().includes(query) ||
      org.slug.toLowerCase().includes(query)
    );
  }, [organizations, searchQuery]);

  // Paginate organizations
  const paginatedOrganizations = useMemo(() => {
    const start = currentPage * pageSize;
    return filteredOrganizations.slice(start, start + pageSize);
  }, [filteredOrganizations, currentPage, pageSize]);

  const totalPages = Math.ceil(filteredOrganizations.length / pageSize);
  const hasMorePages = currentPage < totalPages - 1;
  const hasPreviousPages = currentPage > 0;

  // Close menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  // Focus search input when menu opens
  useEffect(() => {
    if (isOpen && showSearch && searchInputRef.current) {
      setTimeout(() => searchInputRef.current?.focus(), 0);
    }
  }, [isOpen, showSearch]);

  // Reset search and pagination when menu closes
  useEffect(() => {
    if (!isOpen) {
      setSearchQuery('');
      setCurrentPage(0);
      setIsCreating(false);
      setNewOrgName('');
      setError(null);
    }
  }, [isOpen]);

  const handleSelectOrg = useCallback((orgId: string | null) => {
    setActive(orgId);
    const selectedOrg = orgId ? organizations.find(o => o.id === orgId) : null;
    onSwitch?.(selectedOrg || null);
    setIsOpen(false);
  }, [setActive, organizations, onSwitch]);

  const handleCreateOrg = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgName.trim()) return;

    setIsLoading(true);
    setError(null);

    try {
      const newOrg = await create({ name: newOrgName.trim() });
      onSwitch?.(newOrg);
      setIsCreating(false);
      setNewOrgName('');
      setIsOpen(false);
    } catch (error: any) {
      setError(error.message || 'Failed to create organization');
    } finally {
      setIsLoading(false);
    }
  }, [newOrgName, create, onSwitch]);

  if (!isLoaded) {
    return (
      <div style={applyAppearance(styles.skeleton, appearance)} className={className}>
        <div style={styles.skeletonInner} />
      </div>
    );
  }

  const currentOrgName = activeOrg?.name || user?.profile?.name || user?.email || 'Personal';
  const hasOrganizations = organizations.length > 0;

  return (
    <div ref={menuRef} style={styles.container} className={className}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        style={applyAppearance(styles.button, appearance)}
        aria-expanded={isOpen}
        aria-haspopup="true"
        aria-label="Switch organization"
      >
        <BuildingIcon />
        <span style={styles.buttonText}>{currentOrgName}</span>
        <ChevronIcon isOpen={isOpen} />
      </button>

      {isOpen && (
        <div style={applyAppearance(styles.menu, appearance)} role="menu">
          <div style={styles.menuHeader}>
            <span style={styles.menuTitle}>Switch organization</span>
          </div>

          {/* Search Input */}
          {showSearch && hasOrganizations && (
            <div style={styles.searchContainer}>
              <SearchIcon />
              <input
                ref={searchInputRef}
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(0);
                }}
                placeholder="Search organizations..."
                style={applyAppearance(styles.searchInput, appearance)}
              />
              {searchQuery && (
                <button
                  onClick={() => {
                    setSearchQuery('');
                    searchInputRef.current?.focus();
                  }}
                  style={styles.clearSearch}
                  aria-label="Clear search"
                >
                  <CloseIcon />
                </button>
              )}
            </div>
          )}

          {/* Search Results Count */}
          {searchQuery && (
            <div style={styles.searchResults}>
              {filteredOrganizations.length === 0 ? (
                <span>No organizations found</span>
              ) : (
                <span>{filteredOrganizations.length} result{filteredOrganizations.length !== 1 ? 's' : ''}</span>
              )}
            </div>
          )}

          {/* Organization List */}
          <div style={styles.menuItems}>
            {/* Personal Account */}
            {!hidePersonal && !searchQuery && currentPage === 0 && (
              <button
                onClick={() => handleSelectOrg(null)}
                style={{
                  ...applyAppearance(styles.menuItem, appearance),
                  ...(activeOrg === null && styles.menuItemActive),
                }}
                role="menuitem"
              >
                <UserIcon />
                <span style={styles.menuItemText}>
                  {user?.profile?.name || user?.email || 'Personal Account'}
                </span>
                {activeOrg === null && <CheckIcon />}
              </button>
            )}

            {/* Organizations */}
            {paginatedOrganizations.map((org) => (
              <button
                key={org.id}
                onClick={() => handleSelectOrg(org.id)}
                style={{
                  ...applyAppearance(styles.menuItem, appearance),
                  ...(activeOrg?.id === org.id && styles.menuItemActive),
                }}
                role="menuitem"
              >
                <BuildingIcon small />
                <div style={styles.menuItemContent}>
                  <span style={styles.menuItemName}>{org.name}</span>
                  <span style={styles.menuItemSlug}>{org.slug}</span>
                </div>
                {activeOrg?.id === org.id && <CheckIcon />}
              </button>
            ))}

            {/* Empty State */}
            {!hasOrganizations && !isCreating && (
              <div style={styles.emptyState}>
                <div style={styles.emptyIcon}>
                  <BuildingIcon />
                </div>
                <p style={styles.emptyTitle}>No organizations</p>
                <p style={styles.emptyText}>
                  Create one to collaborate with your team
                </p>
              </div>
            )}

            {/* No Search Results */}
            {searchQuery && filteredOrganizations.length === 0 && (
              <div style={styles.emptyState}>
                <div style={styles.emptyIcon}>
                  <SearchIcon large />
                </div>
                <p style={styles.emptyTitle}>No results</p>
                <p style={styles.emptyText}>
                  Try a different search term
                </p>
              </div>
            )}
          </div>

          {/* Pagination */}
          {filteredOrganizations.length > pageSize && (
            <div style={styles.pagination}>
              <button
                onClick={() => setCurrentPage(p => Math.max(0, p - 1))}
                disabled={!hasPreviousPages}
                style={{
                  ...styles.paginationButton,
                  ...(!hasPreviousPages && styles.paginationButtonDisabled),
                }}
                aria-label="Previous page"
              >
                <ChevronLeftIcon />
              </button>
              <span style={styles.paginationInfo}>
                Page {currentPage + 1} of {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={!hasMorePages}
                style={{
                  ...styles.paginationButton,
                  ...(!hasMorePages && styles.paginationButtonDisabled),
                }}
                aria-label="Next page"
              >
                <ChevronRightIcon />
              </button>
            </div>
          )}

          <div style={styles.divider} />

          {/* Create Organization Form */}
          {isCreating ? (
            <form onSubmit={handleCreateOrg} style={styles.createForm}>
              {error && (
                <div style={applyAppearance(styles.createError, appearance)} role="alert">
                  {error}
                </div>
              )}
              <input
                type="text"
                value={newOrgName}
                onChange={(e) => setNewOrgName(e.target.value)}
                placeholder="Organization name"
                autoFocus
                style={applyAppearance(styles.createInput, appearance)}
                disabled={isLoading}
              />
              <div style={styles.createButtons}>
                <button
                  type="submit"
                  disabled={isLoading || !newOrgName.trim()}
                  style={applyAppearance(styles.createButton, appearance)}
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
                  style={applyAppearance(styles.cancelButton, appearance)}
                >
                  Cancel
                </button>
              </div>
            </form>
          ) : (
            <button
              onClick={() => setIsCreating(true)}
              style={applyAppearance(styles.createOrgButton, appearance)}
            >
              <PlusIcon />
              <span>Create organization</span>
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// Icon Components
function BuildingIcon({ small }: { small?: boolean }) {
  return (
    <svg
      width={small ? 16 : 20}
      height={small ? 16 : 20}
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
      width={16}
      height={16}
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

function CheckIcon() {
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
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}

function ChevronIcon({ isOpen }: { isOpen: boolean }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 12 12"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{
        transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
        transition: 'transform 0.2s ease',
      }}
    >
      <path d="M2 4l4 4 4-4" />
    </svg>
  );
}

function SearchIcon({ large }: { large?: boolean }) {
  const size = large ? 32 : 16;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.35-4.35" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

function ChevronLeftIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="15 18 9 12 15 6" />
    </svg>
  );
}

function ChevronRightIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="9 18 15 12 9 6" />
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
    if (baseStyle.color === '#0066cc' || baseStyle.borderColor === '#0066cc') {
      style = { 
        ...style, 
        color: baseStyle.color === '#0066cc' ? variables['colorPrimary'] : style.color,
        borderColor: baseStyle.borderColor === '#0066cc' ? variables['colorPrimary'] : style.borderColor,
      };
    }
    if (baseStyle.backgroundColor === '#0066cc') {
      style = { ...style, backgroundColor: variables['colorPrimary'] };
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
    position: 'relative',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  skeleton: {
    width: '160px',
    height: '40px',
  },
  skeletonInner: {
    width: '100%',
    height: '100%',
    backgroundColor: '#e5e7eb',
    borderRadius: '6px',
    animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
  },
  button: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px 12px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#374151',
    backgroundColor: '#f3f4f6',
    border: '1px solid #e5e7eb',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  buttonText: {
    maxWidth: '120px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  menu: {
    position: 'absolute',
    top: '100%',
    left: '0',
    marginTop: '4px',
    minWidth: '280px',
    maxWidth: '320px',
    backgroundColor: '#fff',
    border: '1px solid #e5e7eb',
    borderRadius: '8px',
    boxShadow: '0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05)',
    zIndex: 1000,
    overflow: 'hidden',
  },
  menuHeader: {
    padding: '8px 12px',
    borderBottom: '1px solid #e5e7eb',
  },
  menuTitle: {
    fontSize: '12px',
    fontWeight: 600,
    color: '#6b7280',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
  },
  searchContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px 12px',
    borderBottom: '1px solid #e5e7eb',
    color: '#6b7280',
  },
  searchInput: {
    flex: 1,
    border: 'none',
    outline: 'none',
    fontSize: '14px',
    padding: '4px 0',
    backgroundColor: 'transparent',
  },
  clearSearch: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '4px',
    color: '#9ca3af',
    backgroundColor: 'transparent',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
  },
  searchResults: {
    padding: '4px 12px',
    fontSize: '12px',
    color: '#6b7280',
    borderBottom: '1px solid #e5e7eb',
    backgroundColor: '#f9fafb',
  },
  menuItems: {
    maxHeight: '280px',
    overflowY: 'auto',
  },
  menuItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    width: '100%',
    padding: '10px 12px',
    fontSize: '14px',
    color: '#374151',
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  menuItemActive: {
    backgroundColor: '#eff6ff',
    color: '#0066cc',
  },
  menuItemContent: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column' as const,
    minWidth: 0,
  },
  menuItemName: {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    textAlign: 'left',
  },
  menuItemSlug: {
    fontSize: '12px',
    color: '#9ca3af',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  pagination: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '8px 12px',
    borderTop: '1px solid #e5e7eb',
    borderBottom: '1px solid #e5e7eb',
  },
  paginationButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '4px',
    color: '#374151',
    backgroundColor: 'transparent',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
  },
  paginationButtonDisabled: {
    color: '#d1d5db',
    cursor: 'not-allowed',
  },
  paginationInfo: {
    fontSize: '12px',
    color: '#6b7280',
  },
  emptyState: {
    padding: '24px',
    textAlign: 'center',
    color: '#6b7280',
  },
  emptyIcon: {
    display: 'flex',
    justifyContent: 'center',
    marginBottom: '12px',
    color: '#d1d5db',
  },
  emptyTitle: {
    margin: '0 0 4px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#374151',
  },
  emptyText: {
    margin: 0,
    fontSize: '12px',
    color: '#9ca3af',
  },
  divider: {
    height: '1px',
    backgroundColor: '#e5e7eb',
    margin: '4px 0',
  },
  createOrgButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    width: '100%',
    padding: '10px 12px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#0066cc',
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  createForm: {
    padding: '12px',
  },
  createError: {
    padding: '8px 12px',
    marginBottom: '8px',
    color: '#dc2626',
    backgroundColor: '#fee2e2',
    borderRadius: '4px',
    fontSize: '13px',
  },
  createInput: {
    width: '100%',
    padding: '8px 12px',
    fontSize: '14px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    marginBottom: '8px',
    outline: 'none',
    boxSizing: 'border-box',
  },
  createButtons: {
    display: 'flex',
    gap: '8px',
  },
  createButton: {
    flex: 1,
    padding: '8px 12px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#fff',
    backgroundColor: '#0066cc',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
  },
  cancelButton: {
    flex: 1,
    padding: '8px 12px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#6b7280',
    backgroundColor: '#f3f4f6',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
  },
};
