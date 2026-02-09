/**
 * OrganizationSwitcher Component
 * 
 * Pre-built organization switching component.
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { useOrganization, useIsOrgAdmin } from '../hooks/useOrganization';
import type { OrganizationSwitcherProps, AuthError, Organization } from '../types';
import { Button, Input } from './ui';
import { classNames, getThemeClass } from '../styles';

type OrgView = 'list' | 'create';

/**
 * Pre-built organization switcher component
 * 
 * @example
 * ```tsx
 * <OrganizationSwitcher 
 *   onSwitch={(org) => console.log('Switched to:', org)}
 *   onCreate={() => console.log('Creating new org')}
 * />
 * ```
 */
export const OrganizationSwitcher: React.FC<OrganizationSwitcherProps> = ({
  hidePersonal = false,
  onSwitch,
  onCreate,
  theme = 'light',
  className,
  style,
}) => {
  const { 
    organization, 
    organizations, 
    isLoading, 
    setActive, 
    create,
    error: orgError 
  } = useOrganization();
  const isAdmin = useIsOrgAdmin();
  
  const [isOpen, setIsOpen] = useState(false);
  const [view, setView] = useState<OrgView>('list');
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgSlug, setNewOrgSlug] = useState('');
  const [isCreating, setIsCreating] = useState(false);
  const [localError, setLocalError] = useState<AuthError | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const error = localError || (orgError ? {
    code: orgError.code || 'org_error',
    message: orgError.message,
  } : null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSwitch = useCallback(async (orgId: string | null) => {
    try {
      setLocalError(null);
      await setActive(orgId);
      onSwitch?.(orgId ? organizations.find(o => o.id === orgId) || null : null);
      setIsOpen(false);
    } catch (err) {
      const authError: AuthError = {
        code: 'switch_failed',
        message: err instanceof Error ? err.message : 'Failed to switch organization.',
      };
      setLocalError(authError);
    }
  }, [setActive, organizations, onSwitch]);

  const handleCreate = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!newOrgName.trim()) return;

    try {
      setIsCreating(true);
      setLocalError(null);
      const newOrg = await create(newOrgName, newOrgSlug || undefined);
      onCreate?.();
      setView('list');
      setNewOrgName('');
      setNewOrgSlug('');
      setIsOpen(false);
    } catch (err) {
      const authError: AuthError = {
        code: 'create_failed',
        message: err instanceof Error ? err.message : 'Failed to create organization.',
      };
      setLocalError(authError);
    } finally {
      setIsCreating(false);
    }
  }, [newOrgName, newOrgSlug, create, onCreate]);

  const generateSlug = useCallback((name: string) => {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }, []);

  const handleNameChange = useCallback((value: string) => {
    setNewOrgName(value);
    if (!newOrgSlug || newOrgSlug === generateSlug(newOrgName)) {
      setNewOrgSlug(generateSlug(value));
    }
  }, [newOrgName, newOrgSlug, generateSlug]);

  const themeClass = getThemeClass(theme);

  // Get display name for current organization
  const getCurrentDisplay = () => {
    if (organization) {
      return organization.name;
    }
    return 'Personal';
  };

  return (
    <div 
      ref={dropdownRef}
      className={classNames('vault-org-switcher', themeClass, className)} 
      style={style}
    >
      <button
        type="button"
        className="vault-org-switcher-trigger"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="listbox"
        disabled={isLoading}
      >
        {organization?.logoUrl ? (
          <img 
            src={organization.logoUrl} 
            alt="" 
            className="vault-org-switcher-logo"
          />
        ) : (
          <div className="vault-org-switcher-logo vault-org-switcher-logo-placeholder">
            {getCurrentDisplay().charAt(0).toUpperCase()}
          </div>
        )}
        <span className="vault-org-switcher-name">{getCurrentDisplay()}</span>
        <svg 
          className={classNames('vault-org-switcher-chevron', isOpen && 'vault-org-switcher-chevron-open')}
          viewBox="0 0 20 20" 
          fill="currentColor"
          aria-hidden="true"
        >
          <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
        </svg>
      </button>

      {isOpen && (
        <div className="vault-org-switcher-dropdown" role="listbox">
          {view === 'list' ? (
            <>
              <div className="vault-org-switcher-section">
                <span className="vault-org-switcher-section-title">
                  {organizations.length > 0 ? 'Organizations' : 'No organizations'}
                </span>
                
                {!hidePersonal && (
                  <button
                    type="button"
                    className={classNames(
                      'vault-org-switcher-item',
                      !organization && 'vault-org-switcher-item-active'
                    )}
                    onClick={() => handleSwitch(null)}
                    role="option"
                    aria-selected={!organization}
                  >
                    <div className="vault-org-switcher-item-logo vault-org-switcher-item-logo-placeholder">
                      P
                    </div>
                    <span className="vault-org-switcher-item-name">Personal</span>
                    {!organization && (
                      <svg className="vault-org-switcher-check" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M16.704 4.153a.75.75 0 01.143 1.052l-8 10.5a.75.75 0 01-1.127.075l-4.5-4.5a.75.75 0 011.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 011.05-.143z" clipRule="evenodd" />
                      </svg>
                    )}
                  </button>
                )}

                {organizations.map((org) => (
                  <button
                    key={org.id}
                    type="button"
                    className={classNames(
                      'vault-org-switcher-item',
                      organization?.id === org.id && 'vault-org-switcher-item-active'
                    )}
                    onClick={() => handleSwitch(org.id)}
                    role="option"
                    aria-selected={organization?.id === org.id}
                  >
                    {org.logoUrl ? (
                      <img 
                        src={org.logoUrl} 
                        alt="" 
                        className="vault-org-switcher-item-logo"
                      />
                    ) : (
                      <div className="vault-org-switcher-item-logo vault-org-switcher-item-logo-placeholder">
                        {org.name.charAt(0).toUpperCase()}
                      </div>
                    )}
                    <div className="vault-org-switcher-item-content">
                      <span className="vault-org-switcher-item-name">{org.name}</span>
                      <span className="vault-org-switcher-item-role">{org.role}</span>
                    </div>
                    {organization?.id === org.id && (
                      <svg className="vault-org-switcher-check" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M16.704 4.153a.75.75 0 01.143 1.052l-8 10.5a.75.75 0 01-1.127.075l-4.5-4.5a.75.75 0 011.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 011.05-.143z" clipRule="evenodd" />
                      </svg>
                    )}
                  </button>
                ))}
              </div>

              <div className="vault-org-switcher-divider" />

              <button
                type="button"
                className="vault-org-switcher-action"
                onClick={() => setView('create')}
              >
                <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                  <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
                </svg>
                Create organization
              </button>

              {error && (
                <div className="vault-org-switcher-error">
                  {error.message}
                </div>
              )}
            </>
          ) : (
            <>
              <div className="vault-org-switcher-header">
                <button
                  type="button"
                  className="vault-org-switcher-back"
                  onClick={() => setView('list')}
                >
                  <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                    <path fillRule="evenodd" d="M17 10a.75.75 0 01-.75.75H5.612l4.158 3.96a.75.75 0 11-1.04 1.08l-5.5-5.25a.75.75 0 010-1.08l5.5-5.25a.75.75 0 111.04 1.08L5.612 9.25H16.25A.75.75 0 0117 10z" clipRule="evenodd" />
                  </svg>
                </button>
                <span className="vault-org-switcher-header-title">Create organization</span>
              </div>

              <form onSubmit={handleCreate} className="vault-org-switcher-form">
                <Input
                  type="text"
                  label="Organization name"
                  placeholder="Acme Inc"
                  value={newOrgName}
                  onChange={(e) => handleNameChange(e.target.value)}
                  disabled={isCreating}
                  required
                  autoFocus
                />

                <Input
                  type="text"
                  label="Slug (optional)"
                  placeholder="acme-inc"
                  value={newOrgSlug}
                  onChange={(e) => setNewOrgSlug(e.target.value)}
                  disabled={isCreating}
                  helperText="Used in URLs"
                />

                {error && (
                  <div className="vault-org-switcher-error">
                    {error.message}
                  </div>
                )}

                <Button
                  type="submit"
                  variant="primary"
                  fullWidth
                  isLoading={isCreating}
                  className="vault-mt-4"
                >
                  Create organization
                </Button>
              </form>
            </>
          )}
        </div>
      )}
    </div>
  );
};
