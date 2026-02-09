/**
 * UserButton Component
 *
 * Displays user avatar with dropdown menu for account management.
 * Uses the Clerk-style theming system.
 *
 * @example
 * ```tsx
 * <UserButton
 *   showName={true}
 *   showManageAccount={true}
 *   menuItems={[{ label: 'Settings', onClick: () => {} }]}
 *   appearance={{
 *     baseTheme: 'dark',
 *     variables: { colorPrimary: '#ff0000' }
 *   }}
 * />
 * ```
 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useAuth } from '../hooks/useAuth';
import { useUser } from '../hooks/useUser';
import { UserButtonProps } from '../types';
import {
  ThemeProvider,
  useTheme,
} from '../theme';

export type { UserButtonProps };

// ============================================================================
// Main Component
// ============================================================================

export function UserButton({
  showName = true,
  avatarUrl,
  onSignOut,
  menuItems = [],
  showManageAccount = true,
  appearance,
  className,
}: UserButtonProps) {
  // Determine if we need to wrap with ThemeProvider
  const [isThemed] = useState(() => {
    try {
      useTheme();
      return true;
    } catch {
      return false;
    }
  });

  const content = (
    <UserButtonContent
      showName={showName}
      avatarUrl={avatarUrl}
      onSignOut={onSignOut}
      menuItems={menuItems}
      showManageAccount={showManageAccount}
      appearance={appearance}
      className={className}
    />
  );

  // Wrap with ThemeProvider if not already themed
  if (!isThemed && appearance) {
    return (
      <ThemeProvider appearance={appearance}>
        {content}
      </ThemeProvider>
    );
  }

  return content;
}

// ============================================================================
// Internal Content Component
// ============================================================================

function UserButtonContent({
  showName,
  avatarUrl,
  onSignOut,
  menuItems,
  showManageAccount,
  className,
}: UserButtonProps) {
  const { signOut, isSignedIn } = useAuth();
  const user = useUser();
  const { getElementClass, cssVariables } = useTheme();

  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

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

  // Handle keyboard navigation
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
    }

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  const handleSignOut = useCallback(async () => {
    await signOut();
    onSignOut?.();
    setIsOpen(false);
  }, [signOut, onSignOut]);

  const handleManageAccount = useCallback(() => {
    window.location.href = '/profile';
    setIsOpen(false);
  }, []);

  if (!isSignedIn || !user) {
    return null;
  }

  const displayName = user.profile?.name || user.email.split('@')[0];
  const initial = displayName.charAt(0).toUpperCase();
  const imageUrl = avatarUrl || user.profile?.picture;

  return (
    <div
      ref={menuRef}
      className={[getElementClass('userButton'), className].filter(Boolean).join(' ')}
      style={{ position: 'relative', display: 'inline-block' }}
    >
      {/* Trigger Button */}
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={getElementClass('userButtonTrigger')}
        aria-expanded={isOpen}
        aria-haspopup="true"
        aria-label="User menu"
      >
        {imageUrl ? (
          <img
            src={imageUrl}
            alt={displayName}
            style={{
              width: '2rem',
              height: '2rem',
              borderRadius: '50%',
              objectFit: 'cover',
            }}
            onError={(e) => {
              (e.target as HTMLImageElement).style.display = 'none';
            }}
          />
        ) : (
          <div className={getElementClass('avatarBox')}>{initial}</div>
        )}
        {showName && (
          <span
            style={{
              fontWeight: 500,
              fontFamily: cssVariables['--vault-font-family'],
              color: cssVariables['--vault-color-text'],
            }}
          >
            {displayName}
          </span>
        )}
        <ChevronIcon isOpen={isOpen} />
      </button>

      {/* Popover Menu */}
      {isOpen && (
        <div className={getElementClass('userButtonPopover')}>
          <div className={getElementClass('userButtonPopoverCard')}>
            {/* User Info */}
            <div
              style={{
                padding: '0.75rem 1rem',
                borderBottom: `1px solid ${cssVariables['--vault-color-border']}`,
              }}
            >
              <div
                style={{
                  fontWeight: 600,
                  fontSize: '0.875rem',
                  fontFamily: cssVariables['--vault-font-family'],
                  color: cssVariables['--vault-color-text'],
                }}
              >
                {displayName}
              </div>
              <div
                style={{
                  fontSize: '0.75rem',
                  fontFamily: cssVariables['--vault-font-family'],
                  color: cssVariables['--vault-color-text-secondary'],
                  marginTop: '0.125rem',
                  wordBreak: 'break-all',
                }}
              >
                {user.email}
              </div>
              {user.emailVerified === false && (
                <span
                  style={{
                    display: 'inline-block',
                    marginTop: '0.25rem',
                    padding: '0.125rem 0.5rem',
                    fontSize: '0.6875rem',
                    fontFamily: cssVariables['--vault-font-family'],
                    color: cssVariables['--vault-color-warning'],
                    backgroundColor: `${cssVariables['--vault-color-warning']}15`,
                    borderRadius: '0.25rem',
                  }}
                >
                  Unverified
                </span>
              )}
            </div>

            {/* Menu Items */}
            <div className={getElementClass('menuList')}>
              {showManageAccount && (
                <button
                  type="button"
                  onClick={handleManageAccount}
                  className={getElementClass('menuItem')}
                  role="menuitem"
                >
                  Manage account
                </button>
              )}

              {menuItems?.map((item, index) => (
                <button
                  key={index}
                  type="button"
                  onClick={() => {
                    item.onClick();
                    setIsOpen(false);
                  }}
                  className={getElementClass('menuItem')}
                  role="menuitem"
                >
                  {item.label}
                </button>
              ))}

              {(showManageAccount || (menuItems && menuItems.length > 0)) && (
                <div
                  style={{
                    height: '1px',
                    backgroundColor: cssVariables['--vault-color-border'],
                    margin: '0.25rem 0',
                  }}
                />
              )}

              <button
                type="button"
                onClick={handleSignOut}
                className={getElementClass('menuItem')}
                role="menuitem"
                style={{ color: cssVariables['--vault-color-danger'] }}
              >
                Sign out
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Chevron Icon
// ============================================================================

function ChevronIcon({ isOpen }: { isOpen: boolean }) {
  const { cssVariables } = useTheme();

  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 12 12"
      fill="none"
      style={{
        marginLeft: '0.25rem',
        transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
        transition: 'transform 0.2s ease',
        color: cssVariables['--vault-color-text-secondary'],
      }}
    >
      <path
        d="M2.5 4.5L6 8L9.5 4.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
