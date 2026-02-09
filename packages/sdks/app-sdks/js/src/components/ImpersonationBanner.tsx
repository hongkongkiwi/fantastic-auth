/**
 * ImpersonationBanner Component
 *
 * Fixed banner displayed when an admin is impersonating a user.
 *
 * @example
 * ```tsx
 * <ImpersonationBanner
 *   onStopImpersonating={() => stopImpersonating()}
 * />
 * ```
 */

import React, { useState, useCallback } from 'react';
import { useAuth } from '../hooks/useAuth';

export interface ImpersonationBannerProps {
  /**
   * Callback when user clicks "Stop Impersonating"
   */
  onStopImpersonating?: () => void;
}

export function ImpersonationBanner({
  onStopImpersonating,
}: ImpersonationBannerProps) {
  const { user } = useAuth();
  const [isStopping, setIsStopping] = useState(false);
  const [isDismissed, setIsDismissed] = useState(false);

  // In a real implementation, this would check if the current session
  // is an impersonation session (likely from auth context or a header)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const isImpersonating = (user as any)?.impersonating === true; // Placeholder check

  const handleStopImpersonating = useCallback(async () => {
    setIsStopping(true);
    try {
      await onStopImpersonating?.();
    } finally {
      setIsStopping(false);
    }
  }, [onStopImpersonating]);

  // Don't render if not impersonating or dismissed
  // Note: In a real implementation, check the actual impersonation state
  // For now, we'll show a demo state if no real check is available
  if (!isImpersonating && !isDismissed) {
    // This is a demo/placeholder - in production, you'd check actual impersonation state
    // Returning null until real impersonation detection is implemented
    return null;
  }

  if (isDismissed) {
    return (
      <button
        onClick={() => setIsDismissed(false)}
        style={styles.showButton}
        title="Show impersonation banner"
      >
        <UserIcon />
      </button>
    );
  }

  return (
    <div style={styles.banner} role="alert" aria-live="polite">
      <div style={styles.content}>
        <div style={styles.icon}>
          <UserIcon />
        </div>
        <div style={styles.text}>
          <span style={styles.label}>Impersonating</span>
          <span style={styles.userInfo}>
            {user?.profile?.name || user?.email || 'Unknown User'}
          </span>
        </div>
      </div>
      <div style={styles.actions}>
        <button
          onClick={handleStopImpersonating}
          disabled={isStopping}
          style={styles.stopButton}
        >
          {isStopping ? (
            <>
              <Spinner />
              <span>Stopping...</span>
            </>
          ) : (
            <>
              <LogOutIcon />
              <span>Stop Impersonating</span>
            </>
          )}
        </button>
        <button
          onClick={() => setIsDismissed(true)}
          style={styles.dismissButton}
          title="Dismiss banner"
          aria-label="Dismiss impersonation banner"
        >
          <CloseIcon />
        </button>
      </div>
    </div>
  );
}

// Icon Components
function UserIcon() {
  return (
    <svg
      width="18"
      height="18"
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

function LogOutIcon() {
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
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <polyline points="16 17 21 12 16 7" />
      <line x1="21" y1="12" x2="9" y2="12" />
    </svg>
  );
}

function CloseIcon() {
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
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

function Spinner() {
  return (
    <div style={styles.spinner}>
      <div style={styles.spinnerInner} />
    </div>
  );
}

// Styles
const styles: Record<string, React.CSSProperties> = {
  banner: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    zIndex: 9999,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '12px 16px',
    backgroundColor: '#7c3aed', // Purple for impersonation
    color: '#fff',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  content: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  icon: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    backgroundColor: 'rgba(255, 255, 255, 0.2)',
    borderRadius: '6px',
  },
  text: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '2px',
  },
  label: {
    fontSize: '11px',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    opacity: 0.8,
  },
  userInfo: {
    fontSize: '14px',
    fontWeight: 500,
  },
  actions: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  stopButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '8px 12px',
    fontSize: '13px',
    fontWeight: 500,
    color: '#7c3aed',
    backgroundColor: '#fff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'all 0.15s ease-in-out',
  },
  dismissButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    color: '#fff',
    backgroundColor: 'rgba(255, 255, 255, 0.2)',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'all 0.15s ease-in-out',
  },
  showButton: {
    position: 'fixed',
    top: '16px',
    right: '16px',
    zIndex: 9999,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '40px',
    height: '40px',
    color: '#fff',
    backgroundColor: '#7c3aed',
    border: 'none',
    borderRadius: '50%',
    cursor: 'pointer',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
  },
  spinner: {
    width: '14px',
    height: '14px',
    animation: 'spin 1s linear infinite',
  },
  spinnerInner: {
    width: '100%',
    height: '100%',
    border: '2px solid rgba(124, 58, 237, 0.3)',
    borderTopColor: '#7c3aed',
    borderRadius: '50%',
  },
};
