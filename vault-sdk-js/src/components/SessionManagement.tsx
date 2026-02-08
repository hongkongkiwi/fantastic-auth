/**
 * SessionManagement Component
 *
 * Manage active user sessions with device info and revocation controls.
 *
 * @example
 * ```tsx
 * <SessionManagement appearance={{ theme: 'light' }} />
 * ```
 */

import React, { useState, useCallback } from 'react';
import { useSessions } from '../hooks/useSessions';
import { useVault } from '../context/VaultContext';
import { Appearance, SessionInfo } from '../types';

export interface SessionManagementProps {
  /**
   * Custom styling
   */
  appearance?: Appearance;
  /**
   * Custom class name
   */
  className?: string;
}

export function SessionManagement({
  appearance,
  className,
}: SessionManagementProps) {
  const { sessions, isLoading, revokeSession, revokeAllOtherSessions } = useSessions();
  const vault = useVault();
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [showConfirmAll, setShowConfirmAll] = useState(false);

  const handleRevoke = useCallback(async (sessionId: string) => {
    setRevokingId(sessionId);
    try {
      await revokeSession(sessionId);
    } finally {
      setRevokingId(null);
    }
  }, [revokeSession]);

  const handleRevokeAllOthers = useCallback(async () => {
    try {
      await revokeAllOtherSessions();
      setShowConfirmAll(false);
    } catch (error) {
      console.error('Failed to revoke all sessions:', error);
    }
  }, [revokeAllOtherSessions]);

  const otherSessionsCount = sessions.filter(s => !s.isCurrent).length;

  return (
    <div style={applyAppearance(styles.container, appearance)} className={className}>
      <div style={styles.header}>
        <div>
          <h2 style={applyAppearance(styles.title, appearance)}>Active Sessions</h2>
          <p style={styles.subtitle}>
            Manage your active sessions across all devices
          </p>
        </div>
      </div>

      {otherSessionsCount > 0 && (
        <div style={styles.warningBanner}>
          <AlertIcon />
          <span>You have {otherSessionsCount} other active session{otherSessionsCount !== 1 ? 's' : ''}</span>
        </div>
      )}

      {showConfirmAll ? (
        <div style={styles.confirmBanner}>
          <p style={styles.confirmText}>
            Are you sure you want to sign out all other devices? This will require you to sign in again on those devices.
          </p>
          <div style={styles.confirmActions}>
            <button
              onClick={handleRevokeAllOthers}
              disabled={isLoading}
              style={applyAppearance(styles.dangerButton, appearance)}
            >
              {isLoading ? 'Signing out...' : 'Yes, sign out all'}
            </button>
            <button
              onClick={() => setShowConfirmAll(false)}
              disabled={isLoading}
              style={applyAppearance(styles.secondaryButton, appearance)}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        otherSessionsCount > 0 && (
          <button
            onClick={() => setShowConfirmAll(true)}
            style={applyAppearance(styles.signOutAllButton, appearance)}
          >
            <LogOutIcon />
            Sign out all other devices
          </button>
        )
      )}

      <div style={styles.sessionsList}>
        {sessions.length === 0 ? (
          <div style={styles.emptyState}>
            <p>No active sessions found</p>
          </div>
        ) : (
          sessions
            .sort((a, b) => (a.isCurrent ? -1 : 1))
            .map((session) => (
              <SessionItem
                key={session.id}
                session={session}
                isCurrent={session.isCurrent}
                onRevoke={() => handleRevoke(session.id)}
                isRevoking={revokingId === session.id}
                appearance={appearance}
              />
            ))
        )}
      </div>
    </div>
  );
}

// Session Item Component
interface SessionItemProps {
  session: SessionInfo;
  isCurrent: boolean;
  onRevoke: () => void;
  isRevoking: boolean;
  appearance?: Appearance;
}

function SessionItem({ session, isCurrent, onRevoke, isRevoking, appearance }: SessionItemProps) {
  const deviceInfo = parseUserAgent(session.userAgent);
  const location = session.ipAddress ? `IP: ${session.ipAddress}` : null;
  const lastActive = formatLastActive(session.lastActiveAt);

  return (
    <div 
      style={{
        ...styles.sessionItem,
        ...(isCurrent && styles.currentSession),
      }}
    >
      <div style={styles.sessionIcon}>
        <DeviceIcon device={deviceInfo.device} />
      </div>
      
      <div style={styles.sessionInfo}>
        <div style={styles.sessionHeader}>
          <span style={styles.deviceName}>
            {deviceInfo.browser} on {deviceInfo.os}
          </span>
          {isCurrent && (
            <span 
              style={{
                ...styles.currentBadge,
                ...(appearance?.variables?.['colorPrimary'] && {
                  backgroundColor: appearance.variables['colorPrimary'],
                }),
              }}
            >
              Current
            </span>
          )}
        </div>
        
        <div style={styles.sessionDetails}>
          {location && <span>{location}</span>}
          <span>Last active {lastActive}</span>
        </div>
        
        <div style={styles.sessionMeta}>
          Started {new Date(session.createdAt).toLocaleDateString()}
        </div>
      </div>

      {!isCurrent && (
        <button
          onClick={onRevoke}
          disabled={isRevoking}
          style={styles.revokeButton}
          title="Sign out this device"
        >
          {isRevoking ? (
            <Spinner />
          ) : (
            <LogOutIcon small />
          )}
        </button>
      )}
    </div>
  );
}

// Helper Functions
function parseUserAgent(userAgent?: string): { browser: string; os: string; device: string } {
  if (!userAgent) {
    return { browser: 'Unknown', os: 'Unknown', device: 'desktop' };
  }

  const ua = userAgent.toLowerCase();
  
  // Detect browser
  let browser = 'Unknown';
  if (ua.includes('firefox')) browser = 'Firefox';
  else if (ua.includes('edg')) browser = 'Edge';
  else if (ua.includes('chrome')) browser = 'Chrome';
  else if (ua.includes('safari')) browser = 'Safari';
  else if (ua.includes('opera')) browser = 'Opera';

  // Detect OS
  let os = 'Unknown';
  if (ua.includes('windows')) os = 'Windows';
  else if (ua.includes('macintosh') || ua.includes('mac os')) os = 'macOS';
  else if (ua.includes('linux')) os = 'Linux';
  else if (ua.includes('android')) os = 'Android';
  else if (ua.includes('iphone') || ua.includes('ipad')) os = 'iOS';

  // Detect device type
  let device = 'desktop';
  if (ua.includes('mobile')) device = 'mobile';
  else if (ua.includes('tablet') || ua.includes('ipad')) device = 'tablet';

  return { browser, os, device };
}

function formatLastActive(lastActiveAt: string): string {
  const lastActive = new Date(lastActiveAt);
  const now = new Date();
  const diffMs = now.getTime() - lastActive.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
  if (diffDays < 7) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
  return lastActive.toLocaleDateString();
}

// Icon Components
function DeviceIcon({ device }: { device: string }) {
  if (device === 'mobile') {
    return (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="7" y="2" width="10" height="20" rx="2" ry="2" />
        <line x1="12" y1="18" x2="12" y2="18" />
      </svg>
    );
  }
  if (device === 'tablet') {
    return (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="4" y="2" width="16" height="20" rx="2" ry="2" />
        <line x1="12" y1="18" x2="12" y2="18" />
      </svg>
    );
  }
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  );
}

function LogOutIcon({ small }: { small?: boolean }) {
  const size = small ? 16 : 18;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <polyline points="16 17 21 12 16 7" />
      <line x1="21" y1="12" x2="9" y2="12" />
    </svg>
  );
}

function AlertIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
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
    maxWidth: '600px',
    margin: '0 auto',
    padding: '24px',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  header: {
    marginBottom: '20px',
  },
  title: {
    margin: '0 0 4px',
    fontSize: '20px',
    fontWeight: 600,
    color: '#1a1a1a',
  },
  subtitle: {
    margin: 0,
    fontSize: '14px',
    color: '#6b7280',
  },
  warningBanner: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '12px 16px',
    marginBottom: '16px',
    fontSize: '14px',
    color: '#92400e',
    backgroundColor: '#fef3c7',
    borderRadius: '6px',
  },
  confirmBanner: {
    padding: '16px',
    marginBottom: '16px',
    backgroundColor: '#fee2e2',
    borderRadius: '6px',
    border: '1px solid #fecaca',
  },
  confirmText: {
    margin: '0 0 12px',
    fontSize: '14px',
    color: '#7f1d1d',
  },
  confirmActions: {
    display: 'flex',
    gap: '8px',
  },
  signOutAllButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '10px 16px',
    marginBottom: '16px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#dc2626',
    backgroundColor: '#fef2f2',
    border: '1px solid #fecaca',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'all 0.15s ease-in-out',
  },
  dangerButton: {
    padding: '8px 16px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#fff',
    backgroundColor: '#dc2626',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  secondaryButton: {
    padding: '8px 16px',
    fontSize: '14px',
    fontWeight: 500,
    color: '#374151',
    backgroundColor: '#fff',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'background-color 0.15s ease-in-out',
  },
  sessionsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
  sessionItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '16px',
    padding: '16px',
    backgroundColor: '#fff',
    border: '1px solid #e5e7eb',
    borderRadius: '8px',
    transition: 'background-color 0.15s ease-in-out',
  },
  currentSession: {
    backgroundColor: '#f0fdf4',
    borderColor: '#bbf7d0',
  },
  sessionIcon: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '44px',
    height: '44px',
    color: '#6b7280',
    backgroundColor: '#f3f4f6',
    borderRadius: '10px',
    flexShrink: 0,
  },
  sessionInfo: {
    flex: 1,
    minWidth: 0,
  },
  sessionHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '4px',
  },
  deviceName: {
    fontSize: '15px',
    fontWeight: 500,
    color: '#1f2937',
  },
  currentBadge: {
    padding: '2px 8px',
    fontSize: '11px',
    fontWeight: 600,
    textTransform: 'uppercase',
    color: '#fff',
    backgroundColor: '#10b981',
    borderRadius: '9999px',
  },
  sessionDetails: {
    display: 'flex',
    gap: '12px',
    fontSize: '13px',
    color: '#6b7280',
    marginBottom: '2px',
  },
  sessionMeta: {
    fontSize: '12px',
    color: '#9ca3af',
  },
  revokeButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '36px',
    height: '36px',
    color: '#dc2626',
    backgroundColor: '#fef2f2',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'all 0.15s ease-in-out',
  },
  emptyState: {
    textAlign: 'center',
    padding: '48px',
    color: '#6b7280',
  },
  spinner: {
    width: '16px',
    height: '16px',
    animation: 'spin 1s linear infinite',
  },
  spinnerInner: {
    width: '100%',
    height: '100%',
    border: '2px solid #e5e7eb',
    borderTopColor: '#6b7280',
    borderRadius: '50%',
  },
};
