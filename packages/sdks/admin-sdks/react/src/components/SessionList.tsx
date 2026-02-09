/**
 * SessionList Component
 * 
 * Pre-built session management component.
 */

import React, { useState, useCallback } from 'react';
import { useSessions } from '@fantasticauth/react';
import type { SessionListProps, SessionInfo, AuthError } from '../types';
import { Button, Alert } from './ui';
import { classNames, getThemeClass } from '../styles';

/**
 * Pre-built session list component
 * 
 * @example
 * ```tsx
 * <SessionList 
 *   onRevoke={(sessionId) => console.log('Revoked:', sessionId)}
 *   showDeviceInfo
 *   showLocation
 * />
 * ```
 */
export const SessionList: React.FC<SessionListProps> = ({
  onRevoke,
  onRevokeAll,
  showDeviceInfo = true,
  showLocation = true,
  theme = 'light',
  className,
  style,
}) => {
  const { sessions, isLoading, error: sessionsError, revokeSession, revokeAllOtherSessions } = useSessions();
  
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokingAll, setRevokingAll] = useState(false);
  const [localError, setLocalError] = useState<AuthError | null>(null);

  const error = localError || (sessionsError ? {
    code: sessionsError.code || 'session_error',
    message: sessionsError.message,
  } : null);

  const formatDate = useCallback((dateString: string): string => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    
    return date.toLocaleDateString();
  }, []);

  const parseUserAgent = useCallback((userAgent?: string): { device: string; browser: string } => {
    if (!userAgent) return { device: 'Unknown device', browser: 'Unknown browser' };

    let device = 'Unknown device';
    let browser = 'Unknown browser';

    // Browser detection
    if (userAgent.includes('Chrome')) browser = 'Chrome';
    else if (userAgent.includes('Firefox')) browser = 'Firefox';
    else if (userAgent.includes('Safari')) browser = 'Safari';
    else if (userAgent.includes('Edge')) browser = 'Edge';

    // Device detection
    if (userAgent.includes('Mobile')) device = 'Mobile';
    else if (userAgent.includes('Tablet')) device = 'Tablet';
    else device = 'Desktop';

    // OS detection
    if (userAgent.includes('Windows')) device += ' (Windows)';
    else if (userAgent.includes('Mac')) device += ' (Mac)';
    else if (userAgent.includes('Linux')) device += ' (Linux)';
    else if (userAgent.includes('Android')) device += ' (Android)';
    else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) device += ' (iOS)';

    return { device, browser };
  }, []);

  const handleRevoke = useCallback(async (sessionId: string) => {
    try {
      setRevokingId(sessionId);
      setLocalError(null);
      await revokeSession(sessionId);
      onRevoke?.(sessionId);
    } catch (err) {
      const authError: AuthError = {
        code: 'revoke_failed',
        message: err instanceof Error ? err.message : 'Failed to revoke session.',
      };
      setLocalError(authError);
    } finally {
      setRevokingId(null);
    }
  }, [revokeSession, onRevoke]);

  const handleRevokeAll = useCallback(async () => {
    if (!window.confirm('Are you sure you want to sign out of all other devices?')) {
      return;
    }

    try {
      setRevokingAll(true);
      setLocalError(null);
      await revokeAllOtherSessions();
      onRevokeAll?.();
    } catch (err) {
      const authError: AuthError = {
        code: 'revoke_all_failed',
        message: err instanceof Error ? err.message : 'Failed to revoke all sessions.',
      };
      setLocalError(authError);
    } finally {
      setRevokingAll(false);
    }
  }, [revokeAllOtherSessions, onRevokeAll]);

  const themeClass = getThemeClass(theme);

  if (isLoading) {
    return (
      <div className={classNames('vault-session-list', themeClass, className)} style={style}>
        <div className="vault-loading">Loading sessions...</div>
      </div>
    );
  }

  // Sort sessions: current first, then by last active
  const sortedSessions = [...sessions].sort((a, b) => {
    if (a.isCurrent) return -1;
    if (b.isCurrent) return 1;
    return new Date(b.lastActiveAt).getTime() - new Date(a.lastActiveAt).getTime();
  });

  const currentSession = sortedSessions.find(s => s.isCurrent);
  const otherSessions = sortedSessions.filter(s => !s.isCurrent);

  return (
    <div className={classNames('vault-session-list', themeClass, className)} style={style}>
      <div className="vault-session-list-header">
        <h2 className="vault-session-list-title">Active sessions</h2>
        <p className="vault-session-list-subtitle">
          Manage your active sessions across all devices.
        </p>
      </div>

      {error && (
        <Alert variant="error" className="vault-mb-4">
          {error.message}
        </Alert>
      )}

      {/* Current Session */}
      {currentSession && (
        <div className="vault-session-section">
          <h3 className="vault-session-section-title">Current session</h3>
          <SessionItem
            session={currentSession}
            isCurrent
            formatDate={formatDate}
            parseUserAgent={parseUserAgent}
            showDeviceInfo={showDeviceInfo}
            showLocation={showLocation}
          />
        </div>
      )}

      {/* Other Sessions */}
      {otherSessions.length > 0 && (
        <div className="vault-session-section">
          <div className="vault-session-section-header">
            <h3 className="vault-session-section-title">
              Other devices ({otherSessions.length})
            </h3>
            <Button
              variant="danger"
              size="sm"
              isLoading={revokingAll}
              onClick={handleRevokeAll}
            >
              Sign out all
            </Button>
          </div>
          
          <div className="vault-session-list-items">
            {otherSessions.map((session) => (
              <SessionItem
                key={session.id}
                session={session}
                isCurrent={false}
                formatDate={formatDate}
                parseUserAgent={parseUserAgent}
                showDeviceInfo={showDeviceInfo}
                showLocation={showLocation}
                onRevoke={() => handleRevoke(session.id)}
                isRevoking={revokingId === session.id}
              />
            ))}
          </div>
        </div>
      )}

      {sortedSessions.length === 0 && (
        <div className="vault-session-empty">
          No active sessions found.
        </div>
      )}
    </div>
  );
};

// Session item sub-component
interface SessionItemProps {
  session: SessionInfo;
  isCurrent: boolean;
  formatDate: (date: string) => string;
  parseUserAgent: (ua?: string) => { device: string; browser: string };
  showDeviceInfo: boolean;
  showLocation: boolean;
  onRevoke?: () => void;
  isRevoking?: boolean;
}

const SessionItem: React.FC<SessionItemProps> = ({
  session,
  isCurrent,
  formatDate,
  parseUserAgent,
  showDeviceInfo,
  showLocation,
  onRevoke,
  isRevoking,
}) => {
  const { device, browser } = parseUserAgent(session.userAgent);

  return (
    <div className={classNames('vault-session-item', isCurrent && 'vault-session-item-current')}>
      <div className="vault-session-icon">
        {device.includes('Mobile') ? (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="5" y="2" width="14" height="20" rx="2" ry="2" />
            <line x1="12" y1="18" x2="12" y2="18" />
          </svg>
        ) : device.includes('Tablet') ? (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="4" y="2" width="16" height="20" rx="2" ry="2" />
            <line x1="12" y1="18" x2="12" y2="18" />
          </svg>
        ) : (
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
            <line x1="8" y1="21" x2="16" y2="21" />
            <line x1="12" y1="17" x2="12" y2="21" />
          </svg>
        )}
      </div>

      <div className="vault-session-content">
        <div className="vault-session-header">
          <span className="vault-session-device">{device}</span>
          {isCurrent && (
            <span className="vault-session-badge vault-session-badge-current">
              Current
            </span>
          )}
        </div>

        {showDeviceInfo && (
          <div className="vault-session-details">
            <span className="vault-session-browser">{browser}</span>
            {showLocation && session.location && (
              <>
                <span className="vault-session-dot">•</span>
                <span className="vault-session-location">{session.location}</span>
              </>
            )}
            {session.ipAddress && (
              <>
                <span className="vault-session-dot">•</span>
                <span className="vault-session-ip">{session.ipAddress}</span>
              </>
            )}
          </div>
        )}

        <div className="vault-session-time">
          Last active {formatDate(session.lastActiveAt)}
        </div>
      </div>

      {onRevoke && (
        <Button
          variant="ghost"
          size="sm"
          isLoading={isRevoking}
          onClick={onRevoke}
          className="vault-session-revoke"
        >
          Sign out
        </Button>
      )}
    </div>
  );
};
