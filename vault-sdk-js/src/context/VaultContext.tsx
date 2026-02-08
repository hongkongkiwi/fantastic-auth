/**
 * Vault Context
 * 
 * React context for Vault authentication state and methods.
 */

import React, { createContext, useContext, useCallback, useEffect, useState, useRef } from 'react';
import { 
  User, 
  Session, 
  SessionInfo,
  VaultConfig, 
  SignInOptions, 
  SignUpOptions,
  MagicLinkOptions,
  OAuthOptions,
  ForgotPasswordOptions,
  ResetPasswordOptions,
  VerifyEmailOptions,
  MfaChallenge,
  ApiError,
  AuthState,
  Organization,
  OrganizationRole,
  MfaMethod,
  TotpSetup,
  Appearance,
} from '../types';
import { VaultApiClient } from '../api/client';
import { ThemeProvider } from '../theme';

// ============================================================================
// Context Value Interface
// ============================================================================

interface VaultContextValue {
  // State
  isLoaded: boolean;
  isSignedIn: boolean;
  user: User | null;
  session: Session | null;
  organization: Organization | null;
  authState: AuthState;
  
  // API Client (for advanced use cases)
  api: VaultApiClient;
  
  // Auth methods
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  signUp: (options: SignUpOptions) => Promise<void>;
  signOut: () => Promise<void>;
  
  // Password reset
  sendForgotPassword: (options: ForgotPasswordOptions) => Promise<void>;
  resetPassword: (options: ResetPasswordOptions) => Promise<{
    user: User;
    session: Session;
  }>;
  
  // Email verification
  verifyEmail: (options: VerifyEmailOptions) => Promise<void>;
  resendVerificationEmail: () => Promise<void>;
  
  // MFA
  mfaChallenge: MfaChallenge | null;
  verifyMfa: (code: string, method: MfaMethod) => Promise<void>;
  setupTotp: () => Promise<TotpSetup | null>;
  verifyTotpSetup: (code: string) => Promise<void>;
  disableMfa: (method: MfaMethod) => Promise<void>;
  generateBackupCodes: () => Promise<string[]>;
  
  // User methods
  updateUser: (updates: Partial<User>) => Promise<void>;
  reloadUser: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  deleteUser: () => Promise<void>;
  
  // Organization methods
  organizations: Organization[];
  setActiveOrganization: (orgId: string | null) => Promise<void>;
  createOrganization: (name: string, slug?: string) => Promise<Organization>;
  leaveOrganization: (orgId: string) => Promise<void>;
  refreshOrganizations: () => Promise<void>;
  
  // Session methods
  sessions: SessionInfo[];
  revokeSession: (sessionId: string) => Promise<void>;
  revokeAllOtherSessions: () => Promise<void>;
  refreshSessions: () => Promise<void>;
  
  // Token & Session
  getToken: () => Promise<string | null>;
  refreshSession: () => Promise<void>;
  
  // Error handling
  lastError: ApiError | null;
  clearError: () => void;
}

// ============================================================================
// Context Creation
// ============================================================================

const VaultContext = createContext<VaultContextValue | null>(null);

export interface VaultProviderProps {
  children: React.ReactNode;
  config: VaultConfig;
  /**
   * Initial user data (for SSR)
   */
  initialUser?: User;
  /**
   * Initial session token (for SSR)
   */
  initialSessionToken?: string;
  /**
   * Callback when authentication state changes
   */
  onAuthStateChange?: (state: AuthState) => void;
  /**
   * Global appearance configuration for components
   */
  appearance?: Appearance;
}

// ============================================================================
// Provider Component
// ============================================================================

export function VaultProvider({ 
  children, 
  config, 
  initialUser,
  initialSessionToken,
  onAuthStateChange,
  appearance,
}: VaultProviderProps) {
  // API client ref to prevent recreation
  const apiRef = useRef(new VaultApiClient(config));
  const api = apiRef.current;

  // Auth state
  const [authState, setAuthState] = useState<AuthState>(
    initialUser 
      ? { status: 'authenticated', user: initialUser, session: {} as Session }
      : { status: 'loading' }
  );
  
  // Organization state
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [activeOrg, setActiveOrg] = useState<Organization | null>(null);
  
  // Sessions state
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  
  // MFA state
  const [mfaChallenge, setMfaChallenge] = useState<MfaChallenge | null>(null);
  
  // Error state
  const [lastError, setLastError] = useState<ApiError | null>(null);

  // Update API client if config changes
  useEffect(() => {
    apiRef.current = new VaultApiClient(config);
  }, [config]);

  // Notify auth state changes
  useEffect(() => {
    onAuthStateChange?.(authState);
  }, [authState, onAuthStateChange]);

  // ============================================================================
  // Initialization
  // ============================================================================

  useEffect(() => {
    const init = async () => {
      // Skip if we have initial user (SSR)
      if (initialUser) {
        // Load organizations
        await refreshOrganizations();
        return;
      }

      try {
        const token = await api.getStoredToken();
        
        if (token) {
          // Validate token and get user
          const session = await api.validateSession(token);
          setAuthState({ 
            status: 'authenticated', 
            user: session.user, 
            session 
          });
          
          // Store refresh token if provided
          if (session.refreshToken) {
            await api.storeRefreshToken(session.refreshToken);
          }
          
          // Load organizations
          await refreshOrganizations();
        } else {
          setAuthState({ status: 'unauthenticated' });
        }
      } catch (error) {
        // Clear invalid token
        await api.clearToken();
        setAuthState({ status: 'unauthenticated' });
      }
    };

    init();
  }, [api, initialUser]);

  // ============================================================================
  // Auth Methods
  // ============================================================================

  const signIn = useCallback(async (options: SignInOptions) => {
    try {
      setAuthState({ status: 'loading' });
      setLastError(null);
      
      const response = await api.signIn(options);
      
      if (response.mfaRequired) {
        setMfaChallenge(response.mfaChallenge as MfaChallenge);
        setAuthState({ 
          status: 'mfa_required', 
          challenge: response.mfaChallenge as MfaChallenge 
        });
      } else {
        await api.storeToken(response.session.accessToken);
        if (response.session.refreshToken) {
          await api.storeRefreshToken(response.session.refreshToken);
        }
        setAuthState({ 
          status: 'authenticated', 
          user: response.user, 
          session: response.session 
        });
        await refreshOrganizations();
      }
    } catch (error) {
      const apiError = error as ApiError;
      setLastError(apiError);
      setAuthState({ 
        status: 'error', 
        error: apiError 
      });
      throw error;
    }
  }, [api]);

  const signInWithMagicLink = useCallback(async (options: MagicLinkOptions) => {
    setLastError(null);
    await api.sendMagicLink(options);
  }, [api]);

  const signInWithOAuth = useCallback(async (options: OAuthOptions) => {
    setLastError(null);
    const { url } = await api.getOAuthUrl(options);
    window.location.href = url;
  }, [api]);

  const signUp = useCallback(async (options: SignUpOptions) => {
    try {
      setAuthState({ status: 'loading' });
      setLastError(null);
      
      const response = await api.signUp(options);
      
      await api.storeToken(response.session.accessToken);
      if (response.session.refreshToken) {
        await api.storeRefreshToken(response.session.refreshToken);
      }
      setAuthState({ 
        status: 'authenticated', 
        user: response.user, 
        session: response.session 
      });
      await refreshOrganizations();
    } catch (error) {
      const apiError = error as ApiError;
      setLastError(apiError);
      setAuthState({ 
        status: 'error', 
        error: apiError 
      });
      throw error;
    }
  }, [api]);

  const signOut = useCallback(async () => {
    try {
      await api.signOut();
    } finally {
      await api.clearToken();
      setAuthState({ status: 'unauthenticated' });
      setActiveOrg(null);
      setOrganizations([]);
      setMfaChallenge(null);
    }
  }, [api]);

  // ============================================================================
  // Password Reset Methods
  // ============================================================================

  const sendForgotPassword = useCallback(async (options: ForgotPasswordOptions) => {
    setLastError(null);
    await api.sendForgotPassword(options);
  }, [api]);

  const resetPassword = useCallback(async (options: ResetPasswordOptions) => {
    try {
      setLastError(null);
      const response = await api.resetPassword(options);
      
      await api.storeToken(response.session.accessToken);
      if (response.session.refreshToken) {
        await api.storeRefreshToken(response.session.refreshToken);
      }
      setAuthState({ 
        status: 'authenticated', 
        user: response.user, 
        session: response.session 
      });
      await refreshOrganizations();
      
      return response;
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api]);

  // ============================================================================
  // Email Verification Methods
  // ============================================================================

  const verifyEmail = useCallback(async (options: VerifyEmailOptions) => {
    try {
      setLastError(null);
      const { user } = await api.verifyEmail(options);
      
      if (authState.status === 'authenticated') {
        setAuthState({
          ...authState,
          user: { ...authState.user, ...user }
        });
      }
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api, authState]);

  const resendVerificationEmail = useCallback(async () => {
    setLastError(null);
    await api.resendVerificationEmail();
  }, [api]);

  // ============================================================================
  // MFA Methods
  // ============================================================================

  const verifyMfa = useCallback(async (code: string, method: MfaMethod) => {
    try {
      setLastError(null);
      const response = await api.verifyMfa(code, method);
      
      await api.storeToken(response.session.accessToken);
      if (response.session.refreshToken) {
        await api.storeRefreshToken(response.session.refreshToken);
      }
      setMfaChallenge(null);
      setAuthState({ 
        status: 'authenticated', 
        user: response.user, 
        session: response.session 
      });
      await refreshOrganizations();
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api]);

  const setupTotp = useCallback(async (): Promise<TotpSetup | null> => {
    try {
      setLastError(null);
      return await api.setupTotp();
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api]);

  const verifyTotpSetup = useCallback(async (code: string) => {
    try {
      setLastError(null);
      await api.verifyTotpSetup(code);
      await reloadUser();
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api]);

  const disableMfa = useCallback(async (method: MfaMethod) => {
    try {
      setLastError(null);
      await api.disableMfa(method);
      await reloadUser();
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api]);

  const generateBackupCodes = useCallback(async (): Promise<string[]> => {
    try {
      setLastError(null);
      const { codes } = await api.generateBackupCodes();
      return codes;
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api]);

  // ============================================================================
  // User Methods
  // ============================================================================

  const updateUser = useCallback(async (updates: Partial<User>) => {
    try {
      setLastError(null);
      const updated = await api.updateUser(updates);
      
      if (authState.status === 'authenticated') {
        setAuthState({
          ...authState,
          user: { ...authState.user, ...updated }
        });
      }
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api, authState]);

  const reloadUser = useCallback(async () => {
    try {
      setLastError(null);
      const user = await api.getCurrentUser();
      
      if (authState.status === 'authenticated') {
        setAuthState({
          ...authState,
          user
        });
      }
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api, authState]);

  const changePassword = useCallback(async (currentPassword: string, newPassword: string) => {
    try {
      setLastError(null);
      await api.changePassword(currentPassword, newPassword);
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api]);

  const deleteUser = useCallback(async () => {
    try {
      setLastError(null);
      await api.deleteUser();
      await api.clearToken();
      setAuthState({ status: 'unauthenticated' });
      setActiveOrg(null);
      setOrganizations([]);
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api]);

  // ============================================================================
  // Organization Methods
  // ============================================================================

  const refreshOrganizations = useCallback(async () => {
    try {
      const orgs = await api.listOrganizations();
      setOrganizations(orgs);
    } catch (error) {
      // Silently fail - not critical
      if (config.debug) {
        console.error('[Vault SDK] Failed to load organizations:', error);
      }
    }
  }, [api, config.debug]);

  const setActiveOrganization = useCallback(async (orgId: string | null) => {
    try {
      setLastError(null);
      
      // Call API to switch organization context in the token
      const response = await api.setActiveOrganization(orgId);
      
      // Update token with new org context
      await api.storeToken(response.session.accessToken);
      if (response.session.refreshToken) {
        await api.storeRefreshToken(response.session.refreshToken);
      }
      
      // Update auth state with new user and session
      if (authState.status === 'authenticated') {
        setAuthState({
          ...authState,
          user: response.user,
          session: { ...authState.session, ...response.session }
        });
      }
      
      // Update active organization
      if (orgId === null) {
        setActiveOrg(null);
      } else {
        const org = organizations.find(o => o.id === orgId);
        if (org) {
          setActiveOrg(org);
        }
      }
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api, organizations, authState]);

  const createOrganization = useCallback(async (name: string, slug?: string) => {
    try {
      setLastError(null);
      const org = await api.createOrganization({ name, slug });
      setOrganizations(prev => [...prev, org]);
      setActiveOrg(org);
      return org;
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api]);

  const leaveOrganization = useCallback(async (orgId: string) => {
    try {
      setLastError(null);
      await api.leaveOrganization(orgId);
      setOrganizations(prev => prev.filter(o => o.id !== orgId));
      if (activeOrg?.id === orgId) {
        setActiveOrg(null);
      }
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api, activeOrg]);

  // ============================================================================
  // Session Methods
  // ============================================================================

  const getToken = useCallback(async () => {
    return api.getStoredToken();
  }, [api]);

  const refreshSession = useCallback(async () => {
    try {
      const { session } = await api.refreshSession();
      await api.storeToken(session.accessToken);
      
      if (authState.status === 'authenticated') {
        setAuthState({
          ...authState,
          session: { ...authState.session, ...session }
        });
      }
    } catch (error) {
      // Clear session on refresh failure
      await api.clearToken();
      setAuthState({ status: 'unauthenticated' });
      throw error;
    }
  }, [api, authState]);

  // ============================================================================
  // Session Management Methods
  // ============================================================================

  const refreshSessions = useCallback(async () => {
    try {
      const sessionsList = await api.listSessions();
      setSessions(sessionsList);
    } catch (error) {
      if (config.debug) {
        console.error('[Vault SDK] Failed to load sessions:', error);
      }
    }
  }, [api, config.debug]);

  const revokeSession = useCallback(async (sessionId: string) => {
    try {
      setLastError(null);
      await api.revokeSession(sessionId);
      setSessions(prev => prev.filter(s => s.id !== sessionId));
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api]);

  const revokeAllOtherSessions = useCallback(async () => {
    try {
      setLastError(null);
      await api.revokeAllSessions();
      // Refresh to get updated list (should only contain current session)
      await refreshSessions();
    } catch (error) {
      setLastError(error as ApiError);
      throw error;
    }
  }, [api, refreshSessions]);

  // ============================================================================
  // Error Handling
  // ============================================================================

  const clearError = useCallback(() => {
    setLastError(null);
    if (authState.status === 'error') {
      setAuthState({ status: 'unauthenticated' });
    }
  }, [authState]);

  // ============================================================================
  // Context Value
  // ============================================================================

  const value: VaultContextValue = {
    // State
    isLoaded: authState.status !== 'loading',
    isSignedIn: authState.status === 'authenticated',
    user: authState.status === 'authenticated' ? authState.user : null,
    session: authState.status === 'authenticated' ? authState.session : null,
    organization: activeOrg,
    authState,
    
    // API Client
    api,
    
    // Auth methods
    signIn,
    signInWithMagicLink,
    signInWithOAuth,
    signUp,
    signOut,
    
    // Password reset
    sendForgotPassword,
    resetPassword,
    
    // Email verification
    verifyEmail,
    resendVerificationEmail,
    
    // MFA
    mfaChallenge,
    verifyMfa,
    setupTotp,
    verifyTotpSetup,
    disableMfa,
    generateBackupCodes,
    
    // User methods
    updateUser,
    reloadUser,
    changePassword,
    deleteUser,
    
    // Organization methods
    organizations,
    setActiveOrganization,
    createOrganization,
    leaveOrganization,
    refreshOrganizations,
    
    // Session methods
    sessions,
    revokeSession,
    revokeAllOtherSessions,
    refreshSessions,
    
    // Token & Session
    getToken,
    refreshSession,
    
    // Error handling
    lastError,
    clearError,
  };

  return (
    <VaultContext.Provider value={value}>
      <ThemeProvider appearance={appearance}>
        {children}
      </ThemeProvider>
    </VaultContext.Provider>
  );
}

// ============================================================================
// Hook
// ============================================================================

export function useVault() {
  const context = useContext(VaultContext);
  
  if (!context) {
    throw new Error('useVault must be used within a VaultProvider');
  }
  
  return context;
}

export { VaultContext };
