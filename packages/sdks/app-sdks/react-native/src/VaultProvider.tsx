/**
 * Vault Provider
 * 
 * React context provider for Vault authentication in React Native.
 * Features secure storage, biometric unlock, and offline support.
 */

import React, { 
  createContext, 
  useContext, 
  useCallback, 
  useEffect, 
  useState, 
  useRef,
  useMemo,
} from 'react';
import { AppState, AppStateStatus } from 'react-native';
import { VaultApiClient, createVaultClient } from './api/client';
import { 
  User, 
  Session, 
  Organization, 
  ApiError,
  AuthState,
  VaultConfig,
  VaultProviderProps,
  AppAuthState,
  SignInOptions,
  SignUpOptions,
  MagicLinkOptions,
  OAuthOptions,
  ForgotPasswordOptions,
  ResetPasswordOptions,
  VerifyEmailOptions,
  MfaChallenge,
  MfaMethod,
  TotpSetup,
} from './types';
import {
  getSessionToken,
  clearSessionTokens,
  getCachedUser,
  getCachedOrganizations,
  isBiometricEnabled,
} from './storage';
import { addDeepLinkListener, parseOAuthCallback } from './deep-linking';

// ============================================================================
// Context Value Interface
// ============================================================================

interface VaultContextValue {
  // State
  isLoaded: boolean;
  isSignedIn: boolean;
  isLocked: boolean;
  user: User | null;
  session: Session | null;
  organization: Organization | null;
  organizations: Organization[];
  authState: AppAuthState;
  
  // Config
  config: VaultConfig;
  
  // API Client
  api: VaultApiClient;
  
  // Auth methods
  signIn: (options: SignInOptions) => Promise<void>;
  signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
  signInWithOAuth: (options: OAuthOptions) => Promise<void>;
  signUp: (options: SignUpOptions) => Promise<void>;
  signOut: () => Promise<void>;
  signInWithBiometric: (challenge: string, signature: string) => Promise<void>;
  
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
  setActiveOrganization: (orgId: string | null) => Promise<void>;
  createOrganization: (name: string, slug?: string) => Promise<Organization>;
  leaveOrganization: (orgId: string) => Promise<void>;
  refreshOrganizations: () => Promise<void>;
  
  // Token & Session
  getToken: () => Promise<string | null>;
  refreshSession: () => Promise<void>;
  
  // Lock/Unlock
  setLocked: (locked: boolean) => void;
  
  // Error handling
  lastError: ApiError | null;
  clearError: () => void;
}

// ============================================================================
// Context Creation
// ============================================================================

const VaultContext = createContext<VaultContextValue | null>(null);

// ============================================================================
// Provider Component
// ============================================================================

export function VaultProvider({ 
  children, 
  config, 
  initialUser,
  onAuthStateChange,
  loadingComponent,
  biometricLockComponent,
}: VaultProviderProps) {
  // API client ref to prevent recreation
  const apiRef = useRef(new VaultApiClient(config));
  const api = apiRef.current;

  // Auth state
  const [authState, setAuthState] = useState<AppAuthState>(
    initialUser 
      ? { status: 'authenticated', user: initialUser, session: {} as Session }
      : { status: 'loading' }
  );
  
  // Lock state (for biometric app lock)
  const [isLocked, setIsLocked] = useState(false);
  
  // Organization state
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [activeOrg, setActiveOrg] = useState<Organization | null>(null);
  
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

  // Handle app state changes (background/foreground)
  useEffect(() => {
    const subscription = AppState.addEventListener('change', (nextAppState: AppStateStatus) => {
      if (nextAppState === 'background') {
        // App went to background - check if we should lock
        checkAndLock();
      }
    });

    return () => {
      subscription.remove();
    };
  }, []);

  const checkAndLock = async () => {
    if (config.enableBiometricUnlock && authState.status === 'authenticated') {
      const biometricEnabled = await isBiometricEnabled();
      if (biometricEnabled) {
        setIsLocked(true);
      }
    }
  };

  // ============================================================================
  // Initialization
  // ============================================================================

  useEffect(() => {
    const init = async () => {
      // Skip if we have initial user (SSR/similar)
      if (initialUser) {
        await loadCachedData();
        return;
      }

      try {
        const token = await getSessionToken();
        
        if (token) {
          // Validate token and get user
          try {
            const session = await api.validateSession(token);
            setAuthState({ 
              status: 'authenticated', 
              user: session.user, 
              session 
            });
            
            // Check if biometric unlock is enabled
            if (config.enableBiometricUnlock) {
              const biometricEnabled = await isBiometricEnabled();
              if (biometricEnabled) {
                setIsLocked(true);
              }
            }
            
            // Load organizations
            await refreshOrganizations();
          } catch {
            // Token invalid, try refresh
            try {
              const newSession = await api.refreshSessionWithDedup();
              setAuthState({ 
                status: 'authenticated', 
                user: newSession.user, 
                session: newSession 
              });
              await refreshOrganizations();
            } catch {
              // Refresh failed, clear tokens
              await clearSessionTokens();
              setAuthState({ status: 'unauthenticated' });
            }
          }
        } else {
          // Try to load cached user for offline mode
          const cachedUser = await getCachedUser();
          if (cachedUser && config.enableOfflineSupport !== false) {
            setAuthState({ status: 'offline', user: cachedUser });
          } else {
            setAuthState({ status: 'unauthenticated' });
          }
        }
      } catch (error) {
        // Clear invalid token
        await clearSessionTokens();
        setAuthState({ status: 'unauthenticated' });
      }
    };

    init();
  }, [api, initialUser, config.enableBiometricUnlock, config.enableOfflineSupport]);

  const loadCachedData = async () => {
    // Load cached organizations
    const cachedOrgs = await getCachedOrganizations();
    if (cachedOrgs) {
      setOrganizations(cachedOrgs);
    }
  };

  // ============================================================================
  // Deep Link Handling
  // ============================================================================

  useEffect(() => {
    const unsubscribe = addDeepLinkListener((url, data) => {
      if (data?.code) {
        // Handle OAuth callback
        handleOAuthCallback(data.provider, data.code);
      } else if (data?.error) {
        setLastError({
          message: data.errorDescription || data.error,
          code: 'oauth_error',
        });
        setAuthState({ status: 'error', error: {
          message: data.errorDescription || data.error,
          code: 'oauth_error',
        }});
      }
    });

    return () => {
      unsubscribe();
    };
  }, [api]);

  const handleOAuthCallback = async (provider: string, code: string) => {
    try {
      setAuthState({ status: 'loading' });
      const response = await api.handleOAuthCallback(provider, code);
      
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
      setAuthState({ status: 'error', error: apiError });
    }
  };

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
          status: 'error', 
          error: { message: 'MFA required', code: 'mfa_required' } 
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
      setAuthState({ status: 'error', error: apiError });
      throw error;
    }
  }, [api]);

  const signInWithBiometric = useCallback(async (challenge: string, signature: string) => {
    try {
      setAuthState({ status: 'loading' });
      setLastError(null);
      
      const response = await api.signInWithBiometric(challenge, signature);
      
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
      setAuthState({ status: 'error', error: apiError });
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
    
    // For React Native, we need to handle this differently
    // The URL will be opened by the component using the hook
    // For now, we throw an error directing to use the hook
    throw new Error(
      'Use useSignIn hook with signInWithOAuth instead for React Native. ' +
      'This opens the OAuth flow in an in-app browser.'
    );
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
      setAuthState({ status: 'error', error: apiError });
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
      setIsLocked(false);
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
  // Token & Session Methods
  // ============================================================================

  const getToken = useCallback(async () => {
    return api.getStoredToken();
  }, [api]);

  const refreshSession = useCallback(async () => {
    try {
      const session = await api.refreshSessionWithDedup();
      
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
  // Lock Methods
  // ============================================================================

  const setLocked = useCallback((locked: boolean) => {
    setIsLocked(locked);
  }, []);

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

  const value: VaultContextValue = useMemo(() => ({
    // State
    isLoaded: authState.status !== 'loading',
    isSignedIn: authState.status === 'authenticated',
    isLocked,
    user: authState.status === 'authenticated' ? authState.user : null,
    session: authState.status === 'authenticated' ? authState.session : null,
    organization: activeOrg,
    organizations,
    authState,
    
    // Config
    config,
    
    // API Client
    api,
    
    // Auth methods
    signIn,
    signInWithMagicLink,
    signInWithOAuth,
    signUp,
    signOut,
    signInWithBiometric,
    
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
    setActiveOrganization,
    createOrganization,
    leaveOrganization,
    refreshOrganizations,
    
    // Token & Session
    getToken,
    refreshSession,
    
    // Lock
    setLocked,
    
    // Error handling
    lastError,
    clearError,
  }), [
    authState, 
    isLocked, 
    activeOrg, 
    organizations, 
    config, 
    api, 
    lastError,
    mfaChallenge,
    signIn,
    signInWithBiometric,
    signInWithMagicLink,
    signInWithOAuth,
    signUp,
    signOut,
    sendForgotPassword,
    resetPassword,
    verifyEmail,
    resendVerificationEmail,
    verifyMfa,
    setupTotp,
    verifyTotpSetup,
    disableMfa,
    generateBackupCodes,
    updateUser,
    reloadUser,
    changePassword,
    deleteUser,
    setActiveOrganization,
    createOrganization,
    leaveOrganization,
    refreshOrganizations,
    getToken,
    refreshSession,
    setLocked,
    clearError,
  ]);

  // ============================================================================
  // Render
  // ============================================================================

  // Show loading component while initializing
  if (authState.status === 'loading' && loadingComponent) {
    return <>{loadingComponent}</>;
  }

  // Show biometric lock screen if locked
  if (isLocked && biometricLockComponent) {
    return (
      <VaultContext.Provider value={value}>
        {biometricLockComponent}
      </VaultContext.Provider>
    );
  }

  return (
    <VaultContext.Provider value={value}>
      {children}
    </VaultContext.Provider>
  );
}

// ============================================================================
// Hook
// ============================================================================

export function useVault(): VaultContextValue {
  const context = useContext(VaultContext);
  
  if (!context) {
    throw new Error('useVault must be used within a VaultProvider');
  }
  
  return context;
}

export { VaultContext };
