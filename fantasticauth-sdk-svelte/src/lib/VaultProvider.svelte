<script lang="ts">
  /**
   * VaultProvider Component
   * 
   * Provides Vault authentication context to the Svelte component tree.
   * Works with both Svelte 4 and Svelte 5.
   * 
   * @example
   * ```svelte
   * <VaultProvider config={{ apiUrl: 'https://api.vault.dev', tenantId: 'my-tenant' }}>
   *   <App />
   * </VaultProvider>
   * ```
   */
  import { setContext } from 'svelte';
  import { writable, derived } from 'svelte/store';
  import type { 
    VaultConfig, 
    User, 
    Session, 
    Organization, 
    SessionInfo,
    MfaChallenge,
    AuthState,
    ApiError,
    SignInOptions,
    SignUpOptions,
    MagicLinkOptions,
    OAuthOptions,
    ForgotPasswordOptions,
    ResetPasswordOptions,
    VerifyEmailOptions,
    MfaMethod,
    TotpSetup,
    Appearance
  } from './types.js';
  import { VaultApiClientImpl } from './api.js';
  import { VAULT_CONTEXT_KEY } from './context.js';

  // Props
  interface Props {
    config: VaultConfig;
    children: import('svelte').Snippet;
    initialUser?: User;
    initialSessionToken?: string;
    onAuthStateChange?: (state: AuthState) => void;
    appearance?: Appearance;
  }

  let { 
    config, 
    children, 
    initialUser, 
    initialSessionToken,
    onAuthStateChange,
    appearance
  }: Props = $props();

  // API client
  const api = new VaultApiClientImpl(config);

  // Writable stores for state
  const authStateStore = writable<AuthState>(
    initialUser 
      ? { status: 'authenticated', user: initialUser, session: {} as Session }
      : { status: 'loading' }
  );
  const organizationsStore = writable<Organization[]>([]);
  const activeOrgStore = writable<Organization | null>(null);
  const sessionsStore = writable<SessionInfo[]>([]);
  const mfaChallengeStore = writable<MfaChallenge | null>(null);
  const lastErrorStore = writable<ApiError | null>(null);

  // Derived stores
  const isLoaded = derived(authStateStore, $state => $state.status !== 'loading');
  const isSignedIn = derived(authStateStore, $state => $state.status === 'authenticated');
  const user = derived(authStateStore, $state => 
    $state.status === 'authenticated' ? $state.user : null
  );
  const session = derived(authStateStore, $state => 
    $state.status === 'authenticated' ? $state.session : null
  );
  const organization = derived(activeOrgStore, $org => $org);
  const authState = derived(authStateStore, $state => $state);
  const organizations = derived(organizationsStore, $orgs => $orgs);
  const sessions = derived(sessionsStore, $sessions => $sessions);
  const mfaChallenge = derived(mfaChallengeStore, $challenge => $challenge);
  const lastError = derived(lastErrorStore, $error => $error);

  // Notify auth state changes
  $effect(() => {
    onAuthStateChange?.($authStateStore);
  });

  // ============================================================================
  // Initialization
  // ============================================================================

  $effect(() => {
    const init = async () => {
      // Skip if we have initial user (SSR)
      if (initialUser) {
        await refreshOrganizations();
        return;
      }

      try {
        const token = await api.getStoredToken();
        
        if (token) {
          // Validate token and get user
          const sessionData = await api.validateSession(token);
          authStateStore.set({ 
            status: 'authenticated', 
            user: sessionData.user, 
            session: sessionData 
          });
          
          // Store refresh token if provided
          if (sessionData.refreshToken) {
            await api.storeRefreshToken(sessionData.refreshToken);
          }
          
          // Load organizations
          await refreshOrganizations();
        } else {
          authStateStore.set({ status: 'unauthenticated' });
        }
      } catch (error) {
        // Clear invalid token
        await api.clearToken();
        authStateStore.set({ status: 'unauthenticated' });
      }
    };

    init();
  });

  // ============================================================================
  // Auth Methods
  // ============================================================================

  async function signIn(options: SignInOptions): Promise<void> {
    try {
      authStateStore.set({ status: 'loading' });
      lastErrorStore.set(null);
      
      const response = await api.signIn(options);
      
      if (response.mfaRequired) {
        mfaChallengeStore.set(response.mfaChallenge as MfaChallenge);
        authStateStore.set({ 
          status: 'mfa_required', 
          challenge: response.mfaChallenge as MfaChallenge 
        });
      } else {
        await api.storeToken(response.session.accessToken);
        if (response.session.refreshToken) {
          await api.storeRefreshToken(response.session.refreshToken);
        }
        authStateStore.set({ 
          status: 'authenticated', 
          user: response.user, 
          session: response.session 
        });
        await refreshOrganizations();
      }
    } catch (error) {
      const apiError = error as ApiError;
      lastErrorStore.set(apiError);
      authStateStore.set({ 
        status: 'error', 
        error: apiError 
      });
      throw error;
    }
  }

  async function signInWithMagicLink(options: MagicLinkOptions): Promise<void> {
    lastErrorStore.set(null);
    await api.sendMagicLink(options);
  }

  async function signInWithOAuth(options: OAuthOptions): Promise<void> {
    lastErrorStore.set(null);
    const { url } = await api.getOAuthUrl(options);
    window.location.href = url;
  }

  async function signUp(options: SignUpOptions): Promise<void> {
    try {
      authStateStore.set({ status: 'loading' });
      lastErrorStore.set(null);
      
      const response = await api.signUp(options);
      
      await api.storeToken(response.session.accessToken);
      if (response.session.refreshToken) {
        await api.storeRefreshToken(response.session.refreshToken);
      }
      authStateStore.set({ 
        status: 'authenticated', 
        user: response.user, 
        session: response.session 
      });
      await refreshOrganizations();
    } catch (error) {
      const apiError = error as ApiError;
      lastErrorStore.set(apiError);
      authStateStore.set({ 
        status: 'error', 
        error: apiError 
      });
      throw error;
    }
  }

  async function signOut(): Promise<void> {
    try {
      await api.signOut();
    } finally {
      await api.clearToken();
      authStateStore.set({ status: 'unauthenticated' });
      activeOrgStore.set(null);
      organizationsStore.set([]);
      mfaChallengeStore.set(null);
    }
  }

  // ============================================================================
  // Password Reset Methods
  // ============================================================================

  async function sendForgotPassword(options: ForgotPasswordOptions): Promise<void> {
    lastErrorStore.set(null);
    await api.sendForgotPassword(options);
  }

  async function resetPassword(options: ResetPasswordOptions): Promise<{ user: User; session: Session }> {
    try {
      lastErrorStore.set(null);
      const response = await api.resetPassword(options);
      
      await api.storeToken(response.session.accessToken);
      if (response.session.refreshToken) {
        await api.storeRefreshToken(response.session.refreshToken);
      }
      authStateStore.set({ 
        status: 'authenticated', 
        user: response.user, 
        session: response.session 
      });
      await refreshOrganizations();
      
      return response;
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  // ============================================================================
  // Email Verification Methods
  // ============================================================================

  async function verifyEmail(options: VerifyEmailOptions): Promise<void> {
    try {
      lastErrorStore.set(null);
      const { user: verifiedUser } = await api.verifyEmail(options);
      
      const currentState = $authStateStore;
      if (currentState.status === 'authenticated') {
        authStateStore.set({
          ...currentState,
          user: { ...currentState.user, ...verifiedUser }
        });
      }
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function resendVerificationEmail(): Promise<void> {
    lastErrorStore.set(null);
    await api.resendVerificationEmail();
  }

  // ============================================================================
  // MFA Methods
  // ============================================================================

  async function verifyMfa(code: string, method: MfaMethod): Promise<void> {
    try {
      lastErrorStore.set(null);
      const response = await api.verifyMfa(code, method);
      
      await api.storeToken(response.session.accessToken);
      if (response.session.refreshToken) {
        await api.storeRefreshToken(response.session.refreshToken);
      }
      mfaChallengeStore.set(null);
      authStateStore.set({ 
        status: 'authenticated', 
        user: response.user, 
        session: response.session 
      });
      await refreshOrganizations();
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function setupTotp(): Promise<TotpSetup | null> {
    try {
      lastErrorStore.set(null);
      return await api.setupTotp();
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function verifyTotpSetup(code: string): Promise<void> {
    try {
      lastErrorStore.set(null);
      await api.verifyTotpSetup(code);
      await reloadUser();
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function disableMfa(method: MfaMethod): Promise<void> {
    try {
      lastErrorStore.set(null);
      await api.disableMfa(method);
      await reloadUser();
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function generateBackupCodes(): Promise<string[]> {
    try {
      lastErrorStore.set(null);
      const { codes } = await api.generateBackupCodes();
      return codes;
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  // ============================================================================
  // User Methods
  // ============================================================================

  async function updateUser(updates: Partial<User>): Promise<void> {
    try {
      lastErrorStore.set(null);
      const updated = await api.updateUser(updates);
      
      const currentState = $authStateStore;
      if (currentState.status === 'authenticated') {
        authStateStore.set({
          ...currentState,
          user: { ...currentState.user, ...updated }
        });
      }
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function reloadUser(): Promise<void> {
    try {
      lastErrorStore.set(null);
      const userData = await api.getCurrentUser();
      
      const currentState = $authStateStore;
      if (currentState.status === 'authenticated') {
        authStateStore.set({
          ...currentState,
          user: userData
        });
      }
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
    try {
      lastErrorStore.set(null);
      await api.changePassword(currentPassword, newPassword);
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function deleteUser(): Promise<void> {
    try {
      lastErrorStore.set(null);
      await api.deleteUser();
      await api.clearToken();
      authStateStore.set({ status: 'unauthenticated' });
      activeOrgStore.set(null);
      organizationsStore.set([]);
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  // ============================================================================
  // Organization Methods
  // ============================================================================

  async function refreshOrganizations(): Promise<void> {
    try {
      const orgs = await api.listOrganizations();
      organizationsStore.set(orgs);
    } catch (error) {
      // Silently fail - not critical
      if (config.debug) {
        console.error('[Vault SDK] Failed to load organizations:', error);
      }
    }
  }

  async function setActiveOrganization(orgId: string | null): Promise<void> {
    try {
      lastErrorStore.set(null);
      
      // Call API to switch organization context in the token
      const response = await api.setActiveOrganization(orgId);
      
      // Update token with new org context
      await api.storeToken(response.session.accessToken);
      if (response.session.refreshToken) {
        await api.storeRefreshToken(response.session.refreshToken);
      }
      
      // Update auth state with new user and session
      const currentState = $authStateStore;
      if (currentState.status === 'authenticated') {
        authStateStore.set({
          ...currentState,
          user: response.user,
          session: { ...currentState.session, ...response.session }
        });
      }
      
      // Update active organization
      if (orgId === null) {
        activeOrgStore.set(null);
      } else {
        const orgs = $organizationsStore;
        const org = orgs.find(o => o.id === orgId);
        if (org) {
          activeOrgStore.set(org);
        }
      }
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function createOrganization(name: string, slug?: string): Promise<Organization> {
    try {
      lastErrorStore.set(null);
      const org = await api.createOrganization({ name, slug });
      organizationsStore.update(prev => [...prev, org]);
      activeOrgStore.set(org);
      return org;
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function leaveOrganization(orgId: string): Promise<void> {
    try {
      lastErrorStore.set(null);
      await api.leaveOrganization(orgId);
      organizationsStore.update(prev => prev.filter(o => o.id !== orgId));
      const currentOrg = $activeOrgStore;
      if (currentOrg?.id === orgId) {
        activeOrgStore.set(null);
      }
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  // ============================================================================
  // Session Methods
  // ============================================================================

  async function getToken(): Promise<string | null> {
    return api.getStoredToken();
  }

  async function refreshSession(): Promise<void> {
    try {
      const { session } = await api.refreshSession();
      await api.storeToken(session.accessToken);
      
      const currentState = $authStateStore;
      if (currentState.status === 'authenticated') {
        authStateStore.set({
          ...currentState,
          session: { ...currentState.session, ...session }
        });
      }
    } catch (error) {
      // Clear session on refresh failure
      await api.clearToken();
      authStateStore.set({ status: 'unauthenticated' });
      throw error;
    }
  }

  async function refreshSessions(): Promise<void> {
    try {
      const sessionsList = await api.listSessions();
      sessionsStore.set(sessionsList);
    } catch (error) {
      if (config.debug) {
        console.error('[Vault SDK] Failed to load sessions:', error);
      }
    }
  }

  async function revokeSession(sessionId: string): Promise<void> {
    try {
      lastErrorStore.set(null);
      await api.revokeSession(sessionId);
      sessionsStore.update(prev => prev.filter(s => s.id !== sessionId));
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  async function revokeAllOtherSessions(): Promise<void> {
    try {
      lastErrorStore.set(null);
      await api.revokeAllSessions();
      // Refresh to get updated list (should only contain current session)
      await refreshSessions();
    } catch (error) {
      lastErrorStore.set(error as ApiError);
      throw error;
    }
  }

  // ============================================================================
  // Error Handling
  // ============================================================================

  function clearError(): void {
    lastErrorStore.set(null);
    const currentState = $authStateStore;
    if (currentState.status === 'error') {
      authStateStore.set({ status: 'unauthenticated' });
    }
  }

  // ============================================================================
  // Context Value
  // ============================================================================

  const contextValue = {
    // State stores
    isLoaded,
    isSignedIn,
    user,
    session,
    organization,
    authState,
    organizations,
    sessions,
    mfaChallenge,
    lastError,
    
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
    
    // Session methods
    revokeSession,
    revokeAllOtherSessions,
    refreshSessions,
    
    // Token & Session
    getToken,
    refreshSession,
    
    // Error handling
    clearError,
  };

  // Set context
  setContext(VAULT_CONTEXT_KEY, contextValue);
</script>

{@render children()}
