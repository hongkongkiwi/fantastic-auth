/**
 * Vault API Client
 *
 * HTTP client for the Vault API.
 */

import type {
  VaultConfig,
  User,
  Session,
  SessionInfo,
  UserProfile,
  SignInOptions,
  SignUpOptions,
  MagicLinkOptions,
  OAuthOptions,
  ForgotPasswordOptions,
  ResetPasswordOptions,
  VerifyEmailOptions,
  Organization,
  OrganizationMember,
  MfaChallenge,
  MfaMethod,
  TotpSetup,
  ApiError,
  WebAuthnOptions,
} from '../types';

const STORAGE_KEY = 'fantasticauth_session_token';
const STORAGE_REFRESH_KEY = 'fantasticauth_refresh_token';
const LEGACY_STORAGE_KEY = 'vault_session_token';
const LEGACY_STORAGE_REFRESH_KEY = 'vault_refresh_token';

type TokenStorageAdapter = NonNullable<VaultConfig['tokenStorageAdapter']>;

export class VaultApiClient {
  private config: VaultConfig;
  private baseUrl: string;
  private memoryStorage = new Map<string, string>();

  constructor(config: VaultConfig) {
    this.config = config;
    this.baseUrl = config.apiUrl.replace(/\/$/, '');
  }

  private getBrowserStorage(): TokenStorageAdapter | null {
    if (typeof window === 'undefined') {
      return null;
    }

    if (this.config.tokenStorageAdapter) {
      return this.config.tokenStorageAdapter;
    }

    const mode = this.config.tokenStorage ?? 'sessionStorage';
    if (mode === 'memory') {
      return null;
    }

    const storage = mode === 'localStorage' ? window.localStorage : window.sessionStorage;
    return {
      getItem: (key: string) => storage.getItem(key),
      setItem: (key: string, value: string) => storage.setItem(key, value),
      removeItem: (key: string) => storage.removeItem(key),
    };
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Tenant-ID': this.config.tenantId,
      ...((options.headers as Record<string, string>) || {}),
    };

    // Add auth token if available
    const token = await this.getStoredToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const fetchFn = this.config.fetch || fetch;

    if (this.config.debug) {
      console.log(`[Vault SDK] ${options.method || 'GET'} ${url}`);
    }

    const response = await fetchFn(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({
        message: 'An error occurred',
        code: 'unknown_error',
      }));

      if (this.config.debug) {
        console.error(`[Vault SDK] Error ${response.status}:`, error);
      }

      throw {
        message: error.message || 'An error occurred',
        code: error.code || 'unknown_error',
        details: error.details,
      } as ApiError;
    }

    // Handle empty responses
    if (response.status === 204) {
      return undefined as T;
    }

    return response.json();
  }

  // ============================================================================
  // Auth Methods
  // ============================================================================

  async signIn(options: SignInOptions): Promise<{
    user: User;
    session: Session;
    mfaRequired?: boolean;
    mfaChallenge?: MfaChallenge;
  }> {
    return this.request('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(options),
    });
  }

  async signUp(options: SignUpOptions): Promise<{
    user: User;
    session: Session;
  }> {
    return this.request('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(options),
    });
  }

  async sendMagicLink(options: MagicLinkOptions): Promise<void> {
    await this.request('/api/v1/auth/magic-link', {
      method: 'POST',
      body: JSON.stringify(options),
    });
  }

  async verifyMagicLink(token: string): Promise<{
    user: User;
    session: Session;
  }> {
    return this.request('/api/v1/auth/magic-link/verify', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  async sendForgotPassword(options: ForgotPasswordOptions): Promise<void> {
    await this.request('/api/v1/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify(options),
    });
  }

  async resetPassword(options: ResetPasswordOptions): Promise<{
    user: User;
    session: Session;
  }> {
    return this.request('/api/v1/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify(options),
    });
  }

  async verifyEmail(options: VerifyEmailOptions): Promise<{
    user: User;
  }> {
    return this.request('/api/v1/auth/verify-email', {
      method: 'POST',
      body: JSON.stringify(options),
    });
  }

  async resendVerificationEmail(): Promise<void> {
    await this.request('/api/v1/auth/verify-email/resend', {
      method: 'POST',
    });
  }

  async getOAuthUrl(options: OAuthOptions): Promise<{ url: string }> {
    const params = new URLSearchParams({
      provider: options.provider,
      ...(options.redirectUrl && { redirect_url: options.redirectUrl }),
    });

    return this.request(`/api/v1/auth/oauth/${options.provider}?${params}`);
  }

  async handleOAuthCallback(provider: string, code: string): Promise<{
    user: User;
    session: Session;
  }> {
    return this.request(`/api/v1/auth/oauth/${provider}/callback`, {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
  }

  async verifyMfa(code: string, method: MfaMethod): Promise<{
    user: User;
    session: Session;
  }> {
    return this.request('/api/v1/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ code, method }),
    });
  }

  async signOut(): Promise<void> {
    await this.request('/api/v1/auth/logout', {
      method: 'POST',
    });
  }

  async refreshSession(): Promise<{
    session: Session;
  }> {
    const refreshToken = await this.getStoredRefreshToken();
    return this.request('/api/v1/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken }),
    });
  }

  async validateSession(token: string): Promise<Session> {
    return this.request('/api/v1/auth/session', {
      headers: { Authorization: `Bearer ${token}` },
    });
  }

  // ============================================================================
  // User Methods
  // ============================================================================

  async getCurrentUser(): Promise<User> {
    return this.request('/api/v1/users/me');
  }

  async updateUser(updates: Partial<User> | Partial<UserProfile>): Promise<User> {
    return this.request('/api/v1/users/me', {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  }

  async deleteUser(): Promise<void> {
    await this.request('/api/v1/users/me', {
      method: 'DELETE',
    });
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.request('/api/v1/users/me/password', {
      method: 'PATCH',
      body: JSON.stringify({ currentPassword, newPassword }),
    });
  }

  async uploadAvatar(file: File): Promise<{ url: string }> {
    const formData = new FormData();
    formData.append('avatar', file);

    const url = `${this.baseUrl}/api/v1/users/me/avatar`;
    const headers: Record<string, string> = {
      'X-Tenant-ID': this.config.tenantId,
    };

    const token = await this.getStoredToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const fetchFn = this.config.fetch || fetch;
    const response = await fetchFn(url, {
      method: 'POST',
      headers,
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({
        message: 'Failed to upload avatar',
        code: 'avatar_upload_error',
      }));
      throw error;
    }

    return response.json();
  }

  // ============================================================================
  // MFA Methods
  // ============================================================================

  async getMfaStatus(): Promise<{
    enabled: boolean;
    methods: MfaMethod[];
  }> {
    return this.request('/api/v1/users/me/mfa');
  }

  async setupTotp(): Promise<TotpSetup> {
    return this.request('/api/v1/users/me/mfa/totp/setup', {
      method: 'POST',
    });
  }

  async verifyTotpSetup(code: string): Promise<void> {
    await this.request('/api/v1/users/me/mfa/totp/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
  }

  async disableMfa(method: MfaMethod): Promise<void> {
    await this.request('/api/v1/users/me/mfa', {
      method: 'DELETE',
      body: JSON.stringify({ method }),
    });
  }

  async generateBackupCodes(): Promise<{ codes: string[] }> {
    return this.request('/api/v1/users/me/mfa/backup-codes', {
      method: 'POST',
    });
  }

  async verifyBackupCode(code: string): Promise<void> {
    await this.request('/api/v1/users/me/mfa/backup-codes/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
  }

  // ============================================================================
  // WebAuthn Methods
  // ============================================================================

  async beginWebAuthnRegistration(): Promise<WebAuthnOptions> {
    return this.request('/api/v1/webauthn/register/begin', {
      method: 'POST',
    });
  }

  async finishWebAuthnRegistration(credential: unknown): Promise<void> {
    await this.request('/api/v1/webauthn/register/finish', {
      method: 'POST',
      body: JSON.stringify({ credential }),
    });
  }

  async beginWebAuthnAuthentication(): Promise<WebAuthnOptions> {
    return this.request('/api/v1/webauthn/authenticate/begin', {
      method: 'POST',
    });
  }

  async finishWebAuthnAuthentication(credential: unknown): Promise<{
    user: User;
    session: Session;
  }> {
    return this.request('/api/v1/webauthn/authenticate/finish', {
      method: 'POST',
      body: JSON.stringify({ credential }),
    });
  }

  async listWebAuthnCredentials(): Promise<Array<{
    id: string;
    name: string;
    createdAt: string;
    lastUsedAt?: string;
  }>> {
    return this.request('/api/v1/users/me/webauthn/credentials');
  }

  async deleteWebAuthnCredential(credentialId: string): Promise<void> {
    await this.request(`/api/v1/users/me/webauthn/credentials/${credentialId}`, {
      method: 'DELETE',
    });
  }

  // ============================================================================
  // Session Methods
  // ============================================================================

  async listSessions(): Promise<SessionInfo[]> {
    return this.request('/api/v1/users/me/sessions');
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.request(`/api/v1/users/me/sessions/${sessionId}`, {
      method: 'DELETE',
    });
  }

  async revokeAllSessions(): Promise<void> {
    await this.request('/api/v1/users/me/sessions', {
      method: 'DELETE',
    });
  }

  // ============================================================================
  // Organization Methods
  // ============================================================================

  async listOrganizations(): Promise<Organization[]> {
    return this.request('/api/v1/organizations');
  }

  async setActiveOrganization(orgId: string | null): Promise<{ user: User; session: Session }> {
    return this.request('/api/v1/users/me/active-organization', {
      method: 'PUT',
      body: JSON.stringify({ organizationId: orgId }),
    });
  }

  async getOrganization(id: string): Promise<Organization> {
    return this.request(`/api/v1/organizations/${id}`);
  }

  async createOrganization(data: { name: string; slug?: string }): Promise<Organization> {
    return this.request('/api/v1/organizations', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateOrganization(id: string, data: Partial<Organization>): Promise<Organization> {
    return this.request(`/api/v1/organizations/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  async deleteOrganization(id: string): Promise<void> {
    await this.request(`/api/v1/organizations/${id}`, {
      method: 'DELETE',
    });
  }

  async leaveOrganization(id: string): Promise<void> {
    await this.request(`/api/v1/organizations/${id}/leave`, {
      method: 'POST',
    });
  }

  async listOrganizationMembers(orgId: string): Promise<OrganizationMember[]> {
    return this.request(`/api/v1/organizations/${orgId}/members`);
  }

  async inviteOrganizationMember(orgId: string, email: string, role: string): Promise<void> {
    await this.request(`/api/v1/organizations/${orgId}/invite`, {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    });
  }

  async removeOrganizationMember(orgId: string, userId: string): Promise<void> {
    await this.request(`/api/v1/organizations/${orgId}/members/${userId}`, {
      method: 'DELETE',
    });
  }

  async updateOrganizationMemberRole(orgId: string, userId: string, role: string): Promise<void> {
    await this.request(`/api/v1/organizations/${orgId}/members/${userId}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    });
  }

  // ============================================================================
  // Session Storage
  // ============================================================================

  async storeToken(token: string): Promise<void> {
    const storage = this.getBrowserStorage();
    if (storage) {
      try {
        storage.setItem(STORAGE_KEY, token);
        storage.removeItem(LEGACY_STORAGE_KEY);
        return;
      } catch {
        // Fall back to in-memory if browser storage is unavailable.
      }
    }
    this.memoryStorage.set(STORAGE_KEY, token);
    this.memoryStorage.delete(LEGACY_STORAGE_KEY);
  }

  async storeRefreshToken(token: string): Promise<void> {
    const storage = this.getBrowserStorage();
    if (storage) {
      try {
        storage.setItem(STORAGE_REFRESH_KEY, token);
        storage.removeItem(LEGACY_STORAGE_REFRESH_KEY);
        return;
      } catch {
        // Fall back to in-memory if browser storage is unavailable.
      }
    }
    this.memoryStorage.set(STORAGE_REFRESH_KEY, token);
    this.memoryStorage.delete(LEGACY_STORAGE_REFRESH_KEY);
  }

  async getStoredToken(): Promise<string | null> {
    if (typeof window === 'undefined') {
      // SSR - return config token if provided
      return this.config.sessionToken || null;
    }
    const storage = this.getBrowserStorage();
    if (storage) {
      try {
        return (
          storage.getItem(STORAGE_KEY) ||
          storage.getItem(LEGACY_STORAGE_KEY)
        );
      } catch {
        // Fall back to in-memory if browser storage is unavailable.
      }
    }
    return (
      this.memoryStorage.get(STORAGE_KEY) ||
      this.memoryStorage.get(LEGACY_STORAGE_KEY) ||
      null
    );
  }

  async getStoredRefreshToken(): Promise<string | null> {
    if (typeof window === 'undefined') {
      return null;
    }
    const storage = this.getBrowserStorage();
    if (storage) {
      try {
        return (
          storage.getItem(STORAGE_REFRESH_KEY) ||
          storage.getItem(LEGACY_STORAGE_REFRESH_KEY)
        );
      } catch {
        // Fall back to in-memory if browser storage is unavailable.
      }
    }
    return (
      this.memoryStorage.get(STORAGE_REFRESH_KEY) ||
      this.memoryStorage.get(LEGACY_STORAGE_REFRESH_KEY) ||
      null
    );
  }

  async clearToken(): Promise<void> {
    const storage = this.getBrowserStorage();
    if (storage) {
      try {
        storage.removeItem(STORAGE_KEY);
        storage.removeItem(STORAGE_REFRESH_KEY);
        storage.removeItem(LEGACY_STORAGE_KEY);
        storage.removeItem(LEGACY_STORAGE_REFRESH_KEY);
      } catch {
        // Ignore storage failures and clear in-memory copy below.
      }
    }
    this.memoryStorage.delete(STORAGE_KEY);
    this.memoryStorage.delete(STORAGE_REFRESH_KEY);
    this.memoryStorage.delete(LEGACY_STORAGE_KEY);
    this.memoryStorage.delete(LEGACY_STORAGE_REFRESH_KEY);
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Check if WebAuthn is supported in the current browser
   */
  isWebAuthnSupported(): boolean {
    return typeof window !== 'undefined' &&
      typeof window.PublicKeyCredential !== 'undefined';
  }
}

// Export singleton instance creation helper
export function createVaultClient(config: VaultConfig): VaultApiClient {
  return new VaultApiClient(config);
}
