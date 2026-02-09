/**
 * Main Vault Auth client implementation
 */

import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios';
import axiosRetry from 'axios-retry';

import {
  VaultAuthConfig,
  User,
  Organization,
  OrganizationMembership,
  Session,
  JWKS,
  TokenPayload,
  PaginatedResponse,
  CreateUserRequest,
  UpdateUserRequest,
  CreateOrganizationRequest,
  UpdateOrganizationRequest,
  AddMemberRequest,
  UpdateMemberRoleRequest,
  APIResponse,
  UserListResponse,
  OrganizationListResponse,
  MembershipListResponse,
  SessionListResponse,
} from './types.js';

import {
  VaultAuthError,
  ConfigurationError,
  TokenExpiredError,
  InvalidTokenError,
  errorFromResponse,
} from './errors.js';

/**
 * Vault Auth client for authentication and user management
 */
export class VaultAuth {
  private readonly http: AxiosInstance;
  private readonly config: Required<VaultAuthConfig>;
  private jwks: JWKS | null = null;
  private jwksFetchedAt: number = 0;

  private _usersAPI?: UsersAPI;
  private _organizationsAPI?: OrganizationsAPI;
  private _sessionsAPI?: SessionsAPI;

  /**
   * Create a new Vault Auth client
   * @param config - Client configuration
   */
  constructor(config: VaultAuthConfig) {
    // Validate API key
    if (!config.apiKey) {
      throw new ConfigurationError('API key is required');
    }
    if (!config.apiKey.startsWith('vault_m2m_')) {
      throw new ConfigurationError("API key must start with 'vault_m2m_'");
    }

    // Set defaults
    this.config = {
      apiKey: config.apiKey,
      baseURL: config.baseURL || 'https://api.vault.dev',
      timeout: config.timeout || 30000,
      maxRetries: config.maxRetries || 3,
      retryDelay: config.retryDelay || 1000,
      requestId: config.requestId,
      jwksCacheTTL: config.jwksCacheTTL || 3600000,
    };

    // Create axios instance
    this.http = axios.create({
      baseURL: this.config.baseURL,
      timeout: this.config.timeout,
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'vault-auth-node/1.0.0',
      },
    });

    // Add request ID if provided
    if (this.config.requestId) {
      this.http.defaults.headers['X-Request-ID'] = this.config.requestId;
    }

    // Configure retry logic
    axiosRetry(this.http, {
      retries: this.config.maxRetries,
      retryDelay: (retryCount) => {
        return this.config.retryDelay * Math.pow(2, retryCount - 1);
      },
      retryCondition: (error: AxiosError) => {
        // Retry on network errors or 5xx responses
        return axiosRetry.isNetworkOrIdempotentRequestError(error) ||
          (error.response?.status !== undefined && error.response.status >= 500);
      },
    });

    // Add response interceptor for error handling
    this.http.interceptors.response.use(
      (response) => response,
      (error: AxiosError<{ message?: string; code?: string; details?: Record<string, unknown> }>) => {
        if (error.response) {
          const { status, data, headers } = error.response;
          const requestId = headers['x-request-id'] as string | undefined;
          throw errorFromResponse(
            status,
            data?.message || 'Unknown error',
            data?.code,
            data?.details,
            requestId,
            headers as Record<string, string>
          );
        }
        throw new VaultAuthError(error.message || 'Request failed');
      }
    );
  }

  /** Users API */
  get users(): UsersAPI {
    if (!this._usersAPI) {
      this._usersAPI = new UsersAPI(this.http);
    }
    return this._usersAPI;
  }

  /** Organizations API */
  get organizations(): OrganizationsAPI {
    if (!this._organizationsAPI) {
      this._organizationsAPI = new OrganizationsAPI(this.http);
    }
    return this._organizationsAPI;
  }

  /** Sessions API */
  get sessions(): SessionsAPI {
    if (!this._sessionsAPI) {
      this._sessionsAPI = new SessionsAPI(this.http);
    }
    return this._sessionsAPI;
  }

  /**
   * Get JWKS, fetching if necessary
   */
  private async getJWKS(): Promise<JWKS> {
    const now = Date.now();
    if (!this.jwks || now - this.jwksFetchedAt > this.config.jwksCacheTTL) {
      const response = await this.http.get<JWKS>('/.well-known/jwks.json');
      this.jwks = response.data;
      this.jwksFetchedAt = now;
    }
    return this.jwks;
  }

  /**
   * Verify a JWT token and return the associated user
   * @param token - JWT token string
   * @returns Authenticated user
   */
  async verifyToken(token: string): Promise<User> {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new InvalidTokenError('Invalid token format');
      }

      // Decode header
      const headerJson = Buffer.from(parts[0] + '==', 'base64url').toString();
      const header = JSON.parse(headerJson) as { kid?: string };

      if (!header.kid) {
        throw new InvalidTokenError('Token missing key ID');
      }

      // Get JWKS
      await this.getJWKS();

      // Decode payload to check expiration
      const payloadJson = Buffer.from(parts[1] + '==', 'base64url').toString();
      const payload = JSON.parse(payloadJson) as { exp?: number };

      if (payload.exp && payload.exp * 1000 < Date.now()) {
        throw new TokenExpiredError();
      }

      // Verify token via API
      const response = await this.http.post<APIResponse<User>>('/api/v1/auth/verify', {
        token,
      });

      return this.parseUser(response.data.data);
    } catch (error) {
      if (error instanceof VaultAuthError) {
        throw error;
      }
      throw new InvalidTokenError(`Token verification failed: ${(error as Error).message}`);
    }
  }

  /**
   * Decode a JWT token without verification
   * @param token - JWT token string
   * @returns Decoded token payload
   */
  decodeToken(token: string): TokenPayload {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new InvalidTokenError('Invalid token format');
      }

      const payloadJson = Buffer.from(parts[1] + '==', 'base64url').toString();
      const payload = JSON.parse(payloadJson) as TokenPayload;
      return payload;
    } catch (error) {
      throw new InvalidTokenError(`Failed to decode token: ${(error as Error).message}`);
    }
  }

  /**
   * Get JWKS (JSON Web Key Set)
   */
  async getJWKS(): Promise<JWKS> {
    return this.getJWKS();
  }

  /**
   * Check Vault API health status
   */
  async healthCheck(): Promise<Record<string, unknown>> {
    const response = await this.http.get<Record<string, unknown>>('/health');
    return response.data;
  }

  /**
   * Parse user from API response
   */
  private parseUser(data: User & Record<string, string>): User {
    return {
      ...data,
      createdAt: data.createdAt ? new Date(data.createdAt) : undefined,
      updatedAt: data.updatedAt ? new Date(data.updatedAt) : undefined,
      lastLoginAt: data.lastLoginAt ? new Date(data.lastLoginAt) : undefined,
    };
  }
}

/**
 * Users API endpoints
 */
export class UsersAPI {
  constructor(private readonly http: AxiosInstance) {}

  /** Get user by ID */
  async get(userId: string): Promise<User> {
    const response = await this.http.get<APIResponse<User>>(`/api/v1/users/${userId}`);
    return this.parseUser(response.data.data);
  }

  /** Get user by email address */
  async getByEmail(email: string): Promise<User> {
    const response = await this.http.get<APIResponse<User>>(`/api/v1/users/email/${email}`);
    return this.parseUser(response.data.data);
  }

  /** List users with optional filtering */
  async list(
    options: {
      page?: number;
      perPage?: number;
      status?: string;
      organizationId?: string;
    } = {}
  ): Promise<PaginatedResponse<User>> {
    const params: Record<string, string | number> = {
      page: options.page || 1,
      per_page: options.perPage || 20,
    };
    if (options.status) params.status = options.status;
    if (options.organizationId) params.organization_id = options.organizationId;

    const response = await this.http.get<APIResponse<UserListResponse>>('/api/v1/users', { params });
    const data = response.data.data;

    return {
      data: data.users.map((u) => this.parseUser(u as User & Record<string, string>)),
      total: data.total,
      page: data.page,
      perPage: data.per_page,
      hasMore: data.has_more,
    };
  }

  /** Create a new user */
  async create(request: CreateUserRequest): Promise<User> {
    const response = await this.http.post<APIResponse<User>>('/api/v1/users', request);
    return this.parseUser(response.data.data);
  }

  /** Update user information */
  async update(userId: string, request: UpdateUserRequest): Promise<User> {
    const response = await this.http.patch<APIResponse<User>>(`/api/v1/users/${userId}`, request);
    return this.parseUser(response.data.data);
  }

  /** Delete a user */
  async delete(userId: string): Promise<void> {
    await this.http.delete(`/api/v1/users/${userId}`);
  }

  /** Update user password */
  async updatePassword(userId: string, password: string): Promise<void> {
    await this.http.patch(`/api/v1/users/${userId}/password`, { password });
  }

  /** Get organizations a user belongs to */
  async getOrganizations(userId: string): Promise<OrganizationMembership[]> {
    const response = await this.http.get<APIResponse<{ memberships: OrganizationMembership[] }>>(
      `/api/v1/users/${userId}/organizations`
    );
    return response.data.data.memberships.map((m) => this.parseMembership(m));
  }

  /** Get user's active sessions */
  async getSessions(userId: string): Promise<Session[]> {
    const response = await this.http.get<APIResponse<SessionListResponse>>(
      `/api/v1/users/${userId}/sessions`
    );
    return response.data.data.sessions.map((s) => this.parseSession(s));
  }

  private parseUser(data: User & Record<string, string>): User {
    return {
      ...data,
      createdAt: data.createdAt ? new Date(data.createdAt) : undefined,
      updatedAt: data.updatedAt ? new Date(data.updatedAt) : undefined,
      lastLoginAt: data.lastLoginAt ? new Date(data.lastLoginAt) : undefined,
    };
  }

  private parseMembership(data: OrganizationMembership & Record<string, string>): OrganizationMembership {
    return {
      ...data,
      joinedAt: data.joinedAt ? new Date(data.joinedAt) : undefined,
      organization: data.organization ? this.parseOrganization(data.organization as Organization & Record<string, string>) : undefined,
    };
  }

  private parseOrganization(data: Organization & Record<string, string>): Organization {
    return {
      ...data,
      createdAt: data.createdAt ? new Date(data.createdAt) : undefined,
      updatedAt: data.updatedAt ? new Date(data.updatedAt) : undefined,
    };
  }

  private parseSession(data: Session & Record<string, string>): Session {
    return {
      ...data,
      createdAt: data.createdAt ? new Date(data.createdAt) : undefined,
      expiresAt: data.expiresAt ? new Date(data.expiresAt) : undefined,
      lastUsedAt: data.lastUsedAt ? new Date(data.lastUsedAt) : undefined,
      revokedAt: data.revokedAt ? new Date(data.revokedAt) : undefined,
    };
  }
}

/**
 * Organizations API endpoints
 */
export class OrganizationsAPI {
  constructor(private readonly http: AxiosInstance) {}

  /** Get organization by ID */
  async get(orgId: string): Promise<Organization> {
    const response = await this.http.get<APIResponse<Organization>>(`/api/v1/organizations/${orgId}`);
    return this.parseOrganization(response.data.data);
  }

  /** Get organization by slug */
  async getBySlug(slug: string): Promise<Organization> {
    const response = await this.http.get<APIResponse<Organization>>(`/api/v1/organizations/slug/${slug}`);
    return this.parseOrganization(response.data.data);
  }

  /** List organizations */
  async list(options: { page?: number; perPage?: number } = {}): Promise<PaginatedResponse<Organization>> {
    const params: Record<string, number> = {
      page: options.page || 1,
      per_page: options.perPage || 20,
    };

    const response = await this.http.get<APIResponse<OrganizationListResponse>>('/api/v1/organizations', { params });
    const data = response.data.data;

    return {
      data: data.organizations.map((o) => this.parseOrganization(o as Organization & Record<string, string>)),
      total: data.total,
      page: data.page,
      perPage: data.per_page,
      hasMore: data.has_more,
    };
  }

  /** Create a new organization */
  async create(request: CreateOrganizationRequest): Promise<Organization> {
    const response = await this.http.post<APIResponse<Organization>>('/api/v1/organizations', request);
    return this.parseOrganization(response.data.data);
  }

  /** Update organization information */
  async update(orgId: string, request: UpdateOrganizationRequest): Promise<Organization> {
    const response = await this.http.patch<APIResponse<Organization>>(`/api/v1/organizations/${orgId}`, request);
    return this.parseOrganization(response.data.data);
  }

  /** Delete an organization */
  async delete(orgId: string): Promise<void> {
    await this.http.delete(`/api/v1/organizations/${orgId}`);
  }

  /** Get organization members */
  async getMembers(orgId: string): Promise<OrganizationMembership[]> {
    const response = await this.http.get<APIResponse<MembershipListResponse>>(
      `/api/v1/organizations/${orgId}/members`
    );
    return response.data.data.members.map((m) => this.parseMembership(m));
  }

  /** Add a member to organization */
  async addMember(orgId: string, request: AddMemberRequest): Promise<OrganizationMembership> {
    const response = await this.http.post<APIResponse<OrganizationMembership>>(
      `/api/v1/organizations/${orgId}/members`,
      request
    );
    return this.parseMembership(response.data.data);
  }

  /** Remove a member from organization */
  async removeMember(orgId: string, userId: string): Promise<void> {
    await this.http.delete(`/api/v1/organizations/${orgId}/members/${userId}`);
  }

  /** Update member's role in organization */
  async updateMemberRole(
    orgId: string,
    userId: string,
    request: UpdateMemberRoleRequest
  ): Promise<OrganizationMembership> {
    const response = await this.http.patch<APIResponse<OrganizationMembership>>(
      `/api/v1/organizations/${orgId}/members/${userId}`,
      request
    );
    return this.parseMembership(response.data.data);
  }

  private parseOrganization(data: Organization & Record<string, string>): Organization {
    return {
      ...data,
      createdAt: data.createdAt ? new Date(data.createdAt) : undefined,
      updatedAt: data.updatedAt ? new Date(data.updatedAt) : undefined,
    };
  }

  private parseMembership(data: OrganizationMembership & Record<string, string>): OrganizationMembership {
    return {
      ...data,
      joinedAt: data.joinedAt ? new Date(data.joinedAt) : undefined,
      organization: data.organization ? this.parseOrganization(data.organization as Organization & Record<string, string>) : undefined,
    };
  }
}

/**
 * Sessions API endpoints
 */
export class SessionsAPI {
  constructor(private readonly http: AxiosInstance) {}

  /** Get session by ID */
  async get(sessionId: string): Promise<Session> {
    const response = await this.http.get<APIResponse<Session>>(`/api/v1/sessions/${sessionId}`);
    return this.parseSession(response.data.data);
  }

  /** Revoke a session */
  async revoke(sessionId: string): Promise<void> {
    await this.http.post(`/api/v1/sessions/${sessionId}/revoke`);
  }

  /** Revoke all sessions for a user */
  async revokeAllUserSessions(userId: string): Promise<void> {
    await this.http.post(`/api/v1/users/${userId}/sessions/revoke-all`);
  }

  private parseSession(data: Session & Record<string, string>): Session {
    return {
      ...data,
      createdAt: data.createdAt ? new Date(data.createdAt) : undefined,
      expiresAt: data.expiresAt ? new Date(data.expiresAt) : undefined,
      lastUsedAt: data.lastUsedAt ? new Date(data.lastUsedAt) : undefined,
      revokedAt: data.revokedAt ? new Date(data.revokedAt) : undefined,
    };
  }
}
