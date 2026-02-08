/**
 * Vault Internal API Client
 * 
 * A TypeScript client for the Vault Internal API, designed for
 * SaaS platform services and internal tools.
 */

import type {
  Tenant,
  CreateTenantRequest,
  UpdateTenantRequest,
  ListTenantsResponse,
  SuspendTenantRequest,
  MigrationRequest,
  MigrationResponse,
  PlatformUser,
  PlatformUserDetail,
  ListPlatformUsersResponse,
  ImpersonateRequest,
  ImpersonateResponse,
  Subscription,
  ListSubscriptionsResponse,
  UpdateSubscriptionRequest,
  Invoice,
  GenerateInvoiceRequest,
  PlatformOverview,
  TenantAnalyticsResponse,
  UsageAnalyticsResponse,
  FeatureFlag,
  CreateFeatureFlagRequest,
  UpdateFeatureFlagRequest,
  OAuthProviderConfig,
  AddOAuthProviderRequest,
  RunMigrationsRequest,
  RunMigrationsResponse,
  TriggerBackupRequest,
  TriggerBackupResponse,
  ListTenantsQuery,
  SearchUsersQuery,
  ListSubscriptionsQuery,
  DateRangeQuery,
  UsageQuery,
  MessageResponse,
} from './generated/client';

export interface VaultInternalClientOptions {
  /** Base URL of the Vault API */
  baseUrl: string;
  /** API Key for authentication */
  apiKey: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom fetch implementation */
  fetch?: typeof fetch;
}

export interface RequestOptions {
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Additional headers */
  headers?: Record<string, string>;
}

export class VaultInternalError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'VaultInternalError';
  }
}

export class VaultInternalClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly fetch: typeof fetch;

  constructor(options: VaultInternalClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.apiKey = options.apiKey;
    this.timeout = options.timeout ?? 30000;
    this.fetch = options.fetch ?? globalThis.fetch;

    if (!this.apiKey) {
      throw new Error('API key is required');
    }
  }

  // ========================================================================
  // HTTP Client
  // ========================================================================

  private async request<T>(
    method: string,
    path: string,
    options: {
      body?: unknown;
      query?: Record<string, string | number | boolean | undefined>;
      requestOptions?: RequestOptions;
    } = {}
  ): Promise<T> {
    const { body, query, requestOptions } = options;

    // Build URL with query parameters
    let url = `${this.baseUrl}${path}`;
    if (query) {
      const params = new URLSearchParams();
      Object.entries(query).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          params.append(key, String(value));
        }
      });
      const queryString = params.toString();
      if (queryString) {
        url += `?${queryString}`;
      }
    }

    // Build headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-API-Key': this.apiKey,
      ...requestOptions?.headers,
    };

    // Build request init
    const init: RequestInit = {
      method,
      headers,
    };

    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }

    // Execute request with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), requestOptions?.timeout ?? this.timeout);

    try {
      const response = await this.fetch(url, {
        ...init,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Handle errors
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new VaultInternalError(
          errorData.error?.message || `HTTP ${response.status}: ${response.statusText}`,
          errorData.error?.code || 'UNKNOWN_ERROR',
          response.status,
          errorData.error?.details
        );
      }

      // Handle empty responses
      if (response.status === 204) {
        return undefined as T;
      }

      return await response.json() as T;
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof VaultInternalError) {
        throw error;
      }
      
      if (error instanceof Error && error.name === 'AbortError') {
        throw new VaultInternalError(
          'Request timeout',
          'TIMEOUT',
          408
        );
      }
      
      throw new VaultInternalError(
        error instanceof Error ? error.message : 'Unknown error',
        'NETWORK_ERROR',
        0
      );
    }
  }

  // ========================================================================
  // Tenant Management
  // ========================================================================

  /**
   * List all tenants on the platform
   */
  async listTenants(query?: ListTenantsQuery): Promise<ListTenantsResponse> {
    return this.request('GET', '/tenants', { query });
  }

  /**
   * Get a specific tenant by ID
   */
  async getTenant(tenantId: string): Promise<Tenant> {
    return this.request('GET', `/tenants/${tenantId}`);
  }

  /**
   * Create a new tenant (SaaS signup)
   */
  async createTenant(data: CreateTenantRequest): Promise<Tenant> {
    return this.request('POST', '/tenants', { body: data });
  }

  /**
   * Update tenant settings
   */
  async updateTenant(tenantId: string, data: UpdateTenantRequest): Promise<Tenant> {
    return this.request('PATCH', `/tenants/${tenantId}`, { body: data });
  }

  /**
   * Delete a tenant permanently
   */
  async deleteTenant(tenantId: string, force = false): Promise<MessageResponse> {
    return this.request('DELETE', `/tenants/${tenantId}`, {
      query: { force },
    });
  }

  /**
   * Suspend a tenant (e.g., for billing issues)
   */
  async suspendTenant(
    tenantId: string,
    data?: SuspendTenantRequest
  ): Promise<Tenant> {
    return this.request('POST', `/tenants/${tenantId}/suspend`, { body: data });
  }

  /**
   * Activate/reactivate a suspended tenant
   */
  async activateTenant(tenantId: string): Promise<Tenant> {
    return this.request('POST', `/tenants/${tenantId}/activate`);
  }

  /**
   * Run database migrations for a specific tenant
   */
  async migrateTenant(
    tenantId: string,
    data?: MigrationRequest
  ): Promise<MigrationResponse> {
    return this.request('POST', `/tenants/${tenantId}/migrate`, { body: data });
  }

  // ========================================================================
  // Platform Users
  // ========================================================================

  /**
   * Search users across all tenants
   */
  async searchUsers(query?: SearchUsersQuery): Promise<ListPlatformUsersResponse> {
    return this.request('GET', '/users', { query });
  }

  /**
   * Get user details with all tenant memberships
   */
  async getUser(userId: string): Promise<PlatformUserDetail> {
    return this.request('GET', `/users/${userId}`);
  }

  /**
   * Generate an impersonation token for support
   * 
   * ⚠️ This is a privileged operation that is heavily audited
   */
  async impersonateUser(
    userId: string,
    data: ImpersonateRequest
  ): Promise<ImpersonateResponse> {
    return this.request('POST', `/users/${userId}/impersonate`, { body: data });
  }

  // ========================================================================
  // Billing
  // ========================================================================

  /**
   * List all subscriptions
   */
  async listSubscriptions(query?: ListSubscriptionsQuery): Promise<ListSubscriptionsResponse> {
    return this.request('GET', '/billing/subscriptions', { query });
  }

  /**
   * Get subscription for a specific tenant
   */
  async getSubscription(tenantId: string): Promise<Subscription> {
    return this.request('GET', `/billing/tenants/${tenantId}/subscription`);
  }

  /**
   * Update tenant subscription (plan, seats, etc.)
   */
  async updateSubscription(
    tenantId: string,
    data: UpdateSubscriptionRequest
  ): Promise<Subscription> {
    return this.request('PATCH', `/billing/tenants/${tenantId}/subscription`, { body: data });
  }

  /**
   * Generate an invoice for a tenant
   */
  async generateInvoice(
    tenantId: string,
    data: GenerateInvoiceRequest
  ): Promise<Invoice> {
    return this.request('POST', `/billing/tenants/${tenantId}/invoice`, { body: data });
  }

  /**
   * Process billing webhook (Stripe, etc.)
   * 
   * Use this to forward webhooks from your payment provider
   */
  async processBillingWebhook(payload: unknown): Promise<void> {
    await this.request('POST', '/billing/webhook', { body: payload });
  }

  // ========================================================================
  // Analytics
  // ========================================================================

  /**
   * Get platform overview metrics (MRR, churn, etc.)
   */
  async getPlatformOverview(): Promise<PlatformOverview> {
    return this.request('GET', '/analytics/overview');
  }

  /**
   * Get tenant growth analytics
   */
  async getTenantAnalytics(query?: DateRangeQuery): Promise<TenantAnalyticsResponse> {
    return this.request('GET', '/analytics/tenants', { query });
  }

  /**
   * Get platform usage metrics
   */
  async getUsageAnalytics(query: UsageQuery): Promise<UsageAnalyticsResponse> {
    return this.request('GET', '/analytics/usage', { query });
  }

  // ========================================================================
  // Configuration
  // ========================================================================

  /**
   * List all feature flags
   */
  async listFeatureFlags(): Promise<FeatureFlag[]> {
    return this.request('GET', '/config/features');
  }

  /**
   * Create a new feature flag
   */
  async createFeatureFlag(data: CreateFeatureFlagRequest): Promise<FeatureFlag> {
    return this.request('POST', '/config/features', { body: data });
  }

  /**
   * Update a feature flag
   */
  async updateFeatureFlag(
    flagId: string,
    data: UpdateFeatureFlagRequest
  ): Promise<FeatureFlag> {
    return this.request('PATCH', `/config/features/${flagId}`, { body: data });
  }

  /**
   * List configured OAuth providers
   */
  async listOAuthProviders(): Promise<OAuthProviderConfig[]> {
    return this.request('GET', '/config/oauth-providers');
  }

  /**
   * Add a new OAuth provider
   */
  async addOAuthProvider(data: AddOAuthProviderRequest): Promise<OAuthProviderConfig> {
    return this.request('POST', '/config/oauth-providers', { body: data });
  }

  // ========================================================================
  // Maintenance
  // ========================================================================

  /**
   * Run database migrations across all tenants
   */
  async runMigrations(data?: RunMigrationsRequest): Promise<RunMigrationsResponse> {
    return this.request('POST', '/maintenance/migrations', { body: data });
  }

  /**
   * Trigger backup for tenant(s) or entire platform
   */
  async triggerBackup(data?: TriggerBackupRequest): Promise<TriggerBackupResponse> {
    return this.request('POST', '/maintenance/backup', { body: data });
  }
}
