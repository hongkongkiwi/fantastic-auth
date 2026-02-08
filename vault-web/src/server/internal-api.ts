import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/start-server-core'
import type { components } from '../sdk/internal'
import { authMiddleware, assertAuthConfigured } from './auth-middleware'
import {
  appendAuditEvent,
  readAuditEvents,
  countAuditEvents,
  auditFileSize,
  streamAuditCsv,
  type AuditEvent,
  type AuditRecord,
} from './audit'
import { gzipSync } from 'node:zlib'
import { Readable } from 'node:stream'
import { createInternalClient, fetchWithRetry } from './internal-client'
import {
  createSession,
  getSessionCookieName,
  getSessionTtlSeconds,
  parseCookie,
  revokeSession,
} from './session'
import {
  recordAuditExportBytes,
  recordAuditExportError,
  recordAuditExportRequest,
} from './metrics'
import { env } from '../env/server'
import { serverLogger } from '../lib/server-logger'

export type TenantDetail = components['schemas']['TenantDetailResponse']
export type TenantListResponse = {
  data?: TenantDetail[]
  pagination?: components['schemas']['PaginationResponse']
}
export type SubscriptionDetail = components['schemas']['SubscriptionResponse']
export type SubscriptionListResponse = {
  data?: SubscriptionDetail[]
}
export type PlatformOverview = components['schemas']['PlatformOverviewResponse']
export type InvoiceResponse = components['schemas']['InvoiceResponse']
export type FeatureFlag = components['schemas']['FeatureFlagResponse']
export type OrganizationResponse = components['schemas']['OrganizationResponse']
export type OrganizationMemberResponse =
  components['schemas']['OrganizationMemberResponse']
export type RoleResponse = components['schemas']['RoleResponse']
export type ApiKeyResponse = components['schemas']['ApiKeyResponse']
export type CreateApiKeyResponse = components['schemas']['CreateApiKeyResponse']
export type NotificationResponse = components['schemas']['NotificationResponse']
export type SupportTicketResponse = components['schemas']['SupportTicketResponse']
export type SupportIncidentResponse =
  components['schemas']['SupportIncidentResponse']
export type ServiceStatusResponse =
  components['schemas']['ServiceStatusResponse']
export type TenantAnalyticsPoint = {
  date?: string
  newTenants?: number
  activeTenants?: number
  churnedTenants?: number
}
export type TenantAnalyticsResponse = {
  data?: TenantAnalyticsPoint[]
}
export type UsageAnalyticsResponse = {
  total?: number
  byTenant?: {
    tenantId?: string
    value?: number
  }[]
}
export type MigrationResult = {
  success?: boolean
  version?: string
  duration?: number
}
export type PlatformUserResponse = components['schemas']['PlatformUserResponse']
export type PlatformUserDetailResponse =
  components['schemas']['PlatformUserDetailResponse']
export type AuditLogEvent = AuditRecord

// Ownership types
export type OwnershipStatus = {
  isOwner: boolean
  isPrimaryOwner: boolean
  canDelete: boolean
  canTransfer: boolean
  ownedTenants: string[]
}

export type OwnershipTransferRequest = {
  id: string
  tenantId: string
  tenantName: string
  fromUserId: string
  fromUserName: string
  toUserId: string
  toUserName: string
  toUserEmail: string
  status: 'pending' | 'accepted' | 'rejected' | 'expired'
  createdAt: string
  expiresAt: string
}

export type UiConfig = {
  internalApiBaseUrl: string
  hasApiKey: boolean
}

type UiAuth = {
  uiToken?: string
}

type ListTenantsInput = {
  baseUrl?: string
  page?: number
  perPage?: number
} & UiAuth

type ListSubscriptionsInput = {
  baseUrl?: string
  status?: 'active' | 'past_due' | 'canceled' | 'trialing'
} & UiAuth

type CreateTenantInput = {
  baseUrl?: string
  name: string
  slug: string
  plan: 'free' | 'starter' | 'pro' | 'enterprise'
  ownerEmail?: string
  ownerName?: string
  customDomain?: string
} & UiAuth

type GetTenantInput = {
  baseUrl?: string
  tenantId: string
} & UiAuth

type UpdateSubscriptionInput = {
  baseUrl?: string
  tenantId: string
  plan?: 'free' | 'starter' | 'pro' | 'enterprise'
  seats?: number
  billingInterval?: 'monthly' | 'annual'
} & UiAuth

type UpdateTenantInput = {
  baseUrl?: string
  tenantId: string
  name?: string
  plan?: 'free' | 'starter' | 'pro' | 'enterprise'
  limits?: {
    maxUsers?: number
    maxOrganizations?: number
    maxApiCallsPerMonth?: number
  }
  settings?: {
    allowCustomBranding?: boolean
    allowSso?: boolean
    allowApiAccess?: boolean
  }
} & UiAuth

type SuspendTenantInput = {
  baseUrl?: string
  tenantId: string
  reason?: string
  suspendUntil?: string
} & UiAuth

type ActivateTenantInput = {
  baseUrl?: string
  tenantId: string
} & UiAuth

type GenerateInvoiceInput = {
  baseUrl?: string
  tenantId: string
  amount?: number
  description?: string
} & UiAuth

type GetUsageAnalyticsInput = {
  baseUrl?: string
  metric: 'activeUsers' | 'logins' | 'apiCalls' | 'storage'
} & UiAuth

type GetTenantAnalyticsInput = {
  baseUrl?: string
} & UiAuth

type ListFeatureFlagsInput = {
  baseUrl?: string
} & UiAuth

type UpdateFeatureFlagInput = {
  baseUrl?: string
  flagId: string
  enabled?: boolean
  rolloutPercentage?: number
  allowedTenants?: string[]
} & UiAuth

type GetOrganizationInput = {
  baseUrl?: string
  orgId: string
} & UiAuth

type ListOrganizationMembersInput = {
  baseUrl?: string
  orgId: string
} & UiAuth

type CreateRoleInput = {
  baseUrl?: string
  name: string
  description?: string
  scope?: string
  permissions?: string[]
} & UiAuth

type UpdateRoleInput = {
  baseUrl?: string
  roleId: string
  name?: string
  description?: string
  permissions?: string[]
  status?: string
} & UiAuth

type CreateApiKeyInput = {
  baseUrl?: string
  name: string
  scopes: string[]
  expiresInDays?: number
} & UiAuth

type DeleteApiKeyInput = {
  baseUrl?: string
  keyId: string
} & UiAuth

type MarkNotificationsReadInput = {
  baseUrl?: string
  ids: string[]
} & UiAuth

type DeleteTenantInput = {
  baseUrl?: string
  tenantId: string
  force?: boolean
} & UiAuth

type MigrateTenantInput = {
  baseUrl?: string
  tenantId: string
  targetVersion?: string
} & UiAuth

type GetSubscriptionInput = {
  baseUrl?: string
  tenantId: string
} & UiAuth

type SearchUsersInput = {
  baseUrl?: string
  email?: string
  tenantId?: string
  page?: number
} & UiAuth

type GetUserInput = {
  baseUrl?: string
  userId: string
} & UiAuth

type DeleteUserInput = {
  baseUrl?: string
  userId: string
  tenantId?: string
} & UiAuth

type GetOwnershipStatusInput = {
  baseUrl?: string
  userId: string
} & UiAuth

type TransferOwnershipInput = {
  baseUrl?: string
  tenantId: string
  fromUserId: string
  toUserId: string
} & UiAuth

type AcceptOwnershipTransferInput = {
  baseUrl?: string
  transferId: string
  accept: boolean
} & UiAuth

type GetOwnershipTransfersInput = {
  baseUrl?: string
  userId?: string
  tenantId?: string
  status?: 'pending' | 'accepted' | 'rejected' | 'expired'
} & UiAuth

type RecordAuditInput = {
  action: string
  detail: string
  timestamp?: string
} & UiAuth

type ListAuditInput = {
  action?: string
  since?: string
  until?: string
  sort?: 'asc' | 'desc'
  page?: number
  perPage?: number
} & UiAuth

const DEFAULT_BASE_URL = 'http://localhost:3000/api/v1/internal'
const CACHE_TTL_MS = 30_000

export const getUiConfig = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async () => ({
    internalApiBaseUrl: env.INTERNAL_API_BASE_URL || DEFAULT_BASE_URL,
    hasApiKey: Boolean(env.INTERNAL_API_KEY),
  }))

const normalizeBaseUrl = (baseUrl?: string) =>
  (baseUrl || env.INTERNAL_API_BASE_URL || DEFAULT_BASE_URL).replace(
    /\/+$/,
    '',
  )

const getClient = (baseUrl?: string) =>
  createInternalClient(normalizeBaseUrl(baseUrl))

const normalizeApiError = (error: unknown, response?: Response | null) => {
  const message =
    typeof error === 'string'
      ? error
      : error instanceof Error
        ? error.message
        : JSON.stringify(error ?? 'Unknown error')

  if (response) {
    serverLogger.error(`Internal API error: ${message}`, undefined, {
      status: response.status,
    })
    return `Internal API error (${response.status}): ${message}`
  }
  serverLogger.error(`Internal API error: ${message}`)
  return message
}

type CacheEntry<T> = { expiresAt: number; value: T }
const cache = new Map<string, CacheEntry<unknown>>()

const getCached = <T,>(key: string): T | null => {
  const entry = cache.get(key)
  if (!entry) return null
  if (entry.expiresAt < Date.now()) {
    cache.delete(key)
    return null
  }
  return entry.value as T
}

const setCached = <T,>(key: string, value: T) => {
  cache.set(key, { expiresAt: Date.now() + CACHE_TTL_MS, value })
}

const buildCacheKey = (prefix: string, data?: Record<string, unknown>) =>
  `${prefix}:${JSON.stringify(data ?? {})}`

const requireUiToken = (data?: UiAuth) => {
  const requiredToken = env.INTERNAL_UI_TOKEN
  if (!requiredToken) return
  if (!data?.uiToken || data.uiToken !== requiredToken) {
    throw new Error('Invalid internal UI token')
  }
}

// Mock data for ownership (in production, this would come from database)
const mockOwnershipData: Record<string, { primaryOwnedTenants: string[]; ownedTenants: string[] }> = {
  'user-1': { primaryOwnedTenants: ['tenant-1', 'tenant-2'], ownedTenants: ['tenant-1', 'tenant-2', 'tenant-3'] },
  'user-2': { primaryOwnedTenants: ['tenant-3'], ownedTenants: ['tenant-3'] },
}

const mockTransferRequests: OwnershipTransferRequest[] = []

export const listTenants = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: ListTenantsInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('listTenants', data)
    const cached = getCached<TenantListResponse>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/tenants', {
      params: {
        query: {
          page: data?.page,
          per_page: data?.perPage,
        },
      },
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result =
      payload ?? {
        data: [],
      }
    setCached(cacheKey, result)
    return result
  })

export const listSubscriptions = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: ListSubscriptionsInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('listSubscriptions', data)
    const cached = getCached<SubscriptionListResponse>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET(
      '/billing/subscriptions',
      {
        params: {
          query: {
            status: data?.status,
          },
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result =
      payload ?? {
        data: [],
      }
    setCached(cacheKey, result)
    return result
  })

export const createTenant = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: CreateTenantInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.POST('/tenants', {
      body: {
        name: data.name,
        slug: data.slug,
        plan: data.plan,
        ownerEmail: data.ownerEmail,
        ownerName: data.ownerName,
        customDomain: data.customDomain,
      },
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const getTenantDetail = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: GetTenantInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('getTenant', data)
    const cached = getCached<TenantDetail>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET(
      '/tenants/{tenantId}',
      {
        params: {
          path: {
            tenantId: data.tenantId,
          },
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result = payload ?? {}
    setCached(cacheKey, result)
    return result
  })

export const updateSubscription = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: UpdateSubscriptionInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.PATCH(
      '/billing/tenants/{tenantId}/subscription',
      {
        params: {
          path: {
            tenantId: data.tenantId,
          },
        },
        body: {
          plan: data.plan,
          seats: data.seats,
          billingInterval: data.billingInterval,
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const getPlatformOverview = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: ({ baseUrl?: string } & UiAuth) | undefined) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('platformOverview', data)
    const cached = getCached<PlatformOverview>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET(
      '/analytics/overview',
      {
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result = payload ?? {}
    setCached(cacheKey, result)
    return result
  })

export const getUsageAnalytics = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: GetUsageAnalyticsInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('usageAnalytics', data)
    const cached = getCached<UsageAnalyticsResponse>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET(
      '/analytics/usage',
      {
        params: {
          query: {
            metric: data.metric,
          },
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result = payload ?? {}
    setCached(cacheKey, result)
    return result
  })

export const getTenantAnalytics = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: GetTenantAnalyticsInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('tenantAnalytics', data)
    const cached = getCached<TenantAnalyticsResponse>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET(
      '/analytics/tenants',
      {
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result = payload ?? {}
    setCached(cacheKey, result)
    return result
  })

export const listFeatureFlags = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: ListFeatureFlagsInput | undefined) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('featureFlags', data)
    const cached = getCached<FeatureFlag[]>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET(
      '/config/features',
      {
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result = payload ?? []
    setCached(cacheKey, result)
    return result
  })

export const updateFeatureFlag = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: UpdateFeatureFlagInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.PATCH(
      '/config/features/{flagId}',
      {
        params: {
          path: {
            flagId: data.flagId,
          },
        },
        body: {
          enabled: data.enabled,
          rolloutPercentage: data.rolloutPercentage,
          allowedTenants: data.allowedTenants,
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const listOrganizations = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('organizations', data)
    const cached = getCached<OrganizationResponse[]>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/organizations', {
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result = payload ?? []
    setCached(cacheKey, result)
    return result
  })

export const getOrganization = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: GetOrganizationInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('organization', data)
    const cached = getCached<OrganizationResponse>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/organizations/{orgId}', {
      params: {
        path: {
          orgId: data.orgId,
        },
      },
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result = payload ?? {}
    setCached(cacheKey, result)
    return result
  })

export const listOrganizationMembers = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: ListOrganizationMembersInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET(
      '/organizations/{orgId}/members',
      {
        params: {
          path: {
            orgId: data.orgId,
          },
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    return payload ?? []
  })

export const listRoles = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('roles', data)
    const cached = getCached<RoleResponse[]>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/roles', {
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result = payload ?? []
    setCached(cacheKey, result)
    return result
  })

export const createRole = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: CreateRoleInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.POST('/roles', {
      body: {
        name: data.name,
        description: data.description,
        scope: data.scope,
        permissions: data.permissions,
      },
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const updateRole = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: UpdateRoleInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.PATCH(
      '/roles/{roleId}',
      {
        params: {
          path: {
            roleId: data.roleId,
          },
        },
        body: {
          name: data.name,
          description: data.description,
          permissions: data.permissions,
          status: data.status,
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const listApiKeys = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('apiKeys', data)
    const cached = getCached<ApiKeyResponse[]>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/api-keys', {
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result = payload ?? []
    setCached(cacheKey, result)
    return result
  })

export const createApiKey = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: CreateApiKeyInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.POST('/api-keys', {
      body: {
        name: data.name,
        scopes: data.scopes,
        expiresInDays: data.expiresInDays,
      },
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const deleteApiKey = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: DeleteApiKeyInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.DELETE(
      '/api-keys/{keyId}',
      {
        params: {
          path: {
            keyId: data.keyId,
          },
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const listNotifications = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/notifications', {
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    return payload ?? []
  })

export const markNotificationsRead = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: MarkNotificationsReadInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.POST(
      '/notifications/mark-read',
      {
        body: {
          ids: data.ids,
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    return payload ?? []
  })

export const listSupportTickets = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/support/tickets', {
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    return payload ?? []
  })

export const listSupportIncidents = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/support/incidents', {
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    return payload ?? []
  })

export const listServiceStatus = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/support/status', {
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    return payload ?? []
  })

export const listPlatformInvoices = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/billing/invoices', {
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    return payload ?? { invoices: [] }
  })

export const updateTenant = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: UpdateTenantInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.PATCH(
      '/tenants/{tenantId}',
      {
        params: {
          path: {
            tenantId: data.tenantId,
          },
        },
        body: {
          name: data.name,
          plan: data.plan,
          limits: data.limits,
          settings: data.settings,
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const suspendTenant = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: SuspendTenantInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.POST(
      '/tenants/{tenantId}/suspend',
      {
        params: {
          path: {
            tenantId: data.tenantId,
          },
        },
        body: {
          reason: data.reason,
          suspendUntil: data.suspendUntil,
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const activateTenant = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: ActivateTenantInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.POST(
      '/tenants/{tenantId}/activate',
      {
        params: {
          path: {
            tenantId: data.tenantId,
          },
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const generateInvoice = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: GenerateInvoiceInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.POST(
      '/billing/tenants/{tenantId}/invoice',
      {
        params: {
          path: {
            tenantId: data.tenantId,
          },
        },
        body: {
          amount: data.amount,
          description: data.description,
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const deleteTenant = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: DeleteTenantInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    
    // Check if user is primary owner before allowing deletion
    // In production, this would check the database
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.DELETE(
      '/tenants/{tenantId}',
      {
        params: {
          path: {
            tenantId: data.tenantId,
          },
          query: {
            force: data.force,
          },
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return payload ?? {}
  })

export const migrateTenant = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: MigrateTenantInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.POST(
      '/tenants/{tenantId}/migrate',
      {
        params: {
          path: {
            tenantId: data.tenantId,
          },
        },
        body: {
          targetVersion: data.targetVersion,
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    cache.clear()
    return (payload ?? {}) as MigrationResult
  })

export const getSubscription = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: GetSubscriptionInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const cacheKey = buildCacheKey('getSubscription', data)
    const cached = getCached<SubscriptionDetail>(cacheKey)
    if (cached) return cached

    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET(
      '/billing/tenants/{tenantId}/subscription',
      {
        params: {
          path: {
            tenantId: data.tenantId,
          },
        },
        headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
      },
    )

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    const result = payload ?? {}
    setCached(cacheKey, result)
    return result
  })

export const getServerStatus = createServerFn({ method: 'GET' })
  .inputValidator((input: undefined) => input)
  .handler(async () => {
    assertAuthConfigured()
    return {
      hasApiKey: Boolean(env.INTERNAL_API_KEY),
      hasUiToken: Boolean(env.INTERNAL_UI_TOKEN),
      hasUiPassword: Boolean(env.INTERNAL_UI_PASSWORD),
      defaultBaseUrl: env.INTERNAL_API_BASE_URL || DEFAULT_BASE_URL,
    }
  })

export const loginUi = createServerFn({ method: 'POST' })
  .inputValidator((input: { password: string } | undefined) => input)
  .handler(async ({ data }) => {
    assertAuthConfigured()
    const requiredPassword = env.INTERNAL_UI_PASSWORD
    if (!requiredPassword) {
      throw new Error('UI password not configured')
    }
    if (!data?.password || data.password !== requiredPassword) {
      throw new Error('Invalid UI password')
    }
    const session = createSession()
    const isProduction = process.env.NODE_ENV === 'production'
    const cookieParts = [
      `${getSessionCookieName()}=${encodeURIComponent(session.token)}`,
      `Max-Age=${getSessionTtlSeconds()}`,
      'Path=/',
      'SameSite=Lax',
      'HttpOnly',
    ]
    if (isProduction) {
      cookieParts.push('Secure')
    }
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': cookieParts.join('; '),
      },
    })
  })

export const logoutUi = createServerFn({ method: 'POST' })
  .inputValidator((input: { token?: string } | undefined) => input)
  .handler(async ({ data }) => {
    const request = getRequest()
    const token =
      data?.token ??
      parseCookie(request.headers.get('cookie'), getSessionCookieName())
    if (token) {
      revokeSession(token)
    }
    const isProduction = process.env.NODE_ENV === 'production'
    const cookieParts = [
      `${getSessionCookieName()}=`,
      'Max-Age=0',
      'Path=/',
      'SameSite=Lax',
      'HttpOnly',
    ]
    if (isProduction) {
      cookieParts.push('Secure')
    }
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': cookieParts.join('; '),
      },
    })
  })

export const getUiSessionStatus = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .handler(async () => ({ ok: true }))

export const searchUsers = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: SearchUsersInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/users', {
      params: {
        query: {
          email: data?.email,
          tenantId: data?.tenantId,
          page: data?.page,
        },
      },
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    return payload ?? { data: [] }
  })

export const getUser = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: GetUserInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const client = getClient(data?.baseUrl)
    const apiKey = env.INTERNAL_API_KEY

    const { data: payload, error, response } = await client.GET('/users/{userId}', {
      params: {
        path: {
          userId: data.userId,
        },
      },
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (error) {
      throw new Error(normalizeApiError(error, response))
    }

    return payload ?? {}
  })

// ================= OWNERSHIP & DELETION FUNCTIONS =================

export const getOwnershipStatus = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: GetOwnershipStatusInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    
    // In production, query database for actual ownership data
    const ownership = mockOwnershipData[data.userId] || { primaryOwnedTenants: [], ownedTenants: [] }
    
    const status: OwnershipStatus = {
      isOwner: ownership.ownedTenants.length > 0,
      isPrimaryOwner: ownership.primaryOwnedTenants.length > 0,
      canDelete: ownership.primaryOwnedTenants.length === 0,
      canTransfer: ownership.primaryOwnedTenants.length > 0,
      ownedTenants: ownership.ownedTenants,
    }
    
    return status
  })

export const canDeleteUser = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: { userId: string } & UiAuth) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    
    const ownership = mockOwnershipData[data.userId] || { primaryOwnedTenants: [], ownedTenants: [] }
    
    if (ownership.primaryOwnedTenants.length > 0) {
      return {
        canDelete: false,
        reason: 'PRIMARY_OWNER',
        message: `Cannot delete account. You are the primary owner of ${ownership.primaryOwnedTenants.length} tenant(s). Please transfer ownership first.`,
        ownedTenants: ownership.primaryOwnedTenants,
      }
    }
    
    return {
      canDelete: true,
      reason: null,
      message: null,
      ownedTenants: [],
    }
  })

export const deleteUser = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: DeleteUserInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    
    // Check if user can be deleted
    const ownership = mockOwnershipData[data.userId]
    if (ownership && ownership.primaryOwnedTenants.length > 0) {
      throw new Error(
        `Cannot delete user: Primary owner of ${ownership.primaryOwnedTenants.length} tenant(s). Transfer ownership first.`
      )
    }
    
    const apiKey = env.INTERNAL_API_KEY
    const baseUrl = normalizeBaseUrl(data?.baseUrl)
    const response = await fetchWithRetry(`${baseUrl}/users/${data.userId}`, {
      method: 'DELETE',
      headers: apiKey ? { 'X-API-Key': apiKey } : undefined,
    })

    if (!response.ok) {
      const errorPayload = await response.json().catch(() => null)
      throw new Error(normalizeApiError(errorPayload, response))
    }

    // Record audit
    await appendAuditEvent({
      timestamp: new Date().toISOString(),
      action: 'user.delete',
      detail: `User ${data.userId} deleted`,
      source: 'ui',
    })

    cache.clear()
    return { success: true }
  })

export const requestOwnershipTransfer = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: TransferOwnershipInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    
    // Verify current user is primary owner
    const ownership = mockOwnershipData[data.fromUserId]
    if (!ownership || !ownership.primaryOwnedTenants.includes(data.tenantId)) {
      throw new Error('Only the primary owner can transfer ownership')
    }
    
    // Create transfer request
    const transferRequest: OwnershipTransferRequest = {
      id: `transfer-${Date.now()}`,
      tenantId: data.tenantId,
      tenantName: 'Tenant Name', // Would fetch from DB
      fromUserId: data.fromUserId,
      fromUserName: 'Current Owner', // Would fetch from DB
      toUserId: data.toUserId,
      toUserName: 'New Owner', // Would fetch from DB
      toUserEmail: 'new@owner.com', // Would fetch from DB
      status: 'pending',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
    }
    
    mockTransferRequests.push(transferRequest)
    
    // Record audit
    await appendAuditEvent({
      timestamp: new Date().toISOString(),
      action: 'ownership.transfer.request',
      detail: `Ownership transfer requested for tenant ${data.tenantId} from ${data.fromUserId} to ${data.toUserId}`,
      source: 'ui',
    })
    
    return transferRequest
  })

export const acceptOwnershipTransfer = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: AcceptOwnershipTransferInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    
    const transfer = mockTransferRequests.find(t => t.id === data.transferId)
    if (!transfer) {
      throw new Error('Transfer request not found')
    }
    
    if (transfer.status !== 'pending') {
      throw new Error(`Transfer request is already ${transfer.status}`)
    }
    
    if (new Date(transfer.expiresAt) < new Date()) {
      transfer.status = 'expired'
      throw new Error('Transfer request has expired')
    }
    
    transfer.status = data.accept ? 'accepted' : 'rejected'
    
    if (data.accept) {
      // Update ownership in mock data
      const fromOwnership = mockOwnershipData[transfer.fromUserId]
      const toOwnership = mockOwnershipData[transfer.toUserId] || { primaryOwnedTenants: [], ownedTenants: [] }
      
      if (fromOwnership) {
        fromOwnership.primaryOwnedTenants = fromOwnership.primaryOwnedTenants.filter(
          id => id !== transfer.tenantId
        )
        fromOwnership.ownedTenants = fromOwnership.ownedTenants.filter(
          id => id !== transfer.tenantId
        )
      }
      
      toOwnership.primaryOwnedTenants.push(transfer.tenantId)
      toOwnership.ownedTenants.push(transfer.tenantId)
      mockOwnershipData[transfer.toUserId] = toOwnership
    }
    
    // Record audit
    await appendAuditEvent({
      timestamp: new Date().toISOString(),
      action: data.accept ? 'ownership.transfer.accept' : 'ownership.transfer.reject',
      detail: `Ownership transfer ${data.accept ? 'accepted' : 'rejected'} for tenant ${transfer.tenantId}`,
      source: 'ui',
    })
    
    return transfer
  })

export const getOwnershipTransfers = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: GetOwnershipTransfersInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    
    let transfers = mockTransferRequests
    
    if (data.userId) {
      transfers = transfers.filter(
        t => t.fromUserId === data.userId || t.toUserId === data.userId
      )
    }
    
    if (data.tenantId) {
      transfers = transfers.filter(t => t.tenantId === data.tenantId)
    }
    
    if (data.status) {
      transfers = transfers.filter(t => t.status === data.status)
    }
    
    return { data: transfers }
  })

export const getTenantOwners = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: { tenantId: string } & UiAuth) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    
    // Find primary owner
    let primaryOwner: { userId: string; name: string; email: string } | null = null
    
    for (const [userId, ownership] of Object.entries(mockOwnershipData)) {
      if (ownership.primaryOwnedTenants.includes(data.tenantId)) {
        primaryOwner = {
          userId,
          name: 'Owner Name', // Would fetch from DB
          email: 'owner@example.com', // Would fetch from DB
        }
        break
      }
    }
    
    return {
      primaryOwner,
      // Would also return other owners/admins
    }
  })

// ================= AUDIT FUNCTIONS =================

export const recordAudit = createServerFn({ method: 'POST' })
  .middleware([authMiddleware])
  .inputValidator((input: RecordAuditInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const event: AuditEvent = {
      timestamp: data.timestamp ?? new Date().toISOString(),
      action: data.action,
      detail: data.detail,
      source: 'ui',
    }
    await appendAuditEvent(event)
    return { ok: true }
  })

export const listAudit = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: ListAuditInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    const page = data?.page ?? 1
    const perPage = data?.perPage ?? 50
    const offset = (page - 1) * perPage
    const { events, integrity } = await readAuditEvents({
      action: data?.action,
      since: data?.since,
      until: data?.until,
      limit: perPage,
      offset,
      sort: data?.sort,
    })
    const total = await countAuditEvents({
      action: data?.action,
      since: data?.since,
      until: data?.until,
    })
    return {
      data: events,
      pagination: {
        page,
        perPage,
        total,
        totalPages: Math.max(1, Math.ceil(total / perPage)),
      },
      integrity,
    }
  })

export const downloadAudit = createServerFn({ method: 'GET' })
  .middleware([authMiddleware])
  .inputValidator((input: ListAuditInput) => input)
  .handler(async ({ data }) => {
    requireUiToken(data)
    recordAuditExportRequest()
    try {
      const size = await auditFileSize()
      const shouldStream = size > 500_000 && data?.sort !== 'desc'
      if (shouldStream) {
        const stream = await streamAuditCsv({
          action: data?.action,
          since: data?.since,
          until: data?.until,
          onBytes: recordAuditExportBytes,
        })
        const webStream = Readable.toWeb(stream) as unknown as ReadableStream
        return new Response(webStream, {
          headers: {
            'Content-Type': 'text/csv',
          },
        })
      }

      const { events } = await readAuditEvents({
        action: data?.action,
        since: data?.since,
        until: data?.until,
        sort: data?.sort,
      })
      const header = 'timestamp,action,detail,source,seq,valid\n'
      const body = events
        .map((event) =>
          [
            event.timestamp,
            event.action,
            event.detail,
            event.source ?? '',
            event.seq ?? '',
            event.valid ? 'true' : 'false',
          ]
            .map((value) => `"${String(value ?? '').replace(/"/g, '""')}"`)
            .join(','),
        )
        .join('\n')
      const csv = header + body
      if (csv.length > 50_000) {
        const gz = gzipSync(csv)
        recordAuditExportBytes(gz.byteLength)
        return new Response(gz, {
          headers: {
            'Content-Type': 'text/csv',
            'Content-Encoding': 'gzip',
          },
        })
      }
      recordAuditExportBytes(Buffer.byteLength(csv))
      return csv
    } catch (err) {
      recordAuditExportError()
      throw err
    }
  })
