/**
 * Type definitions for Vault Auth SDK
 */

/** User status enumeration */
export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
  PENDING_VERIFICATION = 'pending_verification',
}

/** Organization role enumeration */
export enum OrganizationRole {
  OWNER = 'owner',
  ADMIN = 'admin',
  MEMBER = 'member',
}

/** Represents a Vault user */
export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  status: UserStatus;
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  metadata?: Record<string, unknown>;
  createdAt?: Date;
  updatedAt?: Date;
  lastLoginAt?: Date;
}

/** Represents a Vault organization */
export interface Organization {
  id: string;
  name: string;
  slug: string;
  status: string;
  metadata?: Record<string, unknown>;
  createdAt?: Date;
  updatedAt?: Date;
}

/** Represents a user's membership in an organization */
export interface OrganizationMembership {
  id: string;
  userId: string;
  organizationId: string;
  role: OrganizationRole;
  joinedAt?: Date;
  organization?: Organization;
}

/** Represents a user session */
export interface Session {
  id: string;
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  createdAt?: Date;
  expiresAt?: Date;
  lastUsedAt?: Date;
  revokedAt?: Date;
}

/** Represents a JSON Web Key */
export interface JWKSKey {
  kty: string;
  kid: string;
  use?: string;
  alg?: string;
  n?: string;  // RSA modulus
  e?: string;  // RSA exponent
  x?: string;  // EC x coordinate
  y?: string;  // EC y coordinate
  crv?: string; // EC curve
}

/** Represents a JSON Web Key Set */
export interface JWKS {
  keys: JWKSKey[];
}

/** Represents decoded JWT token payload */
export interface TokenPayload {
  sub: string;  // User ID
  exp: number;  // Expiration timestamp
  iat: number;  // Issued at timestamp
  iss: string;  // Issuer
  aud: string;  // Audience
  jti: string;  // JWT ID
  email?: string;
  emailVerified?: boolean;
  orgId?: string;
  orgRole?: string;
}

/** Generic paginated response */
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  perPage: number;
  hasMore: boolean;
}

/** Request to create a user */
export interface CreateUserRequest {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
  emailVerified?: boolean;
  metadata?: Record<string, unknown>;
}

/** Request to update a user */
export interface UpdateUserRequest {
  firstName?: string;
  lastName?: string;
  email?: string;
  metadata?: Record<string, unknown>;
}

/** Request to create an organization */
export interface CreateOrganizationRequest {
  name: string;
  slug?: string;
  metadata?: Record<string, unknown>;
}

/** Request to update an organization */
export interface UpdateOrganizationRequest {
  name?: string;
  slug?: string;
  metadata?: Record<string, unknown>;
}

/** Request to add a member to an organization */
export interface AddMemberRequest {
  userId: string;
  role?: OrganizationRole | string;
}

/** Request to update a member's role */
export interface UpdateMemberRoleRequest {
  role: OrganizationRole | string;
}

/** Vault Auth client configuration */
export interface VaultAuthConfig {
  /** Vault API key (vault_m2m_...) */
  apiKey: string;
  /** Vault API base URL */
  baseURL?: string;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Maximum number of retries on 5xx errors */
  maxRetries?: number;
  /** Base delay between retries in milliseconds */
  retryDelay?: number;
  /** Request ID for tracing */
  requestId?: string;
  /** JWKS cache time-to-live in milliseconds */
  jwksCacheTTL?: number;
}

/** API response wrapper */
export interface APIResponse<T> {
  data: T;
  message?: string;
  code?: string;
  details?: Record<string, unknown>;
}

/** List users response */
export interface UserListResponse {
  users: User[];
  total: number;
  page: number;
  per_page: number;
  has_more: boolean;
}

/** List organizations response */
export interface OrganizationListResponse {
  organizations: Organization[];
  total: number;
  page: number;
  per_page: number;
  has_more: boolean;
}

/** Organization members response */
export interface MembershipListResponse {
  members: OrganizationMembership[];
}

/** Sessions response */
export interface SessionListResponse {
  sessions: Session[];
}
