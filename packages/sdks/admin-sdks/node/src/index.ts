/**
 * Vault Auth Node.js SDK
 * 
 * Official Node.js SDK for Vault authentication and user management.
 */

// Main client
export {
  VaultAuth,
  Fantasticauth,
  UsersAPI,
  OrganizationsAPI,
  SessionsAPI,
  VaultAuth as FantasticauthAuth,
} from './client.js';

// Types
export {
  UserStatus,
  OrganizationRole,
  type User,
  type Organization,
  type OrganizationMembership,
  type Session,
  type JWKSKey,
  type JWKS,
  type TokenPayload,
  type PaginatedResponse,
  type CreateUserRequest,
  type UpdateUserRequest,
  type CreateOrganizationRequest,
  type UpdateOrganizationRequest,
  type AddMemberRequest,
  type UpdateMemberRoleRequest,
  type VaultAuthConfig,
  type VaultAuthConfig as FantasticauthConfig,
  type APIResponse,
} from './types.js';

// Errors
export {
  VaultAuthError,
  VaultAuthError as FantasticauthError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  ServerError,
  ValidationError,
  TokenExpiredError,
  InvalidTokenError,
  ConfigurationError,
  isVaultAuthError,
  isVaultAuthError as isFantasticauthError,
  errorFromResponse,
} from './errors.js';

// Version
export const VERSION = '1.0.0';
