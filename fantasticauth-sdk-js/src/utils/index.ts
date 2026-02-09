/**
 * Vault SDK Utilities
 *
 * Utility functions and helpers for the Vault SDK.
 */

// OAuth Utilities
export {
  oauthProviderMetadata,
  oauthProviderCategories,
  getAllOAuthProviders,
  getOAuthProvidersByCategory,
  getOAuthProviderMetadata,
  getOAuthProviderDisplayName,
  getOAuthProviderColor,
  isPkceEnabled,
  getOAuthProviderDefaultScopes,
  getPopularOAuthProviders,
  getRecommendedOAuthProviders,
  isValidOAuthProvider,
  groupProvidersByCategory,
} from './oauth';
