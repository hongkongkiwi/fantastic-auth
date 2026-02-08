/**
 * OAuth Provider Utilities
 *
 * Comprehensive metadata and utilities for 30+ OAuth providers.
 */

import type { OAuthProvider, OAuthProviderCategory, OAuthProviderMetadata } from '../types';

/**
 * OAuth provider metadata for all supported providers
 */
export const oauthProviderMetadata: Record<OAuthProvider, OAuthProviderMetadata> = {
  // Existing providers
  google: {
    id: 'google',
    name: 'google',
    displayName: 'Google',
    category: 'social',
    icon: 'google',
    color: '#4285F4',
    pkceEnabled: false,
    scopes: ['openid', 'email', 'profile'],
  },
  github: {
    id: 'github',
    name: 'github',
    displayName: 'GitHub',
    category: 'social',
    icon: 'github',
    color: '#181717',
    pkceEnabled: false,
    scopes: ['user:email', 'read:user'],
  },
  microsoft: {
    id: 'microsoft',
    name: 'microsoft',
    displayName: 'Microsoft',
    category: 'professional',
    icon: 'microsoft',
    color: '#2F2F2F',
    pkceEnabled: false,
    scopes: ['openid', 'email', 'profile'],
  },
  apple: {
    id: 'apple',
    name: 'apple',
    displayName: 'Apple',
    category: 'professional',
    icon: 'apple',
    color: '#000000',
    pkceEnabled: true,
    scopes: ['name', 'email'],
  },
  discord: {
    id: 'discord',
    name: 'discord',
    displayName: 'Discord',
    category: 'social',
    icon: 'discord',
    color: '#5865F2',
    pkceEnabled: false,
    scopes: ['identify', 'email'],
  },
  slack: {
    id: 'slack',
    name: 'slack',
    displayName: 'Slack',
    category: 'social',
    icon: 'slack',
    color: '#4A154B',
    pkceEnabled: false,
    scopes: ['identity.basic', 'identity.email'],
  },
  
  // Social/Consumer
  facebook: {
    id: 'facebook',
    name: 'facebook',
    displayName: 'Facebook',
    category: 'social',
    icon: 'facebook',
    color: '#1877F2',
    pkceEnabled: false,
    scopes: ['email', 'public_profile'],
  },
  twitter: {
    id: 'twitter',
    name: 'twitter',
    displayName: 'X (Twitter)',
    category: 'social',
    icon: 'twitter',
    color: '#000000',
    pkceEnabled: true,
    scopes: ['tweet.read', 'users.read'],
  },
  instagram: {
    id: 'instagram',
    name: 'instagram',
    displayName: 'Instagram',
    category: 'social',
    icon: 'instagram',
    color: '#E4405F',
    pkceEnabled: false,
    scopes: ['instagram_graph_user_profile'],
  },
  tiktok: {
    id: 'tiktok',
    name: 'tiktok',
    displayName: 'TikTok',
    category: 'social',
    icon: 'tiktok',
    color: '#000000',
    pkceEnabled: true,
    scopes: ['user.info.basic'],
  },
  snapchat: {
    id: 'snapchat',
    name: 'snapchat',
    displayName: 'Snapchat',
    category: 'social',
    icon: 'snapchat',
    color: '#FFFC00',
    pkceEnabled: true,
    scopes: ['https://auth.snapchat.com/oauth2/api/user.display_name'],
  },
  pinterest: {
    id: 'pinterest',
    name: 'pinterest',
    displayName: 'Pinterest',
    category: 'social',
    icon: 'pinterest',
    color: '#BD081C',
    pkceEnabled: true,
    scopes: ['user_accounts:read'],
  },
  reddit: {
    id: 'reddit',
    name: 'reddit',
    displayName: 'Reddit',
    category: 'social',
    icon: 'reddit',
    color: '#FF4500',
    pkceEnabled: true,
    scopes: ['identity'],
  },
  twitch: {
    id: 'twitch',
    name: 'twitch',
    displayName: 'Twitch',
    category: 'social',
    icon: 'twitch',
    color: '#9146FF',
    pkceEnabled: true,
    scopes: ['user:read:email'],
  },
  spotify: {
    id: 'spotify',
    name: 'spotify',
    displayName: 'Spotify',
    category: 'social',
    icon: 'spotify',
    color: '#1DB954',
    pkceEnabled: true,
    scopes: ['user-read-email', 'user-read-private'],
  },
  
  // Professional
  linkedin: {
    id: 'linkedin',
    name: 'linkedin',
    displayName: 'LinkedIn',
    category: 'professional',
    icon: 'linkedin',
    color: '#0A66C2',
    pkceEnabled: true,
    scopes: ['openid', 'email', 'profile'],
  },
  
  // Developer/Tech
  gitlab: {
    id: 'gitlab',
    name: 'gitlab',
    displayName: 'GitLab',
    category: 'developer',
    icon: 'gitlab',
    color: '#FC6D26',
    pkceEnabled: false,
    scopes: ['read_user', 'openid'],
  },
  bitbucket: {
    id: 'bitbucket',
    name: 'bitbucket',
    displayName: 'Bitbucket',
    category: 'developer',
    icon: 'bitbucket',
    color: '#2684FF',
    pkceEnabled: false,
    scopes: ['account'],
  },
  digitalocean: {
    id: 'digitalocean',
    name: 'digitalocean',
    displayName: 'DigitalOcean',
    category: 'developer',
    icon: 'digitalocean',
    color: '#0080FF',
    pkceEnabled: false,
    scopes: ['read'],
  },
  heroku: {
    id: 'heroku',
    name: 'heroku',
    displayName: 'Heroku',
    category: 'developer',
    icon: 'heroku',
    color: '#430098',
    pkceEnabled: false,
    scopes: ['identity'],
  },
  vercel: {
    id: 'vercel',
    name: 'vercel',
    displayName: 'Vercel',
    category: 'developer',
    icon: 'vercel',
    color: '#000000',
    pkceEnabled: true,
    scopes: ['user'],
  },
  netlify: {
    id: 'netlify',
    name: 'netlify',
    displayName: 'Netlify',
    category: 'developer',
    icon: 'netlify',
    color: '#00C7B7',
    pkceEnabled: false,
    scopes: ['user'],
  },
  cloudflare: {
    id: 'cloudflare',
    name: 'cloudflare',
    displayName: 'Cloudflare',
    category: 'developer',
    icon: 'cloudflare',
    color: '#F48120',
    pkceEnabled: false,
    scopes: ['user:read'],
  },
  
  // Enterprise
  salesforce: {
    id: 'salesforce',
    name: 'salesforce',
    displayName: 'Salesforce',
    category: 'enterprise',
    icon: 'salesforce',
    color: '#00A1E0',
    pkceEnabled: true,
    scopes: ['openid', 'email', 'profile'],
  },
  hubspot: {
    id: 'hubspot',
    name: 'hubspot',
    displayName: 'HubSpot',
    category: 'enterprise',
    icon: 'hubspot',
    color: '#FF7A59',
    pkceEnabled: false,
    scopes: ['oauth'],
  },
  zendesk: {
    id: 'zendesk',
    name: 'zendesk',
    displayName: 'Zendesk',
    category: 'enterprise',
    icon: 'zendesk',
    color: '#03363D',
    pkceEnabled: false,
    scopes: ['read'],
  },
  notion: {
    id: 'notion',
    name: 'notion',
    displayName: 'Notion',
    category: 'enterprise',
    icon: 'notion',
    color: '#000000',
    pkceEnabled: true,
    scopes: ['user:read'],
  },
  figma: {
    id: 'figma',
    name: 'figma',
    displayName: 'Figma',
    category: 'enterprise',
    icon: 'figma',
    color: '#F24E1E',
    pkceEnabled: false,
    scopes: ['file_read'],
  },
  linear: {
    id: 'linear',
    name: 'linear',
    displayName: 'Linear',
    category: 'enterprise',
    icon: 'linear',
    color: '#5E6AD2',
    pkceEnabled: true,
    scopes: ['read', 'issues:read'],
  },
  atlassian: {
    id: 'atlassian',
    name: 'atlassian',
    displayName: 'Atlassian',
    category: 'enterprise',
    icon: 'atlassian',
    color: '#0052CC',
    pkceEnabled: true,
    scopes: ['read:me'],
  },
  okta: {
    id: 'okta',
    name: 'okta',
    displayName: 'Okta',
    category: 'enterprise',
    icon: 'okta',
    color: '#007DC1',
    pkceEnabled: true,
    scopes: ['openid', 'email', 'profile'],
  },
  
  // Regional
  wechat: {
    id: 'wechat',
    name: 'wechat',
    displayName: 'WeChat',
    category: 'regional',
    icon: 'wechat',
    color: '#07C160',
    pkceEnabled: false,
    scopes: ['snsapi_login', 'snsapi_userinfo'],
  },
  line: {
    id: 'line',
    name: 'line',
    displayName: 'LINE',
    category: 'regional',
    icon: 'line',
    color: '#06C755',
    pkceEnabled: true,
    scopes: ['profile', 'openid'],
  },
  kakaotalk: {
    id: 'kakaotalk',
    name: 'kakaotalk',
    displayName: 'KakaoTalk',
    category: 'regional',
    icon: 'kakaotalk',
    color: '#FEE500',
    pkceEnabled: false,
    scopes: ['account_email', 'profile_nickname'],
  },
  vkontakte: {
    id: 'vkontakte',
    name: 'vkontakte',
    displayName: 'VKontakte',
    category: 'regional',
    icon: 'vkontakte',
    color: '#4C75A3',
    pkceEnabled: false,
    scopes: ['email', 'profile'],
  },
  yandex: {
    id: 'yandex',
    name: 'yandex',
    displayName: 'Yandex',
    category: 'regional',
    icon: 'yandex',
    color: '#FC3F1D',
    pkceEnabled: true,
    scopes: ['login:email', 'login:info'],
  },
};

/**
 * Get all OAuth providers
 */
export function getAllOAuthProviders(): OAuthProvider[] {
  return Object.keys(oauthProviderMetadata) as OAuthProvider[];
}

/**
 * Get OAuth providers by category
 */
export function getOAuthProvidersByCategory(category: OAuthProviderCategory): OAuthProvider[] {
  return (Object.keys(oauthProviderMetadata) as OAuthProvider[]).filter(
    (provider) => oauthProviderMetadata[provider].category === category
  );
}

/**
 * Get OAuth provider metadata
 */
export function getOAuthProviderMetadata(provider: OAuthProvider): OAuthProviderMetadata {
  return oauthProviderMetadata[provider];
}

/**
 * Get OAuth provider display name
 */
export function getOAuthProviderDisplayName(provider: OAuthProvider): string {
  return oauthProviderMetadata[provider]?.displayName || provider;
}

/**
 * Get OAuth provider icon color
 */
export function getOAuthProviderColor(provider: OAuthProvider): string {
  return oauthProviderMetadata[provider]?.color || '#000000';
}

/**
 * Check if OAuth provider uses PKCE
 */
export function isPkceEnabled(provider: OAuthProvider): boolean {
  return oauthProviderMetadata[provider]?.pkceEnabled || false;
}

/**
 * Get default scopes for OAuth provider
 */
export function getOAuthProviderDefaultScopes(provider: OAuthProvider): string[] {
  return oauthProviderMetadata[provider]?.scopes || ['openid', 'email', 'profile'];
}

/**
 * OAuth provider categories
 */
export const oauthProviderCategories: { id: OAuthProviderCategory; label: string }[] = [
  { id: 'social', label: 'Social' },
  { id: 'professional', label: 'Professional' },
  { id: 'developer', label: 'Developer' },
  { id: 'enterprise', label: 'Enterprise' },
  { id: 'regional', label: 'Regional' },
];

/**
 * Get popular OAuth providers (most commonly used)
 */
export function getPopularOAuthProviders(): OAuthProvider[] {
  return ['google', 'github', 'microsoft', 'apple', 'facebook', 'twitter', 'linkedin'];
}

/**
 * Get recommended OAuth providers for a specific use case
 */
export function getRecommendedOAuthProviders(useCase: 'b2b' | 'b2c' | 'developer' | 'enterprise'): OAuthProvider[] {
  switch (useCase) {
    case 'b2b':
      return ['google', 'microsoft', 'linkedin', 'slack', 'okta', 'atlassian'];
    case 'b2c':
      return ['google', 'apple', 'facebook', 'twitter', 'instagram', 'tiktok'];
    case 'developer':
      return ['github', 'gitlab', 'bitbucket', 'vercel', 'netlify', 'cloudflare'];
    case 'enterprise':
      return ['okta', 'microsoft', 'salesforce', 'atlassian', 'zendesk', 'hubspot'];
    default:
      return getPopularOAuthProviders();
  }
}

/**
 * Validate OAuth provider
 */
export function isValidOAuthProvider(provider: string): provider is OAuthProvider {
  return provider in oauthProviderMetadata;
}

/**
 * Group providers by category
 */
export function groupProvidersByCategory(): Record<OAuthProviderCategory, OAuthProvider[]> {
  const groups: Record<OAuthProviderCategory, OAuthProvider[]> = {
    social: [],
    professional: [],
    developer: [],
    enterprise: [],
    regional: [],
    custom: [],
  };

  (Object.keys(oauthProviderMetadata) as OAuthProvider[]).forEach((provider) => {
    const category = oauthProviderMetadata[provider].category;
    groups[category].push(provider);
  });

  return groups;
}
