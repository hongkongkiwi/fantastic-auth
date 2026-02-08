export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  avatarUrl?: string;
  phoneNumber?: string;
  status: 'active' | 'suspended' | 'pending' | 'deleted';
  role: 'admin' | 'user' | 'super_admin';
  mfaEnabled: boolean;
  mfaMethods: ('totp' | 'sms' | 'email' | 'webauthn')[];
  lastLoginAt?: string;
  lastLoginIp?: string;
  createdAt: string;
  updatedAt: string;
  metadata?: Record<string, unknown>;
  organizations: OrganizationMembership[];
}

export interface OrganizationMembership {
  organizationId: string;
  organizationName: string;
  role: 'owner' | 'admin' | 'member';
  joinedAt: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  description?: string;
  logoUrl?: string;
  website?: string;
  status: 'active' | 'inactive' | 'suspended';
  plan: 'free' | 'starter' | 'pro' | 'enterprise';
  memberCount: number;
  domain?: string;
  domainVerified: boolean;
  ssoEnabled: boolean;
  ssoProvider?: 'saml' | 'oidc';
  createdAt: string;
  updatedAt: string;
  settings: OrganizationSettings;
}

export interface OrganizationSettings {
  allowPublicSignup: boolean;
  requireEmailVerification: boolean;
  allowMembersToInvite: boolean;
  defaultMemberRole: 'member' | 'admin';
  sessionTimeoutMinutes: number;
}

export interface OrganizationMember {
  userId: string;
  email: string;
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  role: 'owner' | 'admin' | 'member';
  joinedAt: string;
  lastActiveAt?: string;
}

export interface Session {
  id: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  deviceType: 'desktop' | 'mobile' | 'tablet';
  browser: string;
  os: string;
  location?: string;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  eventType: AuditEventType;
  actor: {
    type: 'user' | 'system' | 'api';
    id?: string;
    email?: string;
    ipAddress: string;
    userAgent?: string;
  };
  resource: {
    type: string;
    id: string;
    name?: string;
  };
  action: string;
  status: 'success' | 'failure' | 'blocked';
  details?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export type AuditEventType =
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'user.suspended'
  | 'user.activated'
  | 'user.login'
  | 'user.logout'
  | 'user.mfa_enabled'
  | 'user.mfa_disabled'
  | 'user.password_changed'
  | 'user.email_verified'
  | 'org.created'
  | 'org.updated'
  | 'org.deleted'
  | 'org.member_added'
  | 'org.member_removed'
  | 'org.member_role_changed'
  | 'session.created'
  | 'session.revoked'
  | 'api_key.created'
  | 'api_key.revoked'
  | 'settings.updated'
  | 'webhook.created'
  | 'webhook.updated'
  | 'webhook.deleted'
  | 'oauth_client.created'
  | 'oauth_client.updated'
  | 'saml_connection.created'
  | 'saml_connection.updated';

export interface UserListParams {
  page?: number;
  limit?: number;
  search?: string;
  status?: User['status'] | 'all';
  role?: User['role'] | 'all';
  emailVerified?: boolean | 'all';
  mfaEnabled?: boolean | 'all';
  organizationId?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  dateFrom?: string;
  dateTo?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNextPage: boolean;
    hasPrevPage: boolean;
  };
}

export interface DashboardStats {
  totalUsers: number;
  activeUsers: number;
  newUsersToday: number;
  newUsersThisWeek: number;
  newUsersThisMonth: number;
  totalOrganizations: number;
  activeSessions: number;
  avgSessionsPerUser: number;
  loginAttemptsToday: number;
  failedLoginsToday: number;
  mfaAdoptionRate: number;
}

export interface ActivityData {
  date: string;
  logins: number;
  signups: number;
  failedLogins: number;
  mfaChallenges: number;
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'down';
  services: {
    api: ServiceHealth;
    database: ServiceHealth;
    cache: ServiceHealth;
    queue: ServiceHealth;
  };
  lastChecked: string;
}

interface ServiceHealth {
  status: 'up' | 'down' | 'degraded';
  latency: number;
  message?: string;
}

export interface Webhook {
  id: string;
  url: string;
  description?: string;
  events: string[];
  secret: string;
  active: boolean;
  createdAt: string;
  updatedAt: string;
  lastTriggeredAt?: string;
  lastError?: string;
}

export interface OAuthClient {
  id: string;
  name: string;
  clientId: string;
  clientSecret?: string;
  redirectUris: string[];
  allowedScopes: string[];
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface SAMLConnection {
  id: string;
  name: string;
  organizationId: string;
  provider: string;
  ssoUrl: string;
  entityId: string;
  certificate: string;
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

export type NotificationChannel = 'email' | 'sms' | 'whatsapp'
export type SecurityNotificationEvent =
  | 'login_failed'
  | 'login_blocked_risk'
  | 'password_changed'
  | 'password_reset'
  | 'mfa_enabled'
  | 'mfa_disabled'
  | 'suspicious_login'
  | 'account_locked'
  | 'impersonation_started'
  | 'security_policy_updated'

export interface SecurityNotificationAudience {
  enabled: boolean
  events: SecurityNotificationEvent[]
  channels: NotificationChannel[]
}

export interface SecurityNotificationSettings {
  user: SecurityNotificationAudience
  admin: SecurityNotificationAudience
  admin_roles: string[]
  whatsapp_template_name?: string | null
}

export interface SecuritySettings {
  password_policy: {
    min_length: number
    max_length: number
    require_uppercase: boolean
    require_lowercase: boolean
    require_numbers: boolean
    require_special: boolean
    special_chars: string
    max_consecutive_chars: number
    prevent_common_passwords: boolean
    history_count: number
    expiry_days?: number | null
    check_breach: boolean
    enforcement_mode: 'block' | 'warn' | 'audit'
    min_entropy: number
    prevent_user_info: boolean
  }
  session_lifetime: {
    access_token_minutes: number
    refresh_token_days: number
    absolute_timeout_hours: number
    idle_timeout_minutes: number
  }
  session_limits: {
    max_concurrent_sessions: number
    eviction_policy: string
    enforce_for_ip: boolean
    max_sessions_per_ip: number
  }
  mfa_settings: {
    require_mfa: boolean
    allowed_methods: ('totp' | 'sms' | 'email' | 'webauthn')[]
    grace_period_days: number
    require_mfa_for_roles: string[]
  }
  lockout_policy: {
    max_failed_attempts: number
    lockout_duration_minutes: number
    reset_after_minutes: number
  }
  notifications: SecurityNotificationSettings
}

export interface PrivacySettings {
  analytics_enabled: boolean
  session_recording: boolean
  consent_required: boolean
  consent_types: string[]
  data_retention_days: number
  anonymize_ip: boolean
  allow_data_export: boolean
  allow_account_deletion: boolean
  deletion_grace_period_days: number
  cookie_consent_required: boolean
  min_age_requirement: number
}

export interface EmailTemplate {
  id: string;
  name: string;
  subject: string;
  htmlBody: string;
  textBody: string;
  variables: string[];
  active: boolean;
}

export interface BrandingSettings {
  logoUrl?: string;
  faviconUrl?: string;
  primaryColor: string;
  accentColor: string;
  companyName: string;
  supportEmail: string;
  supportUrl?: string;
  termsUrl?: string;
  privacyUrl?: string;
  customCss?: string;
}

export type Theme = 'light' | 'dark' | 'system';
