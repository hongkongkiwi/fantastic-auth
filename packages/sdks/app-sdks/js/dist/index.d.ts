import * as react_jsx_runtime from 'react/jsx-runtime';
import React$1 from 'react';

/**
 * Vault SDK Billing Types
 *
 * TypeScript types for billing and subscription management.
 */

interface BillingPlan {
    id: string;
    name: string;
    description: string;
    stripePriceId: string;
    amount: number;
    currency: string;
    interval: 'month' | 'year' | 'week' | 'day';
    features: string[];
    metadata: Record<string, any>;
}
type PlanTier = 'free' | 'starter' | 'pro' | 'enterprise';
type SubscriptionStatus$1 = 'incomplete' | 'incomplete_expired' | 'trialing' | 'active' | 'past_due' | 'canceled' | 'unpaid' | 'paused';
interface Subscription {
    id: string;
    tenantId: string;
    stripeSubscriptionId: string;
    stripeCustomerId: string;
    status: SubscriptionStatus$1;
    currentPeriodStart: string;
    currentPeriodEnd: string;
    planId: string;
    plan?: BillingPlan;
    quantity: number;
    cancelAtPeriodEnd: boolean;
    trialStart?: string;
    trialEnd?: string;
    canceledAt?: string;
    createdAt: string;
    updatedAt: string;
}
interface BillingAddress {
    line1?: string;
    line2?: string;
    city?: string;
    state?: string;
    postalCode?: string;
    country?: string;
}
interface PaymentMethod {
    id: string;
    tenantId: string;
    stripePaymentMethodId: string;
    type: string;
    isDefault: boolean;
    card?: CardInfo;
    billingDetails?: BillingDetails;
    createdAt: string;
}
interface CardInfo {
    brand: string;
    last4: string;
    expMonth: number;
    expYear: number;
    country?: string;
    funding?: 'credit' | 'debit' | 'prepaid' | 'unknown';
}
interface BillingDetails {
    name?: string;
    email?: string;
    phone?: string;
    address?: BillingAddress;
}
type InvoiceStatus = 'draft' | 'open' | 'paid' | 'uncollectible' | 'void';
interface Invoice {
    id: string;
    tenantId: string;
    stripeInvoiceId: string;
    subscriptionId?: string;
    status: InvoiceStatus;
    total: number;
    subtotal: number;
    tax: number;
    currency: string;
    invoicePdf?: string;
    hostedInvoiceUrl?: string;
    periodStart?: string;
    periodEnd?: string;
    paidAt?: string;
    createdAt: string;
}
type UsageMetric = 'api_calls' | 'storage_bytes' | 'users' | 'teams' | 'compute_seconds' | 'bandwidth_bytes' | 'events_processed' | 'emails_sent' | 'sms_sent' | 'webhooks_delivered' | string;
interface UsageQuota {
    metric: UsageMetric;
    limit: number;
    warningThreshold?: number;
}
interface UsageSummary {
    metric: UsageMetric;
    periodStart: string;
    periodEnd: string;
    totalUsage: number;
    quota?: UsageQuota;
}
interface CheckoutSession {
    id: string;
    url: string;
    customerId?: string;
    subscriptionId?: string;
    priceId: string;
    mode: 'payment' | 'setup' | 'subscription';
}
interface PortalSession {
    url: string;
}
interface CreateCheckoutOptions {
    priceId: string;
    successUrl: string;
    cancelUrl: string;
    customerEmail?: string;
    allowPromotionCodes?: boolean;
    trialDays?: number;
}
interface CreatePortalOptions {
    returnUrl: string;
}
interface SubscriptionLimits {
    maxUsers?: number;
    maxStorageGb?: number;
    maxApiCallsPerMonth?: number;
    maxProjects?: number;
    features: string[];
}
interface PricingTableProps {
    plans?: BillingPlan[];
    currentPlanId?: string;
    currentInterval?: 'month' | 'year';
    loading?: boolean;
    onSelectPlan?: (plan: BillingPlan) => void;
    onIntervalChange?: (interval: 'month' | 'year') => void;
    showFeatures?: boolean;
    className?: string;
}
interface CheckoutButtonProps {
    priceId: string;
    successUrl: string;
    cancelUrl: string;
    children: React$1.ReactNode;
    disabled?: boolean;
    loading?: boolean;
    onCheckout?: (session: CheckoutSession) => void;
    onError?: (error: Error) => void;
    className?: string;
}
interface QuickCheckoutButtonProps$1 {
    priceId: string;
    children: React$1.ReactNode;
    successPath?: string;
    cancelPath?: string;
    disabled?: boolean;
    onCheckout?: (session: {
        url: string;
    }) => void;
    onError?: (error: Error) => void;
    className?: string;
}
interface CustomerPortalButtonProps {
    children: React$1.ReactNode;
    returnUrl?: string;
    disabled?: boolean;
    onOpen?: () => void;
    onError?: (error: Error) => void;
    className?: string;
}
interface BillingSettingsProps$1 {
    returnUrl?: string;
    showManageSubscription?: boolean;
    showUpdatePayment?: boolean;
    showViewInvoices?: boolean;
    className?: string;
}
interface SubscriptionStatusProps {
    subscription?: Subscription;
    showDetails?: boolean;
    showInvoices?: boolean;
    showUsage?: boolean;
    onCancel?: () => Promise<void>;
    onResume?: () => Promise<void>;
    onUpdate?: (newPlanId: string) => Promise<void>;
    className?: string;
}
interface UsageMeterProps {
    usage: UsageSummary;
    showPercentage?: boolean;
    showRemaining?: boolean;
    className?: string;
}
interface InvoiceListProps$1 {
    invoices: Invoice[];
    loading?: boolean;
    emptyMessage?: string;
    className?: string;
}
interface UseBillingReturn {
    isLoading: boolean;
    error: Error | null;
    plans: BillingPlan[];
    billingEnabled: boolean;
    refreshPlans: () => Promise<void>;
    subscription: Subscription | null;
    refreshSubscription: () => Promise<void>;
    createCheckout: (options: CreateCheckoutOptions) => Promise<CheckoutSession>;
    createPortalSession: (options: CreatePortalOptions) => Promise<PortalSession>;
    cancelSubscription: () => Promise<Subscription>;
    resumeSubscription: () => Promise<Subscription>;
    updateSubscription: (newPriceId: string) => Promise<Subscription>;
    reportUsage: (quantity: number, action?: 'increment' | 'set') => Promise<void>;
    invoices: Invoice[];
    refreshInvoices: () => Promise<void>;
    clearError: () => void;
}

/**
 * Vault SDK Types
 *
 * TypeScript types for the Vault authentication SDK.
 */
interface User {
    id: string;
    tenantId: string;
    email: string;
    emailVerified: boolean;
    status: 'pending' | 'active' | 'suspended' | 'deactivated';
    profile: UserProfile$2;
    mfaEnabled: boolean;
    mfaMethods: MfaMethod[];
    lastLoginAt?: string;
    createdAt: string;
    updatedAt: string;
}
interface UserProfile$2 {
    name?: string;
    givenName?: string;
    familyName?: string;
    picture?: string;
    phoneNumber?: string;
    [key: string]: any;
}
type MfaMethod = 'totp' | 'email' | 'sms' | 'webauthn' | 'backup_codes';
interface Session {
    id: string;
    accessToken: string;
    refreshToken: string;
    expiresAt: string;
    user: User;
}
interface SessionInfo {
    id: string;
    userId: string;
    userAgent?: string;
    ipAddress?: string;
    location?: string;
    createdAt: string;
    lastActiveAt: string;
    expiresAt: string;
    isCurrent: boolean;
}
interface PermissionCheck {
    permission?: string;
    role?: string;
    anyRole?: string[];
}
type Permission = 'org:read' | 'org:write' | 'org:delete' | 'member:read' | 'member:write' | 'member:delete' | 'billing:read' | 'billing:write' | 'settings:read' | 'settings:write' | string;
interface Organization {
    id: string;
    tenantId: string;
    name: string;
    slug: string;
    logoUrl?: string;
    description?: string;
    website?: string;
    maxMembers?: number;
    role: OrganizationRole;
    createdAt: string;
    updatedAt: string;
}
type OrganizationRole = 'owner' | 'admin' | 'member' | 'guest';
interface OrganizationMember {
    id: string;
    userId: string;
    email: string;
    name?: string;
    role: OrganizationRole;
    status: 'pending' | 'active' | 'suspended';
    joinedAt?: string;
}
interface CreateOrganizationOptions {
    name: string;
    slug?: string;
    logo?: File;
    description?: string;
}
interface InviteMemberOptions {
    email: string;
    role: OrganizationRole;
    organizationId?: string;
}
interface UpdateOrganizationOptions {
    name?: string;
    slug?: string;
    logo?: File;
    description?: string;
}
interface VaultConfig {
    apiUrl: string;
    tenantId: string;
    /**
     * @deprecated Use tenantId instead
     */
    tenantSlug?: string;
    /**
     * Enable debug logging
     */
    debug?: boolean;
    /**
     * Session token (for SSR)
     */
    sessionToken?: string;
    /**
     * Custom fetch implementation
     */
    fetch?: typeof fetch;
    /**
     * Turnstile site key for bot protection
     */
    turnstileSiteKey?: string;
    /**
     * OAuth providers configuration
     */
    oauth?: OAuthProvidersConfig;
}
interface SignInOptions {
    email: string;
    password: string;
    turnstileToken?: string;
}
interface SignUpOptions {
    email: string;
    password: string;
    name?: string;
    givenName?: string;
    familyName?: string;
    turnstileToken?: string;
}
interface MagicLinkOptions {
    email: string;
    redirectUrl?: string;
    turnstileToken?: string;
}
/**
 * OAuth provider type - 30+ providers supported
 */
type OAuthProvider$1 = 'google' | 'github' | 'microsoft' | 'apple' | 'discord' | 'slack' | 'facebook' | 'twitter' | 'instagram' | 'tiktok' | 'snapchat' | 'pinterest' | 'reddit' | 'twitch' | 'spotify' | 'linkedin' | 'gitlab' | 'bitbucket' | 'digitalocean' | 'heroku' | 'vercel' | 'netlify' | 'cloudflare' | 'salesforce' | 'hubspot' | 'zendesk' | 'notion' | 'figma' | 'linear' | 'atlassian' | 'okta' | 'wechat' | 'line' | 'kakaotalk' | 'vkontakte' | 'yandex' | string;
/**
 * OAuth provider category
 */
type OAuthProviderCategory = 'social' | 'professional' | 'developer' | 'enterprise' | 'regional' | 'custom';
/**
 * OAuth provider metadata
 */
interface OAuthProviderMetadata {
    id: OAuthProvider$1;
    name: string;
    displayName: string;
    category: OAuthProviderCategory;
    icon?: string;
    color?: string;
    pkceEnabled: boolean;
    scopes: string[];
}
/**
 * OAuth providers configuration
 */
interface OAuthProvidersConfig {
    google?: {
        clientId: string;
    };
    github?: {
        clientId: string;
    };
    microsoft?: {
        clientId: string;
    };
    apple?: {
        clientId: string;
    };
    discord?: {
        clientId: string;
    };
    slack?: {
        clientId: string;
    };
    facebook?: {
        clientId: string;
    };
    twitter?: {
        clientId: string;
    };
    instagram?: {
        clientId: string;
    };
    tiktok?: {
        clientId: string;
    };
    snapchat?: {
        clientId: string;
    };
    pinterest?: {
        clientId: string;
    };
    reddit?: {
        clientId: string;
    };
    twitch?: {
        clientId: string;
    };
    spotify?: {
        clientId: string;
    };
    linkedin?: {
        clientId: string;
    };
    gitlab?: {
        clientId: string;
    };
    bitbucket?: {
        clientId: string;
    };
    digitalocean?: {
        clientId: string;
    };
    heroku?: {
        clientId: string;
    };
    vercel?: {
        clientId: string;
    };
    netlify?: {
        clientId: string;
    };
    cloudflare?: {
        clientId: string;
    };
    salesforce?: {
        clientId: string;
    };
    hubspot?: {
        clientId: string;
    };
    zendesk?: {
        clientId: string;
        subdomain: string;
    };
    notion?: {
        clientId: string;
    };
    figma?: {
        clientId: string;
    };
    linear?: {
        clientId: string;
    };
    atlassian?: {
        clientId: string;
    };
    okta?: {
        clientId: string;
        domain: string;
    };
    wechat?: {
        appId: string;
    };
    line?: {
        clientId: string;
    };
    kakaotalk?: {
        clientId: string;
    };
    vkontakte?: {
        clientId: string;
    };
    yandex?: {
        clientId: string;
    };
}
interface OAuthOptions {
    provider: OAuthProvider$1;
    redirectUrl?: string;
    /**
     * Additional OAuth scopes to request
     */
    scopes?: string[];
    /**
     * Force consent screen even if previously authorized
     */
    prompt?: 'none' | 'login' | 'consent' | 'select_account';
}
interface ForgotPasswordOptions {
    email: string;
    redirectUrl?: string;
}
interface ResetPasswordOptions {
    token: string;
    password: string;
}
interface VerifyEmailOptions {
    token: string;
}
interface MfaChallenge {
    method: MfaMethod;
    expiresAt: string;
}
interface MfaSetupOptions {
    method: Exclude<MfaMethod, 'backup_codes'>;
}
interface MfaVerifyOptions {
    code: string;
    method: MfaMethod;
}
interface TotpSetup {
    secret: string;
    qrCode: string;
    backupCodes: string[];
}
interface WebAuthnOptions {
    challenge: string;
    rp: {
        id: string;
        name: string;
    };
    user: {
        id: string;
        displayName: string;
        name: string;
    };
    pubKeyCredParams: Array<{
        alg: number;
        type: string;
    }>;
    timeout: number;
    authenticatorSelection: {
        authenticatorAttachment?: string;
        requireResidentKey: boolean;
        residentKey: string;
        userVerification: string;
    };
    attestation: string;
}
interface WebAuthnCredential {
    id: string;
    rawId: ArrayBuffer;
    response: AuthenticatorAttestationResponse | AuthenticatorAssertionResponse;
    type: string;
}
interface ApiError {
    code: string;
    message: string;
    details?: Record<string, any>;
}
type AuthState = {
    status: 'loading';
} | {
    status: 'authenticated';
    user: User;
    session: Session;
} | {
    status: 'unauthenticated';
} | {
    status: 'mfa_required';
    challenge: MfaChallenge;
} | {
    status: 'error';
    error: ApiError;
};
/**
 * @deprecated Use Appearance from '../theme' instead
 * Component appearance configuration
 */
interface Appearance$1 {
    /** Base theme - 'light', 'dark', 'neutral', or 'auto' */
    baseTheme?: 'light' | 'dark' | 'neutral' | 'auto';
    /** @deprecated Use baseTheme instead */
    theme?: 'light' | 'dark' | 'auto';
    /** CSS variable overrides */
    variables?: Record<string, string>;
    /** Element style overrides (deprecated, use class names instead) */
    elements?: Record<string, React.CSSProperties>;
    /** Layout configuration */
    layout?: {
        socialButtonsPlacement?: 'top' | 'bottom';
        socialButtonsVariant?: 'iconButton' | 'blockButton' | 'auto';
        showOptionalFields?: boolean;
        shimmer?: boolean;
        logoUrl?: string;
        logoPlacement?: 'inside' | 'outside' | 'none';
    };
    /** Additional CSS to inject */
    appendCss?: string;
}
interface SignInProps {
    /**
     * Redirect URL after successful sign in
     */
    redirectUrl?: string;
    /**
     * Callback after successful sign in
     */
    onSignIn?: () => void;
    /**
     * Callback on sign in error
     */
    onError?: (error: ApiError) => void;
    /**
     * Enable magic link option
     */
    showMagicLink?: boolean;
    /**
     * Enable forgot password link
     */
    showForgotPassword?: boolean;
    /**
     * Enable OAuth providers
     */
    oauthProviders?: OAuthProvider$1[];
    /**
     * Enable WebAuthn/passkey sign in
     */
    showWebAuthn?: boolean;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
interface SignUpProps {
    /**
     * Redirect URL after successful sign up
     */
    redirectUrl?: string;
    /**
     * Callback after successful sign up
     */
    onSignUp?: () => void;
    /**
     * Callback on sign up error
     */
    onError?: (error: ApiError) => void;
    /**
     * Enable OAuth providers
     */
    oauthProviders?: OAuthProvider$1[];
    /**
     * Require name field
     */
    requireName?: boolean;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
interface UserButtonProps {
    /**
     * Show user name in button
     */
    showName?: boolean;
    /**
     * Custom avatar URL
     */
    avatarUrl?: string;
    /**
     * Callback when sign out is clicked
     */
    onSignOut?: () => void;
    /**
     * Custom menu items
     */
    menuItems?: Array<{
        label: string;
        onClick: () => void;
    }>;
    /**
     * Show manage account link
     */
    showManageAccount?: boolean;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
interface UserProfileProps {
    /**
     * Callback when profile is updated
     */
    onUpdate?: (user: User) => void;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
interface ProtectProps {
    /**
     * Child components to render when authenticated
     */
    children: React.ReactNode;
    /**
     * Content to render when unauthenticated (default: redirects to sign in)
     */
    fallback?: React.ReactNode;
    /**
     * Required role for access
     */
    role?: OrganizationRole;
    /**
     * Required permission
     */
    permission?: string;
    /**
     * Custom loading component
     */
    loading?: React.ReactNode;
}
interface WebAuthnButtonProps {
    /**
     * Button mode: 'signin' | 'signup' | 'link'
     */
    mode?: 'signin' | 'signup' | 'link';
    /**
     * Button label
     */
    label?: string;
    /**
     * Callback on success
     */
    onSuccess?: () => void;
    /**
     * Callback on error
     */
    onError?: (error: ApiError) => void;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
interface VerifyEmailProps {
    /**
     * Verification token (from URL query param)
     */
    token?: string;
    /**
     * Callback on successful verification
     */
    onVerified?: () => void;
    /**
     * Callback on error
     */
    onError?: (error: ApiError) => void;
    /**
     * Redirect URL after verification
     */
    redirectUrl?: string;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
interface ResetPasswordProps {
    /**
     * Reset token (from URL query param)
     */
    token?: string;
    /**
     * Callback on successful reset
     */
    onSuccess?: () => void;
    /**
     * Callback on error
     */
    onError?: (error: ApiError) => void;
    /**
     * Redirect URL after reset
     */
    redirectUrl?: string;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
interface MFAFormProps {
    /**
     * MFA challenge (from auth context)
     */
    challenge?: MfaChallenge;
    /**
     * Callback on successful verification
     */
    onVerify?: () => void;
    /**
     * Callback on error
     */
    onError?: (error: ApiError) => void;
    /**
     * Allow backup code fallback
     */
    allowBackupCode?: boolean;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
interface OrganizationSwitcherProps {
    /**
     * Hide personal organization option
     */
    hidePersonal?: boolean;
    /**
     * Callback when organization is switched
     */
    onSwitch?: (org: Organization | null) => void;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
interface UseAuthReturn {
    isLoaded: boolean;
    isSignedIn: boolean;
    user: User | null;
    session: Session | null;
    organization: Organization | null;
    signIn: (options: SignInOptions) => Promise<void>;
    signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
    signInWithOAuth: (options: OAuthOptions) => Promise<void>;
    signUp: (options: SignUpOptions) => Promise<void>;
    signOut: () => Promise<void>;
}
interface UseSignInReturn {
    isLoading: boolean;
    error: ApiError | null;
    signIn: (options: SignInOptions) => Promise<void>;
    signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
    signInWithOAuth: (options: OAuthOptions) => Promise<void>;
    resetError: () => void;
}
interface UseSignUpReturn {
    isLoading: boolean;
    error: ApiError | null;
    signUp: (options: SignUpOptions) => Promise<void>;
    signUpWithOAuth: (options: OAuthOptions) => Promise<void>;
    resetError: () => void;
}
interface UseSessionReturn {
    session: Session | null;
    isLoaded: boolean;
    getToken: () => Promise<string | null>;
    refresh: () => Promise<void>;
}
interface UseUserReturn {
    user: User | null;
    isLoaded: boolean;
    update: (updates: Partial<User>) => Promise<void>;
    reload: () => Promise<void>;
}
interface UseWebAuthnReturn {
    isSupported: boolean;
    isLoading: boolean;
    error: ApiError | null;
    register: (name?: string) => Promise<void>;
    authenticate: () => Promise<Session | null>;
    resetError: () => void;
}
interface UseMfaReturn {
    isLoading: boolean;
    error: ApiError | null;
    setupTotp: () => Promise<TotpSetup | null>;
    verifyTotp: (code: string) => Promise<void>;
    enableMfa: (method: MfaMethod) => Promise<void>;
    disableMfa: (method: MfaMethod) => Promise<void>;
    generateBackupCodes: () => Promise<string[]>;
    resetError: () => void;
}
interface UseOrganizationReturn {
    organization: Organization | null;
    organizations: Organization[];
    organizationList: Organization[];
    isLoaded: boolean;
    isLoading: boolean;
    members: OrganizationMember[];
    setActive: (orgId: string | null) => void;
    setActiveOrganization: (orgId: string | null) => Promise<void>;
    create: (data: {
        name: string;
        slug?: string;
    }) => Promise<Organization>;
    createOrganization: (name: string, slug?: string) => Promise<Organization>;
    leave: (orgId: string) => Promise<void>;
    refreshMembers: () => Promise<void>;
    updateOrganization: (orgId: string, updates: Partial<Organization>) => Promise<Organization>;
    deleteOrganization: (orgId: string) => Promise<void>;
    inviteMember: (orgId: string, email: string, role: OrganizationRole) => Promise<void>;
    removeMember: (orgId: string, userId: string) => Promise<void>;
    updateMemberRole: (orgId: string, userId: string, role: OrganizationRole) => Promise<void>;
}
interface UseSessionsReturn {
    sessions: SessionInfo[];
    isLoading: boolean;
    error: ApiError | null;
    revokeSession: (sessionId: string) => Promise<void>;
    revokeAllOtherSessions: () => Promise<void>;
    refresh: () => Promise<void>;
}
interface UsePermissionsReturn {
    has: (permission: string) => boolean;
    hasRole: (role: string | string[]) => boolean;
    hasAnyRole: (roles: string[]) => boolean;
    permissions: string[];
    role: OrganizationRole | null;
    isLoaded: boolean;
}
interface UseCheckAuthorizationReturn {
    check: (params: PermissionCheck) => boolean;
}

/**
 * Vault API Client
 *
 * HTTP client for the Vault API.
 */

declare class VaultApiClient {
    private config;
    private baseUrl;
    constructor(config: VaultConfig);
    request<T>(endpoint: string, options?: RequestInit): Promise<T>;
    signIn(options: SignInOptions): Promise<{
        user: User;
        session: Session;
        mfaRequired?: boolean;
        mfaChallenge?: MfaChallenge;
    }>;
    signUp(options: SignUpOptions): Promise<{
        user: User;
        session: Session;
    }>;
    sendMagicLink(options: MagicLinkOptions): Promise<void>;
    verifyMagicLink(token: string): Promise<{
        user: User;
        session: Session;
    }>;
    sendForgotPassword(options: ForgotPasswordOptions): Promise<void>;
    resetPassword(options: ResetPasswordOptions): Promise<{
        user: User;
        session: Session;
    }>;
    verifyEmail(options: VerifyEmailOptions): Promise<{
        user: User;
    }>;
    resendVerificationEmail(): Promise<void>;
    getOAuthUrl(options: OAuthOptions): Promise<{
        url: string;
    }>;
    handleOAuthCallback(provider: string, code: string): Promise<{
        user: User;
        session: Session;
    }>;
    verifyMfa(code: string, method: MfaMethod): Promise<{
        user: User;
        session: Session;
    }>;
    signOut(): Promise<void>;
    refreshSession(): Promise<{
        session: Session;
    }>;
    validateSession(token: string): Promise<Session>;
    getCurrentUser(): Promise<User>;
    updateUser(updates: Partial<User> | Partial<UserProfile$2>): Promise<User>;
    deleteUser(): Promise<void>;
    changePassword(currentPassword: string, newPassword: string): Promise<void>;
    uploadAvatar(file: File): Promise<{
        url: string;
    }>;
    getMfaStatus(): Promise<{
        enabled: boolean;
        methods: MfaMethod[];
    }>;
    setupTotp(): Promise<TotpSetup>;
    verifyTotpSetup(code: string): Promise<void>;
    disableMfa(method: MfaMethod): Promise<void>;
    generateBackupCodes(): Promise<{
        codes: string[];
    }>;
    verifyBackupCode(code: string): Promise<void>;
    beginWebAuthnRegistration(): Promise<WebAuthnOptions>;
    finishWebAuthnRegistration(credential: unknown): Promise<void>;
    beginWebAuthnAuthentication(): Promise<WebAuthnOptions>;
    finishWebAuthnAuthentication(credential: unknown): Promise<{
        user: User;
        session: Session;
    }>;
    listWebAuthnCredentials(): Promise<Array<{
        id: string;
        name: string;
        createdAt: string;
        lastUsedAt?: string;
    }>>;
    deleteWebAuthnCredential(credentialId: string): Promise<void>;
    listSessions(): Promise<SessionInfo[]>;
    revokeSession(sessionId: string): Promise<void>;
    revokeAllSessions(): Promise<void>;
    listOrganizations(): Promise<Organization[]>;
    setActiveOrganization(orgId: string | null): Promise<{
        user: User;
        session: Session;
    }>;
    getOrganization(id: string): Promise<Organization>;
    createOrganization(data: {
        name: string;
        slug?: string;
    }): Promise<Organization>;
    updateOrganization(id: string, data: Partial<Organization>): Promise<Organization>;
    deleteOrganization(id: string): Promise<void>;
    leaveOrganization(id: string): Promise<void>;
    listOrganizationMembers(orgId: string): Promise<OrganizationMember[]>;
    inviteOrganizationMember(orgId: string, email: string, role: string): Promise<void>;
    removeOrganizationMember(orgId: string, userId: string): Promise<void>;
    updateOrganizationMemberRole(orgId: string, userId: string, role: string): Promise<void>;
    storeToken(token: string): Promise<void>;
    storeRefreshToken(token: string): Promise<void>;
    getStoredToken(): Promise<string | null>;
    getStoredRefreshToken(): Promise<string | null>;
    clearToken(): Promise<void>;
    getBillingPlans(): Promise<{
        billingEnabled: boolean;
        plans: any[];
    }>;
    getBillingStatus(): Promise<any>;
    getSubscription(): Promise<{
        subscription: any | null;
    }>;
    createSubscription(data: {
        priceId: string;
        successUrl: string;
        cancelUrl: string;
    }): Promise<any>;
    cancelSubscription(): Promise<{
        subscription: any;
    }>;
    resumeSubscription(): Promise<{
        subscription: any;
    }>;
    updateSubscription(newPriceId: string): Promise<{
        subscription: any;
    }>;
    getInvoices(): Promise<{
        invoices: any[];
    }>;
    createPortalSession(returnUrl: string): Promise<{
        url: string;
    }>;
    reportUsage(quantity: number, action?: 'increment' | 'set'): Promise<void>;
    /**
     * Check if WebAuthn is supported in the current browser
     */
    isWebAuthnSupported(): boolean;
}
declare function createVaultClient(config: VaultConfig): VaultApiClient;

interface VaultContextValue {
    isLoaded: boolean;
    isSignedIn: boolean;
    user: User | null;
    session: Session | null;
    organization: Organization | null;
    authState: AuthState;
    api: VaultApiClient;
    signIn: (options: SignInOptions) => Promise<void>;
    signInWithMagicLink: (options: MagicLinkOptions) => Promise<void>;
    signInWithOAuth: (options: OAuthOptions) => Promise<void>;
    signUp: (options: SignUpOptions) => Promise<void>;
    signOut: () => Promise<void>;
    sendForgotPassword: (options: ForgotPasswordOptions) => Promise<void>;
    resetPassword: (options: ResetPasswordOptions) => Promise<{
        user: User;
        session: Session;
    }>;
    verifyEmail: (options: VerifyEmailOptions) => Promise<void>;
    resendVerificationEmail: () => Promise<void>;
    mfaChallenge: MfaChallenge | null;
    verifyMfa: (code: string, method: MfaMethod) => Promise<void>;
    setupTotp: () => Promise<TotpSetup | null>;
    verifyTotpSetup: (code: string) => Promise<void>;
    disableMfa: (method: MfaMethod) => Promise<void>;
    generateBackupCodes: () => Promise<string[]>;
    updateUser: (updates: Partial<User>) => Promise<void>;
    reloadUser: () => Promise<void>;
    changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
    deleteUser: () => Promise<void>;
    organizations: Organization[];
    setActiveOrganization: (orgId: string | null) => Promise<void>;
    createOrganization: (name: string, slug?: string) => Promise<Organization>;
    leaveOrganization: (orgId: string) => Promise<void>;
    refreshOrganizations: () => Promise<void>;
    sessions: SessionInfo[];
    revokeSession: (sessionId: string) => Promise<void>;
    revokeAllOtherSessions: () => Promise<void>;
    refreshSessions: () => Promise<void>;
    getToken: () => Promise<string | null>;
    refreshSession: () => Promise<void>;
    lastError: ApiError | null;
    clearError: () => void;
}
declare const VaultContext: React$1.Context<VaultContextValue | null>;
interface VaultProviderProps {
    children: React$1.ReactNode;
    config: VaultConfig;
    /**
     * Initial user data (for SSR)
     */
    initialUser?: User;
    /**
     * Initial session token (for SSR)
     */
    initialSessionToken?: string;
    /**
     * Callback when authentication state changes
     */
    onAuthStateChange?: (state: AuthState) => void;
    /**
     * Global appearance configuration for components
     */
    appearance?: Appearance$1;
}
declare function VaultProvider({ children, config, initialUser, initialSessionToken, onAuthStateChange, appearance, }: VaultProviderProps): react_jsx_runtime.JSX.Element;
declare function useVault(): VaultContextValue;

/**
 * Theme Types
 *
 * Clerk-style theming system types for Vault React SDK.
 */
interface ThemeVariables {
    /** Primary brand color */
    colorPrimary: string;
    /** Primary color on hover state */
    colorPrimaryHover: string;
    /** Page/app background color */
    colorBackground: string;
    /** Input field background color */
    colorInputBackground: string;
    /** Primary text color */
    colorText: string;
    /** Secondary/muted text color */
    colorTextSecondary: string;
    /** Error/danger color */
    colorDanger: string;
    /** Success color */
    colorSuccess: string;
    /** Warning color */
    colorWarning: string;
    /** Input text color */
    colorInputText: string;
    /** Input border color */
    colorInputBorder: string;
    /** Base font family */
    fontFamily: string;
    /** Font family for buttons */
    fontFamilyButtons: string;
    /** Base font size */
    fontSize: string;
    /** Base font weight */
    fontWeight: string | number;
    /** Border radius for components */
    borderRadius: string;
    /** Base spacing unit */
    spacing: string;
    /** Color for shimmer animation */
    colorShimmer?: string;
    /** Focus ring color */
    colorFocus?: string;
    /** Card/elevated surface background */
    colorSurface?: string;
    /** Divider/border color */
    colorBorder?: string;
    /** Avatar background color */
    colorAvatarBackground?: string;
}
interface ElementStyles {
    /** Primary form button styles */
    formButtonPrimary?: string;
    /** Secondary form button styles */
    formButtonSecondary?: string;
    /** Form field container styles */
    formField?: string;
    /** Form input styles */
    formFieldInput?: string;
    /** Form label styles */
    formFieldLabel?: string;
    /** Form error message styles */
    formFieldError?: string;
    /** Social buttons container */
    socialButtons?: string;
    /** Individual social button/icon styles */
    socialButtonsIconButton?: string;
    /** Root container styles */
    root?: string;
    /** Card container styles */
    card?: string;
    /** Header container styles */
    header?: string;
    /** Header title styles */
    headerTitle?: string;
    /** Header subtitle styles */
    headerSubtitle?: string;
    /** Divider line styles */
    dividerLine?: string;
    /** Divider text styles */
    dividerText?: string;
    /** Alert/notification styles */
    alert?: string;
    /** Alert error variant */
    alertError?: string;
    /** Alert success variant */
    alertSuccess?: string;
    /** Alert warning variant */
    alertWarning?: string;
    /** Spinner/loading styles */
    spinner?: string;
    /** User button styles */
    userButton?: string;
    /** User button popover styles */
    userButtonPopover?: string;
    /** User button popover card */
    userButtonPopoverCard?: string;
    /** User button trigger styles */
    userButtonTrigger?: string;
    /** Avatar placeholder styles */
    avatarBox?: string;
    /** Menu item styles */
    menuItem?: string;
    /** Menu list styles */
    menuList?: string;
}
interface LayoutOptions {
    /** Placement of social buttons relative to form */
    socialButtonsPlacement: 'top' | 'bottom';
    /** Visual variant for social buttons */
    socialButtonsVariant: 'iconButton' | 'blockButton' | 'auto';
    /** Whether to show optional fields by default */
    showOptionalFields: boolean;
    /** Enable shimmer loading effect */
    shimmer: boolean;
    /** Help page URL for support links */
    helpPageUrl?: string;
    /** Privacy page URL */
    privacyPageUrl?: string;
    /** Terms page URL */
    termsPageUrl?: string;
    /** Logo URL to display */
    logoUrl?: string;
    /** Logo placement */
    logoPlacement?: 'inside' | 'outside' | 'none';
    /** Enable animations */
    animations?: boolean;
}
interface Appearance {
    /** Base theme to use */
    baseTheme?: 'light' | 'dark' | 'neutral' | 'auto';
    /** CSS variable overrides */
    variables?: Partial<ThemeVariables>;
    /** Element class name overrides */
    elements?: ElementStyles;
    /** Layout configuration */
    layout?: Partial<LayoutOptions>;
    /** Additional CSS to inject */
    appendCss?: string;
}
interface Theme {
    /** Theme identifier */
    id: string;
    /** Theme name */
    name: string;
    /** CSS variables */
    variables: ThemeVariables;
    /** Element class names */
    elements: ElementStyles;
    /** Layout options */
    layout: LayoutOptions;
    /** Whether this is a dark theme */
    isDark: boolean;
}
interface ThemeContextValue {
    /** Current theme */
    theme: Theme;
    /** Current appearance configuration */
    appearance: Appearance;
    /** Generated CSS variables */
    cssVariables: Record<string, string>;
    /** Get element class names */
    getElementClass: (elementName: keyof ElementStyles) => string;
    /** Check if layout option is enabled */
    getLayoutOption: <K extends keyof LayoutOptions>(key: K) => LayoutOptions[K];
    /** Check if current theme is dark */
    isDark: boolean;
}
interface ThemeProviderProps {
    /** Child components */
    children: React.ReactNode;
    /** Appearance configuration */
    appearance?: Appearance;
    /** Default theme (overrides baseTheme in appearance) */
    defaultTheme?: 'light' | 'dark' | 'neutral';
}

declare const ThemeContext: React$1.Context<ThemeContextValue | null>;
declare function ThemeProvider({ children, appearance, defaultTheme, }: ThemeProviderProps): react_jsx_runtime.JSX.Element;
declare function useTheme(): ThemeContextValue;
declare function withTheme<P extends object>(Component: React$1.ComponentType<P & {
    theme: ThemeContextValue;
}>): React$1.FC<P>;

/**
 * Default Themes
 *
 * Pre-defined light, dark, and neutral themes following Clerk's design system.
 */

declare const lightTheme: Theme;
declare const darkTheme: Theme;
declare const neutralTheme: Theme;
declare const themes: Record<string, Theme>;
/**
 * Get a theme by ID
 */
declare function getTheme(themeId: string): Theme;

/**
 * Theme Utilities
 *
 * Helper functions for theme manipulation and CSS generation.
 */

/**
 * Merge appearance configuration with base theme
 */
declare function mergeThemes(base: Theme, appearance?: Appearance): Theme;
/**
 * Generate CSS custom properties from theme variables
 */
declare function generateCSSVariables(vars: ThemeVariables): Record<string, string>;
/**
 * Convert CSS variables object to inline style string
 */
declare function cssVariablesToStyle(vars: Record<string, string>): React.CSSProperties;
/**
 * Create a combined class name for an element
 */
declare function createElementStyles(elements: ElementStyles, elementName: keyof ElementStyles): string;
/**
 * Get all class names for an element as an array
 */
declare function getElementClasses(elements: ElementStyles, elementName: keyof ElementStyles): string[];
/**
 * Get layout option with fallback
 */
declare function getLayoutOption<K extends keyof LayoutOptions>(layout: Partial<LayoutOptions>, key: K, defaultValue?: LayoutOptions[K]): LayoutOptions[K];
/**
 * Apply CSS variables to a style object
 */
declare function applyCSSVariables(baseStyle: React.CSSProperties, vars: Record<string, string>): React.CSSProperties;
/**
 * Merge class names
 */
declare function cx(...classes: (string | undefined | null | false)[]): string;
interface BaseComponentStyles {
    buttonPrimary: React.CSSProperties;
    buttonSecondary: React.CSSProperties;
    input: React.CSSProperties;
    label: React.CSSProperties;
    card: React.CSSProperties;
    alert: React.CSSProperties;
    alertError: React.CSSProperties;
    alertSuccess: React.CSSProperties;
    alertWarning: React.CSSProperties;
    spinner: React.CSSProperties;
}
/**
 * Generate base component styles from CSS variables
 */
declare function generateBaseStyles(vars: Record<string, string>): BaseComponentStyles;

/**
 * useAuth Hook
 *
 * Primary hook for authentication state and actions.
 *
 * @example
 * ```tsx
 * function App() {
 *   const { isSignedIn, user, signOut } = useAuth();
 *
 *   if (!isSignedIn) {
 *     return <SignIn />;
 *   }
 *
 *   return (
 *     <div>
 *       <p>Hello {user?.email}</p>
 *       <button onClick={signOut}>Sign out</button>
 *     </div>
 *   );
 * }
 * ```
 */

/**
 * Hook to access authentication state and methods.
 * Must be used within a VaultProvider.
 *
 * @returns Authentication state and methods
 */
declare function useAuth(): UseAuthReturn;
/**
 * Hook to get the current authentication state only.
 * Useful when you only need to check if user is signed in.
 *
 * @returns Object with isLoaded and isSignedIn booleans
 */
declare function useAuthState(): {
    isLoaded: boolean;
    isSignedIn: boolean;
};
/**
 * Hook to check if the current user has a specific role.
 *
 * @param role - The role to check for
 * @returns Boolean indicating if user has the role
 */
declare function useHasRole(role: string): boolean;
/**
 * Hook to require authentication.
 * Returns the user or throws if not authenticated.
 *
 * @returns The current user
 * @throws Error if not authenticated
 */
declare function useRequireAuth(): {
    user: User;
    session: Session;
    organization: Organization | null;
};

/**
 * useUser Hook
 *
 * Hook for user data and management.
 *
 * @example
 * ```tsx
 * function Profile() {
 *   const user = useUser();
 *   const { updateUser, reloadUser } = useUpdateUser();
 *
 *   if (!user) return null;
 *
 *   return <div>Hello {user.email}</div>;
 * }
 * ```
 */

/**
 * Hook to get the current user.
 * Returns null if not signed in.
 *
 * @returns The current user or null
 */
declare function useUser(): User | null;
/**
 * Hook for user management operations.
 *
 * @returns Object with update and reload functions
 */
declare function useUpdateUser(): {
    updateUser: (updates: Partial<User>) => Promise<void>;
    reloadUser: () => Promise<void>;
    isLoading: boolean;
    error: ApiError | null;
};
/**
 * Complete hook for user data and management.
 *
 * @returns User data and management functions
 */
declare function useUserManager(): UseUserReturn & {
    isLoading: boolean;
    error: ApiError | null;
    changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
    deleteUser: () => Promise<void>;
};

/**
 * useSession Hook
 *
 * Hook for session management.
 *
 * @example
 * ```tsx
 * function App() {
 *   const { session, getToken } = useSession();
 *
 *   useEffect(() => {
 *     // Get token for API calls
 *     getToken().then(token => {
 *       // Use token for external API calls
 *     });
 *   }, []);
 * }
 * ```
 */

/**
 * Hook to access the current session.
 *
 * @returns Session data and methods
 */
declare function useSession(): UseSessionReturn;
/**
 * Hook to get the session token.
 * Useful for making authenticated API calls.
 *
 * @returns Function to get the current token
 */
declare function useToken(): () => Promise<string | null>;
/**
 * Hook to get the current session ID.
 *
 * @returns The current session ID or null
 */
declare function useSessionId(): string | null;

/**
 * useSessions Hook
 *
 * Hook for managing all user sessions with polling support.
 *
 * @example
 * ```tsx
 * function SessionManager() {
 *   const { sessions, isLoading, revokeSession, revokeAllOtherSessions } = useSessions();
 *
 *   return (
 *     <div>
 *       <h3>Active Sessions</h3>
 *       {sessions.map(session => (
 *         <SessionItem
 *           key={session.id}
 *           session={session}
 *           onRevoke={() => revokeSession(session.id)}
 *         />
 *       ))}
 *       <button onClick={revokeAllOtherSessions}>
 *         Sign out all other devices
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */

/**
 * Hook for managing all user sessions.
 * Automatically polls for session updates every 30 seconds when user is signed in.
 *
 * @param options - Optional configuration for polling
 * @param options.pollingInterval - Custom polling interval in milliseconds (default: 30000)
 * @returns Session management functions and state
 */
declare function useSessions(options?: {
    pollingInterval?: number;
}): UseSessionsReturn;

/**
 * useSignIn Hook
 *
 * Hook for sign-in functionality with loading and error states.
 *
 * @example
 * ```tsx
 * function SignInPage() {
 *   const { signIn, isLoading, error } = useSignIn();
 *
 *   const handleSubmit = async (e) => {
 *     e.preventDefault();
 *     const formData = new FormData(e.target);
 *     try {
 *       await signIn({
 *         email: formData.get('email'),
 *         password: formData.get('password'),
 *       });
 *     } catch (err) {
 *       // Handle error
 *     }
 *   };
 *
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       <input name="email" type="email" />
 *       <input name="password" type="password" />
 *       {error && <p>{error.message}</p>}
 *       <button disabled={isLoading}>
 *         {isLoading ? 'Signing in...' : 'Sign In'}
 *       </button>
 *     </form>
 *   );
 * }
 * ```
 */

/**
 * Hook for sign-in operations.
 * Provides loading states and error handling.
 *
 * @returns Sign-in methods and state
 */
declare function useSignIn(): UseSignInReturn;

/**
 * useSignUp Hook
 *
 * Hook for sign-up functionality with loading and error states.
 *
 * @example
 * ```tsx
 * function SignUpPage() {
 *   const { signUp, isLoading, error } = useSignUp();
 *
 *   const handleSubmit = async (e) => {
 *     e.preventDefault();
 *     const formData = new FormData(e.target);
 *     try {
 *       await signUp({
 *         email: formData.get('email'),
 *         password: formData.get('password'),
 *         name: formData.get('name'),
 *       });
 *     } catch (err) {
 *       // Handle error
 *     }
 *   };
 *
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       <input name="name" placeholder="Full Name" />
 *       <input name="email" type="email" />
 *       <input name="password" type="password" />
 *       {error && <p>{error.message}</p>}
 *       <button disabled={isLoading}>
 *         {isLoading ? 'Creating account...' : 'Sign Up'}
 *       </button>
 *     </form>
 *   );
 * }
 * ```
 */

/**
 * Hook for sign-up operations.
 * Provides loading states and error handling.
 *
 * @returns Sign-up methods and state
 */
declare function useSignUp(): UseSignUpReturn;

/**
 * useWebAuthn Hook
 *
 * Hook for WebAuthn/Passkey authentication.
 *
 * @example
 * ```tsx
 * function PasskeyButton() {
 *   const { isSupported, register, authenticate, isLoading } = useWebAuthn();
 *
 *   if (!isSupported) {
 *     return <p>Passkeys not supported on this device</p>;
 *   }
 *
 *   return (
 *     <>
 *       <button onClick={() => register()} disabled={isLoading}>
 *         Register Passkey
 *       </button>
 *       <button onClick={() => authenticate()} disabled={isLoading}>
 *         Sign in with Passkey
 *       </button>
 *     </>
 *   );
 * }
 * ```
 */

/**
 * Hook for WebAuthn/Passkey operations.
 *
 * @returns WebAuthn methods and state
 */
declare function useWebAuthn(): UseWebAuthnReturn;
/**
 * Hook to check if WebAuthn is supported on the current device.
 *
 * @returns Boolean indicating WebAuthn support
 */
declare function useIsWebAuthnSupported(): boolean;

/**
 * Hook for MFA operations.
 * Provides methods to setup, verify, and manage MFA methods.
 *
 * @returns MFA methods and state
 */
declare function useMfa(): UseMfaReturn;
/**
 * Hook to verify MFA challenge during sign-in.
 *
 * @returns MFA verification state and method
 */
declare function useMfaChallenge(): {
    challenge: MfaChallenge | null;
    isRequired: boolean;
    verify: (code: string, method: MfaMethod) => Promise<void>;
    isLoading: boolean;
    error: ApiError | null;
};

/**
 * useOrganization Hook
 *
 * Hook for organization management.
 *
 * @example
 * ```tsx
 * function OrganizationSwitcher() {
 *   const { organizations, setActive, create, isLoading } = useOrganization();
 *
 *   return (
 *     <select onChange={(e) => setActive(e.target.value)}>
 *       {organizations.map(org => (
 *         <option key={org.id} value={org.id}>{org.name}</option>
 *       ))}
 *     </select>
 *   );
 * }
 * ```
 */

/**
 * Hook for organization operations.
 *
 * @returns Organization state and methods
 */
declare function useOrganization(): UseOrganizationReturn;
/**
 * Hook to get the current active organization.
 *
 * @returns The current organization or null
 */
declare function useActiveOrganization(): Organization | null;
/**
 * Hook to check if user has a specific organization role.
 *
 * @param role - The role to check for
 * @returns Boolean indicating if user has the role
 */
declare function useOrganizationRole(role: string): boolean;
/**
 * Hook to check if user is an organization admin or owner.
 *
 * @returns Boolean indicating admin status
 */
declare function useIsOrgAdmin(): boolean;

/**
 * usePermissions Hook
 *
 * Hook for checking user permissions based on organization role.
 *
 * @example
 * ```tsx
 * function AdminPanel() {
 *   const { has, hasRole, permissions, role, isLoaded } = usePermissions();
 *
 *   if (!isLoaded) return <Loading />;
 *
 *   if (has('org:delete')) {
 *     return <DeleteOrgButton />;
 *   }
 *
 *   if (hasRole('admin')) {
 *     return <AdminDashboard />;
 *   }
 *
 *   return <MemberView />;
 * }
 * ```
 */

/**
 * Hook for checking user permissions derived from organization role.
 *
 * @returns Permission checking functions and current role info
 */
declare function usePermissions(): UsePermissionsReturn;

/**
 * useCheckAuthorization Hook
 *
 * Hook for declarative permission and role checking.
 *
 * @example
 * ```tsx
 * function ProtectedComponent() {
 *   const { check } = useCheckAuthorization();
 *
 *   // Check specific permission
 *   const canDeleteOrg = check({ permission: 'org:delete' });
 *
 *   // Check specific role
 *   const isAdmin = check({ role: 'admin' });
 *
 *   // Check any of multiple roles
 *   const isAdminOrOwner = check({ anyRole: ['admin', 'owner'] });
 *
 *   return (
 *     <div>
 *       {canDeleteOrg && <DeleteButton />}
 *       {isAdminOrOwner && <AdminControls />}
 *     </div>
 *   );
 * }
 * ```
 */

/**
 * Hook for checking authorization with a unified check function.
 *
 * @returns Authorization checking function
 */
declare function useCheckAuthorization(): UseCheckAuthorizationReturn;

/**
 * Vault SDK Billing Hook
 *
 * React hook for billing and subscription management.
 */

/**
 * Hook for managing billing and subscriptions
 *
 * @example
 * ```tsx
 * function PricingPage() {
 *   const { plans, createCheckout, isLoading } = useBilling();
 *
 *   const handleSubscribe = async (plan: BillingPlan) => {
 *     const session = await createCheckout({
 *       priceId: plan.stripePriceId,
 *       successUrl: window.location.origin + '/success',
 *       cancelUrl: window.location.origin + '/cancel',
 *     });
 *     window.location.href = session.url;
 *   };
 *
 *   return (
 *     <div>
 *       {plans.map(plan => (
 *         <button key={plan.id} onClick={() => handleSubscribe(plan)}>
 *           Subscribe to {plan.name}
 *         </button>
 *       ))}
 *     </div>
 *   );
 * }
 * ```
 */
declare function useBilling(): UseBillingReturn;
/**
 * Hook for managing a specific subscription
 *
 * @example
 * ```tsx
 * function SubscriptionDetails() {
 *   const { subscription, isActive, daysUntilRenewal, cancel } = useSubscription();
 *
 *   if (!subscription) return <div>No subscription</div>;
 *
 *   return (
 *     <div>
 *       <p>Status: {subscription.status}</p>
 *       <p>Renews in: {daysUntilRenewal} days</p>
 *       <button onClick={cancel}>Cancel</button>
 *     </div>
 *   );
 * }
 * ```
 */
declare function useSubscription(): {
    subscription: Subscription | null;
    isLoading: boolean;
    error: Error | null;
    isActive: boolean;
    isTrialing: boolean;
    isCanceled: boolean;
    daysUntilRenewal: number;
    daysLeftInTrial: number | null;
    willRenew: boolean;
    refresh: () => Promise<void>;
    cancel: () => Promise<Subscription>;
    resume: () => Promise<Subscription>;
    update: (newPriceId: string) => Promise<Subscription>;
};
/**
 * Hook for managing usage-based billing
 *
 * @example
 * ```tsx
 * function UsageMeter() {
 *   const { usage, percentage, isNearLimit } = useUsage();
 *
 *   return (
 *     <div>
 *       <progress value={percentage} max={100} />
 *       {isNearLimit && <p>You're approaching your limit!</p>}
 *     </div>
 *   );
 * }
 * ```
 */
declare function useUsage(): {
    usage: UsageSummary | null;
    isLoading: boolean;
    error: Error | null;
    isNearLimit: boolean;
    isOverLimit: boolean;
    percentage: number;
    remaining: number;
    refresh: () => Promise<void>;
    report: (quantity: number, action?: "increment" | "set") => Promise<void>;
};

declare function SignIn({ redirectUrl, onSignIn, onError, showMagicLink, showForgotPassword, oauthProviders, showWebAuthn, appearance, className, }: SignInProps): react_jsx_runtime.JSX.Element;

declare function SignUp({ redirectUrl, onSignUp, onError, oauthProviders, requireName, appearance, className, }: SignUpProps): react_jsx_runtime.JSX.Element;

declare function UserButton({ showName, avatarUrl, onSignOut, menuItems, showManageAccount, appearance, className, }: UserButtonProps): react_jsx_runtime.JSX.Element;

declare function UserProfile$1({ onUpdate, appearance, className, }: UserProfileProps): react_jsx_runtime.JSX.Element;

declare function WebAuthnButton({ mode, label, onSuccess, onError, appearance, className, }: WebAuthnButtonProps): react_jsx_runtime.JSX.Element;

declare function VerifyEmail({ token, onVerified, onError, redirectUrl, appearance, className, }: VerifyEmailProps): react_jsx_runtime.JSX.Element;

declare function ResetPassword({ token, onSuccess, onError, redirectUrl, appearance, className, }: ResetPasswordProps): react_jsx_runtime.JSX.Element;

declare function MFAForm({ challenge: propChallenge, onVerify, onError, allowBackupCode, appearance, className, }: MFAFormProps): react_jsx_runtime.JSX.Element;

interface OrganizationSwitcherExtendedProps extends OrganizationSwitcherProps {
    /**
     * Show search input to filter organizations
     */
    showSearch?: boolean;
    /**
     * Maximum number of organizations to show before pagination
     */
    pageSize?: number;
}

declare function OrganizationSwitcher({ hidePersonal, onSwitch, appearance, className, showSearch, pageSize, }: OrganizationSwitcherExtendedProps): react_jsx_runtime.JSX.Element;

interface CreateOrganizationProps {
    /**
     * Callback after successful organization creation
     */
    onCreate?: (org: Organization) => void;
    /**
     * Callback when user cancels
     */
    onCancel?: () => void;
    /**
     * Redirect URL after successful creation
     */
    redirectUrl?: string;
    /**
     * Skip the invitation screen after creation
     */
    skipInvitationScreen?: boolean;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
declare function CreateOrganization({ onCreate, onCancel, redirectUrl, skipInvitationScreen, appearance, className, }: CreateOrganizationProps): react_jsx_runtime.JSX.Element;

interface OrganizationProfileProps {
    /**
     * Organization to display (defaults to active organization)
     */
    organization?: Organization;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
declare function OrganizationProfile({ organization: propOrg, appearance, className, }: OrganizationProfileProps): react_jsx_runtime.JSX.Element;

interface OrganizationListProps {
    /**
     * Callback when an organization is selected
     */
    onSelect?: (org: Organization) => void;
    /**
     * Hide the create organization button
     */
    hideCreateButton?: boolean;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
declare function OrganizationList({ onSelect, hideCreateButton, appearance, className, }: OrganizationListProps): react_jsx_runtime.JSX.Element;

interface SessionManagementProps {
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Custom class name
     */
    className?: string;
}
declare function SessionManagement({ appearance, className, }: SessionManagementProps): react_jsx_runtime.JSX.Element;

interface WaitlistProps {
    /**
     * Callback when email is submitted
     */
    onSubmit?: (email: string) => void;
    /**
     * Redirect URL after successful submission
     */
    redirectUrl?: string;
    /**
     * Custom styling
     */
    appearance?: Appearance$1;
    /**
     * Social proof text (e.g., "Join 1,000+ others")
     */
    socialProof?: string;
    /**
     * Custom class name
     */
    className?: string;
}
declare function Waitlist({ onSubmit, redirectUrl, appearance, socialProof, className, }: WaitlistProps): react_jsx_runtime.JSX.Element;

/**
 * ImpersonationBanner Component
 *
 * Fixed banner displayed when an admin is impersonating a user.
 *
 * @example
 * ```tsx
 * <ImpersonationBanner
 *   onStopImpersonating={() => stopImpersonating()}
 * />
 * ```
 */
interface ImpersonationBannerProps {
    /**
     * Callback when user clicks "Stop Impersonating"
     */
    onStopImpersonating?: () => void;
}
declare function ImpersonationBanner({ onStopImpersonating, }: ImpersonationBannerProps): react_jsx_runtime.JSX.Element | null;

interface SignedInProps {
    children: React$1.ReactNode;
}
/**
 * Renders children only when user is signed in.
 */
declare function SignedIn({ children }: SignedInProps): react_jsx_runtime.JSX.Element | null;
interface SignedOutProps {
    children: React$1.ReactNode;
}
/**
 * Renders children only when user is signed out.
 */
declare function SignedOut({ children }: SignedOutProps): react_jsx_runtime.JSX.Element | null;
interface RequireAuthProps {
    children: React$1.ReactNode;
    fallback?: React$1.ReactNode;
    loading?: React$1.ReactNode;
}
/**
 * Renders children only when user is signed in.
 * Shows fallback (or default message) when signed out.
 * Shows loading state while auth is loading.
 */
declare function RequireAuth({ children, fallback, loading }: RequireAuthProps): react_jsx_runtime.JSX.Element;

declare function Protect({ children, fallback, role, permission, loading, }: ProtectProps): react_jsx_runtime.JSX.Element;
/**
 * RedirectToSignIn Component
 *
 * Redirects to sign in page.
 *
 * @example
 * ```tsx
 * <RedirectToSignIn redirectUrl="/dashboard" />
 * ```
 */
declare function RedirectToSignIn({ redirectUrl }: {
    redirectUrl?: string;
}): react_jsx_runtime.JSX.Element;
/**
 * RedirectToSignUp Component
 *
 * Redirects to sign up page.
 *
 * @example
 * ```tsx
 * <RedirectToSignUp redirectUrl="/dashboard" />
 * ```
 */
declare function RedirectToSignUp({ redirectUrl }: {
    redirectUrl?: string;
}): react_jsx_runtime.JSX.Element;

/**
 * Pricing Table Component
 *
 * Displays available billing plans with features and pricing.
 */

/**
 * PricingTable component for displaying subscription plans
 *
 * @example
 * ```tsx
 * <PricingTable
 *   currentPlanId="pro"
 *   onSelectPlan={(plan) => handleSubscribe(plan)}
 * />
 * ```
 */
declare const PricingTable: React$1.FC<PricingTableProps>;

/**
 * Checkout Button Component
 *
 * Button that creates a Stripe checkout session and redirects to it.
 */

/**
 * CheckoutButton component for initiating subscription checkout
 *
 * @example
 * ```tsx
 * <CheckoutButton
 *   priceId="price_123"
 *   successUrl="https://example.com/success"
 *   cancelUrl="https://example.com/cancel"
 * >
 *   Subscribe Now
 * </CheckoutButton>
 * ```
 */
declare const CheckoutButton: React$1.FC<CheckoutButtonProps>;
/**
 * Quick checkout button with minimal configuration
 * Uses current URL for success/cancel callbacks
 *
 * @example
 * ```tsx
 * <QuickCheckoutButton priceId="price_123">
 *   Subscribe Now
 * </QuickCheckoutButton>
 * ```
 */
interface QuickCheckoutButtonProps {
    priceId: string;
    children: React$1.ReactNode;
    successPath?: string;
    cancelPath?: string;
    disabled?: boolean;
    onCheckout?: (session: {
        url: string;
    }) => void;
    onError?: (error: Error) => void;
    className?: string;
}
declare const QuickCheckoutButton: React$1.FC<QuickCheckoutButtonProps>;

/**
 * Customer Portal Components
 *
 * Components for managing billing through Stripe Customer Portal.
 */

/**
 * CustomerPortalButton opens the Stripe Customer Portal
 *
 * @example
 * ```tsx
 * <CustomerPortalButton returnUrl="https://example.com/settings">
 *   Manage Billing
 * </CustomerPortalButton>
 * ```
 */
declare const CustomerPortalButton: React$1.FC<CustomerPortalButtonProps>;
/**
 * ManageSubscriptionButton - Opens portal to the subscription management page
 */
declare const ManageSubscriptionButton: React$1.FC<CustomerPortalButtonProps>;
/**
 * UpdatePaymentMethodButton - Opens portal to update payment methods
 */
declare const UpdatePaymentMethodButton: React$1.FC<CustomerPortalButtonProps>;
/**
 * ViewInvoicesButton - Opens portal to view invoice history
 */
declare const ViewInvoicesButton: React$1.FC<CustomerPortalButtonProps>;
/**
 * BillingSettings component - Combines common billing actions
 */
interface BillingSettingsProps {
    returnUrl?: string;
    showManageSubscription?: boolean;
    showUpdatePayment?: boolean;
    showViewInvoices?: boolean;
    className?: string;
}
declare const BillingSettings: React$1.FC<BillingSettingsProps>;

/**
 * Subscription Status Components
 *
 * Components for displaying and managing subscription status.
 */

/**
 * SubscriptionStatus component
 *
 * Displays current subscription details with actions
 *
 * @example
 * ```tsx
 * <SubscriptionStatus
 *   showDetails={true}
 *   showInvoices={true}
 *   onCancel={() => cancelSubscription()}
 * />
 * ```
 */
declare const SubscriptionStatus: React$1.FC<SubscriptionStatusProps>;
/**
 * UsageMeter component
 *
 * Displays usage with progress bar
 */
declare const UsageMeter: React$1.FC<UsageMeterProps>;
/**
 * InvoiceList component
 *
 * Displays list of invoices
 */
interface InvoiceListProps {
    invoices: Invoice[];
    loading?: boolean;
    emptyMessage?: string;
    className?: string;
}
declare const InvoiceList: React$1.FC<InvoiceListProps>;

/**
 * Button Component
 *
 * Themed button component with primary and secondary variants.
 */

interface ButtonProps extends React$1.ButtonHTMLAttributes<HTMLButtonElement> {
    /** Button visual variant */
    variant?: 'primary' | 'secondary' | 'ghost';
    /** Button size */
    size?: 'sm' | 'md' | 'lg';
    /** Loading state */
    isLoading?: boolean;
    /** Loading text (defaults to spinner) */
    loadingText?: string;
    /** Full width button */
    fullWidth?: boolean;
    /** Custom element class name */
    elementClassName?: string;
}
declare const Button: React$1.ForwardRefExoticComponent<ButtonProps & React$1.RefAttributes<HTMLButtonElement>>;

/**
 * Input Component
 *
 * Themed input component with label, error states, and full theming support.
 */

interface InputProps extends Omit<React$1.InputHTMLAttributes<HTMLInputElement>, 'size'> {
    /** Input label */
    label?: string;
    /** Error message */
    error?: string;
    /** Helper text */
    helperText?: string;
    /** Custom input class name */
    inputClassName?: string;
    /** Custom label class name */
    labelClassName?: string;
    /** Custom error class name */
    errorClassName?: string;
    /** Custom field container class name */
    fieldClassName?: string;
    /** Input size */
    size?: 'sm' | 'md' | 'lg';
}
declare const Input: React$1.ForwardRefExoticComponent<InputProps & React$1.RefAttributes<HTMLInputElement>>;

/**
 * Card Component
 *
 * Themed card container component.
 */

interface CardProps extends React$1.HTMLAttributes<HTMLDivElement> {
    /** Card padding */
    padding?: 'none' | 'sm' | 'md' | 'lg';
    /** Card width */
    width?: 'auto' | 'sm' | 'md' | 'lg' | 'full';
    /** Center the card horizontally */
    centered?: boolean;
}
declare const Card: React$1.ForwardRefExoticComponent<CardProps & React$1.RefAttributes<HTMLDivElement>>;
interface CardHeaderProps extends React$1.HTMLAttributes<HTMLDivElement> {
    /** Card title */
    title?: string;
    /** Card subtitle */
    subtitle?: string;
    /** Show logo */
    showLogo?: boolean;
    /** Logo URL */
    logoUrl?: string;
}
declare const CardHeader: React$1.ForwardRefExoticComponent<CardHeaderProps & React$1.RefAttributes<HTMLDivElement>>;
interface CardContentProps extends React$1.HTMLAttributes<HTMLDivElement> {
    /** Content spacing */
    spacing?: 'none' | 'sm' | 'md' | 'lg';
}
declare const CardContent: React$1.ForwardRefExoticComponent<CardContentProps & React$1.RefAttributes<HTMLDivElement>>;
interface CardFooterProps extends React$1.HTMLAttributes<HTMLDivElement> {
    /** Footer alignment */
    align?: 'left' | 'center' | 'right';
}
declare const CardFooter: React$1.ForwardRefExoticComponent<CardFooterProps & React$1.RefAttributes<HTMLDivElement>>;

/**
 * Divider Component
 *
 * Themed divider with optional text.
 */
interface DividerProps {
    /** Divider text */
    text?: string;
    /** Vertical spacing */
    spacing?: 'sm' | 'md' | 'lg';
    /** Custom class name for the line */
    lineClassName?: string;
    /** Custom class name for the text */
    textClassName?: string;
}
declare function Divider({ text, spacing, lineClassName, textClassName, }: DividerProps): react_jsx_runtime.JSX.Element;

interface HeaderProps {
    /** Header title */
    title?: string;
    /** Header subtitle */
    subtitle?: string;
    /** Show logo */
    showLogo?: boolean;
    /** Custom logo URL (overrides layout config) */
    logoUrl?: string;
    /** Logo element (overrides URL) */
    logo?: React$1.ReactNode;
    /** Header alignment */
    align?: 'left' | 'center' | 'right';
    /** Custom title class name */
    titleClassName?: string;
    /** Custom subtitle class name */
    subtitleClassName?: string;
    /** Children to render after title/subtitle */
    children?: React$1.ReactNode;
}
declare function Header({ title, subtitle, showLogo, logoUrl, logo, align, titleClassName, subtitleClassName, children, }: HeaderProps): react_jsx_runtime.JSX.Element;

type OAuthProvider = 'google' | 'github' | 'microsoft' | 'apple' | 'discord' | 'slack' | 'facebook' | 'twitter' | 'instagram' | 'tiktok' | 'snapchat' | 'pinterest' | 'reddit' | 'twitch' | 'spotify' | 'linkedin' | 'gitlab' | 'bitbucket' | 'digitalocean' | 'heroku' | 'vercel' | 'netlify' | 'cloudflare' | 'salesforce' | 'hubspot' | 'zendesk' | 'notion' | 'figma' | 'linear' | 'atlassian' | 'okta' | 'wechat' | 'line' | 'kakaotalk' | 'vkontakte' | 'yandex';
interface SocialButtonProps extends React$1.ButtonHTMLAttributes<HTMLButtonElement> {
    /** OAuth provider */
    provider: OAuthProvider;
    /** Button variant */
    variant?: 'block' | 'icon';
    /** Custom label (overrides default) */
    label?: string;
    /** Loading state */
    isLoading?: boolean;
    /** Custom class name */
    elementClassName?: string;
}
declare function SocialButton({ provider, variant, label, isLoading, elementClassName, disabled, style, children, ...props }: SocialButtonProps): react_jsx_runtime.JSX.Element;
interface SocialButtonsProps {
    /** Social buttons to render */
    children: React$1.ReactNode;
    /** Layout variant */
    layout?: 'vertical' | 'horizontal';
    /** Custom class name */
    className?: string;
}
declare function SocialButtons({ children, layout, className, }: SocialButtonsProps): react_jsx_runtime.JSX.Element;

type AlertVariant = 'error' | 'success' | 'warning' | 'info';
interface AlertProps extends React$1.HTMLAttributes<HTMLDivElement> {
    /** Alert variant */
    variant?: AlertVariant;
    /** Alert title */
    title?: string;
    /** Show icon */
    showIcon?: boolean;
    /** Custom icon */
    icon?: React$1.ReactNode;
    /** Dismissible alert */
    onDismiss?: () => void;
}
declare function Alert({ variant, title, showIcon, icon, onDismiss, children, className, style, ...props }: AlertProps): react_jsx_runtime.JSX.Element;

interface SpinnerProps {
    /** Spinner size */
    size?: 'sm' | 'md' | 'lg' | 'xl' | number;
    /** Use shimmer animation instead of spin */
    shimmer?: boolean;
    /** Shimmer width (for block shimmer) */
    shimmerWidth?: string | number;
    /** Shimmer height (for block shimmer) */
    shimmerHeight?: string | number;
    /** Custom class name */
    className?: string;
    /** Custom style */
    style?: React$1.CSSProperties;
}
declare function Spinner({ size, shimmer, shimmerWidth, shimmerHeight, className, style, }: SpinnerProps): react_jsx_runtime.JSX.Element;
interface SpinnerOverlayProps {
    /** Whether to show overlay */
    isLoading: boolean;
    /** Children to render */
    children: React$1.ReactNode;
    /** Spinner size */
    size?: SpinnerProps['size'];
    /** Use shimmer */
    shimmer?: boolean;
    /** Overlay opacity */
    opacity?: number;
    /** Custom class name */
    className?: string;
}
declare function SpinnerOverlay({ isLoading, children, size, shimmer, opacity, className, }: SpinnerOverlayProps): react_jsx_runtime.JSX.Element;
interface SkeletonProps {
    /** Number of skeleton lines */
    lines?: number;
    /** Line height */
    lineHeight?: string | number;
    /** Gap between lines */
    gap?: string | number;
    /** Custom class name */
    className?: string;
}
declare function Skeleton({ lines, lineHeight, gap, className, }: SkeletonProps): react_jsx_runtime.JSX.Element;

/**
 * Master Key Derivation for Zero-Knowledge Architecture
 *
 * This module implements client-side key derivation using Argon2id.
 * In the browser, we use a WebAssembly implementation of Argon2.
 *
 * @module zk/keyDerivation
 */
/**
 * Master key derived from password
 */
interface MasterKey {
    /** Symmetric encryption key (raw bytes) */
    encryptionKey: Uint8Array;
    /** Authentication key for HMAC */
    authenticationKey: Uint8Array;
    /** RSA private key for unwrapping data keys */
    rsaPrivateKey: CryptoKey;
    /** RSA public key for wrapping data keys */
    rsaPublicKey: CryptoKey;
    /** Raw key material (for serialization) */
    keyMaterial: Uint8Array;
}
/**
 * Argon2id parameters
 */
interface Argon2Params {
    /** Memory cost in KB */
    memoryCost: number;
    /** Number of iterations */
    timeCost: number;
    /** Degree of parallelism */
    parallelism: number;
}
/**
 * Default Argon2id parameters
 */
declare const DEFAULT_ARGON2_PARAMS: Argon2Params;
/**
 * Conservative parameters (higher security, slower)
 */
declare const CONSERVATIVE_ARGON2_PARAMS: Argon2Params;
/**
 * Fast parameters (for testing only)
 */
declare const FAST_ARGON2_PARAMS: Argon2Params;
/**
 * Generate a cryptographically secure random salt
 */
declare function generateSalt(): Uint8Array;
/**
 * Derive master key from password using PBKDF2 (fallback for browsers without Argon2)
 *
 * For production, use argon2-browser WASM implementation
 */
declare function deriveMasterKey(password: string, salt: Uint8Array, params?: Argon2Params): Promise<MasterKey>;
/**
 * Export master key to portable format (for storage)
 */
declare function exportMasterKey(masterKey: MasterKey): Promise<{
    encryptionKey: string;
    authenticationKey: string;
    rsaPrivateKey: string;
    rsaPublicKey: string;
}>;
/**
 * Import master key from portable format
 */
declare function importMasterKey(exported: {
    encryptionKey: string;
    authenticationKey: string;
    rsaPrivateKey: string;
    rsaPublicKey: string;
}): Promise<MasterKey>;
/**
 * Encrypt RSA private key for server storage
 */
declare function encryptPrivateKeyForStorage(privateKey: CryptoKey, encryptionKey: Uint8Array): Promise<string>;
/**
 * Decrypt RSA private key from server storage
 */
declare function decryptPrivateKeyFromStorage(encryptedKey: string, encryptionKey: Uint8Array): Promise<CryptoKey>;
/**
 * Generate password commitment for ZK proof
 */
declare function generatePasswordCommitment(password: string, salt: Uint8Array): Promise<Uint8Array>;

/**
 * Client-Side Encryption for Zero-Knowledge Architecture
 *
 * This module implements browser-based encryption ensuring that user data
 * is encrypted before being sent to the server. The server only stores
 * encrypted blobs and cannot decrypt them.
 *
 * @module zk/encryption
 */

/**
 * Data Encryption Key - 256 bits random key
 */
type DataEncryptionKey = CryptoKey;
/**
 * Wrapped (encrypted) DEK
 */
interface WrappedDek {
    /** RSA-OAEP encrypted DEK */
    ciphertext: Uint8Array;
}
/**
 * Encrypted user data with all necessary metadata
 */
interface EncryptedUserData {
    /** Protocol version */
    version: number;
    /** AES-GCM ciphertext */
    ciphertext: Uint8Array;
    /** IV/nonce (12 bytes) */
    nonce: Uint8Array;
    /** RSA-OAEP wrapped data encryption key */
    encryptedDek: WrappedDek;
    /** Timestamp of encryption */
    encryptedAt: string;
}
/**
 * User profile data structure
 */
interface UserProfile {
    name?: string;
    givenName?: string;
    familyName?: string;
    middleName?: string;
    nickname?: string;
    preferredUsername?: string;
    profile?: string;
    picture?: string;
    website?: string;
    gender?: string;
    birthdate?: string;
    zoneinfo?: string;
    locale?: string;
    email?: string;
    phoneNumber?: string;
    phoneNumberVerified?: boolean;
    address?: Address;
    [key: string]: unknown;
}
/**
 * Physical address
 */
interface Address {
    formatted?: string;
    streetAddress?: string;
    locality?: string;
    region?: string;
    postalCode?: string;
    country?: string;
}
/**
 * Generate a random Data Encryption Key
 */
declare function generateDek(): Promise<DataEncryptionKey>;
/**
 * Wrap DEK with RSA public key using RSA-OAEP
 */
declare function wrapDek(dek: DataEncryptionKey, publicKey: CryptoKey): Promise<WrappedDek>;
/**
 * Unwrap DEK with RSA private key
 */
declare function unwrapDek(wrappedDek: WrappedDek, privateKey: CryptoKey): Promise<DataEncryptionKey>;
/**
 * Encrypt data with AES-GCM
 */
declare function aesGcmEncrypt(data: Uint8Array, key: CryptoKey): Promise<{
    ciphertext: Uint8Array;
    nonce: Uint8Array;
}>;
/**
 * Decrypt data with AES-GCM
 */
declare function aesGcmDecrypt(ciphertext: Uint8Array, nonce: Uint8Array, key: CryptoKey): Promise<Uint8Array>;
/**
 * Encrypt user profile data
 */
declare function encryptUserData(profile: UserProfile, masterKey: MasterKey): Promise<EncryptedUserData>;
/**
 * Decrypt user profile data
 */
declare function decryptUserData(encryptedData: EncryptedUserData, masterKey: MasterKey): Promise<UserProfile>;
/**
 * Serialize encrypted data for transmission
 */
declare function serializeEncryptedData(data: EncryptedUserData): string;
/**
 * Deserialize encrypted data from transmission
 */
declare function deserializeEncryptedData(json: string): EncryptedUserData;
/**
 * Encrypt arbitrary data with master key
 */
declare function encryptWithMasterKey(data: Uint8Array, masterKey: MasterKey): Promise<EncryptedUserData>;
/**
 * Decrypt arbitrary data with master key
 */
declare function decryptWithMasterKey(encryptedData: EncryptedUserData, masterKey: MasterKey): Promise<Uint8Array>;

/**
 * Zero-Knowledge Password Proofs
 *
 * This module implements zero-knowledge proofs that allow a user to prove
 * knowledge of their password without revealing it to the server.
 *
 * @module zk/proofs
 */
/**
 * Zero-knowledge password proof
 */
interface ZkPasswordProof {
    /** Protocol version */
    version: number;
    /** Challenge used in this proof */
    challenge: Uint8Array;
    /** Response to challenge */
    response: Uint8Array;
    /** Blinding factor commitment */
    blindedCommitment: Uint8Array;
}
/**
 * ZK Password Prover (client-side)
 */
declare class ZkPasswordProver {
    /**
     * Generate a ZK proof of password knowledge
     */
    static prove(password: string, salt: Uint8Array, challenge?: Uint8Array): Promise<ZkPasswordProof>;
    /**
     * Generate commitment for registration
     */
    static commit(password: string, salt: Uint8Array): Promise<Uint8Array>;
}
/**
 * ZK Password Verifier (server-side simulation for testing)
 */
declare class ZkPasswordVerifier {
    /**
     * Verify a ZK password proof
     */
    static verify(proof: ZkPasswordProof, expectedCommitment: Uint8Array, salt: Uint8Array): Promise<boolean>;
}
/**
 * Generate a random challenge
 */
declare function generateChallenge(): Uint8Array;
/**
 * Full ZK authentication flow
 */
declare class ZkAuthentication {
    /**
     * Server generates challenge
     */
    static serverChallenge(): Uint8Array;
    /**
     * Client generates proof
     */
    static clientProve(password: string, salt: Uint8Array, challenge: Uint8Array): Promise<ZkPasswordProof>;
    /**
     * Server verifies proof
     */
    static serverVerify(proof: ZkPasswordProof, expectedCommitment: Uint8Array, salt: Uint8Array): Promise<boolean>;
}
/**
 * Serialize proof for transmission
 */
declare function serializeProof(proof: ZkPasswordProof): string;
/**
 * Deserialize proof from transmission
 */
declare function deserializeProof(json: string): ZkPasswordProof;

/**
 * Social Recovery Using Shamir's Secret Sharing
 *
 * This module implements account recovery without server knowledge.
 * The master key is split into multiple shares distributed to trusted contacts.
 *
 * @module zk/recovery
 */

/**
 * A single share of the secret
 */
interface RecoveryShare {
    /** Share index (1-255) */
    index: number;
    /** Share value (point on the polynomial) */
    value: Uint8Array;
    /** Share metadata */
    metadata: ShareMetadata;
}
/**
 * Metadata for a recovery share
 */
interface ShareMetadata {
    /** User ID this share belongs to */
    userId: string;
    /** Timestamp when share was created */
    createdAt: string;
    /** Threshold required for recovery */
    threshold: number;
    /** Total number of shares */
    totalShares: number;
    /** Share version */
    version: number;
}
/**
 * Recovery session for tracking recovery attempts
 */
interface RecoverySession {
    /** Session ID */
    id: string;
    /** User ID being recovered */
    userId: string;
    /** Collected shares so far */
    collectedShares: RecoveryShare[];
    /** Threshold required */
    threshold: number;
    /** Session created at */
    createdAt: string;
    /** Session expires at */
    expiresAt: string;
    /** Session status */
    status: RecoverySessionStatus;
}
/**
 * Recovery session status
 */
declare enum RecoverySessionStatus {
    Collecting = "collecting",
    Ready = "ready",
    Completed = "completed",
    Expired = "expired",
    Failed = "failed"
}
/**
 * Social recovery implementation
 */
declare class SocialRecovery {
    /**
     * Split master key into shares
     */
    static createShares(masterKey: MasterKey, threshold: number, totalShares: number, userId: string): RecoveryShare[];
    /**
     * Recover master key from shares
     */
    static recoverFromShares(shares: RecoveryShare[]): MasterKey;
    /**
     * Get share hash for verification
     */
    static getShareHash(share: RecoveryShare): Promise<Uint8Array>;
    /**
     * Generate share hashes for verification
     */
    static generateShareHashes(shares: RecoveryShare[]): Promise<Uint8Array[]>;
    /**
     * Serialize share for transmission
     */
    static serializeShare(share: RecoveryShare): string;
    /**
     * Deserialize share from transmission
     */
    static deserializeShare(json: string): RecoveryShare;
}
/**
 * Share validator
 */
declare class ShareValidator {
    /**
     * Validate a share's structure
     */
    static validateStructure(share: RecoveryShare): void;
    /**
     * Validate a set of shares for recovery
     */
    static validateSet(shares: RecoveryShare[]): void;
}
/**
 * Recovery session manager
 */
declare class RecoverySessionManager {
    private sessions;
    /**
     * Create a new recovery session
     */
    createSession(userId: string, threshold: number): RecoverySession;
    /**
     * Get a session by ID
     */
    getSession(id: string): RecoverySession | undefined;
    /**
     * Add a share to a session
     */
    addShare(sessionId: string, share: RecoveryShare): RecoverySession;
    /**
     * Complete a recovery session
     */
    completeSession(sessionId: string, success: boolean): RecoverySession;
    /**
     * Get number of shares still needed
     */
    sharesNeeded(session: RecoverySession): number;
}

/**
 * Zero-Knowledge Architecture SDK
 *
 * This module provides client-side encryption for the Vault SDK.
 * All encryption happens in the browser - the server never sees plaintext data.
 *
 * @example
 * ```typescript
 * import {
 *   deriveMasterKey,
 *   encryptUserData,
 *   decryptUserData,
 *   ZkPasswordProver
 * } from '@vault/sdk/zk';
 *
 * // Derive master key from password
 * const salt = generateSalt();
 * const masterKey = await deriveMasterKey(password, salt);
 *
 * // Encrypt user data
 * const encrypted = await encryptUserData(userProfile, masterKey);
 *
 * // Send to server (server never sees plaintext)
 * await api.storeEncryptedData(encrypted);
 *
 * // Later: decrypt
 * const decrypted = await decryptUserData(encrypted, masterKey);
 * ```
 *
 * @module zk
 */

/**
 * Zero-knowledge module version
 */
declare const ZK_VERSION = "1.0.0";
/**
 * Check if Web Crypto API is available
 */
declare function isWebCryptoAvailable(): boolean;
/**
 * Initialize the zero-knowledge module
 *
 * @throws Error if Web Crypto API is not available
 */
declare function initZk(): void;
/**
 * Zero-knowledge error types
 */
declare class ZkError extends Error {
    code: string;
    details?: Record<string, unknown> | undefined;
    constructor(message: string, code: string, details?: Record<string, unknown> | undefined);
}
/**
 * Encryption error
 */
declare class ZkEncryptionError extends ZkError {
    constructor(message: string, details?: Record<string, unknown>);
}
/**
 * Key derivation error
 */
declare class ZkKeyDerivationError extends ZkError {
    constructor(message: string, details?: Record<string, unknown>);
}
/**
 * Proof error
 */
declare class ZkProofError extends ZkError {
    constructor(message: string, details?: Record<string, unknown>);
}
/**
 * Recovery error
 */
declare class ZkRecoveryError extends ZkError {
    constructor(message: string, details?: Record<string, unknown>);
}

/**
 * OAuth Provider Utilities
 *
 * Comprehensive metadata and utilities for 30+ OAuth providers.
 */

/**
 * OAuth provider metadata for all supported providers
 */
declare const oauthProviderMetadata: Record<OAuthProvider$1, OAuthProviderMetadata>;
/**
 * Get all OAuth providers
 */
declare function getAllOAuthProviders(): OAuthProvider$1[];
/**
 * Get OAuth providers by category
 */
declare function getOAuthProvidersByCategory(category: OAuthProviderCategory): OAuthProvider$1[];
/**
 * Get OAuth provider metadata
 */
declare function getOAuthProviderMetadata(provider: OAuthProvider$1): OAuthProviderMetadata;
/**
 * Get OAuth provider display name
 */
declare function getOAuthProviderDisplayName(provider: OAuthProvider$1): string;
/**
 * Get OAuth provider icon color
 */
declare function getOAuthProviderColor(provider: OAuthProvider$1): string;
/**
 * Check if OAuth provider uses PKCE
 */
declare function isPkceEnabled(provider: OAuthProvider$1): boolean;
/**
 * Get default scopes for OAuth provider
 */
declare function getOAuthProviderDefaultScopes(provider: OAuthProvider$1): string[];
/**
 * OAuth provider categories
 */
declare const oauthProviderCategories: {
    id: OAuthProviderCategory;
    label: string;
}[];
/**
 * Get popular OAuth providers (most commonly used)
 */
declare function getPopularOAuthProviders(): OAuthProvider$1[];
/**
 * Get recommended OAuth providers for a specific use case
 */
declare function getRecommendedOAuthProviders(useCase: 'b2b' | 'b2c' | 'developer' | 'enterprise'): OAuthProvider$1[];
/**
 * Validate OAuth provider
 */
declare function isValidOAuthProvider(provider: string): provider is OAuthProvider$1;
/**
 * Group providers by category
 */
declare function groupProvidersByCategory(): Record<OAuthProviderCategory, OAuthProvider$1[]>;

/**
 * Vault React SDK
 *
 * A comprehensive React SDK for Vault authentication and user management.
 *
 * @example
 * ```tsx
 * import { VaultProvider, useAuth, SignIn } from '@vault/react';
 *
 * function App() {
 *   return (
 *     <VaultProvider
 *       config={{
 *         apiUrl: "https://api.vault.dev",
 *         tenantId: "my-tenant"
 *       }}
 *     >
 *       <YourApp />
 *     </VaultProvider>
 *   );
 * }
 *
 * function YourApp() {
 *   const { isSignedIn, user, signOut } = useAuth();
 *
 *   if (!isSignedIn) {
 *     return <SignIn />;
 *   }
 *
 *   return <div>Hello {user?.email}!</div>;
 * }
 * ```
 */

declare const VERSION = "0.1.0";

export { Alert, BillingSettings, Button, CONSERVATIVE_ARGON2_PARAMS, Card, CardContent, CardFooter, CardHeader, CheckoutButton, CreateOrganization, CustomerPortalButton, DEFAULT_ARGON2_PARAMS, Divider, FAST_ARGON2_PARAMS, Header, ImpersonationBanner, Input, InvoiceList, MFAForm, ManageSubscriptionButton, OrganizationList, OrganizationProfile, OrganizationSwitcher, PricingTable, Protect, QuickCheckoutButton, RecoverySessionManager, RecoverySessionStatus, RedirectToSignIn, RedirectToSignUp, RequireAuth, ResetPassword, SessionManagement, ShareValidator, SignIn, SignUp, SignedIn, SignedOut, Skeleton, SocialButton, SocialButtons, SocialRecovery, Spinner, SpinnerOverlay, SubscriptionStatus, ThemeContext, ThemeProvider, UpdatePaymentMethodButton, UsageMeter, UserButton, UserProfile$1 as UserProfile, VERSION, VaultApiClient, VaultContext, VaultProvider, VerifyEmail, ViewInvoicesButton, Waitlist, WebAuthnButton, ZK_VERSION, ZkAuthentication, ZkEncryptionError, ZkError, ZkKeyDerivationError, ZkPasswordProver, ZkPasswordVerifier, ZkProofError, ZkRecoveryError, aesGcmDecrypt, aesGcmEncrypt, applyCSSVariables, createElementStyles, createVaultClient, cssVariablesToStyle, cx, darkTheme, decryptPrivateKeyFromStorage, decryptUserData, decryptWithMasterKey, deriveMasterKey, deserializeEncryptedData, deserializeProof, encryptPrivateKeyForStorage, encryptUserData, encryptWithMasterKey, exportMasterKey, generateBaseStyles, generateCSSVariables, generateChallenge, generateDek, generatePasswordCommitment, generateSalt, getAllOAuthProviders, getElementClasses, getLayoutOption, getOAuthProviderColor, getOAuthProviderDefaultScopes, getOAuthProviderDisplayName, getOAuthProviderMetadata, getOAuthProvidersByCategory, getPopularOAuthProviders, getRecommendedOAuthProviders, getTheme, groupProvidersByCategory, importMasterKey, initZk, isPkceEnabled, isValidOAuthProvider, isWebCryptoAvailable, lightTheme, mergeThemes, neutralTheme, oauthProviderCategories, oauthProviderMetadata, serializeEncryptedData, serializeProof, themes, unwrapDek, useActiveOrganization, useAuth, useAuthState, useBilling, useCheckAuthorization, useHasRole, useIsOrgAdmin, useIsWebAuthnSupported, useMfa, useMfaChallenge, useOrganization, useOrganizationRole, usePermissions, useRequireAuth, useSession, useSessionId, useSessions, useSignIn, useSignUp, useSubscription, useTheme, useToken, useUpdateUser, useUsage, useUser, useUserManager, useVault, useWebAuthn, withTheme, wrapDek };
export type { Address, AlertProps, AlertVariant, ApiError, Appearance, Argon2Params, AuthState, BaseComponentStyles, BillingPlan, BillingSettingsProps$1 as BillingSettingsProps, ButtonProps, CardContentProps, CardFooterProps, CardHeaderProps, CardProps, CheckoutButtonProps, CheckoutSession, Appearance$1 as ComponentAppearance, CreateCheckoutOptions, CreateOrganizationOptions, CreateOrganizationProps, CreatePortalOptions, CustomerPortalButtonProps, DataEncryptionKey, DividerProps, ElementStyles, EncryptedUserData, ForgotPasswordOptions, HeaderProps, ImpersonationBannerProps, InputProps, InviteMemberOptions, Invoice, InvoiceListProps$1 as InvoiceListProps, InvoiceStatus, LayoutOptions, MFAFormProps, MagicLinkOptions, MasterKey, MfaChallenge, MfaMethod, MfaSetupOptions, MfaVerifyOptions, OAuthOptions, OAuthProvider, Organization, OrganizationListProps, OrganizationMember, OrganizationProfileProps, OrganizationRole, OrganizationSwitcherExtendedProps, OrganizationSwitcherProps, PaymentMethod, Permission, PermissionCheck, PlanTier, PortalSession, PricingTableProps, ProtectProps, QuickCheckoutButtonProps$1 as QuickCheckoutButtonProps, RecoverySession, RecoveryShare, RequireAuthProps, ResetPasswordOptions, ResetPasswordProps, Session, SessionInfo, SessionManagementProps, ShareMetadata, SignInOptions, SignInProps, SignUpOptions, SignUpProps, SignedInProps, SignedOutProps, SkeletonProps, SocialButtonProps, SocialButtonsProps, SpinnerOverlayProps, SpinnerProps, Subscription, SubscriptionLimits, SubscriptionStatusProps, SubscriptionStatus$1 as SubscriptionStatusType, Theme, ThemeContextValue, ThemeProviderProps, ThemeVariables, TotpSetup, UpdateOrganizationOptions, UsageMeterProps, UsageMetric, UsageSummary, UseAuthReturn, UseCheckAuthorizationReturn, UseMfaReturn, UseOrganizationReturn, UsePermissionsReturn, UseSessionReturn, UseSessionsReturn, UseSignInReturn, UseSignUpReturn, UseUserReturn, UseWebAuthnReturn, User, UserButtonProps, UserProfileProps, UserProfile$2 as UserProfileType, VaultConfig, VaultProviderProps, VerifyEmailOptions, VerifyEmailProps, WaitlistProps, WebAuthnButtonProps, WebAuthnCredential, WebAuthnOptions, WrappedDek, ZkPasswordProof, UserProfile as ZkUserProfile };
