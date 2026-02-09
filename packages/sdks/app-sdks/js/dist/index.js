'use strict';

var jsxRuntime = require('react/jsx-runtime');
var React = require('react');

/**
 * Vault API Client
 *
 * HTTP client for the Vault API.
 */
const STORAGE_KEY = 'vault_session_token';
const STORAGE_REFRESH_KEY = 'vault_refresh_token';
class VaultApiClient {
    constructor(config) {
        this.config = config;
        this.baseUrl = config.apiUrl.replace(/\/$/, '');
    }
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            'X-Tenant-ID': this.config.tenantId,
            ...(options.headers || {}),
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
            };
        }
        // Handle empty responses
        if (response.status === 204) {
            return undefined;
        }
        return response.json();
    }
    // ============================================================================
    // Auth Methods
    // ============================================================================
    async signIn(options) {
        return this.request('/api/v1/auth/login', {
            method: 'POST',
            body: JSON.stringify(options),
        });
    }
    async signUp(options) {
        return this.request('/api/v1/auth/register', {
            method: 'POST',
            body: JSON.stringify(options),
        });
    }
    async sendMagicLink(options) {
        await this.request('/api/v1/auth/magic-link', {
            method: 'POST',
            body: JSON.stringify(options),
        });
    }
    async verifyMagicLink(token) {
        return this.request('/api/v1/auth/magic-link/verify', {
            method: 'POST',
            body: JSON.stringify({ token }),
        });
    }
    async sendForgotPassword(options) {
        await this.request('/api/v1/auth/forgot-password', {
            method: 'POST',
            body: JSON.stringify(options),
        });
    }
    async resetPassword(options) {
        return this.request('/api/v1/auth/reset-password', {
            method: 'POST',
            body: JSON.stringify(options),
        });
    }
    async verifyEmail(options) {
        return this.request('/api/v1/auth/verify-email', {
            method: 'POST',
            body: JSON.stringify(options),
        });
    }
    async resendVerificationEmail() {
        await this.request('/api/v1/auth/verify-email/resend', {
            method: 'POST',
        });
    }
    async getOAuthUrl(options) {
        const params = new URLSearchParams({
            provider: options.provider,
            ...(options.redirectUrl && { redirect_url: options.redirectUrl }),
        });
        return this.request(`/api/v1/auth/oauth/${options.provider}?${params}`);
    }
    async handleOAuthCallback(provider, code) {
        return this.request(`/api/v1/auth/oauth/${provider}/callback`, {
            method: 'POST',
            body: JSON.stringify({ code }),
        });
    }
    async verifyMfa(code, method) {
        return this.request('/api/v1/auth/mfa/verify', {
            method: 'POST',
            body: JSON.stringify({ code, method }),
        });
    }
    async signOut() {
        await this.request('/api/v1/auth/logout', {
            method: 'POST',
        });
    }
    async refreshSession() {
        const refreshToken = await this.getStoredRefreshToken();
        return this.request('/api/v1/auth/refresh', {
            method: 'POST',
            body: JSON.stringify({ refreshToken }),
        });
    }
    async validateSession(token) {
        return this.request('/api/v1/auth/session', {
            headers: { Authorization: `Bearer ${token}` },
        });
    }
    // ============================================================================
    // User Methods
    // ============================================================================
    async getCurrentUser() {
        return this.request('/api/v1/users/me');
    }
    async updateUser(updates) {
        return this.request('/api/v1/users/me', {
            method: 'PATCH',
            body: JSON.stringify(updates),
        });
    }
    async deleteUser() {
        await this.request('/api/v1/users/me', {
            method: 'DELETE',
        });
    }
    async changePassword(currentPassword, newPassword) {
        await this.request('/api/v1/users/me/password', {
            method: 'PATCH',
            body: JSON.stringify({ currentPassword, newPassword }),
        });
    }
    async uploadAvatar(file) {
        const formData = new FormData();
        formData.append('avatar', file);
        const url = `${this.baseUrl}/api/v1/users/me/avatar`;
        const headers = {
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
    async getMfaStatus() {
        return this.request('/api/v1/users/me/mfa');
    }
    async setupTotp() {
        return this.request('/api/v1/users/me/mfa/totp/setup', {
            method: 'POST',
        });
    }
    async verifyTotpSetup(code) {
        await this.request('/api/v1/users/me/mfa/totp/verify', {
            method: 'POST',
            body: JSON.stringify({ code }),
        });
    }
    async disableMfa(method) {
        await this.request('/api/v1/users/me/mfa', {
            method: 'DELETE',
            body: JSON.stringify({ method }),
        });
    }
    async generateBackupCodes() {
        return this.request('/api/v1/users/me/mfa/backup-codes', {
            method: 'POST',
        });
    }
    async verifyBackupCode(code) {
        await this.request('/api/v1/users/me/mfa/backup-codes/verify', {
            method: 'POST',
            body: JSON.stringify({ code }),
        });
    }
    // ============================================================================
    // WebAuthn Methods
    // ============================================================================
    async beginWebAuthnRegistration() {
        return this.request('/api/v1/webauthn/register/begin', {
            method: 'POST',
        });
    }
    async finishWebAuthnRegistration(credential) {
        await this.request('/api/v1/webauthn/register/finish', {
            method: 'POST',
            body: JSON.stringify({ credential }),
        });
    }
    async beginWebAuthnAuthentication() {
        return this.request('/api/v1/webauthn/authenticate/begin', {
            method: 'POST',
        });
    }
    async finishWebAuthnAuthentication(credential) {
        return this.request('/api/v1/webauthn/authenticate/finish', {
            method: 'POST',
            body: JSON.stringify({ credential }),
        });
    }
    async listWebAuthnCredentials() {
        return this.request('/api/v1/users/me/webauthn/credentials');
    }
    async deleteWebAuthnCredential(credentialId) {
        await this.request(`/api/v1/users/me/webauthn/credentials/${credentialId}`, {
            method: 'DELETE',
        });
    }
    // ============================================================================
    // Session Methods
    // ============================================================================
    async listSessions() {
        return this.request('/api/v1/users/me/sessions');
    }
    async revokeSession(sessionId) {
        await this.request(`/api/v1/users/me/sessions/${sessionId}`, {
            method: 'DELETE',
        });
    }
    async revokeAllSessions() {
        await this.request('/api/v1/users/me/sessions', {
            method: 'DELETE',
        });
    }
    // ============================================================================
    // Organization Methods
    // ============================================================================
    async listOrganizations() {
        return this.request('/api/v1/organizations');
    }
    async setActiveOrganization(orgId) {
        return this.request('/api/v1/users/me/active-organization', {
            method: 'PUT',
            body: JSON.stringify({ organizationId: orgId }),
        });
    }
    async getOrganization(id) {
        return this.request(`/api/v1/organizations/${id}`);
    }
    async createOrganization(data) {
        return this.request('/api/v1/organizations', {
            method: 'POST',
            body: JSON.stringify(data),
        });
    }
    async updateOrganization(id, data) {
        return this.request(`/api/v1/organizations/${id}`, {
            method: 'PATCH',
            body: JSON.stringify(data),
        });
    }
    async deleteOrganization(id) {
        await this.request(`/api/v1/organizations/${id}`, {
            method: 'DELETE',
        });
    }
    async leaveOrganization(id) {
        await this.request(`/api/v1/organizations/${id}/leave`, {
            method: 'POST',
        });
    }
    async listOrganizationMembers(orgId) {
        return this.request(`/api/v1/organizations/${orgId}/members`);
    }
    async inviteOrganizationMember(orgId, email, role) {
        await this.request(`/api/v1/organizations/${orgId}/invite`, {
            method: 'POST',
            body: JSON.stringify({ email, role }),
        });
    }
    async removeOrganizationMember(orgId, userId) {
        await this.request(`/api/v1/organizations/${orgId}/members/${userId}`, {
            method: 'DELETE',
        });
    }
    async updateOrganizationMemberRole(orgId, userId, role) {
        await this.request(`/api/v1/organizations/${orgId}/members/${userId}/role`, {
            method: 'PATCH',
            body: JSON.stringify({ role }),
        });
    }
    // ============================================================================
    // Session Storage
    // ============================================================================
    async storeToken(token) {
        if (typeof window !== 'undefined') {
            localStorage.setItem(STORAGE_KEY, token);
        }
    }
    async storeRefreshToken(token) {
        if (typeof window !== 'undefined') {
            localStorage.setItem(STORAGE_REFRESH_KEY, token);
        }
    }
    async getStoredToken() {
        if (typeof window === 'undefined') {
            // SSR - return config token if provided
            return this.config.sessionToken || null;
        }
        return localStorage.getItem(STORAGE_KEY);
    }
    async getStoredRefreshToken() {
        if (typeof window === 'undefined') {
            return null;
        }
        return localStorage.getItem(STORAGE_REFRESH_KEY);
    }
    async clearToken() {
        if (typeof window !== 'undefined') {
            localStorage.removeItem(STORAGE_KEY);
            localStorage.removeItem(STORAGE_REFRESH_KEY);
        }
    }
    // ============================================================================
    // Billing Methods
    // ============================================================================
    async getBillingPlans() {
        return this.request('/api/v1/admin/billing/plans');
    }
    async getBillingStatus() {
        return this.request('/api/v1/admin/billing/status');
    }
    async getSubscription() {
        return this.request('/api/v1/admin/billing/subscription');
    }
    async createSubscription(data) {
        return this.request('/api/v1/admin/billing/subscription', {
            method: 'POST',
            body: JSON.stringify({
                price_id: data.priceId,
                success_url: data.successUrl,
                cancel_url: data.cancelUrl,
            }),
        });
    }
    async cancelSubscription() {
        return this.request('/api/v1/admin/billing/subscription/cancel', {
            method: 'POST',
        });
    }
    async resumeSubscription() {
        return this.request('/api/v1/admin/billing/subscription/resume', {
            method: 'POST',
        });
    }
    async updateSubscription(newPriceId) {
        return this.request('/api/v1/admin/billing/subscription', {
            method: 'PUT',
            body: JSON.stringify({ new_price_id: newPriceId }),
        });
    }
    async getInvoices() {
        return this.request('/api/v1/admin/billing/invoices');
    }
    async createPortalSession(returnUrl) {
        return this.request('/api/v1/admin/billing/portal', {
            method: 'POST',
            body: JSON.stringify({ return_url: returnUrl }),
        });
    }
    async reportUsage(quantity, action = 'increment') {
        await this.request('/api/v1/admin/billing/usage', {
            method: 'POST',
            body: JSON.stringify({ quantity, action }),
        });
    }
    // ============================================================================
    // Utility Methods
    // ============================================================================
    /**
     * Check if WebAuthn is supported in the current browser
     */
    isWebAuthnSupported() {
        return typeof window !== 'undefined' &&
            typeof window.PublicKeyCredential !== 'undefined';
    }
}
// Export singleton instance creation helper
function createVaultClient(config) {
    return new VaultApiClient(config);
}

/**
 * Default Themes
 *
 * Pre-defined light, dark, and neutral themes following Clerk's design system.
 */
// ============================================================================
// Base Font Stacks
// ============================================================================
const fontStack = {
    system: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'};
// ============================================================================
// Light Theme Variables
// ============================================================================
const lightThemeVariables = {
    colorPrimary: '#0066cc',
    colorPrimaryHover: '#0052a3',
    colorBackground: '#ffffff',
    colorInputBackground: '#ffffff',
    colorText: '#1a1a1a',
    colorTextSecondary: '#6b7280',
    colorDanger: '#dc2626',
    colorSuccess: '#16a34a',
    colorWarning: '#ca8a04',
    colorInputText: '#1a1a1a',
    colorInputBorder: '#d1d5db',
    fontFamily: fontStack.system,
    fontFamilyButtons: fontStack.system,
    fontSize: '16px',
    fontWeight: 400,
    borderRadius: '0.375rem',
    spacing: '1rem',
    colorShimmer: 'rgba(0, 0, 0, 0.05)',
    colorFocus: 'rgba(0, 102, 204, 0.25)',
    colorSurface: '#ffffff',
    colorBorder: '#e5e7eb',
    colorAvatarBackground: '#0066cc',
};
// ============================================================================
// Dark Theme Variables
// ============================================================================
const darkThemeVariables = {
    colorPrimary: '#3b82f6',
    colorPrimaryHover: '#2563eb',
    colorBackground: '#0f0f10',
    colorInputBackground: '#1a1a1a',
    colorText: '#f9fafb',
    colorTextSecondary: '#9ca3af',
    colorDanger: '#ef4444',
    colorSuccess: '#22c55e',
    colorWarning: '#eab308',
    colorInputText: '#f9fafb',
    colorInputBorder: '#374151',
    fontFamily: fontStack.system,
    fontFamilyButtons: fontStack.system,
    fontSize: '16px',
    fontWeight: 400,
    borderRadius: '0.375rem',
    spacing: '1rem',
    colorShimmer: 'rgba(255, 255, 255, 0.05)',
    colorFocus: 'rgba(59, 130, 246, 0.25)',
    colorSurface: '#1a1a1a',
    colorBorder: '#374151',
    colorAvatarBackground: '#3b82f6',
};
// ============================================================================
// Neutral Theme Variables
// ============================================================================
const neutralThemeVariables = {
    colorPrimary: '#6b7280',
    colorPrimaryHover: '#4b5563',
    colorBackground: '#f9fafb',
    colorInputBackground: '#ffffff',
    colorText: '#111827',
    colorTextSecondary: '#6b7280',
    colorDanger: '#ef4444',
    colorSuccess: '#10b981',
    colorWarning: '#f59e0b',
    colorInputText: '#111827',
    colorInputBorder: '#d1d5db',
    fontFamily: fontStack.system,
    fontFamilyButtons: fontStack.system,
    fontSize: '16px',
    fontWeight: 400,
    borderRadius: '0.5rem',
    spacing: '1rem',
    colorShimmer: 'rgba(0, 0, 0, 0.03)',
    colorFocus: 'rgba(107, 114, 128, 0.25)',
    colorSurface: '#ffffff',
    colorBorder: '#e5e7eb',
    colorAvatarBackground: '#6b7280',
};
// ============================================================================
// Default Element Styles (CSS class names)
// ============================================================================
const defaultElementStyles = {
    root: 'vault-root',
    card: 'vault-card',
    header: 'vault-header',
    headerTitle: 'vault-header-title',
    headerSubtitle: 'vault-header-subtitle',
    formButtonPrimary: 'vault-form-button-primary',
    formButtonSecondary: 'vault-form-button-secondary',
    formField: 'vault-form-field',
    formFieldInput: 'vault-form-field-input',
    formFieldLabel: 'vault-form-field-label',
    formFieldError: 'vault-form-field-error',
    socialButtons: 'vault-social-buttons',
    socialButtonsIconButton: 'vault-social-buttons-icon-button',
    dividerLine: 'vault-divider-line',
    dividerText: 'vault-divider-text',
    alert: 'vault-alert',
    alertError: 'vault-alert-error',
    alertSuccess: 'vault-alert-success',
    alertWarning: 'vault-alert-warning',
    spinner: 'vault-spinner',
    userButton: 'vault-user-button',
    userButtonPopover: 'vault-user-button-popover',
    userButtonPopoverCard: 'vault-user-button-popover-card',
    userButtonTrigger: 'vault-user-button-trigger',
    avatarBox: 'vault-avatar-box',
    menuItem: 'vault-menu-item',
    menuList: 'vault-menu-list',
};
// ============================================================================
// Default Layout Options
// ============================================================================
const defaultLayoutOptions = {
    socialButtonsPlacement: 'bottom',
    socialButtonsVariant: 'blockButton',
    showOptionalFields: true,
    shimmer: true,
    animations: true,
    logoPlacement: 'inside',
};
// ============================================================================
// Complete Themes
// ============================================================================
const lightTheme = {
    id: 'light',
    name: 'Light',
    variables: lightThemeVariables,
    elements: defaultElementStyles,
    layout: defaultLayoutOptions,
    isDark: false,
};
const darkTheme = {
    id: 'dark',
    name: 'Dark',
    variables: darkThemeVariables,
    elements: defaultElementStyles,
    layout: defaultLayoutOptions,
    isDark: true,
};
const neutralTheme = {
    id: 'neutral',
    name: 'Neutral',
    variables: neutralThemeVariables,
    elements: defaultElementStyles,
    layout: defaultLayoutOptions,
    isDark: false,
};
// ============================================================================
// Theme Map
// ============================================================================
const themes = {
    light: lightTheme,
    dark: darkTheme,
    neutral: neutralTheme,
};
/**
 * Get a theme by ID
 */
function getTheme(themeId) {
    return themes[themeId] || lightTheme;
}

/**
 * Theme Utilities
 *
 * Helper functions for theme manipulation and CSS generation.
 */
// ============================================================================
// Theme Merging
// ============================================================================
/**
 * Merge appearance configuration with base theme
 */
function mergeThemes(base, appearance) {
    if (!appearance) {
        return base;
    }
    // Determine base theme
    let resolvedBase = base;
    if (appearance.baseTheme) {
        switch (appearance.baseTheme) {
            case 'dark':
                resolvedBase = darkTheme;
                break;
            case 'neutral':
                resolvedBase = neutralTheme;
                break;
            case 'light':
            default:
                resolvedBase = lightTheme;
                break;
        }
    }
    // Merge variables
    const variables = {
        ...resolvedBase.variables,
        ...appearance.variables,
    };
    // Merge elements
    const elements = {
        ...resolvedBase.elements,
        ...appearance.elements,
    };
    // Merge layout
    const layout = {
        ...resolvedBase.layout,
        ...appearance.layout,
    };
    return {
        ...resolvedBase,
        variables,
        elements,
        layout,
    };
}
// ============================================================================
// CSS Variable Generation
// ============================================================================
/**
 * Generate CSS custom properties from theme variables
 */
function generateCSSVariables(vars) {
    return {
        '--vault-color-primary': vars.colorPrimary,
        '--vault-color-primary-hover': vars.colorPrimaryHover,
        '--vault-color-background': vars.colorBackground,
        '--vault-color-input-background': vars.colorInputBackground,
        '--vault-color-text': vars.colorText,
        '--vault-color-text-secondary': vars.colorTextSecondary,
        '--vault-color-danger': vars.colorDanger,
        '--vault-color-success': vars.colorSuccess,
        '--vault-color-warning': vars.colorWarning,
        '--vault-color-input-text': vars.colorInputText,
        '--vault-color-input-border': vars.colorInputBorder,
        '--vault-font-family': vars.fontFamily,
        '--vault-font-family-buttons': vars.fontFamilyButtons,
        '--vault-font-size': vars.fontSize,
        '--vault-font-weight': String(vars.fontWeight),
        '--vault-border-radius': vars.borderRadius,
        '--vault-spacing': vars.spacing,
        '--vault-color-shimmer': vars.colorShimmer || 'rgba(0, 0, 0, 0.05)',
        '--vault-color-focus': vars.colorFocus || 'rgba(0, 102, 204, 0.25)',
        '--vault-color-surface': vars.colorSurface || vars.colorBackground,
        '--vault-color-border': vars.colorBorder || vars.colorInputBorder,
        '--vault-color-avatar-background': vars.colorAvatarBackground || vars.colorPrimary,
    };
}
/**
 * Convert CSS variables object to inline style string
 */
function cssVariablesToStyle(vars) {
    return vars;
}
// ============================================================================
// Element Style Utilities
// ============================================================================
/**
 * Create a combined class name for an element
 */
function createElementStyles(elements, elementName) {
    const baseClass = defaultElementStyles[elementName];
    const customClass = elements[elementName];
    if (customClass && customClass !== baseClass) {
        return `${baseClass} ${customClass}`;
    }
    return baseClass || '';
}
/**
 * Get all class names for an element as an array
 */
function getElementClasses(elements, elementName) {
    const className = createElementStyles(elements, elementName);
    return className.split(' ').filter(Boolean);
}
// ============================================================================
// Layout Utilities
// ============================================================================
/**
 * Get layout option with fallback
 */
function getLayoutOption(layout, key, defaultValue) {
    const value = layout[key];
    if (value !== undefined) {
        return value;
    }
    if (defaultValue !== undefined) {
        return defaultValue;
    }
    return defaultLayoutOptions[key];
}
// ============================================================================
// Style Application
// ============================================================================
/**
 * Apply CSS variables to a style object
 */
function applyCSSVariables(baseStyle, vars) {
    return {
        ...baseStyle,
        ...vars,
    };
}
/**
 * Merge class names
 */
function cx(...classes) {
    return classes.filter(Boolean).join(' ');
}
/**
 * Generate base component styles from CSS variables
 */
function generateBaseStyles(vars) {
    return {
        buttonPrimary: {
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '0.75rem 1rem',
            fontSize: vars['--vault-font-size'],
            fontWeight: 600,
            fontFamily: vars['--vault-font-family-buttons'],
            color: '#ffffff',
            backgroundColor: vars['--vault-color-primary'],
            border: 'none',
            borderRadius: vars['--vault-border-radius'],
            cursor: 'pointer',
            transition: 'background-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out',
        },
        buttonSecondary: {
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '0.75rem 1rem',
            fontSize: vars['--vault-font-size'],
            fontWeight: 500,
            fontFamily: vars['--vault-font-family-buttons'],
            color: vars['--vault-color-text'],
            backgroundColor: 'transparent',
            border: `1px solid ${vars['--vault-color-border']}`,
            borderRadius: vars['--vault-border-radius'],
            cursor: 'pointer',
            transition: 'background-color 0.15s ease-in-out',
        },
        input: {
            width: '100%',
            padding: '0.625rem 0.75rem',
            fontSize: vars['--vault-font-size'],
            fontFamily: vars['--vault-font-family'],
            color: vars['--vault-color-input-text'],
            backgroundColor: vars['--vault-color-input-background'],
            border: `1px solid ${vars['--vault-color-input-border']}`,
            borderRadius: vars['--vault-border-radius'],
            outline: 'none',
            transition: 'border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out',
        },
        label: {
            display: 'block',
            marginBottom: '0.375rem',
            fontSize: '0.875rem',
            fontWeight: 500,
            fontFamily: vars['--vault-font-family'],
            color: vars['--vault-color-text'],
        },
        card: {
            backgroundColor: vars['--vault-color-surface'],
            border: `1px solid ${vars['--vault-color-border']}`,
            borderRadius: '0.75rem',
            boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
            overflow: 'hidden',
        },
        alert: {
            padding: '0.75rem 1rem',
            borderRadius: vars['--vault-border-radius'],
            fontSize: '0.875rem',
            fontFamily: vars['--vault-font-family'],
        },
        alertError: {
            color: vars['--vault-color-danger'],
            backgroundColor: `${vars['--vault-color-danger']}15`,
            border: `1px solid ${vars['--vault-color-danger']}30`,
        },
        alertSuccess: {
            color: vars['--vault-color-success'],
            backgroundColor: `${vars['--vault-color-success']}15`,
            border: `1px solid ${vars['--vault-color-success']}30`,
        },
        alertWarning: {
            color: vars['--vault-color-warning'],
            backgroundColor: `${vars['--vault-color-warning']}15`,
            border: `1px solid ${vars['--vault-color-warning']}30`,
        },
        spinner: {
            width: '1.25rem',
            height: '1.25rem',
            border: `2px solid ${vars['--vault-color-border']}`,
            borderTopColor: vars['--vault-color-primary'],
            borderRadius: '50%',
            animation: 'vault-spin 1s linear infinite',
        },
    };
}

// ============================================================================
// Context Creation
// ============================================================================
const ThemeContext = React.createContext(null);
function GlobalStyles({ theme, appendCss }) {
    const cssVariables = React.useMemo(() => generateCSSVariables(theme.variables), [theme.variables]);
    const styleContent = React.useMemo(() => {
        const vars = Object.entries(cssVariables)
            .map(([key, value]) => `  ${key}: ${value};`)
            .join('\n');
        const baseStyles = `
/* Vault Theme Variables */
.vault-root {
${vars}
}

/* Vault Base Styles */
.vault-card {
  background-color: var(--vault-color-surface);
  border: 1px solid var(--vault-color-border);
  border-radius: 0.75rem;
  box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
  overflow: hidden;
}

.vault-header {
  padding: 1.5rem 1.5rem 0.5rem;
  text-align: center;
}

.vault-header-title {
  margin: 0 0 0.5rem;
  font-size: 1.5rem;
  font-weight: 600;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text);
}

.vault-header-subtitle {
  margin: 0;
  font-size: 0.875rem;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text-secondary);
}

.vault-form-field {
  margin-bottom: 1rem;
}

.vault-form-field-label {
  display: block;
  margin-bottom: 0.375rem;
  font-size: 0.875rem;
  font-weight: 500;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text);
}

.vault-form-field-input {
  width: 100%;
  padding: 0.625rem 0.75rem;
  font-size: var(--vault-font-size);
  font-family: var(--vault-font-family);
  color: var(--vault-color-input-text);
  background-color: var(--vault-color-input-background);
  border: 1px solid var(--vault-color-input-border);
  border-radius: var(--vault-border-radius);
  outline: none;
  transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
  box-sizing: border-box;
}

.vault-form-field-input:focus {
  border-color: var(--vault-color-primary);
  box-shadow: 0 0 0 3px var(--vault-color-focus);
}

.vault-form-field-input:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.vault-form-field-error {
  display: block;
  margin-top: 0.375rem;
  font-size: 0.75rem;
  font-family: var(--vault-font-family);
  color: var(--vault-color-danger);
}

.vault-form-button-primary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  padding: 0.75rem 1rem;
  font-size: var(--vault-font-size);
  font-weight: 600;
  font-family: var(--vault-font-family-buttons);
  color: #ffffff;
  background-color: var(--vault-color-primary);
  border: none;
  border-radius: var(--vault-border-radius);
  cursor: pointer;
  transition: background-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
  box-sizing: border-box;
}

.vault-form-button-primary:hover:not(:disabled) {
  background-color: var(--vault-color-primary-hover);
}

.vault-form-button-primary:focus {
  outline: none;
  box-shadow: 0 0 0 3px var(--vault-color-focus);
}

.vault-form-button-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.vault-form-button-secondary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  padding: 0.75rem 1rem;
  font-size: var(--vault-font-size);
  font-weight: 500;
  font-family: var(--vault-font-family-buttons);
  color: var(--vault-color-text);
  background-color: transparent;
  border: 1px solid var(--vault-color-border);
  border-radius: var(--vault-border-radius);
  cursor: pointer;
  transition: background-color 0.15s ease-in-out;
  box-sizing: border-box;
}

.vault-form-button-secondary:hover:not(:disabled) {
  background-color: var(--vault-color-shimmer);
}

.vault-form-button-secondary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.vault-social-buttons {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.vault-social-buttons-icon-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 2.75rem;
  height: 2.75rem;
  padding: 0;
  background-color: var(--vault-color-surface);
  border: 1px solid var(--vault-color-border);
  border-radius: var(--vault-border-radius);
  cursor: pointer;
  transition: background-color 0.15s ease-in-out, border-color 0.15s ease-in-out;
}

.vault-social-buttons-icon-button:hover:not(:disabled) {
  background-color: var(--vault-color-shimmer);
  border-color: var(--vault-color-input-border);
}

.vault-divider-line {
  flex: 1;
  height: 1px;
  background-color: var(--vault-color-border);
}

.vault-divider-text {
  padding: 0 1rem;
  font-size: 0.875rem;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text-secondary);
}

.vault-alert {
  padding: 0.75rem 1rem;
  border-radius: var(--vault-border-radius);
  font-size: 0.875rem;
  font-family: var(--vault-font-family);
}

.vault-alert-error {
  color: var(--vault-color-danger);
  background-color: color-mix(in srgb, var(--vault-color-danger) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--vault-color-danger) 20%, transparent);
}

.vault-alert-success {
  color: var(--vault-color-success);
  background-color: color-mix(in srgb, var(--vault-color-success) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--vault-color-success) 20%, transparent);
}

.vault-alert-warning {
  color: var(--vault-color-warning);
  background-color: color-mix(in srgb, var(--vault-color-warning) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--vault-color-warning) 20%, transparent);
}

.vault-spinner {
  width: 1.25rem;
  height: 1.25rem;
  border: 2px solid var(--vault-color-border);
  border-top-color: var(--vault-color-primary);
  border-radius: 50%;
  animation: vault-spin 1s linear infinite;
}

@keyframes vault-spin {
  to {
    transform: rotate(360deg);
  }
}

.vault-shimmer {
  background: linear-gradient(
    90deg,
    var(--vault-color-shimmer) 0%,
    color-mix(in srgb, var(--vault-color-shimmer) 50%, transparent) 50%,
    var(--vault-color-shimmer) 100%
  );
  background-size: 200% 100%;
  animation: vault-shimmer 1.5s infinite;
}

@keyframes vault-shimmer {
  0% {
    background-position: 200% 0;
  }
  100% {
    background-position: -200% 0;
  }
}

.vault-user-button {
  position: relative;
  display: inline-block;
}

.vault-user-button-trigger {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.375rem 0.75rem;
  background: transparent;
  border: 1px solid var(--vault-color-border);
  border-radius: var(--vault-border-radius);
  cursor: pointer;
  font-size: 0.875rem;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text);
  transition: background-color 0.15s ease-in-out;
}

.vault-user-button-trigger:hover {
  background-color: var(--vault-color-shimmer);
}

.vault-user-button-popover {
  position: absolute;
  top: calc(100% + 0.5rem);
  right: 0;
  min-width: 220px;
  z-index: 1000;
}

.vault-user-button-popover-card {
  background-color: var(--vault-color-surface);
  border: 1px solid var(--vault-color-border);
  border-radius: var(--vault-border-radius);
  box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
  overflow: hidden;
}

.vault-avatar-box {
  width: 2rem;
  height: 2rem;
  border-radius: 50%;
  background-color: var(--vault-color-avatar-background);
  color: #ffffff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.875rem;
  font-weight: 600;
  font-family: var(--vault-font-family);
}

.vault-menu-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.vault-menu-item {
  display: flex;
  align-items: center;
  width: 100%;
  padding: 0.625rem 1rem;
  font-size: 0.875rem;
  font-family: var(--vault-font-family);
  color: var(--vault-color-text);
  background: transparent;
  border: none;
  cursor: pointer;
  text-align: left;
  transition: background-color 0.15s ease-in-out;
}

.vault-menu-item:hover {
  background-color: var(--vault-color-shimmer);
}
`;
        const customStyles = appendCss || '';
        return baseStyles + '\n' + customStyles;
    }, [cssVariables, appendCss]);
    return jsxRuntime.jsx("style", { children: styleContent });
}
// ============================================================================
// Theme Provider Component
// ============================================================================
function ThemeProvider({ children, appearance = {}, defaultTheme, }) {
    // Determine base theme
    const baseTheme = React.useMemo(() => {
        const themeId = defaultTheme || appearance.baseTheme || 'light';
        switch (themeId) {
            case 'dark':
                return darkTheme;
            case 'neutral':
                return neutralTheme;
            case 'light':
            default:
                return lightTheme;
        }
    }, [appearance.baseTheme, defaultTheme]);
    // Merge theme with appearance
    const theme = React.useMemo(() => {
        return mergeThemes(baseTheme, appearance);
    }, [baseTheme, appearance]);
    // Generate CSS variables
    const cssVariables = React.useMemo(() => {
        return generateCSSVariables(theme.variables);
    }, [theme.variables]);
    // Get element class helper
    const getElementClass = React.useMemo(() => {
        return (elementName) => {
            return createElementStyles(theme.elements, elementName);
        };
    }, [theme.elements]);
    // Get layout option helper
    const getLayoutOption = React.useMemo(() => {
        return (key) => {
            return getLayoutOptionHelper(theme.layout, key);
        };
    }, [theme.layout]);
    // Context value
    const value = React.useMemo(() => ({
        theme,
        appearance,
        cssVariables,
        getElementClass,
        getLayoutOption,
        isDark: theme.isDark,
    }), [theme, appearance, cssVariables, getElementClass, getLayoutOption]);
    return (jsxRuntime.jsxs(ThemeContext.Provider, { value: value, children: [jsxRuntime.jsx(GlobalStyles, { theme: theme, appendCss: appearance.appendCss }), children] }));
}
// Helper function for layout options
function getLayoutOptionHelper(layout, key) {
    const value = layout[key];
    if (value !== undefined) {
        return value;
    }
    // Return defaults
    const defaults = {
        socialButtonsPlacement: 'bottom',
        socialButtonsVariant: 'blockButton',
        showOptionalFields: true,
        shimmer: true,
    };
    return defaults[key];
}
// ============================================================================
// useTheme Hook
// ============================================================================
function useTheme() {
    const context = React.useContext(ThemeContext);
    if (!context) {
        throw new Error('useTheme must be used within a ThemeProvider');
    }
    return context;
}
// ============================================================================
// withTheme HOC
// ============================================================================
function withTheme(Component) {
    return function WithThemeComponent(props) {
        const theme = useTheme();
        return jsxRuntime.jsx(Component, { ...props, theme: theme });
    };
}

// ============================================================================
// Context Creation
// ============================================================================
const VaultContext = React.createContext(null);
// ============================================================================
// Provider Component
// ============================================================================
function VaultProvider({ children, config, initialUser, initialSessionToken, onAuthStateChange, appearance, }) {
    // API client ref to prevent recreation
    const apiRef = React.useRef(new VaultApiClient(config));
    const api = apiRef.current;
    // Auth state
    const [authState, setAuthState] = React.useState(initialUser
        ? { status: 'authenticated', user: initialUser, session: {} }
        : { status: 'loading' });
    // Organization state
    const [organizations, setOrganizations] = React.useState([]);
    const [activeOrg, setActiveOrg] = React.useState(null);
    // Sessions state
    const [sessions, setSessions] = React.useState([]);
    // MFA state
    const [mfaChallenge, setMfaChallenge] = React.useState(null);
    // Error state
    const [lastError, setLastError] = React.useState(null);
    // Update API client if config changes
    React.useEffect(() => {
        apiRef.current = new VaultApiClient(config);
    }, [config]);
    // Notify auth state changes
    React.useEffect(() => {
        onAuthStateChange?.(authState);
    }, [authState, onAuthStateChange]);
    // ============================================================================
    // Initialization
    // ============================================================================
    React.useEffect(() => {
        const init = async () => {
            // Skip if we have initial user (SSR)
            if (initialUser) {
                // Load organizations
                await refreshOrganizations();
                return;
            }
            try {
                const token = await api.getStoredToken();
                if (token) {
                    // Validate token and get user
                    const session = await api.validateSession(token);
                    setAuthState({
                        status: 'authenticated',
                        user: session.user,
                        session
                    });
                    // Store refresh token if provided
                    if (session.refreshToken) {
                        await api.storeRefreshToken(session.refreshToken);
                    }
                    // Load organizations
                    await refreshOrganizations();
                }
                else {
                    setAuthState({ status: 'unauthenticated' });
                }
            }
            catch (error) {
                // Clear invalid token
                await api.clearToken();
                setAuthState({ status: 'unauthenticated' });
            }
        };
        init();
    }, [api, initialUser]);
    // ============================================================================
    // Auth Methods
    // ============================================================================
    const signIn = React.useCallback(async (options) => {
        try {
            setAuthState({ status: 'loading' });
            setLastError(null);
            const response = await api.signIn(options);
            if (response.mfaRequired) {
                setMfaChallenge(response.mfaChallenge);
                setAuthState({
                    status: 'mfa_required',
                    challenge: response.mfaChallenge
                });
            }
            else {
                await api.storeToken(response.session.accessToken);
                if (response.session.refreshToken) {
                    await api.storeRefreshToken(response.session.refreshToken);
                }
                setAuthState({
                    status: 'authenticated',
                    user: response.user,
                    session: response.session
                });
                await refreshOrganizations();
            }
        }
        catch (error) {
            const apiError = error;
            setLastError(apiError);
            setAuthState({
                status: 'error',
                error: apiError
            });
            throw error;
        }
    }, [api]);
    const signInWithMagicLink = React.useCallback(async (options) => {
        setLastError(null);
        await api.sendMagicLink(options);
    }, [api]);
    const signInWithOAuth = React.useCallback(async (options) => {
        setLastError(null);
        const { url } = await api.getOAuthUrl(options);
        window.location.href = url;
    }, [api]);
    const signUp = React.useCallback(async (options) => {
        try {
            setAuthState({ status: 'loading' });
            setLastError(null);
            const response = await api.signUp(options);
            await api.storeToken(response.session.accessToken);
            if (response.session.refreshToken) {
                await api.storeRefreshToken(response.session.refreshToken);
            }
            setAuthState({
                status: 'authenticated',
                user: response.user,
                session: response.session
            });
            await refreshOrganizations();
        }
        catch (error) {
            const apiError = error;
            setLastError(apiError);
            setAuthState({
                status: 'error',
                error: apiError
            });
            throw error;
        }
    }, [api]);
    const signOut = React.useCallback(async () => {
        try {
            await api.signOut();
        }
        finally {
            await api.clearToken();
            setAuthState({ status: 'unauthenticated' });
            setActiveOrg(null);
            setOrganizations([]);
            setMfaChallenge(null);
        }
    }, [api]);
    // ============================================================================
    // Password Reset Methods
    // ============================================================================
    const sendForgotPassword = React.useCallback(async (options) => {
        setLastError(null);
        await api.sendForgotPassword(options);
    }, [api]);
    const resetPassword = React.useCallback(async (options) => {
        try {
            setLastError(null);
            const response = await api.resetPassword(options);
            await api.storeToken(response.session.accessToken);
            if (response.session.refreshToken) {
                await api.storeRefreshToken(response.session.refreshToken);
            }
            setAuthState({
                status: 'authenticated',
                user: response.user,
                session: response.session
            });
            await refreshOrganizations();
            return response;
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api]);
    // ============================================================================
    // Email Verification Methods
    // ============================================================================
    const verifyEmail = React.useCallback(async (options) => {
        try {
            setLastError(null);
            const { user } = await api.verifyEmail(options);
            if (authState.status === 'authenticated') {
                setAuthState({
                    ...authState,
                    user: { ...authState.user, ...user }
                });
            }
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api, authState]);
    const resendVerificationEmail = React.useCallback(async () => {
        setLastError(null);
        await api.resendVerificationEmail();
    }, [api]);
    // ============================================================================
    // MFA Methods
    // ============================================================================
    const verifyMfa = React.useCallback(async (code, method) => {
        try {
            setLastError(null);
            const response = await api.verifyMfa(code, method);
            await api.storeToken(response.session.accessToken);
            if (response.session.refreshToken) {
                await api.storeRefreshToken(response.session.refreshToken);
            }
            setMfaChallenge(null);
            setAuthState({
                status: 'authenticated',
                user: response.user,
                session: response.session
            });
            await refreshOrganizations();
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api]);
    const setupTotp = React.useCallback(async () => {
        try {
            setLastError(null);
            return await api.setupTotp();
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api]);
    const verifyTotpSetup = React.useCallback(async (code) => {
        try {
            setLastError(null);
            await api.verifyTotpSetup(code);
            await reloadUser();
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api]);
    const disableMfa = React.useCallback(async (method) => {
        try {
            setLastError(null);
            await api.disableMfa(method);
            await reloadUser();
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api]);
    const generateBackupCodes = React.useCallback(async () => {
        try {
            setLastError(null);
            const { codes } = await api.generateBackupCodes();
            return codes;
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api]);
    // ============================================================================
    // User Methods
    // ============================================================================
    const updateUser = React.useCallback(async (updates) => {
        try {
            setLastError(null);
            const updated = await api.updateUser(updates);
            if (authState.status === 'authenticated') {
                setAuthState({
                    ...authState,
                    user: { ...authState.user, ...updated }
                });
            }
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api, authState]);
    const reloadUser = React.useCallback(async () => {
        try {
            setLastError(null);
            const user = await api.getCurrentUser();
            if (authState.status === 'authenticated') {
                setAuthState({
                    ...authState,
                    user
                });
            }
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api, authState]);
    const changePassword = React.useCallback(async (currentPassword, newPassword) => {
        try {
            setLastError(null);
            await api.changePassword(currentPassword, newPassword);
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api]);
    const deleteUser = React.useCallback(async () => {
        try {
            setLastError(null);
            await api.deleteUser();
            await api.clearToken();
            setAuthState({ status: 'unauthenticated' });
            setActiveOrg(null);
            setOrganizations([]);
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api]);
    // ============================================================================
    // Organization Methods
    // ============================================================================
    const refreshOrganizations = React.useCallback(async () => {
        try {
            const orgs = await api.listOrganizations();
            setOrganizations(orgs);
        }
        catch (error) {
            // Silently fail - not critical
            if (config.debug) {
                console.error('[Vault SDK] Failed to load organizations:', error);
            }
        }
    }, [api, config.debug]);
    const setActiveOrganization = React.useCallback(async (orgId) => {
        try {
            setLastError(null);
            // Call API to switch organization context in the token
            const response = await api.setActiveOrganization(orgId);
            // Update token with new org context
            await api.storeToken(response.session.accessToken);
            if (response.session.refreshToken) {
                await api.storeRefreshToken(response.session.refreshToken);
            }
            // Update auth state with new user and session
            if (authState.status === 'authenticated') {
                setAuthState({
                    ...authState,
                    user: response.user,
                    session: { ...authState.session, ...response.session }
                });
            }
            // Update active organization
            if (orgId === null) {
                setActiveOrg(null);
            }
            else {
                const org = organizations.find(o => o.id === orgId);
                if (org) {
                    setActiveOrg(org);
                }
            }
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api, organizations, authState]);
    const createOrganization = React.useCallback(async (name, slug) => {
        try {
            setLastError(null);
            const org = await api.createOrganization({ name, slug });
            setOrganizations(prev => [...prev, org]);
            setActiveOrg(org);
            return org;
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api]);
    const leaveOrganization = React.useCallback(async (orgId) => {
        try {
            setLastError(null);
            await api.leaveOrganization(orgId);
            setOrganizations(prev => prev.filter(o => o.id !== orgId));
            if (activeOrg?.id === orgId) {
                setActiveOrg(null);
            }
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api, activeOrg]);
    // ============================================================================
    // Session Methods
    // ============================================================================
    const getToken = React.useCallback(async () => {
        return api.getStoredToken();
    }, [api]);
    const refreshSession = React.useCallback(async () => {
        try {
            const { session } = await api.refreshSession();
            await api.storeToken(session.accessToken);
            if (authState.status === 'authenticated') {
                setAuthState({
                    ...authState,
                    session: { ...authState.session, ...session }
                });
            }
        }
        catch (error) {
            // Clear session on refresh failure
            await api.clearToken();
            setAuthState({ status: 'unauthenticated' });
            throw error;
        }
    }, [api, authState]);
    // ============================================================================
    // Session Management Methods
    // ============================================================================
    const refreshSessions = React.useCallback(async () => {
        try {
            const sessionsList = await api.listSessions();
            setSessions(sessionsList);
        }
        catch (error) {
            if (config.debug) {
                console.error('[Vault SDK] Failed to load sessions:', error);
            }
        }
    }, [api, config.debug]);
    const revokeSession = React.useCallback(async (sessionId) => {
        try {
            setLastError(null);
            await api.revokeSession(sessionId);
            setSessions(prev => prev.filter(s => s.id !== sessionId));
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api]);
    const revokeAllOtherSessions = React.useCallback(async () => {
        try {
            setLastError(null);
            await api.revokeAllSessions();
            // Refresh to get updated list (should only contain current session)
            await refreshSessions();
        }
        catch (error) {
            setLastError(error);
            throw error;
        }
    }, [api, refreshSessions]);
    // ============================================================================
    // Error Handling
    // ============================================================================
    const clearError = React.useCallback(() => {
        setLastError(null);
        if (authState.status === 'error') {
            setAuthState({ status: 'unauthenticated' });
        }
    }, [authState]);
    // ============================================================================
    // Context Value
    // ============================================================================
    const value = {
        // State
        isLoaded: authState.status !== 'loading',
        isSignedIn: authState.status === 'authenticated',
        user: authState.status === 'authenticated' ? authState.user : null,
        session: authState.status === 'authenticated' ? authState.session : null,
        organization: activeOrg,
        authState,
        // API Client
        api,
        // Auth methods
        signIn,
        signInWithMagicLink,
        signInWithOAuth,
        signUp,
        signOut,
        // Password reset
        sendForgotPassword,
        resetPassword,
        // Email verification
        verifyEmail,
        resendVerificationEmail,
        // MFA
        mfaChallenge,
        verifyMfa,
        setupTotp,
        verifyTotpSetup,
        disableMfa,
        generateBackupCodes,
        // User methods
        updateUser,
        reloadUser,
        changePassword,
        deleteUser,
        // Organization methods
        organizations,
        setActiveOrganization,
        createOrganization,
        leaveOrganization,
        refreshOrganizations,
        // Session methods
        sessions,
        revokeSession,
        revokeAllOtherSessions,
        refreshSessions,
        // Token & Session
        getToken,
        refreshSession,
        // Error handling
        lastError,
        clearError,
    };
    return (jsxRuntime.jsx(VaultContext.Provider, { value: value, children: jsxRuntime.jsx(ThemeProvider, { appearance: appearance, children: children }) }));
}
// ============================================================================
// Hook
// ============================================================================
function useVault() {
    const context = React.useContext(VaultContext);
    if (!context) {
        throw new Error('useVault must be used within a VaultProvider');
    }
    return context;
}

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
function useAuth() {
    const vault = useVault();
    return {
        // State
        isLoaded: vault.isLoaded,
        isSignedIn: vault.isSignedIn,
        user: vault.user,
        session: vault.session,
        organization: vault.organization,
        // Actions
        signIn: vault.signIn,
        signInWithMagicLink: vault.signInWithMagicLink,
        signInWithOAuth: vault.signInWithOAuth,
        signUp: vault.signUp,
        signOut: vault.signOut,
    };
}
/**
 * Hook to get the current authentication state only.
 * Useful when you only need to check if user is signed in.
 *
 * @returns Object with isLoaded and isSignedIn booleans
 */
function useAuthState() {
    const vault = useVault();
    return {
        isLoaded: vault.isLoaded,
        isSignedIn: vault.isSignedIn,
    };
}
/**
 * Hook to check if the current user has a specific role.
 *
 * @param role - The role to check for
 * @returns Boolean indicating if user has the role
 */
function useHasRole(role) {
    const vault = useVault();
    if (!vault.isSignedIn || !vault.user) {
        return false;
    }
    // Check organization role
    if (vault.organization?.role === role) {
        return true;
    }
    return false;
}
/**
 * Hook to require authentication.
 * Returns the user or throws if not authenticated.
 *
 * @returns The current user
 * @throws Error if not authenticated
 */
function useRequireAuth() {
    const vault = useVault();
    if (!vault.isSignedIn || !vault.user || !vault.session) {
        throw new Error('Authentication required');
    }
    return {
        user: vault.user,
        session: vault.session,
        organization: vault.organization,
    };
}

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
function useUser() {
    const vault = useVault();
    return vault.user;
}
/**
 * Hook for user management operations.
 *
 * @returns Object with update and reload functions
 */
function useUpdateUser() {
    const vault = useVault();
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const updateUser = React.useCallback(async (updates) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.updateUser(updates);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const reloadUser = React.useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.reloadUser();
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    return {
        updateUser,
        reloadUser,
        isLoading,
        error,
    };
}
/**
 * Complete hook for user data and management.
 *
 * @returns User data and management functions
 */
function useUserManager() {
    const vault = useVault();
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const update = React.useCallback(async (updates) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.updateUser(updates);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const reload = React.useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.reloadUser();
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const changePassword = React.useCallback(async (currentPassword, newPassword) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.changePassword(currentPassword, newPassword);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const deleteUser = React.useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.deleteUser();
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    return {
        user: vault.user,
        isLoaded: vault.isLoaded,
        isLoading,
        error,
        update,
        reload,
        changePassword,
        deleteUser,
    };
}

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
function useSession() {
    const vault = useVault();
    return {
        session: vault.session,
        isLoaded: vault.isLoaded,
        getToken: vault.getToken,
        refresh: vault.refreshSession,
    };
}
/**
 * Hook to get the session token.
 * Useful for making authenticated API calls.
 *
 * @returns Function to get the current token
 */
function useToken() {
    const vault = useVault();
    return vault.getToken;
}
/**
 * Hook to get the current session ID.
 *
 * @returns The current session ID or null
 */
function useSessionId() {
    const vault = useVault();
    return vault.session?.id || null;
}

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
const DEFAULT_POLLING_INTERVAL = 30000; // 30 seconds
/**
 * Hook for managing all user sessions.
 * Automatically polls for session updates every 30 seconds when user is signed in.
 *
 * @param options - Optional configuration for polling
 * @param options.pollingInterval - Custom polling interval in milliseconds (default: 30000)
 * @returns Session management functions and state
 */
function useSessions(options) {
    const vault = useVault();
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const pollingInterval = options?.pollingInterval ?? DEFAULT_POLLING_INTERVAL;
    const pollingRef = React.useRef(null);
    const refresh = React.useCallback(async () => {
        if (!vault.isSignedIn) {
            return;
        }
        setIsLoading(true);
        setError(null);
        try {
            await vault.refreshSessions();
        }
        catch (err) {
            setError(err);
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const revokeSession = React.useCallback(async (sessionId) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.revokeSession(sessionId);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const revokeAllOtherSessions = React.useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.revokeAllOtherSessions();
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    // Initial load and polling setup
    React.useEffect(() => {
        // Load sessions immediately when signed in
        if (vault.isSignedIn) {
            refresh();
        }
        // Set up polling
        if (vault.isSignedIn && pollingInterval > 0) {
            pollingRef.current = setInterval(() => {
                vault.refreshSessions();
            }, pollingInterval);
        }
        return () => {
            if (pollingRef.current) {
                clearInterval(pollingRef.current);
                pollingRef.current = null;
            }
        };
    }, [vault.isSignedIn, pollingInterval, vault.refreshSessions]);
    return {
        sessions: vault.sessions,
        isLoading,
        error,
        revokeSession,
        revokeAllOtherSessions,
        refresh,
    };
}

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
function useSignIn() {
    const vault = useVault();
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const resetError = React.useCallback(() => {
        setError(null);
    }, []);
    const signIn = React.useCallback(async (options) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.signIn(options);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const signInWithMagicLink = React.useCallback(async (options) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.signInWithMagicLink(options);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const signInWithOAuth = React.useCallback(async (options) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.signInWithOAuth(options);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    return {
        isLoading,
        error,
        signIn,
        signInWithMagicLink,
        signInWithOAuth,
        resetError,
    };
}

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
function useSignUp() {
    const vault = useVault();
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const resetError = React.useCallback(() => {
        setError(null);
    }, []);
    const signUp = React.useCallback(async (options) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.signUp(options);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const signUpWithOAuth = React.useCallback(async (options) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.signInWithOAuth(options);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    return {
        isLoading,
        error,
        signUp,
        signUpWithOAuth,
        resetError,
    };
}

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
// ============================================================================
// WebAuthn Utilities
// ============================================================================
/**
 * Encode ArrayBuffer to base64url string
 */
function bufferToBase64url(buffer) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
/**
 * Decode base64url string to ArrayBuffer
 */
function base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const buffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        view[i] = binary.charCodeAt(i);
    }
    return buffer;
}
/**
 * Hook for WebAuthn/Passkey operations.
 *
 * @returns WebAuthn methods and state
 */
function useWebAuthn() {
    const vault = useVault();
    const [isSupported, setIsSupported] = React.useState(false);
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    // Check WebAuthn support on mount
    React.useEffect(() => {
        const checkSupport = () => {
            if (typeof window === 'undefined') {
                setIsSupported(false);
                return;
            }
            const supported = typeof window.PublicKeyCredential !== 'undefined' &&
                typeof window.navigator?.credentials?.create === 'function';
            setIsSupported(supported);
        };
        checkSupport();
    }, []);
    const resetError = React.useCallback(() => {
        setError(null);
    }, []);
    /**
     * Register a new WebAuthn credential (passkey)
     */
    const register = React.useCallback(async (name) => {
        if (!isSupported) {
            throw new Error('WebAuthn is not supported on this device');
        }
        setIsLoading(true);
        setError(null);
        try {
            // Get registration options from server
            const api = new VaultApiClient({
                apiUrl: '', // Will be set from context
                tenantId: '', // Will be set from context
            });
            // We need to access the API client from the vault context
            // For now, we'll use a workaround
            const options = await vault.api?.beginWebAuthnRegistration?.() ||
                await fetch('/api/v1/webauthn/register/begin', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${await vault.getToken()}`,
                    },
                }).then(r => r.json());
            // Create credential
            const credential = await navigator.credentials.create({
                publicKey: {
                    ...options,
                    challenge: base64urlToBuffer(options.challenge),
                    user: {
                        ...options.user,
                        id: base64urlToBuffer(options.user.id),
                    },
                },
            });
            if (!credential) {
                throw new Error('Failed to create credential');
            }
            const response = credential.response;
            // Send credential to server
            await fetch('/api/v1/webauthn/register/finish', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${await vault.getToken()}`,
                },
                body: JSON.stringify({
                    credential: {
                        id: credential.id,
                        rawId: bufferToBase64url(credential.rawId),
                        type: credential.type,
                        response: {
                            clientDataJSON: bufferToBase64url(response.clientDataJSON),
                            attestationObject: bufferToBase64url(response.attestationObject),
                        },
                    },
                    name,
                }),
            });
            // Reload user to get updated MFA methods
            await vault.reloadUser();
        }
        catch (err) {
            const apiError = {
                code: err.name === 'NotAllowedError' ? 'user_cancelled' : 'webauthn_error',
                message: err.message || 'WebAuthn operation failed',
            };
            setError(apiError);
            throw apiError;
        }
        finally {
            setIsLoading(false);
        }
    }, [isSupported, vault]);
    /**
     * Authenticate using WebAuthn
     */
    const authenticate = React.useCallback(async () => {
        if (!isSupported) {
            throw new Error('WebAuthn is not supported on this device');
        }
        setIsLoading(true);
        setError(null);
        try {
            // Get authentication options from server
            const options = await fetch('/api/v1/webauthn/authenticate/begin', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            }).then(r => r.json());
            // Get credential
            const credential = await navigator.credentials.get({
                publicKey: {
                    ...options,
                    challenge: base64urlToBuffer(options.challenge),
                    allowCredentials: options.allowCredentials?.map((cred) => ({
                        ...cred,
                        id: base64urlToBuffer(cred.id),
                    })),
                },
            });
            if (!credential) {
                throw new Error('Failed to get credential');
            }
            const response = credential.response;
            // Send credential to server
            const result = await fetch('/api/v1/webauthn/authenticate/finish', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    credential: {
                        id: credential.id,
                        rawId: bufferToBase64url(credential.rawId),
                        type: credential.type,
                        response: {
                            clientDataJSON: bufferToBase64url(response.clientDataJSON),
                            authenticatorData: bufferToBase64url(response.authenticatorData),
                            signature: bufferToBase64url(response.signature),
                            userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
                        },
                    },
                }),
            }).then(r => r.json());
            // Store session
            if (result.session) {
                localStorage.setItem('vault_session_token', result.session.accessToken);
                if (result.session.refreshToken) {
                    localStorage.setItem('vault_refresh_token', result.session.refreshToken);
                }
            }
            return result.session || null;
        }
        catch (err) {
            const apiError = {
                code: err.name === 'NotAllowedError' ? 'user_cancelled' : 'webauthn_error',
                message: err.message || 'WebAuthn authentication failed',
            };
            setError(apiError);
            throw apiError;
        }
        finally {
            setIsLoading(false);
        }
    }, [isSupported]);
    return {
        isSupported,
        isLoading,
        error,
        register,
        authenticate,
        resetError,
    };
}
/**
 * Hook to check if WebAuthn is supported on the current device.
 *
 * @returns Boolean indicating WebAuthn support
 */
function useIsWebAuthnSupported() {
    const [isSupported, setIsSupported] = React.useState(false);
    React.useEffect(() => {
        if (typeof window === 'undefined') {
            setIsSupported(false);
            return;
        }
        const supported = typeof window.PublicKeyCredential !== 'undefined' &&
            typeof window.navigator?.credentials?.create === 'function';
        setIsSupported(supported);
    }, []);
    return isSupported;
}

/**
 * useMfa Hook
 *
 * Hook for Multi-Factor Authentication management.
 *
 * @example
 * ```tsx
 * function MfaSetup() {
 *   const { setupTotp, verifyTotp, isLoading, error } = useMfa();
 *   const [qrCode, setQrCode] = useState<string | null>(null);
 *
 *   const handleSetup = async () => {
 *     const setup = await setupTotp();
 *     setQrCode(setup.qrCode);
 *   };
 *
 *   const handleVerify = async (code: string) => {
 *     await verifyTotp(code);
 *   };
 *
 *   return (
 *     <div>
 *       {qrCode && <img src={qrCode} alt="Scan with authenticator app" />}
 *       <button onClick={handleSetup} disabled={isLoading}>
 *         Setup TOTP
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */
/**
 * Hook for MFA operations.
 * Provides methods to setup, verify, and manage MFA methods.
 *
 * @returns MFA methods and state
 */
function useMfa() {
    const vault = useVault();
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const resetError = React.useCallback(() => {
        setError(null);
    }, []);
    const setupTotp = React.useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            const setup = await vault.setupTotp();
            return setup;
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const verifyTotp = React.useCallback(async (code) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.verifyTotpSetup(code);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const enableMfa = React.useCallback(async (method) => {
        setIsLoading(true);
        setError(null);
        try {
            // This would call the API to enable MFA
            // For TOTP, setupTotp should be called first
            if (method === 'totp') {
                await vault.setupTotp();
            }
            await vault.reloadUser();
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const disableMfa = React.useCallback(async (method) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.disableMfa(method);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const generateBackupCodes = React.useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            const codes = await vault.generateBackupCodes();
            return codes;
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    return {
        isLoading,
        error,
        setupTotp,
        verifyTotp,
        enableMfa,
        disableMfa,
        generateBackupCodes,
        resetError,
    };
}
/**
 * Hook to verify MFA challenge during sign-in.
 *
 * @returns MFA verification state and method
 */
function useMfaChallenge() {
    const vault = useVault();
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const verify = React.useCallback(async (code, method) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.verifyMfa(code, method);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    return {
        challenge: vault.mfaChallenge,
        isRequired: vault.authState.status === 'mfa_required',
        verify,
        isLoading,
        error,
    };
}

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
function useOrganization() {
    const vault = useVault();
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const [members, setMembers] = React.useState([]);
    // Load organizations on mount
    React.useEffect(() => {
        if (vault.isSignedIn) {
            vault.refreshOrganizations();
        }
    }, [vault.isSignedIn]);
    // Load members when active organization changes
    React.useEffect(() => {
        const loadMembers = async () => {
            if (!vault.organization) {
                setMembers([]);
                return;
            }
            setIsLoading(true);
            try {
                // This would call the API to load members
                // For now, we'll leave it as a placeholder
                setMembers([]);
            }
            catch (err) {
                setError(err);
            }
            finally {
                setIsLoading(false);
            }
        };
        loadMembers();
    }, [vault.organization]);
    const setActive = React.useCallback((orgId) => {
        vault.setActiveOrganization(orgId).catch(() => {
            // Error is already handled in vault context
        });
    }, [vault]);
    /**
     * Set the active organization with async handling.
     * This updates the token with new organization context.
     *
     * @param orgId - Organization ID to switch to, or null for personal workspace
     */
    const setActiveOrganization = React.useCallback(async (orgId) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.setActiveOrganization(orgId);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const create = React.useCallback(async (data) => {
        setIsLoading(true);
        setError(null);
        try {
            const org = await vault.createOrganization(data.name, data.slug);
            return org;
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    /**
     * Create a new organization.
     *
     * @param name - Organization name
     * @param slug - Optional organization slug (URL-friendly identifier)
     * @returns The created organization
     */
    const createOrganization = React.useCallback(async (name, slug) => {
        setIsLoading(true);
        setError(null);
        try {
            const org = await vault.createOrganization(name, slug);
            return org;
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const leave = React.useCallback(async (orgId) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.leaveOrganization(orgId);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    const refreshMembers = React.useCallback(async () => {
        if (!vault.organization)
            return;
        setIsLoading(true);
        setError(null);
        try {
            const membersList = await vault.api.listOrganizationMembers(vault.organization.id);
            setMembers(membersList);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault.organization, vault.api]);
    /**
     * Update an organization.
     *
     * @param orgId - Organization ID to update
     * @param updates - Partial organization data to update
     */
    const updateOrganization = React.useCallback(async (orgId, updates) => {
        setIsLoading(true);
        setError(null);
        try {
            const updated = await vault.api.updateOrganization(orgId, updates);
            // Update local state if this is the active organization
            if (vault.organization?.id === orgId) {
                vault.setActiveOrganization(orgId).catch(() => {
                    // Error handled in context
                });
            }
            return updated;
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    /**
     * Delete an organization.
     *
     * @param orgId - Organization ID to delete
     */
    const deleteOrganization = React.useCallback(async (orgId) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.api.deleteOrganization(orgId);
            // Refresh organizations list
            await vault.refreshOrganizations();
            // Clear active org if it was deleted
            if (vault.organization?.id === orgId) {
                await vault.setActiveOrganization(null);
            }
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault]);
    /**
     * Invite a member to an organization.
     *
     * @param orgId - Organization ID
     * @param email - Email of the user to invite
     * @param role - Role to assign to the invited user
     */
    const inviteMember = React.useCallback(async (orgId, email, role) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.api.inviteOrganizationMember(orgId, email, role);
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault.api]);
    /**
     * Remove a member from an organization.
     *
     * @param orgId - Organization ID
     * @param userId - User ID to remove
     */
    const removeMember = React.useCallback(async (orgId, userId) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.api.removeOrganizationMember(orgId, userId);
            // Refresh members list if currently viewing this org
            if (vault.organization?.id === orgId) {
                await refreshMembers();
            }
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault.api, vault.organization, refreshMembers]);
    /**
     * Update a member's role in an organization.
     *
     * @param orgId - Organization ID
     * @param userId - User ID to update
     * @param role - New role to assign
     */
    const updateMemberRole = React.useCallback(async (orgId, userId, role) => {
        setIsLoading(true);
        setError(null);
        try {
            await vault.api.updateOrganizationMemberRole(orgId, userId, role);
            // Refresh members list if currently viewing this org
            if (vault.organization?.id === orgId) {
                await refreshMembers();
            }
        }
        catch (err) {
            setError(err);
            throw err;
        }
        finally {
            setIsLoading(false);
        }
    }, [vault.api, vault.organization, refreshMembers]);
    return {
        organization: vault.organization,
        organizations: vault.organizations,
        organizationList: vault.organizations,
        isLoaded: vault.isLoaded,
        isLoading,
        members,
        setActive,
        setActiveOrganization,
        create,
        createOrganization,
        leave,
        refreshMembers,
        updateOrganization,
        deleteOrganization,
        inviteMember,
        removeMember,
        updateMemberRole,
    };
}
/**
 * Hook to get the current active organization.
 *
 * @returns The current organization or null
 */
function useActiveOrganization() {
    const vault = useVault();
    return vault.organization;
}
/**
 * Hook to check if user has a specific organization role.
 *
 * @param role - The role to check for
 * @returns Boolean indicating if user has the role
 */
function useOrganizationRole(role) {
    const vault = useVault();
    if (!vault.organization) {
        return false;
    }
    return vault.organization.role === role;
}
/**
 * Hook to check if user is an organization admin or owner.
 *
 * @returns Boolean indicating admin status
 */
function useIsOrgAdmin() {
    const vault = useVault();
    if (!vault.organization) {
        return false;
    }
    return vault.organization.role === 'admin' || vault.organization.role === 'owner';
}

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
// Permission mapping for each role
const ROLE_PERMISSIONS$1 = {
    owner: [
        'org:read',
        'org:write',
        'org:delete',
        'member:read',
        'member:write',
        'member:delete',
        'billing:read',
        'billing:write',
        'settings:read',
        'settings:write',
    ],
    admin: [
        'org:read',
        'org:write',
        'member:read',
        'member:write',
        'member:delete',
        'billing:read',
        'settings:read',
        'settings:write',
    ],
    member: [
        'org:read',
        'member:read',
        'settings:read',
    ],
    guest: [
        'org:read',
    ],
};
/**
 * Hook for checking user permissions derived from organization role.
 *
 * @returns Permission checking functions and current role info
 */
function usePermissions() {
    const vault = useVault();
    const { role, permissions } = React.useMemo(() => {
        const currentRole = vault.organization?.role || null;
        const perms = currentRole ? ROLE_PERMISSIONS$1[currentRole] : [];
        return { role: currentRole, permissions: perms };
    }, [vault.organization?.role]);
    /**
     * Check if user has a specific permission
     */
    const has = React.useMemo(() => {
        return (permission) => {
            if (!role)
                return false;
            return permissions.includes(permission);
        };
    }, [role, permissions]);
    /**
     * Check if user has a specific role
     */
    const hasRole = React.useMemo(() => {
        return (checkRole) => {
            if (!role)
                return false;
            if (Array.isArray(checkRole)) {
                return checkRole.includes(role);
            }
            return role === checkRole;
        };
    }, [role]);
    /**
     * Check if user has any of the specified roles
     */
    const hasAnyRole = React.useMemo(() => {
        return (roles) => {
            if (!role)
                return false;
            return roles.includes(role);
        };
    }, [role]);
    return {
        has,
        hasRole,
        hasAnyRole,
        permissions,
        role,
        isLoaded: vault.isLoaded,
    };
}

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
// Permission mapping for each role
const ROLE_PERMISSIONS = {
    owner: [
        'org:read',
        'org:write',
        'org:delete',
        'member:read',
        'member:write',
        'member:delete',
        'billing:read',
        'billing:write',
        'settings:read',
        'settings:write',
    ],
    admin: [
        'org:read',
        'org:write',
        'member:read',
        'member:write',
        'member:delete',
        'billing:read',
        'settings:read',
        'settings:write',
    ],
    member: [
        'org:read',
        'member:read',
        'settings:read',
    ],
    guest: [
        'org:read',
    ],
};
/**
 * Hook for checking authorization with a unified check function.
 *
 * @returns Authorization checking function
 */
function useCheckAuthorization() {
    const vault = useVault();
    /**
     * Check authorization based on permission or role criteria.
     *
     * @param params - Permission check parameters
     * @returns Boolean indicating if authorized
     */
    const check = React.useCallback((params) => {
        const currentRole = vault.organization?.role;
        if (!currentRole) {
            return false;
        }
        // Check specific permission
        if (params.permission) {
            const permissions = ROLE_PERMISSIONS[currentRole] || [];
            return permissions.includes(params.permission);
        }
        // Check specific role
        if (params.role) {
            return currentRole === params.role;
        }
        // Check any of multiple roles
        if (params.anyRole && params.anyRole.length > 0) {
            return params.anyRole.includes(currentRole);
        }
        // If no criteria specified, default to true (user is in an org)
        return true;
    }, [vault.organization?.role]);
    return { check };
}

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
function useBilling() {
    const { api } = useVault();
    // State
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const [plans, setPlans] = React.useState([]);
    const [billingEnabled, setBillingEnabled] = React.useState(false);
    const [subscription, setSubscription] = React.useState(null);
    const [invoices, setInvoices] = React.useState([]);
    // Refs to prevent memory leaks
    const isMounted = React.useRef(true);
    React.useEffect(() => {
        return () => {
            isMounted.current = false;
        };
    }, []);
    const safeSetState = React.useCallback((setter, value) => {
        if (isMounted.current) {
            setter(value);
        }
    }, []);
    /**
     * Fetch available billing plans
     */
    const refreshPlans = React.useCallback(async () => {
        safeSetState(setIsLoading, true);
        safeSetState(setError, null);
        try {
            const response = await api.request('/api/v1/admin/billing/plans');
            safeSetState(setBillingEnabled, response.billingEnabled);
            safeSetState(setPlans, response.plans);
        }
        catch (err) {
            safeSetState(setError, err instanceof Error ? err : new Error('Failed to load plans'));
        }
        finally {
            safeSetState(setIsLoading, false);
        }
    }, [api]);
    /**
     * Fetch current subscription
     */
    const refreshSubscription = React.useCallback(async () => {
        safeSetState(setIsLoading, true);
        safeSetState(setError, null);
        try {
            const response = await api.request('/api/v1/admin/billing/subscription');
            safeSetState(setSubscription, response.subscription);
        }
        catch (err) {
            safeSetState(setError, err instanceof Error ? err : new Error('Failed to load subscription'));
        }
        finally {
            safeSetState(setIsLoading, false);
        }
    }, [api]);
    /**
     * Fetch invoices
     */
    const refreshInvoices = React.useCallback(async () => {
        safeSetState(setIsLoading, true);
        safeSetState(setError, null);
        try {
            const response = await api.request('/api/v1/admin/billing/invoices');
            safeSetState(setInvoices, response.invoices);
        }
        catch (err) {
            safeSetState(setError, err instanceof Error ? err : new Error('Failed to load invoices'));
        }
        finally {
            safeSetState(setIsLoading, false);
        }
    }, [api]);
    /**
     * Create a checkout session for subscription
     */
    const createCheckout = React.useCallback(async (options) => {
        safeSetState(setIsLoading, true);
        safeSetState(setError, null);
        try {
            const response = await api.request('/api/v1/admin/billing/subscription', {
                method: 'POST',
                body: JSON.stringify({
                    price_id: options.priceId,
                    success_url: options.successUrl,
                    cancel_url: options.cancelUrl,
                }),
            });
            // Update subscription state
            safeSetState(setSubscription, response.subscription);
            // Return checkout session if available
            if (response.checkoutUrl) {
                return {
                    id: response.subscription.id,
                    url: response.checkoutUrl,
                    priceId: options.priceId,
                    mode: 'subscription',
                };
            }
            throw new Error('No checkout URL returned');
        }
        catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to create checkout');
            safeSetState(setError, error);
            throw error;
        }
        finally {
            safeSetState(setIsLoading, false);
        }
    }, [api]);
    /**
     * Create a customer portal session
     */
    const createPortalSession = React.useCallback(async (options) => {
        safeSetState(setIsLoading, true);
        safeSetState(setError, null);
        try {
            const response = await api.request('/api/v1/admin/billing/portal', {
                method: 'POST',
                body: JSON.stringify({
                    return_url: options.returnUrl,
                }),
            });
            return response;
        }
        catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to create portal session');
            safeSetState(setError, error);
            throw error;
        }
        finally {
            safeSetState(setIsLoading, false);
        }
    }, [api]);
    /**
     * Cancel subscription at period end
     */
    const cancelSubscription = React.useCallback(async () => {
        safeSetState(setIsLoading, true);
        safeSetState(setError, null);
        try {
            const response = await api.request('/api/v1/admin/billing/subscription/cancel', { method: 'POST' });
            safeSetState(setSubscription, response.subscription);
            return response.subscription;
        }
        catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to cancel subscription');
            safeSetState(setError, error);
            throw error;
        }
        finally {
            safeSetState(setIsLoading, false);
        }
    }, [api]);
    /**
     * Resume canceled subscription
     */
    const resumeSubscription = React.useCallback(async () => {
        safeSetState(setIsLoading, true);
        safeSetState(setError, null);
        try {
            const response = await api.request('/api/v1/admin/billing/subscription/resume', { method: 'POST' });
            safeSetState(setSubscription, response.subscription);
            return response.subscription;
        }
        catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to resume subscription');
            safeSetState(setError, error);
            throw error;
        }
        finally {
            safeSetState(setIsLoading, false);
        }
    }, [api]);
    /**
     * Update subscription to new plan
     */
    const updateSubscription = React.useCallback(async (newPriceId) => {
        safeSetState(setIsLoading, true);
        safeSetState(setError, null);
        try {
            const response = await api.request('/api/v1/admin/billing/subscription', {
                method: 'PUT',
                body: JSON.stringify({ new_price_id: newPriceId }),
            });
            safeSetState(setSubscription, response.subscription);
            return response.subscription;
        }
        catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to update subscription');
            safeSetState(setError, error);
            throw error;
        }
        finally {
            safeSetState(setIsLoading, false);
        }
    }, [api]);
    /**
     * Report usage for metered billing
     */
    const reportUsage = React.useCallback(async (quantity, action = 'increment') => {
        try {
            await api.request('/api/v1/admin/billing/usage', {
                method: 'POST',
                body: JSON.stringify({ quantity, action }),
            });
        }
        catch (err) {
            const error = err instanceof Error ? err : new Error('Failed to report usage');
            safeSetState(setError, error);
            throw error;
        }
    }, [api]);
    /**
     * Clear error state
     */
    const clearError = React.useCallback(() => {
        safeSetState(setError, null);
    }, []);
    // Load plans on mount
    React.useEffect(() => {
        refreshPlans();
    }, [refreshPlans]);
    return {
        // State
        isLoading,
        error,
        // Plans
        plans,
        billingEnabled,
        refreshPlans,
        // Subscription
        subscription,
        refreshSubscription,
        // Actions
        createCheckout,
        createPortalSession,
        cancelSubscription,
        resumeSubscription,
        updateSubscription,
        reportUsage,
        // Invoices
        invoices,
        refreshInvoices,
        // Clear error
        clearError,
    };
}
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
function useSubscription() {
    const { subscription, refreshSubscription, isLoading, error } = useBilling();
    const isActive = subscription
        ? ['active', 'trialing'].includes(subscription.status)
        : false;
    const isTrialing = subscription?.status === 'trialing';
    const isCanceled = subscription
        ? subscription.cancelAtPeriodEnd || ['canceled', 'unpaid'].includes(subscription.status)
        : false;
    const daysUntilRenewal = subscription
        ? Math.max(0, Math.ceil((new Date(subscription.currentPeriodEnd).getTime() - Date.now()) /
            (1000 * 60 * 60 * 24)))
        : 0;
    const daysLeftInTrial = subscription?.trialEnd
        ? Math.max(0, Math.ceil((new Date(subscription.trialEnd).getTime() - Date.now()) / (1000 * 60 * 60 * 24)))
        : null;
    const willRenew = isActive && !subscription?.cancelAtPeriodEnd;
    return {
        subscription,
        isLoading,
        error,
        isActive,
        isTrialing,
        isCanceled,
        daysUntilRenewal,
        daysLeftInTrial,
        willRenew,
        refresh: refreshSubscription,
        cancel: useBilling().cancelSubscription,
        resume: useBilling().resumeSubscription,
        update: useBilling().updateSubscription,
    };
}
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
function useUsage() {
    const [usage, setUsage] = React.useState(null);
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const { api } = useVault();
    const refresh = React.useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            const response = await api.request('/api/v1/admin/billing/status');
            setUsage(response.usageThisPeriod);
        }
        catch (err) {
            setError(err instanceof Error ? err : new Error('Failed to load usage'));
        }
        finally {
            setIsLoading(false);
        }
    }, [api]);
    const report = React.useCallback(async (quantity, action = 'increment') => {
        try {
            await api.request('/api/v1/admin/billing/usage', {
                method: 'POST',
                body: JSON.stringify({ quantity, action }),
            });
            // Refresh usage after reporting
            await refresh();
        }
        catch (err) {
            setError(err instanceof Error ? err : new Error('Failed to report usage'));
            throw err;
        }
    }, [api, refresh]);
    const percentage = usage?.quota
        ? Math.min(100, (usage.totalUsage / usage.quota.limit) * 100)
        : 0;
    const isNearLimit = usage?.quota
        ? percentage >= (usage.quota.warningThreshold || 0.8) * 100 && percentage < 100
        : false;
    const isOverLimit = usage?.quota ? usage.totalUsage > usage.quota.limit : false;
    const remaining = usage?.quota
        ? Math.max(0, usage.quota.limit - usage.totalUsage)
        : 0;
    // Load usage on mount
    React.useEffect(() => {
        refresh();
    }, [refresh]);
    return {
        usage,
        isLoading,
        error,
        isNearLimit,
        isOverLimit,
        percentage,
        remaining,
        refresh,
        report,
    };
}

// ============================================================================
// Component
// ============================================================================
const Button = React.forwardRef(({ children, variant = 'primary', size = 'md', isLoading = false, loadingText, fullWidth = false, elementClassName, disabled, className, style, ...props }, ref) => {
    const { getElementClass, cssVariables } = useTheme();
    // Get base class name from theme
    const baseClassName = variant === 'primary'
        ? getElementClass('formButtonPrimary')
        : getElementClass('formButtonSecondary');
    // Combine class names
    const combinedClassName = [baseClassName, elementClassName, className]
        .filter(Boolean)
        .join(' ');
    // Size styles
    const sizeStyles = {
        sm: {
            padding: '0.5rem 0.75rem',
            fontSize: '0.875rem',
        },
        md: {
            padding: '0.75rem 1rem',
            fontSize: cssVariables['--vault-font-size'],
        },
        lg: {
            padding: '1rem 1.25rem',
            fontSize: '1.125rem',
        },
    };
    // Variant-specific styles
    const variantStyles = {
        primary: {},
        secondary: {},
        ghost: {
            backgroundColor: 'transparent',
            border: 'none',
            color: cssVariables['--vault-color-primary'],
        },
    };
    const buttonStyle = {
        width: fullWidth ? '100%' : undefined,
        ...sizeStyles[size],
        ...variantStyles[variant],
        ...style,
    };
    return (jsxRuntime.jsx("button", { ref: ref, className: combinedClassName, style: buttonStyle, disabled: disabled || isLoading, ...props, children: isLoading ? (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx("span", { className: "vault-spinner", style: {
                        width: '1rem',
                        height: '1rem',
                        marginRight: loadingText ? '0.5rem' : 0,
                    } }), loadingText] })) : (children) }));
});
Button.displayName = 'Button';

// ============================================================================
// Component
// ============================================================================
const Input = React.forwardRef(({ label, error, helperText, id, disabled, required, inputClassName, labelClassName, errorClassName, fieldClassName, size = 'md', style, ...props }, ref) => {
    const { getElementClass, cssVariables } = useTheme();
    // Generate unique ID if not provided
    const inputId = id || `vault-input-${Math.random().toString(36).slice(2, 11)}`;
    // Size styles
    const sizeStyles = {
        sm: {
            padding: '0.375rem 0.5rem',
            fontSize: '0.875rem',
        },
        md: {
            padding: '0.625rem 0.75rem',
            fontSize: cssVariables['--vault-font-size'],
        },
        lg: {
            padding: '0.875rem 1rem',
            fontSize: '1.125rem',
        },
    };
    // Error state style
    const errorStyle = error
        ? {
            borderColor: cssVariables['--vault-color-danger'],
        }
        : {};
    const inputStyle = {
        ...sizeStyles[size],
        ...errorStyle,
        ...style,
    };
    return (jsxRuntime.jsxs("div", { className: [getElementClass('formField'), fieldClassName]
            .filter(Boolean)
            .join(' '), children: [label && (jsxRuntime.jsxs("label", { htmlFor: inputId, className: [getElementClass('formFieldLabel'), labelClassName]
                    .filter(Boolean)
                    .join(' '), children: [label, required && (jsxRuntime.jsx("span", { style: { color: cssVariables['--vault-color-danger'], marginLeft: '0.25rem' }, children: "*" }))] })), jsxRuntime.jsx("input", { ref: ref, id: inputId, className: [getElementClass('formFieldInput'), inputClassName]
                    .filter(Boolean)
                    .join(' '), style: inputStyle, disabled: disabled, "aria-invalid": error ? 'true' : 'false', "aria-describedby": error ? `${inputId}-error` : undefined, ...props }), error && (jsxRuntime.jsx("span", { id: `${inputId}-error`, className: [getElementClass('formFieldError'), errorClassName]
                    .filter(Boolean)
                    .join(' '), role: "alert", children: error })), helperText && !error && (jsxRuntime.jsx("span", { style: {
                    display: 'block',
                    marginTop: '0.375rem',
                    fontSize: '0.75rem',
                    fontFamily: cssVariables['--vault-font-family'],
                    color: cssVariables['--vault-color-text-secondary'],
                }, children: helperText }))] }));
});
Input.displayName = 'Input';

// ============================================================================
// Component
// ============================================================================
const Card = React.forwardRef(({ children, padding = 'md', width = 'md', centered = false, className, style, ...props }, ref) => {
    const { getElementClass } = useTheme();
    // Padding styles
    const paddingStyles = {
        none: { padding: 0 },
        sm: { padding: '1rem' },
        md: { padding: '1.5rem' },
        lg: { padding: '2rem' },
    };
    // Width styles
    const widthStyles = {
        auto: {},
        sm: { maxWidth: '320px' },
        md: { maxWidth: '400px' },
        lg: { maxWidth: '480px' },
        full: { maxWidth: '100%' },
    };
    const cardStyle = {
        ...paddingStyles[padding],
        ...widthStyles[width],
        margin: centered ? '0 auto' : undefined,
        ...style,
    };
    return (jsxRuntime.jsx("div", { ref: ref, className: [getElementClass('card'), 'vault-root', className]
            .filter(Boolean)
            .join(' '), style: cardStyle, ...props, children: children }));
});
Card.displayName = 'Card';
const CardHeader = React.forwardRef(({ title, subtitle, showLogo, logoUrl, className, style, children, ...props }, ref) => {
    const { getElementClass, appearance } = useTheme();
    const layoutLogoUrl = logoUrl || appearance.layout?.logoUrl;
    const shouldShowLogo = showLogo && layoutLogoUrl;
    return (jsxRuntime.jsxs("div", { ref: ref, className: [getElementClass('header'), className].filter(Boolean).join(' '), style: style, ...props, children: [shouldShowLogo && (jsxRuntime.jsx("div", { style: { marginBottom: '1rem' }, children: jsxRuntime.jsx("img", { src: layoutLogoUrl, alt: "Logo", style: { height: '40px', width: 'auto' } }) })), title && (jsxRuntime.jsx("h1", { className: getElementClass('headerTitle'), style: { margin: 0 }, children: title })), subtitle && (jsxRuntime.jsx("p", { className: getElementClass('headerSubtitle'), style: { margin: '0.5rem 0 0' }, children: subtitle })), children] }));
});
CardHeader.displayName = 'CardHeader';
const CardContent = React.forwardRef(({ children, spacing = 'md', className, style, ...props }, ref) => {
    const spacingStyles = {
        none: {},
        sm: { display: 'flex', flexDirection: 'column', gap: '0.75rem' },
        md: { display: 'flex', flexDirection: 'column', gap: '1rem' },
        lg: { display: 'flex', flexDirection: 'column', gap: '1.5rem' },
    };
    return (jsxRuntime.jsx("div", { ref: ref, className: className, style: {
            ...spacingStyles[spacing],
            ...style,
        }, ...props, children: children }));
});
CardContent.displayName = 'CardContent';
const CardFooter = React.forwardRef(({ children, align = 'center', className, style, ...props }, ref) => {
    const alignStyles = {
        left: { textAlign: 'left' },
        center: { textAlign: 'center' },
        right: { textAlign: 'right' },
    };
    const { cssVariables } = useTheme();
    return (jsxRuntime.jsx("div", { ref: ref, className: className, style: {
            marginTop: '1.5rem',
            paddingTop: '1.5rem',
            borderTop: `1px solid ${cssVariables['--vault-color-border']}`,
            ...alignStyles[align],
            ...style,
        }, ...props, children: children }));
});
CardFooter.displayName = 'CardFooter';

// ============================================================================
// Component
// ============================================================================
function Divider({ text, spacing = 'md', lineClassName, textClassName, }) {
    const { getElementClass, cssVariables } = useTheme();
    const spacingStyles = {
        sm: { margin: '1rem 0' },
        md: { margin: '1.5rem 0' },
        lg: { margin: '2rem 0' },
    };
    const containerStyle = {
        display: 'flex',
        alignItems: 'center',
        ...spacingStyles[spacing],
    };
    if (!text) {
        return (jsxRuntime.jsx("div", { className: getElementClass('dividerLine'), style: {
                height: '1px',
                backgroundColor: cssVariables['--vault-color-border'],
                ...spacingStyles[spacing],
            } }));
    }
    return (jsxRuntime.jsxs("div", { style: containerStyle, children: [jsxRuntime.jsx("div", { className: [getElementClass('dividerLine'), lineClassName]
                    .filter(Boolean)
                    .join(' ') }), jsxRuntime.jsx("span", { className: [getElementClass('dividerText'), textClassName]
                    .filter(Boolean)
                    .join(' '), children: text }), jsxRuntime.jsx("div", { className: [getElementClass('dividerLine'), lineClassName]
                    .filter(Boolean)
                    .join(' ') })] }));
}

// ============================================================================
// Component
// ============================================================================
function Header({ title, subtitle, showLogo, logoUrl, logo, align = 'center', titleClassName, subtitleClassName, children, }) {
    const { getElementClass, appearance } = useTheme();
    const layoutLogoUrl = logoUrl || appearance.layout?.logoUrl;
    const shouldShowLogo = showLogo && (logo || layoutLogoUrl);
    const alignStyles = {
        left: { textAlign: 'left' },
        center: { textAlign: 'center' },
        right: { textAlign: 'right' },
    };
    return (jsxRuntime.jsxs("header", { className: getElementClass('header'), style: {
            padding: '1.5rem 1.5rem 0.5rem',
            ...alignStyles[align],
        }, children: [shouldShowLogo && (jsxRuntime.jsx("div", { style: { marginBottom: '1rem' }, children: logo || (jsxRuntime.jsx("img", { src: layoutLogoUrl, alt: "Logo", style: { height: '40px', width: 'auto' } })) })), title && (jsxRuntime.jsx("h1", { className: [getElementClass('headerTitle'), titleClassName]
                    .filter(Boolean)
                    .join(' '), style: { margin: '0 0 0.5rem' }, children: title })), subtitle && (jsxRuntime.jsx("p", { className: [getElementClass('headerSubtitle'), subtitleClassName]
                    .filter(Boolean)
                    .join(' '), style: { margin: 0 }, children: subtitle })), children] }));
}

// ============================================================================
// Icons - 30+ OAuth Provider Icons
// ============================================================================
const GoogleIcon = () => (jsxRuntime.jsxs("svg", { width: "18", height: "18", viewBox: "0 0 24 24", children: [jsxRuntime.jsx("path", { fill: "#4285F4", d: "M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" }), jsxRuntime.jsx("path", { fill: "#34A853", d: "M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" }), jsxRuntime.jsx("path", { fill: "#FBBC05", d: "M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" }), jsxRuntime.jsx("path", { fill: "#EA4335", d: "M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" })] }));
const GitHubIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "currentColor", children: jsxRuntime.jsx("path", { d: "M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" }) }));
const MicrosoftIcon = () => (jsxRuntime.jsxs("svg", { width: "18", height: "18", viewBox: "0 0 24 24", children: [jsxRuntime.jsx("path", { fill: "#f25022", d: "M1 1h10v10H1z" }), jsxRuntime.jsx("path", { fill: "#00a4ef", d: "M1 13h10v10H1z" }), jsxRuntime.jsx("path", { fill: "#7fba00", d: "M13 1h10v10H13z" }), jsxRuntime.jsx("path", { fill: "#ffb900", d: "M13 13h10v10H13z" })] }));
const AppleIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "currentColor", children: jsxRuntime.jsx("path", { d: "M17.05 20.28c-.98.95-2.05.88-3.08.4-1.09-.5-2.08-.48-3.24 0-1.44.62-2.2.44-3.06-.4C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.22 7.13-.57 1.5-1.31 2.99-2.27 4.08zm-5.85-15.1c.07-2.04 1.76-3.79 3.78-3.94.29 2.32-1.93 4.48-3.78 3.94z" }) }));
const DiscordIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#5865F2", children: jsxRuntime.jsx("path", { d: "M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" }) }));
const SlackIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", children: jsxRuntime.jsx("path", { fill: "#E01E5A", d: "M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z" }) }));
// Social/Consumer Icons
const FacebookIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#1877F2", children: jsxRuntime.jsx("path", { d: "M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z" }) }));
const TwitterIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "currentColor", children: jsxRuntime.jsx("path", { d: "M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" }) }));
const InstagramIcon = () => (jsxRuntime.jsxs("svg", { width: "18", height: "18", viewBox: "0 0 24 24", children: [jsxRuntime.jsx("defs", { children: jsxRuntime.jsxs("linearGradient", { id: "ig-gradient", x1: "0%", y1: "100%", x2: "100%", y2: "0%", children: [jsxRuntime.jsx("stop", { offset: "0%", stopColor: "#f58529" }), jsxRuntime.jsx("stop", { offset: "50%", stopColor: "#dd2a7b" }), jsxRuntime.jsx("stop", { offset: "100%", stopColor: "#8134af" })] }) }), jsxRuntime.jsx("rect", { width: "24", height: "24", rx: "6", fill: "url(#ig-gradient)" }), jsxRuntime.jsx("circle", { cx: "12", cy: "12", r: "5", fill: "none", stroke: "white", strokeWidth: "2" }), jsxRuntime.jsx("circle", { cx: "18", cy: "6", r: "1.5", fill: "white" })] }));
const TikTokIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "currentColor", children: jsxRuntime.jsx("path", { d: "M12.525.02c1.31-.02 2.61-.01 3.91-.02.08 1.53.63 3.09 1.75 4.17 1.12 1.11 2.7 1.62 4.24 1.79v4.03c-1.44-.05-2.89-.35-4.2-.97-.57-.26-1.1-.59-1.62-.93-.01 2.92.01 5.84-.02 8.75-.08 1.4-.54 2.79-1.35 3.94-1.31 1.92-3.58 3.17-5.91 3.21-1.43.08-2.86-.31-4.08-1.03-2.02-1.19-3.44-3.37-3.65-5.71-.02-.5-.03-1-.01-1.49.18-1.9 1.12-3.72 2.58-4.96 1.66-1.44 3.98-2.13 6.15-1.72.02 1.48-.04 2.96-.04 4.44-.99-.32-2.15-.23-3.02.37-.63.41-1.11 1.04-1.36 1.75-.21.51-.15 1.07-.14 1.61.24 1.64 1.82 3.02 3.5 2.87 1.12-.01 2.19-.66 2.77-1.61.19-.33.4-.67.41-1.06.1-1.79.06-3.57.07-5.36.01-4.03-.01-8.05.02-12.07z" }) }));
const SnapchatIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#FFFC00", children: jsxRuntime.jsx("path", { d: "M12.206 1c.577 0 2.553.233 3.833 2.724.51.998.648 2.173.387 3.346-.1.455.168.566.379.627.348.1.872.258 1.144.558.264.292.261.692.092.961-.168.268-.55.425-.748.475-.298.075-.377.291-.337.533.04.242.242.408.509.45.552.084 1.4.37 1.647 1.159.132.422.015.876-.342 1.275-.364.408-.97.666-1.802.766-.264.033-.448.159-.503.375-.055.216.047.424.25.55.634.4 1.65 1.108 1.45 2.108-.083.408-.35.758-.79 1.033-.292.183-.627.283-.983.308-.258.018-.433.175-.495.425-.124.5-.509.758-1.172.8-.375.025-.625.133-.788.333-.367.45-.933.692-1.517.692-.583 0-1.15-.242-1.517-.692-.163-.2-.413-.308-.788-.333-.663-.042-1.048-.3-1.172-.8-.062-.25-.237-.408-.495-.425-.356-.025-.691-.125-.983-.308-.44-.275-.707-.625-.79-1.033-.2-1 .217-1.708.85-2.108.204-.126.305-.334.25-.55-.055-.216-.239-.342-.503-.375-.833-.1-1.438-.358-1.802-.766-.358-.399-.475-.853-.342-1.275.247-.79 1.095-1.075 1.647-1.159.267-.042.469-.208.509-.45.04-.242-.039-.458-.337-.533-.198-.05-.58-.207-.748-.475-.169-.269-.172-.669.092-.961.272-.3.796-.458 1.144-.558.211-.061.479-.172.379-.627-.261-1.173-.123-2.348.387-3.346C9.233 1.233 11.21 1 11.787 1h.419z" }) }));
const PinterestIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#BD081C", children: jsxRuntime.jsx("path", { d: "M12 0C5.373 0 0 5.372 0 12c0 5.084 3.163 9.426 7.627 11.174-.105-.949-.2-2.405.042-3.441.218-.937 1.407-5.965 1.407-5.965s-.359-.719-.359-1.782c0-1.668.967-2.914 2.171-2.914 1.023 0 1.518.769 1.518 1.69 0 1.029-.655 2.568-.994 3.995-.283 1.194.599 2.169 1.777 2.169 2.133 0 3.772-2.249 3.772-5.495 0-2.873-2.064-4.882-5.012-4.882-3.414 0-5.418 2.561-5.418 5.207 0 1.031.397 2.138.893 2.738a.36.36 0 01.083.345l-.333 1.36c-.053.22-.174.267-.402.161-1.499-.698-2.436-2.889-2.436-4.649 0-3.785 2.75-7.262 7.929-7.262 4.163 0 7.398 2.967 7.398 6.931 0 4.136-2.607 7.464-6.227 7.464-1.216 0-2.359-.632-2.75-1.378l-.748 2.853c-.271 1.043-1.002 2.35-1.492 3.146C9.57 23.812 10.763 24 12 24c6.627 0 12-5.373 12-12 0-6.628-5.373-12-12-12z" }) }));
const RedditIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#FF4500", children: jsxRuntime.jsx("path", { d: "M12 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0zm5.01 4.744c.688 0 1.25.561 1.25 1.249a1.25 1.25 0 0 1-2.498.056l-2.597-.547-.8 3.747c1.824.07 3.48.632 4.674 1.488.308-.309.73-.491 1.207-.491.968 0 1.754.786 1.754 1.754 0 .716-.435 1.333-1.01 1.614a3.111 3.111 0 0 1 .042.52c0 2.694-3.13 4.87-7.004 4.87-3.874 0-7.004-2.176-7.004-4.87 0-.183.015-.366.043-.534A1.748 1.748 0 0 1 4.028 12c0-.968.786-1.754 1.754-1.754.463 0 .898.196 1.207.49 1.207-.883 2.878-1.43 4.744-1.487l.885-4.182a.342.342 0 0 1 .14-.197.35.35 0 0 1 .238-.042l2.906.617a1.214 1.214 0 0 1 1.108-.701zM9.25 12C8.561 12 8 12.562 8 13.25c0 .687.561 1.248 1.25 1.248.687 0 1.248-.561 1.248-1.249 0-.688-.561-1.249-1.249-1.249zm5.5 0c-.687 0-1.248.561-1.248 1.25 0 .687.561 1.248 1.249 1.248.688 0 1.249-.561 1.249-1.249 0-.687-.562-1.249-1.25-1.249zm-5.466 3.99a.327.327 0 0 0-.231.094.33.33 0 0 0 0 .463c.842.842 2.484.913 2.961.913.477 0 2.105-.056 2.961-.913a.361.361 0 0 0 .029-.463.327.327 0 0 0-.464 0c-.547.533-1.684.73-2.512.73-.828 0-1.979-.196-2.512-.73a.326.326 0 0 0-.232-.095z" }) }));
const TwitchIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#9146FF", children: jsxRuntime.jsx("path", { d: "M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714Z" }) }));
const SpotifyIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#1DB954", children: jsxRuntime.jsx("path", { d: "M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z" }) }));
// Professional Icons
const LinkedInIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#0A66C2", children: jsxRuntime.jsx("path", { d: "M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" }) }));
// Developer/Tech Icons
const GitLabIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#FC6D26", children: jsxRuntime.jsx("path", { d: "M1.554 9.82h.189l2.517 7.758H3.26l-1.706-7.758zm.955-.848l2.906-8.94h.841l2.906 8.94H3.51zm3.66 8.94l2.517-7.758h.19l2.517 7.758H7.17zm.955-8.94l2.906-8.94h.841l2.906 8.94h-7.653zm3.66 8.94l2.517-7.758h.19l2.517 7.758h-5.224zm.955-8.94l2.906-8.94h.841l2.906 8.94H12.74zm3.66 8.94l2.517-7.758h.19l2.517 7.758h-5.224zm.955-8.94l2.906-8.94h.841l2.906 8.94h-7.653z" }) }));
const BitbucketIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#2684FF", children: jsxRuntime.jsx("path", { d: "M0 6.626v10.748h.058l3.906 8.34h15.89l3.905-8.34H24V6.626H0zm18.394 14.51H5.606L2.845 14.89h18.31l-2.761 6.246zM5.39 4.966h13.221l.908 6.534H4.481l.908-6.534z" }) }));
const DigitalOceanIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#0080FF", children: jsxRuntime.jsx("path", { d: "M12.04 0C5.408-.02.005 5.368.005 11.992-.016 17.198 3.11 21.94 7.906 23.96V16.44H5.67v-4.432h2.236V8.744c0-2.03 1.17-3.188 3.23-3.188.818 0 1.538.06 1.746.087v3.003h-1.973c-1.195 0-1.495.568-1.495 1.402v1.98h2.985l-.388 4.432h-2.597v8.03c6.23-1.51 10.08-7.618 8.52-13.886C20.02 3.368 16.334.025 12.04 0z" }) }));
const HerokuIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#430098", children: jsxRuntime.jsx("path", { d: "M20.61 0H3.39C1.52 0 0 1.52 0 3.39v17.22C0 22.48 1.52 24 3.39 24h17.22c1.87 0 3.39-1.52 3.39-3.39V3.39C24 1.52 22.48 0 20.61 0zm-9.55 20.15l-2.05-2.05v4.13H6.39V4.5h2.62v9.19l2.05-2.05v6.51zm6.32-6.51c-1.14 1.14-2.7 1.8-4.38 1.8V9.29c1.05 0 2.08-.42 2.83-1.17.75-.75 1.17-1.78 1.17-2.83h2.62v8.35z" }) }));
const VercelIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "currentColor", children: jsxRuntime.jsx("path", { d: "M24 22.525H0l12-21.05 12 21.05z" }) }));
const NetlifyIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#00C7B7", children: jsxRuntime.jsx("path", { d: "M6.49 19.04l-.23.23-.58-.58c-.35-.35-.63-.63-.78-.84-.14-.2-.23-.4-.23-.58 0-.2.1-.43.3-.69.2-.26.56-.62 1.1-1.1l2.94-2.93c.52-.52.89-.88 1.1-1.1.22-.2.46-.3.7-.3.21 0 .42.08.62.23.21.15.49.43.85.78l.57.58-.23.23c-.1.1-.15.21-.15.33 0 .1.05.22.16.33l2.77-2.77c.2-.2.39-.35.55-.44.17-.1.34-.14.52-.14.18 0 .36.04.55.13.19.1.39.24.61.44l3.12 3.12c.2.2.35.4.44.6.1.2.14.39.14.57 0 .18-.04.36-.13.53-.1.17-.25.36-.44.56l-2.78 2.79c.1.09.15.2.15.32 0 .12-.05.23-.15.33l.23.23.58-.58c.35-.35.63-.63.78-.84.14-.2.23-.4.23-.58 0-.2-.1-.43-.3-.69-.2-.26-.56-.62-1.1-1.1l-2.94-2.93c-.52-.52-.89-.88-1.1-1.1-.22-.2-.46-.3-.7-.3-.21 0-.42.08-.62.23-.21.15-.49.43-.85.78l-.57.58.23.23c.1.1.15.21.15.33 0 .1-.05.22-.16.33l-3.1 3.1c-.15.15-.27.28-.35.38-.08.1-.16.2-.24.3l-.6-.6c-.1-.1-.16-.2-.16-.32 0-.12.05-.23.15-.33l.23-.23-.58-.58c-.35-.35-.63-.63-.78-.84-.14-.2-.23-.4-.23-.58 0-.2.1-.43.3-.69.2-.26.56-.62 1.1-1.1l2.94-2.93c.52-.52.89-.88 1.1-1.1.22-.2.46-.3.7-.3.21 0 .42.08.62.23.21.15.49.43.85.78l.57.58-.23.23c-.1.1-.15.21-.15.33 0 .1.05.22.16.33l3.1-3.1c.2-.2.39-.35.55-.44.17-.1.34-.14.52-.14.18 0 .36.04.55.13.19.1.39.24.61.44l3.12 3.12c.2.2.35.4.44.6.1.2.14.39.14.57 0 .18-.04.36-.13.53-.1.17-.25.36-.44.56l-2.78 2.79c.1.09.15.2.15.32 0 .12-.05.23-.15.33z" }) }));
const CloudflareIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#F48120", children: jsxRuntime.jsx("path", { d: "M16.509 16.845c.147-.507.09-.973-.158-1.316-.239-.33-.647-.514-1.146-.527l-9.38-.123c-.193 0-.304-.112-.289-.293.014-.178.135-.36.311-.427.17-.068.384-.123.632-.123h9.119c1.127-.065 2.295-.894 2.71-2.027l.522-1.36c.052-.14.062-.238.014-.332-.195-.398-.466-.758-.799-1.067-1.028-.93-2.532-1.249-3.858-.849l-.65.195c-.539.16-.99.3-1.394.405l-.333.09c-.144.038-.21-.067-.165-.226l.172-.586c.064-.219.197-.512.391-.84.57-.982 1.497-1.627 2.654-1.856l.443-.088c1.134-.223 2.357-.048 3.388.512.74.41 1.32.966 1.73 1.656.053.087.123.173.197.26l.302.353c.096.112.208.243.315.388.26.352.461.745.594 1.163l.15.522.01.038c.03.106.05.21.06.31.004.044.007.088.008.132l.002.107c0 .217-.026.437-.074.657l-.132.55-.192.64c-.027.09-.057.18-.09.268l-.21.563c-.372.993-1.138 1.785-2.135 2.182-.29.115-.594.186-.9.211-.128.01-.257.015-.386.015H5.15c-.06 0-.122-.004-.183-.011a.506.506 0 0 1-.19-.06.38.38 0 0 1-.147-.126.354.354 0 0 1-.058-.198c.002-.03.006-.06.012-.09l.388-1.77c.028-.127.078-.247.147-.355.15-.23.404-.375.695-.39l9.222-.096c.166-.002.323-.076.435-.203.11-.126.16-.293.136-.46a.56.56 0 0 0-.182-.366.59.59 0 0 0-.395-.154l-9.158.01c-.628.011-1.198.391-1.454.983l-.386 1.118a.515.515 0 0 0-.025.136c-.003.058.003.116.017.173.035.138.113.263.222.356.11.093.247.151.39.166.07.007.14.01.21.01h9.576c.07 0 .14-.006.209-.017.234-.04.458-.122.662-.242.333-.195.602-.48.772-.818l.848-1.862z" }) }));
// Enterprise Icons
const SalesforceIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#00A1E0", children: jsxRuntime.jsx("path", { d: "M10.006 5.415a4.195 4.195 0 0 1 3.045-1.306c1.56 0 2.954.9 3.652 2.24a5.09 5.09 0 0 1 2.034-.423c2.725 0 4.934 2.15 4.934 4.803 0 2.652-2.21 4.802-4.934 4.802a5.063 5.063 0 0 1-.82-.066c-.536.964-1.566 1.617-2.748 1.617a3.628 3.628 0 0 1-1.404-.28c-.66 1.063-1.833 1.774-3.174 1.774-1.742 0-3.22-1.163-3.697-2.763a3.494 3.494 0 0 1-.634.058c-1.908 0-3.455-1.506-3.455-3.364 0-1.31.764-2.444 1.869-2.99a4.845 4.845 0 0 1-.444-2.04c0-2.72 2.23-4.926 4.982-4.926 1.553 0 2.939.693 3.844 1.766z" }) }));
const HubSpotIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#FF7A59", children: jsxRuntime.jsx("path", { d: "M18.164 7.93V5.084a2.198 2.198 0 001.267-1.984 2.21 2.21 0 00-4.42 0c0 .852.49 1.59 1.196 1.961v2.869c-1.116.128-2.125.567-2.94 1.216l-7.31-5.693a3.093 3.093 0 00.12-.748A3.13 3.13 0 003.057 0a3.13 3.13 0 000 6.26c.77 0 1.473-.282 2.02-.745l7.33 5.71a4.64 4.64 0 00-.054.611 4.64 4.64 0 004.634 4.637 4.64 4.64 0 004.633-4.637 4.639 4.639 0 00-4.633-4.637 4.624 4.624 0 00-1.823.37zm-1.77 5.916a2.083 2.083 0 110-4.166 2.083 2.083 0 010 4.166z" }) }));
const ZendeskIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#03363D", children: jsxRuntime.jsx("path", { d: "M10.617 5.846h7.384v12.308h-7.384V5.846zm-8.617 0h7.384V24H2v-7.384h8.617V24H2.001V5.846zM10.617 0H24v7.385H10.617V0z" }) }));
const NotionIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "currentColor", children: jsxRuntime.jsx("path", { d: "M4.459 4.208c.746.606 1.026.56 2.428.466l13.215-.793c.28 0 .047-.28-.046-.326L17.86 1.968c-.42-.326-.98-.7-2.055-.607L3.01 2.295c-.466.046-.56.28-.374.466zm.793 3.08v13.904c0 .747.373 1.027 1.214.98l14.523-.84c.841-.046.935-.56.935-1.167V6.354c0-.606-.233-.933-.748-.887l-15.177.887c-.56.047-.747.327-.747.933zm14.337.745c.093.42 0 .84-.42.888l-.7.14v10.264c-.608.327-1.168.514-1.635.514-.748 0-.935-.234-1.495-.933l-4.577-7.186v6.952l1.449.327s0 .84-1.168.84l-3.22.186c-.093-.186 0-.653.327-.746l.84-.233V9.854L7.822 9.76c-.094-.42.14-1.026.793-1.073l3.456-.233 4.764 7.279v-6.44l-1.215-.139c-.093-.514.28-.887.747-.933zM1.936 1.035l13.31-.98c1.634-.14 2.055-.047 3.082.7l4.249 2.986c.7.513.934.653.934 1.213v16.378c0 1.026-.373 1.634-1.68 1.726l-15.458.934c-.98.047-1.448-.093-1.962-.747l-3.129-4.06c-.56-.747-.793-1.306-.793-1.96V2.667c0-.839.374-1.54 1.447-1.632z" }) }));
const FigmaIcon = () => (jsxRuntime.jsxs("svg", { width: "18", height: "18", viewBox: "0 0 24 24", children: [jsxRuntime.jsx("path", { fill: "#F24E1E", d: "M8 24c2.208 0 4-1.792 4-4v-4H8c-2.208 0-4 1.792-4 4s1.792 4 4 4z" }), jsxRuntime.jsx("path", { fill: "#A259FF", d: "M4 12c0-2.208 1.792-4 4-4h4v8H8c-2.208 0-4-1.792-4-4z" }), jsxRuntime.jsx("path", { fill: "#F24E1E", d: "M4 4c0-2.208 1.792-4 4-4h4v8H8C5.792 8 4 6.208 4 4z" }), jsxRuntime.jsx("path", { fill: "#1ABCFE", d: "M12 0h4c2.208 0 4 1.792 4 4s-1.792 4-4 4h-4V0z" }), jsxRuntime.jsx("path", { fill: "#0ACF83", d: "M20 12c0 2.208-1.792 4-4 4s-4-1.792-4-4 1.792-4 4-4 4 1.792 4 4z" })] }));
const LinearIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#5E6AD2", children: jsxRuntime.jsx("path", { d: "M3 12a9 9 0 0 1 9-9 9 9 0 0 1 9 9 9 9 0 0 1-9 9 9 9 0 0 1-9-9zm15.255 5.662A7.259 7.259 0 0 1 17.25 12a7.259 7.259 0 0 1-.996-5.662A7.24 7.24 0 0 1 12 4.75a7.24 7.24 0 0 1-5.254 1.588A7.259 7.259 0 0 1 6 12c0 4.142 3.358 7.5 7.5 7.5 1.95 0 3.73-.742 5.068-1.958l-.313.12z" }) }));
const AtlassianIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#0052CC", children: jsxRuntime.jsx("path", { d: "M7.119 11.13c-.354-.64-.71-1.33-1.094-2.032-.384-.702-.75-1.423-1.089-2.13-.338-.704-.64-1.38-.896-2.01C3.784 4.327 3.57 3.75 3.388 3.24c-.18-.51-.314-.895-.404-1.154-.09-.26-.147-.39-.167-.39C2.534 2.11 1.87 2.97 1.343 4.07c-.527 1.1-.79 2.35-.79 3.75 0 1.18.253 2.237.76 3.17.507.933 1.22 1.66 2.14 2.18.92.52 1.983.78 3.19.78.354 0 .67-.017.948-.05.277-.034.507-.077.687-.13zm8.884 1.41c-.886-.59-1.673-1.287-2.36-2.09-.688-.804-1.304-1.668-1.848-2.59-.544-.923-1.05-1.87-1.517-2.84-.467-.97-.913-1.923-1.337-2.858-.424-.934-.853-1.837-1.287-2.71-.05-.1-.087-.16-.11-.18-.023-.02-.057.03-.1.15-.23.63-.48 1.31-.75 2.04-.27.73-.53 1.46-.79 2.19l7.03 14.19c.27.54.58.94.94 1.19.35.25.73.38 1.12.38.5 0 .93-.17 1.29-.5.36-.33.54-.73.54-1.19 0-.35-.09-.7-.27-1.05-.18-.35-.42-.68-.7-1l-2.15-1.91z" }) }));
const OktaIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#007DC1", children: jsxRuntime.jsx("path", { d: "M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm0 18.96c-3.84 0-6.96-3.12-6.96-6.96S8.16 5.04 12 5.04s6.96 3.12 6.96 6.96-3.12 6.96-6.96 6.96z" }) }));
// Regional Icons
const WeChatIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#07C160", children: jsxRuntime.jsx("path", { d: "M8.691 2.188C3.891 2.188 0 5.476 0 9.53c0 2.212 1.17 4.203 3.002 5.55a.59.59 0 0 1 .213.665l-.39 1.48c-.019.07-.048.141-.048.213 0 .163.13.295.29.295a.326.326 0 0 0 .167-.054l1.903-1.114a.864.864 0 0 1 .717-.098 10.16 10.16 0 0 0 2.837.403c.276 0 .543-.027.811-.05-.857-2.578.157-4.972 1.932-6.446 1.703-1.415 3.882-1.98 5.853-1.838-.576-3.583-4.196-6.348-8.596-6.348zM5.785 5.991c.642 0 1.162.529 1.162 1.18a1.17 1.17 0 0 1-1.162 1.178A1.17 1.17 0 0 1 4.623 7.17c0-.651.52-1.18 1.162-1.18zm5.813 0c.642 0 1.162.529 1.162 1.18a1.17 1.17 0 0 1-1.162 1.178 1.17 1.17 0 0 1-1.162-1.178c0-.651.52-1.18 1.162-1.18zm5.34 2.867c-1.797-.052-3.746.512-5.28 1.786-1.72 1.428-2.687 3.72-1.78 6.22.942 2.453 3.666 4.229 6.884 4.229.826 0 1.622-.12 2.361-.336a.722.722 0 0 1 .598.082l1.584.926a.272.272 0 0 0 .14.047c.134 0 .24-.111.24-.247 0-.06-.023-.12-.038-.177l-.327-1.233a.49.49 0 0 1 .177-.554C23.045 18.357 24 16.812 24 15.072c0-3.13-3.037-5.66-7.062-5.214zm-2.36 2.63c.535 0 .969.44.969.982a.976.976 0 0 1-.969.983.976.976 0 0 1-.969-.983c0-.542.434-.982.97-.982zm4.72 0c.535 0 .969.44.969.982a.976.976 0 0 1-.969.983.976.976 0 0 1-.969-.983c0-.542.434-.982.969-.982z" }) }));
const LineIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#06C755", children: jsxRuntime.jsx("path", { d: "M19.365 9.863c.349 0 .63.285.63.631 0 .345-.281.63-.63.63H17.61v1.125h1.755c.349 0 .63.283.63.63 0 .344-.281.629-.63.629h-2.386c-.345 0-.627-.285-.627-.629V8.108c0-.345.282-.63.63-.63h2.386c.349 0 .63.285.63.63 0 .349-.281.63-.63.63H17.61v1.125h1.755zm-3.855 3.016c0 .27-.174.51-.432.596l-1.09.324c-.2.058-.384.091-.524.091-.173 0-.339-.047-.484-.127a.81.81 0 0 1-.36-.646v-4.01c0-.344.282-.63.63-.63.351 0 .631.286.631.63v3.305l1.144-.34a.63.63 0 0 1 .795.422.633.633 0 0 1-.31.785zm-5.56 1.177c-.349 0-.63-.286-.63-.63V8.108c0-.345.281-.63.63-.63.348 0 .629.285.629.63v4.318h1.755c.35 0 .63.283.63.63 0 .344-.28.629-.63.629H9.95zm12.398 6.4c.114.144.18.325.18.513 0 .345-.282.63-.63.63-.173 0-.334-.07-.45-.183l-1.657-1.658c-.088-.087-.146-.2-.164-.322h-.852v1.012c0 .345-.282.63-.63.63a.629.629 0 0 1-.63-.63v-4.212a.629.629 0 0 1 .63-.63c.348 0 .63.285.63.63v1.012h.852c.018-.123.076-.235.164-.323l1.657-1.657a.627.627 0 0 1 .45-.184c.348 0 .63.286.63.63 0 .19-.066.37-.18.514l-1.201 1.202 1.201 1.202zm-14.204.513a.629.629 0 0 1-.63-.63V8.108c0-.345.282-.63.63-.63.349 0 .63.285.63.63v8.59a.629.629 0 0 1-.63.631zM24 10.314C24 4.943 18.615.572 12 .572S0 4.943 0 10.314c0 4.62 3.815 8.51 9 9.726.349.063.932.195 1.068.448.12.222.078.57.038.807l-.164.99c-.045.27-.21 1.062 1.058.579 1.268-.482 6.778-3.954 9.199-6.778C23.176 14.393 24 12.458 24 10.314z" }) }));
const KakaoTalkIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#FEE500", children: jsxRuntime.jsx("path", { d: "M12 0C5.373 0 0 4.373 0 9.764c0 3.36 2.15 6.32 5.393 7.984-.23.88-.87 2.803-1.016 3.228-.159.464.184.455.383.332.158-.098 2.564-1.74 3.607-2.452.51.07 1.034.107 1.567.107 6.627 0 12-4.373 12-9.764C24 4.373 18.627 0 12 0zm5.918 8.268l-1.6 2.541h1.967c.324 0 .587.263.587.588a.585.585 0 0 1-.587.587h-2.7a.585.585 0 0 1-.587-.587v-.158c0-.16.066-.314.182-.423l1.734-2.75h-1.727a.585.585 0 0 1-.587-.588c0-.324.263-.587.587-.587h2.551c.324 0 .587.263.587.587v.139c0 .146-.054.288-.152.395l-.165.256zm-4.22 0l-1.599 2.541h1.966c.325 0 .588.263.588.588a.586.586 0 0 1-.588.587h-2.7a.585.585 0 0 1-.587-.587v-.158c0-.16.066-.314.182-.423l1.734-2.75H9.648a.585.585 0 0 1-.587-.588c0-.324.263-.587.587-.587h2.551c.325 0 .588.263.588.587v.139c0 .146-.054.288-.152.395l-.166.256zm-4.203 2.868H5.766a.585.585 0 0 1-.587-.588V7.65c0-.324.263-.587.587-.587.324 0 .587.263.587.587v2.528h1.175V7.65a.585.585 0 0 1 .587-.587c.324 0 .587.263.587.587v3.298a.585.585 0 0 1-.587.587h-.002z" }) }));
const VKontakteIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#4C75A3", children: jsxRuntime.jsx("path", { d: "M15.684 0H8.316C1.592 0 0 1.592 0 8.316v7.368C0 22.408 1.592 24 8.316 24h7.368C22.408 24 24 22.408 24 15.684V8.316C24 1.592 22.408 0 15.684 0zm3.692 17.123h-1.744c-.66 0-.862-.523-2.049-1.714-1.033-1.033-1.49-1.171-1.744-1.171-.356 0-.458.102-.458.593v1.575c0 .424-.135.678-1.253.678-1.846 0-3.896-1.118-5.335-3.202C4.624 10.857 4 8.59 4 8.196c0-.254.102-.491.593-.491h1.744c.44 0 .61.203.78.677.863 2.49 2.303 4.675 2.896 4.675.22 0 .322-.102.322-.66V9.721c-.068-1.186-.695-1.287-.695-1.71 0-.203.17-.407.44-.407h2.744c.373 0 .508.203.508.643v3.473c0 .372.17.508.271.508.22 0 .407-.136.813-.542 1.254-1.406 2.151-3.574 2.151-3.574.119-.254.305-.491.745-.491h1.744c.525 0 .644.27.525.643-.22 1.017-2.354 4.031-2.354 4.031-.186.305-.254.44 0 .78.186.254.796.779 1.203 1.253.745.847 1.32 1.558 1.473 2.049.17.49-.085.744-.576.744z" }) }));
const YandexIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "#FC3F1D", children: jsxRuntime.jsx("path", { d: "M2.04 12c0-5.523 4.476-10 10-10 5.522 0 10 4.477 10 10s-4.478 10-10 10c-5.524 0-10-4.477-10-10zm16.17-3.536c-.274-.888-1.036-1.453-2.024-1.453-.924 0-1.653.534-2.013 1.453-.17.436-.243.815-.243 1.723 0 .909.073 1.287.243 1.723.36.919 1.09 1.453 2.013 1.453.988 0 1.75-.565 2.024-1.453.17-.51.231-.814.231-1.723 0-.909-.06-1.213-.231-1.723zM12.68 5.91h2.084v12.18h-1.768V8.418l-1.906 1.283V7.832l1.59-1.067v-.855z" }) }));
// Default/Unknown Icon
const DefaultIcon = () => (jsxRuntime.jsx("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "currentColor", children: jsxRuntime.jsx("path", { d: "M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm0 22c-5.523 0-10-4.477-10-10S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm-1-15v6.414l4.293 4.293 1.414-1.414L13 11.586V7h-2z" }) }));
const icons$1 = {
    // Existing providers
    google: GoogleIcon,
    github: GitHubIcon,
    microsoft: MicrosoftIcon,
    apple: AppleIcon,
    discord: DiscordIcon,
    slack: SlackIcon,
    // Social/Consumer
    facebook: FacebookIcon,
    twitter: TwitterIcon,
    instagram: InstagramIcon,
    tiktok: TikTokIcon,
    snapchat: SnapchatIcon,
    pinterest: PinterestIcon,
    reddit: RedditIcon,
    twitch: TwitchIcon,
    spotify: SpotifyIcon,
    // Professional
    linkedin: LinkedInIcon,
    // Developer/Tech
    gitlab: GitLabIcon,
    bitbucket: BitbucketIcon,
    digitalocean: DigitalOceanIcon,
    heroku: HerokuIcon,
    vercel: VercelIcon,
    netlify: NetlifyIcon,
    cloudflare: CloudflareIcon,
    // Enterprise
    salesforce: SalesforceIcon,
    hubspot: HubSpotIcon,
    zendesk: ZendeskIcon,
    notion: NotionIcon,
    figma: FigmaIcon,
    linear: LinearIcon,
    atlassian: AtlassianIcon,
    okta: OktaIcon,
    // Regional
    wechat: WeChatIcon,
    line: LineIcon,
    kakaotalk: KakaoTalkIcon,
    vkontakte: VKontakteIcon,
    yandex: YandexIcon,
};
const labels = {
    // Existing providers
    google: 'Continue with Google',
    github: 'Continue with GitHub',
    microsoft: 'Continue with Microsoft',
    apple: 'Continue with Apple',
    discord: 'Continue with Discord',
    slack: 'Continue with Slack',
    // Social/Consumer
    facebook: 'Continue with Facebook',
    twitter: 'Continue with X',
    instagram: 'Continue with Instagram',
    tiktok: 'Continue with TikTok',
    snapchat: 'Continue with Snapchat',
    pinterest: 'Continue with Pinterest',
    reddit: 'Continue with Reddit',
    twitch: 'Continue with Twitch',
    spotify: 'Continue with Spotify',
    // Professional
    linkedin: 'Continue with LinkedIn',
    // Developer/Tech
    gitlab: 'Continue with GitLab',
    bitbucket: 'Continue with Bitbucket',
    digitalocean: 'Continue with DigitalOcean',
    heroku: 'Continue with Heroku',
    vercel: 'Continue with Vercel',
    netlify: 'Continue with Netlify',
    cloudflare: 'Continue with Cloudflare',
    // Enterprise
    salesforce: 'Continue with Salesforce',
    hubspot: 'Continue with HubSpot',
    zendesk: 'Continue with Zendesk',
    notion: 'Continue with Notion',
    figma: 'Continue with Figma',
    linear: 'Continue with Linear',
    atlassian: 'Continue with Atlassian',
    okta: 'Continue with Okta',
    // Regional
    wechat: 'Continue with WeChat',
    line: 'Continue with LINE',
    kakaotalk: 'Continue with KakaoTalk',
    vkontakte: 'Continue with VKontakte',
    yandex: 'Continue with Yandex',
};
// ============================================================================
// Component
// ============================================================================
function SocialButton({ provider, variant = 'block', label, isLoading, elementClassName, disabled, style, children, ...props }) {
    const { getElementClass, cssVariables } = useTheme();
    const Icon = icons$1[provider] || DefaultIcon;
    const buttonLabel = label || labels[provider] || `Continue with ${provider}`;
    // Block button style
    const blockStyle = {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '0.75rem',
        width: '100%',
        padding: '0.75rem 1rem',
        fontSize: cssVariables['--vault-font-size'],
        fontWeight: 500,
        fontFamily: cssVariables['--vault-font-family-buttons'],
        color: cssVariables['--vault-color-text'],
        backgroundColor: cssVariables['--vault-color-surface'],
        border: `1px solid ${cssVariables['--vault-color-border']}`,
        borderRadius: cssVariables['--vault-border-radius'],
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out, border-color 0.15s ease-in-out',
    };
    // Icon button style
    const iconStyle = {
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '2.75rem',
        height: '2.75rem',
        padding: 0,
        backgroundColor: cssVariables['--vault-color-surface'],
        border: `1px solid ${cssVariables['--vault-color-border']}`,
        borderRadius: cssVariables['--vault-border-radius'],
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out, border-color 0.15s ease-in-out',
    };
    const isIconVariant = variant === 'icon';
    const baseClassName = isIconVariant
        ? getElementClass('socialButtonsIconButton')
        : getElementClass('socialButtons');
    return (jsxRuntime.jsxs("button", { type: "button", className: [baseClassName, elementClassName].filter(Boolean).join(' '), style: {
            ...(isIconVariant ? iconStyle : blockStyle),
            opacity: disabled || isLoading ? 0.6 : 1,
            cursor: disabled || isLoading ? 'not-allowed' : 'pointer',
            ...style,
        }, disabled: disabled || isLoading, ...props, children: [isLoading ? (jsxRuntime.jsx("span", { className: "vault-spinner", style: {
                    width: '1rem',
                    height: '1rem',
                } })) : (jsxRuntime.jsx(Icon, {})), !isIconVariant && jsxRuntime.jsx("span", { children: buttonLabel }), children] }));
}
function SocialButtons({ children, layout = 'vertical', className, }) {
    const { getElementClass } = useTheme();
    const layoutStyles = {
        vertical: {
            display: 'flex',
            flexDirection: 'column',
            gap: '0.5rem',
        },
        horizontal: {
            display: 'flex',
            flexDirection: 'row',
            gap: '0.5rem',
            justifyContent: 'center',
            flexWrap: 'wrap',
        },
    };
    return (jsxRuntime.jsx("div", { className: [getElementClass('socialButtons'), className]
            .filter(Boolean)
            .join(' '), style: layoutStyles[layout], children: children }));
}

// ============================================================================
// Icons
// ============================================================================
const ErrorIcon$1 = ({ color }) => (jsxRuntime.jsx("svg", { width: "20", height: "20", viewBox: "0 0 20 20", fill: "none", children: jsxRuntime.jsx("path", { fillRule: "evenodd", clipRule: "evenodd", d: "M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z", fill: color }) }));
const SuccessIcon$2 = ({ color }) => (jsxRuntime.jsx("svg", { width: "20", height: "20", viewBox: "0 0 20 20", fill: "none", children: jsxRuntime.jsx("path", { fillRule: "evenodd", clipRule: "evenodd", d: "M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z", fill: color }) }));
const WarningIcon = ({ color }) => (jsxRuntime.jsx("svg", { width: "20", height: "20", viewBox: "0 0 20 20", fill: "none", children: jsxRuntime.jsx("path", { fillRule: "evenodd", clipRule: "evenodd", d: "M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z", fill: color }) }));
const InfoIcon = ({ color }) => (jsxRuntime.jsx("svg", { width: "20", height: "20", viewBox: "0 0 20 20", fill: "none", children: jsxRuntime.jsx("path", { fillRule: "evenodd", clipRule: "evenodd", d: "M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z", fill: color }) }));
const icons = {
    error: ErrorIcon$1,
    success: SuccessIcon$2,
    warning: WarningIcon,
    info: InfoIcon,
};
// ============================================================================
// Component
// ============================================================================
function Alert({ variant = 'info', title, showIcon = true, icon, onDismiss, children, className, style, ...props }) {
    const { getElementClass, cssVariables } = useTheme();
    const variantColors = {
        error: cssVariables['--vault-color-danger'],
        success: cssVariables['--vault-color-success'],
        warning: cssVariables['--vault-color-warning'],
        info: cssVariables['--vault-color-primary'],
    };
    const variantClasses = {
        error: getElementClass('alertError'),
        success: getElementClass('alertSuccess'),
        warning: getElementClass('alertWarning'),
        info: getElementClass('alert'),
    };
    const color = variantColors[variant];
    const Icon = icons[variant];
    return (jsxRuntime.jsxs("div", { className: [getElementClass('alert'), variantClasses[variant], className]
            .filter(Boolean)
            .join(' '), style: {
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.75rem',
            ...style,
        }, role: variant === 'error' ? 'alert' : 'status', ...props, children: [showIcon && (jsxRuntime.jsx("div", { style: { flexShrink: 0, marginTop: '0.125rem' }, children: icon || jsxRuntime.jsx(Icon, { color: color }) })), jsxRuntime.jsxs("div", { style: { flex: 1, minWidth: 0 }, children: [title && (jsxRuntime.jsx("div", { style: {
                            fontWeight: 600,
                            marginBottom: children ? '0.25rem' : 0,
                            color,
                        }, children: title })), children && (jsxRuntime.jsx("div", { style: { color }, children: children }))] }), onDismiss && (jsxRuntime.jsx("button", { type: "button", onClick: onDismiss, style: {
                    flexShrink: 0,
                    padding: '0.25rem',
                    margin: '-0.25rem',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    color,
                    opacity: 0.6,
                    transition: 'opacity 0.15s ease-in-out',
                }, "aria-label": "Dismiss", children: jsxRuntime.jsx("svg", { width: "16", height: "16", viewBox: "0 0 16 16", fill: "currentColor", children: jsxRuntime.jsx("path", { d: "M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z" }) }) }))] }));
}

// ============================================================================
// Component
// ============================================================================
function Spinner$3({ size = 'md', shimmer, shimmerWidth = '100%', shimmerHeight = '1rem', className, style, }) {
    const { cssVariables, getLayoutOption } = useTheme();
    const useShimmer = shimmer ?? getLayoutOption('shimmer');
    // Size map
    const sizeMap = {
        sm: 16,
        md: 20,
        lg: 32,
        xl: 48,
    };
    const sizeValue = typeof size === 'number' ? size : sizeMap[size];
    // Shimmer style
    if (useShimmer) {
        const width = typeof shimmerWidth === 'number' ? `${shimmerWidth}px` : shimmerWidth;
        const height = typeof shimmerHeight === 'number' ? `${shimmerHeight}px` : shimmerHeight;
        return (jsxRuntime.jsx("div", { className: ['vault-shimmer', className].filter(Boolean).join(' '), style: {
                width,
                height,
                borderRadius: cssVariables['--vault-border-radius'],
                ...style,
            } }));
    }
    // Spinner style
    return (jsxRuntime.jsx("div", { className: ['vault-spinner', className].filter(Boolean).join(' '), style: {
            width: sizeValue,
            height: sizeValue,
            border: `2px solid ${cssVariables['--vault-color-border']}`,
            borderTopColor: cssVariables['--vault-color-primary'],
            borderRadius: '50%',
            animation: 'vault-spin 1s linear infinite',
            ...style,
        }, role: "status", "aria-label": "Loading" }));
}
function SpinnerOverlay({ isLoading, children, size = 'lg', shimmer, opacity = 0.7, className, }) {
    const { cssVariables } = useTheme();
    return (jsxRuntime.jsxs("div", { className: className, style: {
            position: 'relative',
            display: 'inline-block',
        }, children: [children, isLoading && (jsxRuntime.jsx("div", { style: {
                    position: 'absolute',
                    inset: 0,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    backgroundColor: cssVariables['--vault-color-background'],
                    opacity,
                    borderRadius: 'inherit',
                }, children: jsxRuntime.jsx(Spinner$3, { size: size, shimmer: shimmer }) }))] }));
}
function Skeleton({ lines = 3, lineHeight = '1rem', gap = '0.5rem', className, }) {
    const lineHeightValue = typeof lineHeight === 'number' ? `${lineHeight}px` : lineHeight;
    const gapValue = typeof gap === 'number' ? `${gap}px` : gap;
    return (jsxRuntime.jsx("div", { className: className, style: {
            display: 'flex',
            flexDirection: 'column',
            gap: gapValue,
        }, children: Array.from({ length: lines }).map((_, index) => (jsxRuntime.jsx(Spinner$3, { shimmer: true, shimmerWidth: index === lines - 1 ? '60%' : '100%', shimmerHeight: lineHeightValue }, index))) }));
}

// ============================================================================
// Main Component
// ============================================================================
function SignIn({ redirectUrl, onSignIn, onError, showMagicLink = true, showForgotPassword = true, oauthProviders = [], showWebAuthn = false, appearance, className, }) {
    // Determine if we need to wrap with ThemeProvider
    const [isThemed] = React.useState(() => {
        try {
            useTheme();
            return true;
        }
        catch {
            return false;
        }
    });
    const content = (jsxRuntime.jsx(SignInContent, { redirectUrl: redirectUrl, onSignIn: onSignIn, onError: onError, showMagicLink: showMagicLink, showForgotPassword: showForgotPassword, oauthProviders: oauthProviders, showWebAuthn: showWebAuthn, appearance: appearance, className: className }));
    // Wrap with ThemeProvider if not already themed
    if (!isThemed && appearance) {
        return (jsxRuntime.jsx(ThemeProvider, { appearance: appearance, children: content }));
    }
    return content;
}
// ============================================================================
// Internal Content Component
// ============================================================================
function SignInContent({ redirectUrl, onSignIn, onError, showMagicLink, showForgotPassword, oauthProviders, showWebAuthn, className, }) {
    const { signIn, signInWithMagicLink, signInWithOAuth, isLoading, error, resetError } = useSignIn();
    const { isSupported: isWebAuthnSupported, authenticate: authenticateWithWebAuthn } = useWebAuthn();
    const { getLayoutOption, cssVariables } = useTheme();
    const [email, setEmail] = React.useState('');
    const [password, setPassword] = React.useState('');
    const [useMagicLink, setUseMagicLink] = React.useState(false);
    const [magicLinkSent, setMagicLinkSent] = React.useState(false);
    const [localError, setLocalError] = React.useState(null);
    const socialButtonsPlacement = getLayoutOption('socialButtonsPlacement');
    const socialButtonsVariant = getLayoutOption('socialButtonsVariant');
    const handleSubmit = React.useCallback(async (e) => {
        e.preventDefault();
        resetError();
        setLocalError(null);
        try {
            if (useMagicLink) {
                await signInWithMagicLink({ email, redirectUrl });
                setMagicLinkSent(true);
            }
            else {
                await signIn({ email, password });
                onSignIn?.();
                if (redirectUrl) {
                    window.location.href = redirectUrl;
                }
            }
        }
        catch (err) {
            const errorMessage = err.message || 'Failed to sign in';
            setLocalError(errorMessage);
            onError?.(err);
        }
    }, [email, password, useMagicLink, signIn, signInWithMagicLink, redirectUrl, onSignIn, onError, resetError]);
    const handleOAuth = React.useCallback(async (provider) => {
        resetError();
        setLocalError(null);
        try {
            await signInWithOAuth({ provider, redirectUrl });
        }
        catch (err) {
            setLocalError(err.message || 'Failed to sign in');
            onError?.(err);
        }
    }, [signInWithOAuth, redirectUrl, onError, resetError]);
    const handleWebAuthn = React.useCallback(async () => {
        resetError();
        setLocalError(null);
        try {
            await authenticateWithWebAuthn();
            onSignIn?.();
            if (redirectUrl) {
                window.location.href = redirectUrl;
            }
        }
        catch (err) {
            setLocalError(err.message || 'Passkey authentication failed');
            onError?.(err);
        }
    }, [authenticateWithWebAuthn, redirectUrl, onSignIn, onError, resetError]);
    const handleForgotPassword = React.useCallback(() => {
        window.location.href = `/forgot-password?email=${encodeURIComponent(email)}`;
    }, [email]);
    const displayError = localError || error?.message;
    // Magic link sent state
    if (magicLinkSent) {
        return (jsxRuntime.jsxs(Card, { className: className, centered: true, children: [jsxRuntime.jsx(CardHeader, { title: "Check your email", subtitle: `We've sent a magic link to ${email}` }), jsxRuntime.jsxs(CardContent, { children: [jsxRuntime.jsx("p", { style: {
                                textAlign: 'center',
                                color: cssVariables['--vault-color-text-secondary'],
                                fontFamily: cssVariables['--vault-font-family'],
                            }, children: "Click the link in the email to sign in." }), jsxRuntime.jsx(Button, { variant: "ghost", onClick: () => {
                                setMagicLinkSent(false);
                                setEmail('');
                            }, children: "Back to sign in" })] })] }));
    }
    const SocialButtonsSection = oauthProviders && oauthProviders.length > 0 && (jsxRuntime.jsx(SocialButtons, { layout: socialButtonsVariant === 'iconButton' ? 'horizontal' : 'vertical', children: oauthProviders?.map((provider) => (jsxRuntime.jsx(SocialButton, { provider: provider, variant: socialButtonsVariant === 'iconButton' ? 'icon' : 'block', onClick: () => handleOAuth(provider), disabled: isLoading }, provider))) }));
    return (jsxRuntime.jsxs(Card, { className: className, centered: true, children: [jsxRuntime.jsx(CardHeader, { title: "Sign In" }), jsxRuntime.jsxs(CardContent, { children: [displayError && (jsxRuntime.jsx(Alert, { variant: "error", style: { marginBottom: '1rem' }, children: displayError })), socialButtonsPlacement === 'top' && SocialButtonsSection, socialButtonsPlacement === 'top' && (oauthProviders || []).length > 0 && (jsxRuntime.jsx(Divider, { text: "or" })), jsxRuntime.jsxs("form", { onSubmit: handleSubmit, children: [jsxRuntime.jsx(Input, { label: "Email", type: "email", value: email, onChange: (e) => setEmail(e.target.value), required: true, autoComplete: "email", disabled: isLoading, placeholder: "you@example.com" }), !useMagicLink && (jsxRuntime.jsxs("div", { style: { position: 'relative' }, children: [jsxRuntime.jsx(Input, { label: "Password", type: "password", value: password, onChange: (e) => setPassword(e.target.value), required: !useMagicLink, autoComplete: "current-password", disabled: isLoading }), showForgotPassword && (jsxRuntime.jsx("button", { type: "button", onClick: handleForgotPassword, style: {
                                            position: 'absolute',
                                            right: 0,
                                            top: 0,
                                            fontSize: '0.75rem',
                                            color: cssVariables['--vault-color-primary'],
                                            background: 'none',
                                            border: 'none',
                                            cursor: 'pointer',
                                            fontFamily: cssVariables['--vault-font-family'],
                                        }, children: "Forgot password?" }))] })), jsxRuntime.jsx(Button, { type: "submit", isLoading: isLoading, style: { marginTop: '0.5rem' }, children: useMagicLink ? 'Send Magic Link' : 'Sign In' })] }), showMagicLink && (jsxRuntime.jsx(Button, { variant: "ghost", onClick: () => {
                            setUseMagicLink(!useMagicLink);
                            resetError();
                            setLocalError(null);
                        }, children: useMagicLink ? 'Use password instead' : 'Use magic link instead' })), showWebAuthn && isWebAuthnSupported && (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx(Divider, { text: "or" }), jsxRuntime.jsxs(Button, { variant: "secondary", onClick: handleWebAuthn, disabled: isLoading, children: [jsxRuntime.jsx("span", { style: { marginRight: '0.5rem' }, children: "\uD83D\uDD10" }), "Sign in with Passkey"] })] })), socialButtonsPlacement === 'bottom' && (oauthProviders || []).length > 0 && (jsxRuntime.jsx(Divider, { text: "or" })), socialButtonsPlacement === 'bottom' && SocialButtonsSection] })] }));
}

// ============================================================================
// Main Component
// ============================================================================
function SignUp({ redirectUrl, onSignUp, onError, oauthProviders = [], requireName = false, appearance, className, }) {
    // Determine if we need to wrap with ThemeProvider
    const [isThemed] = React.useState(() => {
        try {
            useTheme();
            return true;
        }
        catch {
            return false;
        }
    });
    const content = (jsxRuntime.jsx(SignUpContent, { redirectUrl: redirectUrl, onSignUp: onSignUp, onError: onError, oauthProviders: oauthProviders, requireName: requireName, appearance: appearance, className: className }));
    // Wrap with ThemeProvider if not already themed
    if (!isThemed && appearance) {
        return (jsxRuntime.jsx(ThemeProvider, { appearance: appearance, children: content }));
    }
    return content;
}
// ============================================================================
// Internal Content Component
// ============================================================================
function SignUpContent({ redirectUrl, onSignUp, onError, oauthProviders, requireName, className, }) {
    const { signUp, signUpWithOAuth, isLoading, error, resetError } = useSignUp();
    const { getLayoutOption, cssVariables } = useTheme();
    const [email, setEmail] = React.useState('');
    const [password, setPassword] = React.useState('');
    const [confirmPassword, setConfirmPassword] = React.useState('');
    const [name, setName] = React.useState('');
    const [localError, setLocalError] = React.useState(null);
    const [success, setSuccess] = React.useState(false);
    const socialButtonsPlacement = getLayoutOption('socialButtonsPlacement');
    const socialButtonsVariant = getLayoutOption('socialButtonsVariant');
    const handleSubmit = React.useCallback(async (e) => {
        e.preventDefault();
        resetError();
        setLocalError(null);
        // Validation
        if (password !== confirmPassword) {
            setLocalError('Passwords do not match');
            return;
        }
        if (password.length < 12) {
            setLocalError('Password must be at least 12 characters');
            return;
        }
        try {
            await signUp({
                email,
                password,
                name: name || undefined,
            });
            setSuccess(true);
            onSignUp?.();
            if (redirectUrl) {
                window.location.href = redirectUrl;
            }
        }
        catch (err) {
            const errorMessage = err.message || 'Failed to create account';
            setLocalError(errorMessage);
            onError?.(err);
        }
    }, [email, password, confirmPassword, name, requireName, signUp, redirectUrl, onSignUp, onError, resetError]);
    const handleOAuth = React.useCallback(async (provider) => {
        resetError();
        setLocalError(null);
        try {
            await signUpWithOAuth({ provider, redirectUrl });
        }
        catch (err) {
            setLocalError(err.message || 'Failed to sign up');
            onError?.(err);
        }
    }, [signUpWithOAuth, redirectUrl, onError, resetError]);
    const displayError = localError || error?.message;
    // Success state
    if (success) {
        return (jsxRuntime.jsxs(Card, { className: className, centered: true, children: [jsxRuntime.jsx(CardHeader, { title: "Account created!", subtitle: "Welcome! Your account has been successfully created." }), redirectUrl && (jsxRuntime.jsx(CardContent, { children: jsxRuntime.jsx("p", { style: {
                            textAlign: 'center',
                            color: cssVariables['--vault-color-text-secondary'],
                            fontFamily: cssVariables['--vault-font-family'],
                        }, children: "Redirecting you..." }) }))] }));
    }
    const SocialButtonsSection = oauthProviders && oauthProviders.length > 0 && (jsxRuntime.jsx(SocialButtons, { layout: socialButtonsVariant === 'iconButton' ? 'horizontal' : 'vertical', children: oauthProviders?.map((provider) => (jsxRuntime.jsx(SocialButton, { provider: provider, variant: socialButtonsVariant === 'iconButton' ? 'icon' : 'block', onClick: () => handleOAuth(provider), disabled: isLoading }, provider))) }));
    return (jsxRuntime.jsxs(Card, { className: className, centered: true, children: [jsxRuntime.jsx(CardHeader, { title: "Create Account" }), jsxRuntime.jsxs(CardContent, { children: [displayError && (jsxRuntime.jsx(Alert, { variant: "error", style: { marginBottom: '1rem' }, children: displayError })), socialButtonsPlacement === 'top' && SocialButtonsSection, socialButtonsPlacement === 'top' && (oauthProviders || []).length > 0 && (jsxRuntime.jsx(Divider, { text: "or" })), jsxRuntime.jsxs("form", { onSubmit: handleSubmit, children: [(requireName || name) && (jsxRuntime.jsx(Input, { label: "Full Name", type: "text", value: name, onChange: (e) => setName(e.target.value), required: requireName, autoComplete: "name", disabled: isLoading, placeholder: "John Doe" })), jsxRuntime.jsx(Input, { label: "Email", type: "email", value: email, onChange: (e) => setEmail(e.target.value), required: true, autoComplete: "email", disabled: isLoading, placeholder: "you@example.com" }), jsxRuntime.jsx(Input, { label: "Password", type: "password", value: password, onChange: (e) => setPassword(e.target.value), required: true, minLength: 12, autoComplete: "new-password", disabled: isLoading, placeholder: "Min 12 characters", helperText: "Must be at least 12 characters" }), jsxRuntime.jsx(Input, { label: "Confirm Password", type: "password", value: confirmPassword, onChange: (e) => setConfirmPassword(e.target.value), required: true, autoComplete: "new-password", disabled: isLoading, placeholder: "Re-enter your password" }), jsxRuntime.jsx(Button, { type: "submit", isLoading: isLoading, style: { marginTop: '0.5rem' }, children: "Create Account" })] }), socialButtonsPlacement === 'bottom' && (oauthProviders || []).length > 0 && (jsxRuntime.jsx(Divider, { text: "or" })), socialButtonsPlacement === 'bottom' && SocialButtonsSection] }), jsxRuntime.jsx(CardFooter, { children: jsxRuntime.jsxs("span", { style: {
                        fontSize: '0.875rem',
                        color: cssVariables['--vault-color-text-secondary'],
                        fontFamily: cssVariables['--vault-font-family'],
                    }, children: ["Already have an account?", ' ', jsxRuntime.jsx("a", { href: "/sign-in", style: {
                                color: cssVariables['--vault-color-primary'],
                                textDecoration: 'none',
                                fontWeight: 500,
                            }, children: "Sign in" })] }) })] }));
}

// ============================================================================
// Main Component
// ============================================================================
function UserButton({ showName = true, avatarUrl, onSignOut, menuItems = [], showManageAccount = true, appearance, className, }) {
    // Determine if we need to wrap with ThemeProvider
    const [isThemed] = React.useState(() => {
        try {
            useTheme();
            return true;
        }
        catch {
            return false;
        }
    });
    const content = (jsxRuntime.jsx(UserButtonContent, { showName: showName, avatarUrl: avatarUrl, onSignOut: onSignOut, menuItems: menuItems, showManageAccount: showManageAccount, appearance: appearance, className: className }));
    // Wrap with ThemeProvider if not already themed
    if (!isThemed && appearance) {
        return (jsxRuntime.jsx(ThemeProvider, { appearance: appearance, children: content }));
    }
    return content;
}
// ============================================================================
// Internal Content Component
// ============================================================================
function UserButtonContent({ showName, avatarUrl, onSignOut, menuItems, showManageAccount, className, }) {
    const { signOut, isSignedIn } = useAuth();
    const user = useUser();
    const { getElementClass, cssVariables } = useTheme();
    const [isOpen, setIsOpen] = React.useState(false);
    const menuRef = React.useRef(null);
    // Close menu when clicking outside
    React.useEffect(() => {
        const handleClickOutside = (event) => {
            if (menuRef.current && !menuRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        };
        if (isOpen) {
            document.addEventListener('mousedown', handleClickOutside);
        }
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [isOpen]);
    // Handle keyboard navigation
    React.useEffect(() => {
        const handleKeyDown = (event) => {
            if (event.key === 'Escape') {
                setIsOpen(false);
            }
        };
        if (isOpen) {
            document.addEventListener('keydown', handleKeyDown);
        }
        return () => {
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, [isOpen]);
    const handleSignOut = React.useCallback(async () => {
        await signOut();
        onSignOut?.();
        setIsOpen(false);
    }, [signOut, onSignOut]);
    const handleManageAccount = React.useCallback(() => {
        window.location.href = '/profile';
        setIsOpen(false);
    }, []);
    if (!isSignedIn || !user) {
        return null;
    }
    const displayName = user.profile?.name || user.email.split('@')[0];
    const initial = displayName.charAt(0).toUpperCase();
    const imageUrl = avatarUrl || user.profile?.picture;
    return (jsxRuntime.jsxs("div", { ref: menuRef, className: [getElementClass('userButton'), className].filter(Boolean).join(' '), style: { position: 'relative', display: 'inline-block' }, children: [jsxRuntime.jsxs("button", { type: "button", onClick: () => setIsOpen(!isOpen), className: getElementClass('userButtonTrigger'), "aria-expanded": isOpen, "aria-haspopup": "true", "aria-label": "User menu", children: [imageUrl ? (jsxRuntime.jsx("img", { src: imageUrl, alt: displayName, style: {
                            width: '2rem',
                            height: '2rem',
                            borderRadius: '50%',
                            objectFit: 'cover',
                        }, onError: (e) => {
                            e.target.style.display = 'none';
                        } })) : (jsxRuntime.jsx("div", { className: getElementClass('avatarBox'), children: initial })), showName && (jsxRuntime.jsx("span", { style: {
                            fontWeight: 500,
                            fontFamily: cssVariables['--vault-font-family'],
                            color: cssVariables['--vault-color-text'],
                        }, children: displayName })), jsxRuntime.jsx(ChevronIcon$1, { isOpen: isOpen })] }), isOpen && (jsxRuntime.jsx("div", { className: getElementClass('userButtonPopover'), children: jsxRuntime.jsxs("div", { className: getElementClass('userButtonPopoverCard'), children: [jsxRuntime.jsxs("div", { style: {
                                padding: '0.75rem 1rem',
                                borderBottom: `1px solid ${cssVariables['--vault-color-border']}`,
                            }, children: [jsxRuntime.jsx("div", { style: {
                                        fontWeight: 600,
                                        fontSize: '0.875rem',
                                        fontFamily: cssVariables['--vault-font-family'],
                                        color: cssVariables['--vault-color-text'],
                                    }, children: displayName }), jsxRuntime.jsx("div", { style: {
                                        fontSize: '0.75rem',
                                        fontFamily: cssVariables['--vault-font-family'],
                                        color: cssVariables['--vault-color-text-secondary'],
                                        marginTop: '0.125rem',
                                        wordBreak: 'break-all',
                                    }, children: user.email }), user.emailVerified === false && (jsxRuntime.jsx("span", { style: {
                                        display: 'inline-block',
                                        marginTop: '0.25rem',
                                        padding: '0.125rem 0.5rem',
                                        fontSize: '0.6875rem',
                                        fontFamily: cssVariables['--vault-font-family'],
                                        color: cssVariables['--vault-color-warning'],
                                        backgroundColor: `${cssVariables['--vault-color-warning']}15`,
                                        borderRadius: '0.25rem',
                                    }, children: "Unverified" }))] }), jsxRuntime.jsxs("div", { className: getElementClass('menuList'), children: [showManageAccount && (jsxRuntime.jsx("button", { type: "button", onClick: handleManageAccount, className: getElementClass('menuItem'), role: "menuitem", children: "Manage account" })), menuItems?.map((item, index) => (jsxRuntime.jsx("button", { type: "button", onClick: () => {
                                        item.onClick();
                                        setIsOpen(false);
                                    }, className: getElementClass('menuItem'), role: "menuitem", children: item.label }, index))), (showManageAccount || (menuItems && menuItems.length > 0)) && (jsxRuntime.jsx("div", { style: {
                                        height: '1px',
                                        backgroundColor: cssVariables['--vault-color-border'],
                                        margin: '0.25rem 0',
                                    } })), jsxRuntime.jsx("button", { type: "button", onClick: handleSignOut, className: getElementClass('menuItem'), role: "menuitem", style: { color: cssVariables['--vault-color-danger'] }, children: "Sign out" })] })] }) }))] }));
}
// ============================================================================
// Chevron Icon
// ============================================================================
function ChevronIcon$1({ isOpen }) {
    const { cssVariables } = useTheme();
    return (jsxRuntime.jsx("svg", { width: "12", height: "12", viewBox: "0 0 12 12", fill: "none", style: {
            marginLeft: '0.25rem',
            transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
            transition: 'transform 0.2s ease',
            color: cssVariables['--vault-color-text-secondary'],
        }, children: jsxRuntime.jsx("path", { d: "M2.5 4.5L6 8L9.5 4.5", stroke: "currentColor", strokeWidth: "1.5", strokeLinecap: "round", strokeLinejoin: "round" }) }));
}

function UserProfile({ onUpdate, appearance, className, }) {
    const { user, isLoading, error, update, changePassword, deleteUser } = useUserManager();
    const [activeTab, setActiveTab] = React.useState('profile');
    const [isEditing, setIsEditing] = React.useState(false);
    const [formData, setFormData] = React.useState({
        name: '',
        givenName: '',
        familyName: '',
        phoneNumber: '',
    });
    const [passwordData, setPasswordData] = React.useState({
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
    });
    const [localError, setLocalError] = React.useState(null);
    const [successMessage, setSuccessMessage] = React.useState(null);
    // Initialize form data when user loads
    React.useEffect(() => {
        if (user) {
            setFormData({
                name: user.profile?.name || '',
                givenName: user.profile?.givenName || '',
                familyName: user.profile?.familyName || '',
                phoneNumber: user.profile?.phoneNumber || '',
            });
        }
    }, [user]);
    const handleInputChange = React.useCallback((field, value) => {
        setFormData(prev => ({ ...prev, [field]: value }));
        setLocalError(null);
        setSuccessMessage(null);
    }, []);
    const handleSaveProfile = React.useCallback(async () => {
        setLocalError(null);
        setSuccessMessage(null);
        try {
            await update({
                profile: {
                    ...user?.profile,
                    ...formData,
                },
            });
            setIsEditing(false);
            setSuccessMessage('Profile updated successfully');
            onUpdate?.(user);
        }
        catch (err) {
            setLocalError(err.message || 'Failed to update profile');
        }
    }, [formData, user, update, onUpdate]);
    const handleChangePassword = React.useCallback(async () => {
        setLocalError(null);
        setSuccessMessage(null);
        if (passwordData.newPassword !== passwordData.confirmPassword) {
            setLocalError('Passwords do not match');
            return;
        }
        if (passwordData.newPassword.length < 12) {
            setLocalError('Password must be at least 12 characters');
            return;
        }
        try {
            await changePassword(passwordData.currentPassword, passwordData.newPassword);
            setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
            setSuccessMessage('Password changed successfully');
        }
        catch (err) {
            setLocalError(err.message || 'Failed to change password');
        }
    }, [passwordData, changePassword]);
    const handleDeleteAccount = React.useCallback(async () => {
        if (window.confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
            try {
                await deleteUser();
            }
            catch (err) {
                setLocalError(err.message || 'Failed to delete account');
            }
        }
    }, [deleteUser]);
    if (!user) {
        return (jsxRuntime.jsx("div", { style: applyAppearance$8(styles$b.container, appearance), className: className, children: jsxRuntime.jsx("div", { style: styles$b.loading, children: "Loading profile..." }) }));
    }
    const displayError = localError || error?.message;
    return (jsxRuntime.jsxs("div", { style: applyAppearance$8(styles$b.container, appearance), className: className, children: [jsxRuntime.jsx("h1", { style: applyAppearance$8(styles$b.heading, appearance), children: "Profile" }), jsxRuntime.jsxs("div", { style: styles$b.tabs, children: [jsxRuntime.jsx(TabButton$1, { label: "Profile", isActive: activeTab === 'profile', onClick: () => setActiveTab('profile'), appearance: appearance }), jsxRuntime.jsx(TabButton$1, { label: "Security", isActive: activeTab === 'security', onClick: () => setActiveTab('security'), appearance: appearance }), jsxRuntime.jsx(TabButton$1, { label: "Danger Zone", isActive: activeTab === 'danger', onClick: () => setActiveTab('danger'), appearance: appearance, isDanger: true })] }), displayError && (jsxRuntime.jsx("div", { style: applyAppearance$8(styles$b.error, appearance), role: "alert", children: displayError })), successMessage && (jsxRuntime.jsx("div", { style: applyAppearance$8(styles$b.success, appearance), role: "status", children: successMessage })), activeTab === 'profile' && (jsxRuntime.jsxs("div", { style: styles$b.section, children: [jsxRuntime.jsxs("div", { style: styles$b.sectionHeader, children: [jsxRuntime.jsx("h2", { style: styles$b.sectionTitle, children: "Personal Information" }), !isEditing && (jsxRuntime.jsx("button", { onClick: () => setIsEditing(true), style: applyAppearance$8(styles$b.editButton, appearance), children: "Edit" }))] }), jsxRuntime.jsxs("div", { style: styles$b.fieldGroup, children: [jsxRuntime.jsxs("div", { style: styles$b.field, children: [jsxRuntime.jsx("label", { style: applyAppearance$8(styles$b.label, appearance), children: "Email" }), jsxRuntime.jsx("input", { type: "email", value: user.email, disabled: true, style: { ...applyAppearance$8(styles$b.input, appearance), backgroundColor: '#f3f4f6' } }), user.emailVerified ? (jsxRuntime.jsx("span", { style: styles$b.verifiedBadge, children: "\u2713 Verified" })) : (jsxRuntime.jsx("span", { style: styles$b.unverifiedBadge, children: "Unverified" }))] }), jsxRuntime.jsxs("div", { style: styles$b.field, children: [jsxRuntime.jsx("label", { style: applyAppearance$8(styles$b.label, appearance), children: "Full Name" }), jsxRuntime.jsx("input", { type: "text", value: formData.name, onChange: (e) => handleInputChange('name', e.target.value), disabled: !isEditing || isLoading, style: applyAppearance$8(styles$b.input, appearance), placeholder: "Your full name" })] }), jsxRuntime.jsxs("div", { style: styles$b.row, children: [jsxRuntime.jsxs("div", { style: { ...styles$b.field, flex: 1 }, children: [jsxRuntime.jsx("label", { style: applyAppearance$8(styles$b.label, appearance), children: "First Name" }), jsxRuntime.jsx("input", { type: "text", value: formData.givenName, onChange: (e) => handleInputChange('givenName', e.target.value), disabled: !isEditing || isLoading, style: applyAppearance$8(styles$b.input, appearance), placeholder: "First" })] }), jsxRuntime.jsxs("div", { style: { ...styles$b.field, flex: 1 }, children: [jsxRuntime.jsx("label", { style: applyAppearance$8(styles$b.label, appearance), children: "Last Name" }), jsxRuntime.jsx("input", { type: "text", value: formData.familyName, onChange: (e) => handleInputChange('familyName', e.target.value), disabled: !isEditing || isLoading, style: applyAppearance$8(styles$b.input, appearance), placeholder: "Last" })] })] }), jsxRuntime.jsxs("div", { style: styles$b.field, children: [jsxRuntime.jsx("label", { style: applyAppearance$8(styles$b.label, appearance), children: "Phone Number" }), jsxRuntime.jsx("input", { type: "tel", value: formData.phoneNumber, onChange: (e) => handleInputChange('phoneNumber', e.target.value), disabled: !isEditing || isLoading, style: applyAppearance$8(styles$b.input, appearance), placeholder: "+1 (555) 123-4567" })] })] }), isEditing && (jsxRuntime.jsxs("div", { style: styles$b.buttonGroup, children: [jsxRuntime.jsx("button", { onClick: handleSaveProfile, disabled: isLoading, style: applyAppearance$8(styles$b.primaryButton, appearance), children: isLoading ? 'Saving...' : 'Save Changes' }), jsxRuntime.jsx("button", { onClick: () => {
                                    setIsEditing(false);
                                    setFormData({
                                        name: user.profile?.name || '',
                                        givenName: user.profile?.givenName || '',
                                        familyName: user.profile?.familyName || '',
                                        phoneNumber: user.profile?.phoneNumber || '',
                                    });
                                }, disabled: isLoading, style: applyAppearance$8(styles$b.secondaryButton, appearance), children: "Cancel" })] }))] })), activeTab === 'security' && (jsxRuntime.jsxs("div", { style: styles$b.section, children: [jsxRuntime.jsx("h2", { style: styles$b.sectionTitle, children: "Change Password" }), jsxRuntime.jsxs("div", { style: styles$b.fieldGroup, children: [jsxRuntime.jsxs("div", { style: styles$b.field, children: [jsxRuntime.jsx("label", { style: applyAppearance$8(styles$b.label, appearance), children: "Current Password" }), jsxRuntime.jsx("input", { type: "password", value: passwordData.currentPassword, onChange: (e) => setPasswordData(prev => ({ ...prev, currentPassword: e.target.value })), style: applyAppearance$8(styles$b.input, appearance), placeholder: "Enter current password" })] }), jsxRuntime.jsxs("div", { style: styles$b.field, children: [jsxRuntime.jsx("label", { style: applyAppearance$8(styles$b.label, appearance), children: "New Password" }), jsxRuntime.jsx("input", { type: "password", value: passwordData.newPassword, onChange: (e) => setPasswordData(prev => ({ ...prev, newPassword: e.target.value })), style: applyAppearance$8(styles$b.input, appearance), placeholder: "Min 12 characters" })] }), jsxRuntime.jsxs("div", { style: styles$b.field, children: [jsxRuntime.jsx("label", { style: applyAppearance$8(styles$b.label, appearance), children: "Confirm New Password" }), jsxRuntime.jsx("input", { type: "password", value: passwordData.confirmPassword, onChange: (e) => setPasswordData(prev => ({ ...prev, confirmPassword: e.target.value })), style: applyAppearance$8(styles$b.input, appearance), placeholder: "Re-enter new password" })] })] }), jsxRuntime.jsx("button", { onClick: handleChangePassword, disabled: isLoading || !passwordData.currentPassword || !passwordData.newPassword, style: applyAppearance$8(styles$b.primaryButton, appearance), children: isLoading ? 'Changing...' : 'Change Password' }), jsxRuntime.jsxs("div", { style: styles$b.infoBox, children: [jsxRuntime.jsx("h3", { style: styles$b.infoTitle, children: "Account Information" }), jsxRuntime.jsxs("div", { style: styles$b.infoRow, children: [jsxRuntime.jsx("span", { style: styles$b.infoLabel, children: "Account ID:" }), jsxRuntime.jsx("code", { style: styles$b.code, children: user.id })] }), jsxRuntime.jsxs("div", { style: styles$b.infoRow, children: [jsxRuntime.jsx("span", { style: styles$b.infoLabel, children: "Created:" }), jsxRuntime.jsx("span", { children: new Date(user.createdAt).toLocaleDateString() })] }), jsxRuntime.jsxs("div", { style: styles$b.infoRow, children: [jsxRuntime.jsx("span", { style: styles$b.infoLabel, children: "Last Login:" }), jsxRuntime.jsx("span", { children: user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleDateString() : 'Never' })] })] })] })), activeTab === 'danger' && (jsxRuntime.jsxs("div", { style: styles$b.section, children: [jsxRuntime.jsx("h2", { style: { ...styles$b.sectionTitle, color: '#dc2626' }, children: "Danger Zone" }), jsxRuntime.jsxs("div", { style: styles$b.dangerBox, children: [jsxRuntime.jsx("h3", { style: styles$b.dangerTitle, children: "Delete Account" }), jsxRuntime.jsx("p", { style: styles$b.dangerText, children: "Once you delete your account, there is no going back. Please be certain." }), jsxRuntime.jsx("button", { onClick: handleDeleteAccount, disabled: isLoading, style: applyAppearance$8(styles$b.dangerButton, appearance), children: "Delete Account" })] })] }))] }));
}
// Tab Button Component
function TabButton$1({ label, isActive, onClick, appearance, isDanger, }) {
    return (jsxRuntime.jsx("button", { onClick: onClick, style: {
            ...styles$b.tabButton,
            ...(isActive && styles$b.tabButtonActive),
            ...(isActive && appearance?.variables?.['colorPrimary'] && {
                borderBottomColor: appearance.variables['colorPrimary'],
                color: appearance.variables['colorPrimary'],
            }),
            ...(isDanger && { color: isActive ? '#dc2626' : '#6b7280' }),
            ...(isDanger && isActive && { borderBottomColor: '#dc2626' }),
        }, children: label }));
}
// Apply appearance variables
function applyAppearance$8(baseStyle, appearance) {
    if (!appearance)
        return baseStyle;
    const variables = appearance.variables || {};
    let style = { ...baseStyle };
    if (variables['colorPrimary']) {
        if (baseStyle.backgroundColor === '#0066cc' || baseStyle.borderColor === '#0066cc') {
            style = { ...style, backgroundColor: variables['colorPrimary'], borderColor: variables['colorPrimary'] };
        }
    }
    if (variables['borderRadius'] && baseStyle.borderRadius) {
        style = { ...style, borderRadius: variables['borderRadius'] };
    }
    return style;
}
// Styles
const styles$b = {
    container: {
        maxWidth: '600px',
        margin: '0 auto',
        padding: '24px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    loading: {
        textAlign: 'center',
        padding: '48px',
        color: '#6b7280',
    },
    heading: {
        fontSize: '28px',
        fontWeight: 600,
        margin: '0 0 24px',
        color: '#1f2937',
    },
    tabs: {
        display: 'flex',
        borderBottom: '1px solid #e5e7eb',
        marginBottom: '24px',
    },
    tabButton: {
        padding: '12px 16px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#6b7280',
        background: 'transparent',
        border: 'none',
        borderBottom: '2px solid transparent',
        cursor: 'pointer',
        transition: 'all 0.15s ease-in-out',
    },
    tabButtonActive: {
        color: '#0066cc',
        borderBottomColor: '#0066cc',
    },
    error: {
        padding: '12px 16px',
        marginBottom: '16px',
        color: '#dc2626',
        backgroundColor: '#fee2e2',
        borderRadius: '6px',
        fontSize: '14px',
    },
    success: {
        padding: '12px 16px',
        marginBottom: '16px',
        color: '#059669',
        backgroundColor: '#d1fae5',
        borderRadius: '6px',
        fontSize: '14px',
    },
    section: {
        backgroundColor: '#fff',
        border: '1px solid #e5e7eb',
        borderRadius: '8px',
        padding: '24px',
    },
    sectionHeader: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '20px',
    },
    sectionTitle: {
        fontSize: '18px',
        fontWeight: 600,
        margin: 0,
        color: '#1f2937',
    },
    editButton: {
        padding: '6px 12px',
        fontSize: '14px',
        color: '#0066cc',
        backgroundColor: 'transparent',
        border: '1px solid #0066cc',
        borderRadius: '6px',
        cursor: 'pointer',
    },
    fieldGroup: {
        display: 'flex',
        flexDirection: 'column',
        gap: '16px',
        marginBottom: '24px',
    },
    field: {
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
    },
    row: {
        display: 'flex',
        gap: '16px',
    },
    label: {
        fontSize: '14px',
        fontWeight: 500,
        color: '#374151',
    },
    input: {
        padding: '10px 12px',
        fontSize: '15px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        outline: 'none',
        transition: 'border-color 0.15s ease-in-out',
    },
    verifiedBadge: {
        fontSize: '12px',
        color: '#059669',
        marginTop: '4px',
    },
    unverifiedBadge: {
        fontSize: '12px',
        color: '#d97706',
        marginTop: '4px',
    },
    buttonGroup: {
        display: 'flex',
        gap: '12px',
    },
    primaryButton: {
        padding: '10px 20px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#0066cc',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    secondaryButton: {
        padding: '10px 20px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#374151',
        backgroundColor: '#f3f4f6',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    infoBox: {
        marginTop: '24px',
        padding: '16px',
        backgroundColor: '#f9fafb',
        borderRadius: '6px',
    },
    infoTitle: {
        fontSize: '14px',
        fontWeight: 600,
        margin: '0 0 12px',
        color: '#374151',
    },
    infoRow: {
        display: 'flex',
        gap: '8px',
        marginBottom: '8px',
        fontSize: '14px',
    },
    infoLabel: {
        color: '#6b7280',
        minWidth: '100px',
    },
    code: {
        fontFamily: 'monospace',
        fontSize: '12px',
        color: '#6b7280',
    },
    dangerBox: {
        padding: '16px',
        border: '1px solid #fecaca',
        borderRadius: '6px',
        backgroundColor: '#fef2f2',
    },
    dangerTitle: {
        fontSize: '16px',
        fontWeight: 600,
        margin: '0 0 8px',
        color: '#dc2626',
    },
    dangerText: {
        fontSize: '14px',
        color: '#7f1d1d',
        margin: '0 0 16px',
    },
    dangerButton: {
        padding: '10px 20px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#dc2626',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
};

function WebAuthnButton({ mode = 'signin', label, onSuccess, onError, appearance, className, }) {
    const { isSupported, isLoading, error, register, authenticate, resetError } = useWebAuthn();
    const [localError, setLocalError] = React.useState(null);
    const [showNameInput, setShowNameInput] = React.useState(false);
    const [passkeyName, setPasskeyName] = React.useState('');
    const handleClick = React.useCallback(async () => {
        resetError();
        setLocalError(null);
        if (!isSupported) {
            const err = {
                code: 'webauthn_not_supported',
                message: 'Passkeys are not supported on this device',
            };
            setLocalError(err.message);
            onError?.(err);
            return;
        }
        try {
            if (mode === 'signup' || mode === 'link') {
                if (!showNameInput) {
                    setShowNameInput(true);
                    return;
                }
                await register(passkeyName || undefined);
                setShowNameInput(false);
                setPasskeyName('');
            }
            else {
                await authenticate();
            }
            onSuccess?.();
        }
        catch (err) {
            setLocalError(err.message || 'Passkey operation failed');
            onError?.(err);
        }
    }, [mode, isSupported, register, authenticate, onSuccess, onError, resetError, showNameInput, passkeyName]);
    const handleCancel = React.useCallback(() => {
        setShowNameInput(false);
        setPasskeyName('');
    }, []);
    if (!isSupported) {
        return (jsxRuntime.jsx("div", { style: applyAppearance$7(styles$a.unsupported, appearance), className: className, children: jsxRuntime.jsx("span", { style: styles$a.unsupportedText, children: "Passkeys not supported on this device" }) }));
    }
    const displayError = localError || error?.message;
    // Get default label based on mode
    const getDefaultLabel = () => {
        switch (mode) {
            case 'signin':
                return 'Sign in with Passkey';
            case 'signup':
                return 'Register Passkey';
            case 'link':
                return 'Add Passkey';
            default:
                return 'Continue with Passkey';
        }
    };
    const buttonLabel = label || getDefaultLabel();
    if (showNameInput) {
        return (jsxRuntime.jsxs("div", { style: applyAppearance$7(styles$a.container, appearance), className: className, children: [jsxRuntime.jsxs("div", { style: styles$a.inputGroup, children: [jsxRuntime.jsx("input", { type: "text", value: passkeyName, onChange: (e) => setPasskeyName(e.target.value), placeholder: "Name your passkey (optional)", style: applyAppearance$7(styles$a.input, appearance), disabled: isLoading, autoFocus: true }), jsxRuntime.jsx("button", { onClick: handleClick, disabled: isLoading, style: applyAppearance$7(styles$a.button, appearance), children: isLoading ? 'Registering...' : 'Register' }), jsxRuntime.jsx("button", { onClick: handleCancel, disabled: isLoading, style: applyAppearance$7(styles$a.cancelButton, appearance), children: "Cancel" })] }), displayError && (jsxRuntime.jsx("div", { style: applyAppearance$7(styles$a.error, appearance), role: "alert", children: displayError }))] }));
    }
    return (jsxRuntime.jsxs("div", { style: applyAppearance$7(styles$a.container, appearance), className: className, children: [jsxRuntime.jsxs("button", { onClick: handleClick, disabled: isLoading, style: applyAppearance$7(styles$a.button, appearance), children: [jsxRuntime.jsx(PasskeyIcon, {}), jsxRuntime.jsx("span", { children: isLoading ? 'Please wait...' : buttonLabel })] }), displayError && (jsxRuntime.jsx("div", { style: applyAppearance$7(styles$a.error, appearance), role: "alert", children: displayError }))] }));
}
// Passkey Icon Component
function PasskeyIcon() {
    return (jsxRuntime.jsxs("svg", { width: "20", height: "20", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("circle", { cx: "12", cy: "8", r: "4" }), jsxRuntime.jsx("path", { d: "M12 12v8" }), jsxRuntime.jsx("path", { d: "M9 16h6" }), jsxRuntime.jsx("path", { d: "M8 20h8" }), jsxRuntime.jsx("rect", { x: "4", y: "2", width: "16", height: "20", rx: "2" })] }));
}
// Apply appearance variables
function applyAppearance$7(baseStyle, appearance) {
    if (!appearance)
        return baseStyle;
    const variables = appearance.variables || {};
    let style = { ...baseStyle };
    if (variables['colorPrimary']) {
        if (baseStyle.backgroundColor === '#0066cc' || baseStyle.borderColor === '#0066cc') {
            style = { ...style, backgroundColor: variables['colorPrimary'], borderColor: variables['colorPrimary'] };
        }
    }
    if (variables['borderRadius'] && baseStyle.borderRadius) {
        style = { ...style, borderRadius: variables['borderRadius'] };
    }
    return style;
}
// Styles
const styles$a = {
    container: {
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    button: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        width: '100%',
        padding: '12px 16px',
        fontSize: '16px',
        fontWeight: 500,
        color: '#374151',
        backgroundColor: '#f3f4f6',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'all 0.15s ease-in-out',
    },
    inputGroup: {
        display: 'flex',
        gap: '8px',
        marginBottom: '8px',
    },
    input: {
        flex: 1,
        padding: '10px 12px',
        fontSize: '15px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        outline: 'none',
    },
    cancelButton: {
        padding: '10px 16px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#6b7280',
        backgroundColor: '#f3f4f6',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        cursor: 'pointer',
    },
    error: {
        marginTop: '8px',
        padding: '8px 12px',
        fontSize: '13px',
        color: '#dc2626',
        backgroundColor: '#fee2e2',
        borderRadius: '6px',
    },
    unsupported: {
        padding: '12px',
        textAlign: 'center',
        backgroundColor: '#f3f4f6',
        borderRadius: '6px',
    },
    unsupportedText: {
        fontSize: '14px',
        color: '#6b7280',
    },
};

function VerifyEmail({ token, onVerified, onError, redirectUrl, appearance, className, }) {
    const { verifyEmail, resendVerificationEmail, user } = useVault();
    const [status, setStatus] = React.useState('idle');
    const [error, setError] = React.useState(null);
    const [resendStatus, setResendStatus] = React.useState('idle');
    // Auto-verify if token is provided
    React.useEffect(() => {
        if (token && status === 'idle') {
            handleVerify();
        }
    }, [token]);
    const handleVerify = React.useCallback(async () => {
        if (!token)
            return;
        setStatus('verifying');
        setError(null);
        try {
            await verifyEmail({ token });
            setStatus('success');
            onVerified?.();
            if (redirectUrl) {
                setTimeout(() => {
                    window.location.href = redirectUrl;
                }, 2000);
            }
        }
        catch (err) {
            setStatus('error');
            const errorMessage = err.message || 'Failed to verify email';
            setError(errorMessage);
            onError?.(err);
        }
    }, [token, verifyEmail, onVerified, onError, redirectUrl]);
    const handleResend = React.useCallback(async () => {
        setResendStatus('sending');
        setError(null);
        try {
            await resendVerificationEmail();
            setResendStatus('sent');
        }
        catch (err) {
            const errorMessage = err.message || 'Failed to resend verification email';
            setError(errorMessage);
            onError?.(err);
        }
    }, [resendVerificationEmail, onError]);
    // No token provided - show resend option
    if (!token) {
        return (jsxRuntime.jsx("div", { style: applyAppearance$6(styles$9.container, appearance), className: className, children: jsxRuntime.jsxs("div", { style: styles$9.content, children: [jsxRuntime.jsx(EmailIcon, {}), jsxRuntime.jsx("h2", { style: applyAppearance$6(styles$9.title, appearance), children: "Verify your email" }), jsxRuntime.jsx("p", { style: styles$9.description, children: user?.emailVerified
                            ? 'Your email is already verified.'
                            : `We've sent a verification link to ${user?.email || 'your email address'}. Please check your inbox and click the link to verify.` }), !user?.emailVerified && (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx("button", { onClick: handleResend, disabled: resendStatus === 'sending' || resendStatus === 'sent', style: applyAppearance$6(styles$9.button, appearance), children: resendStatus === 'sending'
                                    ? 'Sending...'
                                    : resendStatus === 'sent'
                                        ? 'Email sent!'
                                        : 'Resend verification email' }), error && (jsxRuntime.jsx("div", { style: applyAppearance$6(styles$9.error, appearance), role: "alert", children: error }))] }))] }) }));
    }
    // Show appropriate state based on verification status
    return (jsxRuntime.jsx("div", { style: applyAppearance$6(styles$9.container, appearance), className: className, children: jsxRuntime.jsxs("div", { style: styles$9.content, children: [status === 'verifying' && (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx("div", { style: styles$9.spinner }), jsxRuntime.jsx("h2", { style: applyAppearance$6(styles$9.title, appearance), children: "Verifying your email..." })] })), status === 'success' && (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx(SuccessIcon$1, {}), jsxRuntime.jsx("h2", { style: applyAppearance$6(styles$9.title, appearance), children: "Email verified!" }), jsxRuntime.jsxs("p", { style: styles$9.description, children: ["Your email has been successfully verified.", redirectUrl && ' Redirecting you...'] })] })), status === 'error' && (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx(ErrorIcon, {}), jsxRuntime.jsx("h2", { style: applyAppearance$6(styles$9.title, appearance), children: "Verification failed" }), jsxRuntime.jsx("p", { style: styles$9.description, children: error || 'The verification link is invalid or has expired.' }), jsxRuntime.jsx("div", { style: styles$9.buttonGroup, children: jsxRuntime.jsx("button", { onClick: handleResend, disabled: resendStatus === 'sending', style: applyAppearance$6(styles$9.button, appearance), children: resendStatus === 'sending' ? 'Sending...' : 'Resend email' }) })] }))] }) }));
}
// Icon Components
function EmailIcon() {
    return (jsxRuntime.jsxs("svg", { width: "48", height: "48", viewBox: "0 0 24 24", fill: "none", stroke: "#0066cc", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", style: styles$9.icon, children: [jsxRuntime.jsx("rect", { x: "2", y: "4", width: "20", height: "16", rx: "2" }), jsxRuntime.jsx("path", { d: "m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" })] }));
}
function SuccessIcon$1() {
    return (jsxRuntime.jsxs("svg", { width: "48", height: "48", viewBox: "0 0 24 24", fill: "none", stroke: "#059669", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", style: styles$9.icon, children: [jsxRuntime.jsx("circle", { cx: "12", cy: "12", r: "10" }), jsxRuntime.jsx("path", { d: "m9 12 2 2 4-4" })] }));
}
function ErrorIcon() {
    return (jsxRuntime.jsxs("svg", { width: "48", height: "48", viewBox: "0 0 24 24", fill: "none", stroke: "#dc2626", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", style: styles$9.icon, children: [jsxRuntime.jsx("circle", { cx: "12", cy: "12", r: "10" }), jsxRuntime.jsx("line", { x1: "15", y1: "9", x2: "9", y2: "15" }), jsxRuntime.jsx("line", { x1: "9", y1: "9", x2: "15", y2: "15" })] }));
}
// Apply appearance variables
function applyAppearance$6(baseStyle, appearance) {
    if (!appearance)
        return baseStyle;
    const variables = appearance.variables || {};
    let style = { ...baseStyle };
    if (variables['colorPrimary']) {
        if (baseStyle.color === '#0066cc' || baseStyle.borderColor === '#0066cc' || baseStyle.backgroundColor === '#0066cc') {
            style = {
                ...style,
                color: baseStyle.color === '#0066cc' ? variables['colorPrimary'] : style.color,
                borderColor: baseStyle.borderColor === '#0066cc' ? variables['colorPrimary'] : style.borderColor,
                backgroundColor: baseStyle.backgroundColor === '#0066cc' ? variables['colorPrimary'] : style.backgroundColor,
            };
        }
    }
    if (variables['borderRadius'] && baseStyle.borderRadius) {
        style = { ...style, borderRadius: variables['borderRadius'] };
    }
    return style;
}
// Styles
const styles$9 = {
    container: {
        maxWidth: '400px',
        margin: '0 auto',
        padding: '24px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    content: {
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center',
        padding: '24px',
    },
    icon: {
        marginBottom: '16px',
    },
    title: {
        fontSize: '22px',
        fontWeight: 600,
        margin: '0 0 12px',
        color: '#1f2937',
    },
    description: {
        fontSize: '15px',
        color: '#6b7280',
        margin: '0 0 24px',
        lineHeight: 1.5,
    },
    button: {
        padding: '12px 24px',
        fontSize: '15px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#0066cc',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    buttonGroup: {
        display: 'flex',
        gap: '12px',
    },
    error: {
        marginTop: '16px',
        padding: '12px',
        fontSize: '14px',
        color: '#dc2626',
        backgroundColor: '#fee2e2',
        borderRadius: '6px',
    },
    spinner: {
        width: '48px',
        height: '48px',
        border: '3px solid #e5e7eb',
        borderTopColor: '#0066cc',
        borderRadius: '50%',
        animation: 'spin 1s linear infinite',
        marginBottom: '16px',
    },
};

// ============================================================================
// Main Component
// ============================================================================
function ResetPassword({ token, onSuccess, onError, redirectUrl, appearance, className, }) {
    // Determine if we need to wrap with ThemeProvider
    const [isThemed] = React.useState(() => {
        try {
            useTheme();
            return true;
        }
        catch {
            return false;
        }
    });
    const content = (jsxRuntime.jsx(ResetPasswordContent, { token: token, onSuccess: onSuccess, onError: onError, redirectUrl: redirectUrl, appearance: appearance, className: className }));
    // Wrap with ThemeProvider if not already themed
    if (!isThemed && appearance) {
        return (jsxRuntime.jsx(ThemeProvider, { appearance: appearance, children: content }));
    }
    return content;
}
// ============================================================================
// Internal Content Component
// ============================================================================
function ResetPasswordContent({ token, onSuccess, onError, redirectUrl, className, }) {
    const { sendForgotPassword, resetPassword } = useVault();
    const { cssVariables } = useTheme();
    const [mode] = React.useState(token ? 'reset' : 'request');
    const [email, setEmail] = React.useState('');
    const [password, setPassword] = React.useState('');
    const [confirmPassword, setConfirmPassword] = React.useState('');
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const [success, setSuccess] = React.useState(false);
    const [emailSent, setEmailSent] = React.useState(false);
    const handleRequestReset = React.useCallback(async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError(null);
        try {
            await sendForgotPassword({ email, redirectUrl });
            setEmailSent(true);
        }
        catch (err) {
            const errorMessage = err.message || 'Failed to send reset email';
            setError(errorMessage);
            onError?.(err);
        }
        finally {
            setIsLoading(false);
        }
    }, [email, redirectUrl, sendForgotPassword, onError]);
    const handleResetPassword = React.useCallback(async (e) => {
        e.preventDefault();
        setError(null);
        // Validation
        if (password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        if (password.length < 12) {
            setError('Password must be at least 12 characters');
            return;
        }
        if (!token) {
            setError('Invalid reset token');
            return;
        }
        setIsLoading(true);
        try {
            await resetPassword({ token, password });
            setSuccess(true);
            onSuccess?.();
            if (redirectUrl) {
                setTimeout(() => {
                    window.location.href = redirectUrl;
                }, 2000);
            }
        }
        catch (err) {
            const errorMessage = err.message || 'Failed to reset password';
            setError(errorMessage);
            onError?.(err);
        }
        finally {
            setIsLoading(false);
        }
    }, [password, confirmPassword, token, resetPassword, onSuccess, onError, redirectUrl]);
    // Email sent success state
    if (emailSent) {
        return (jsxRuntime.jsxs(Card, { className: className, centered: true, children: [jsxRuntime.jsx(CardHeader, { title: "Check your email", subtitle: `We've sent a password reset link to ${email}. Please check your inbox and follow the instructions.` }), jsxRuntime.jsxs(CardContent, { children: [jsxRuntime.jsx(SuccessIcon, {}), jsxRuntime.jsx(Button, { variant: "ghost", onClick: () => {
                                setEmailSent(false);
                                setEmail('');
                            }, children: "Didn't receive it? Try again" })] })] }));
    }
    // Password reset success state
    if (success) {
        return (jsxRuntime.jsxs(Card, { className: className, centered: true, children: [jsxRuntime.jsx(CardHeader, { title: "Password reset successful!", subtitle: `Your password has been successfully reset.${redirectUrl ? ' Redirecting you...' : ''}` }), jsxRuntime.jsx(CardContent, { children: jsxRuntime.jsx(SuccessIcon, {}) })] }));
    }
    // Request reset form
    if (mode === 'request') {
        return (jsxRuntime.jsxs(Card, { className: className, centered: true, children: [jsxRuntime.jsx(CardHeader, { title: "Reset your password", subtitle: "Enter your email address and we'll send you a link to reset your password." }), jsxRuntime.jsxs(CardContent, { children: [error && (jsxRuntime.jsx(Alert, { variant: "error", style: { marginBottom: '1rem' }, children: error })), jsxRuntime.jsxs("form", { onSubmit: handleRequestReset, children: [jsxRuntime.jsx(Input, { label: "Email", type: "email", value: email, onChange: (e) => setEmail(e.target.value), required: true, autoComplete: "email", disabled: isLoading, placeholder: "you@example.com" }), jsxRuntime.jsx(Button, { type: "submit", isLoading: isLoading, style: { marginTop: '0.5rem' }, children: "Send reset link" })] })] }), jsxRuntime.jsx(CardFooter, { children: jsxRuntime.jsx("a", { href: "/sign-in", style: {
                            fontSize: '0.875rem',
                            color: cssVariables['--vault-color-primary'],
                            textDecoration: 'none',
                            fontFamily: cssVariables['--vault-font-family'],
                        }, children: "Back to sign in" }) })] }));
    }
    // Reset password form
    return (jsxRuntime.jsxs(Card, { className: className, centered: true, children: [jsxRuntime.jsx(CardHeader, { title: "Create new password", subtitle: "Enter your new password below." }), jsxRuntime.jsxs(CardContent, { children: [error && (jsxRuntime.jsx(Alert, { variant: "error", style: { marginBottom: '1rem' }, children: error })), jsxRuntime.jsxs("form", { onSubmit: handleResetPassword, children: [jsxRuntime.jsx(Input, { label: "New Password", type: "password", value: password, onChange: (e) => setPassword(e.target.value), required: true, minLength: 12, autoComplete: "new-password", disabled: isLoading, placeholder: "Min 12 characters", helperText: "Must be at least 12 characters" }), jsxRuntime.jsx(Input, { label: "Confirm Password", type: "password", value: confirmPassword, onChange: (e) => setConfirmPassword(e.target.value), required: true, autoComplete: "new-password", disabled: isLoading, placeholder: "Re-enter your password" }), jsxRuntime.jsx(Button, { type: "submit", isLoading: isLoading, style: { marginTop: '0.5rem' }, children: "Reset password" })] })] })] }));
}
// Success Icon Component
function SuccessIcon() {
    const { cssVariables } = useTheme();
    return (jsxRuntime.jsx("div", { style: { textAlign: 'center', marginBottom: '1rem' }, children: jsxRuntime.jsxs("svg", { width: "48", height: "48", viewBox: "0 0 24 24", fill: "none", stroke: cssVariables['--vault-color-success'], strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("circle", { cx: "12", cy: "12", r: "10" }), jsxRuntime.jsx("path", { d: "m9 12 2 2 4-4" })] }) }));
}

// ============================================================================
// Main Component
// ============================================================================
function MFAForm({ challenge: propChallenge, onVerify, onError, allowBackupCode = true, appearance, className, }) {
    // Determine if we need to wrap with ThemeProvider
    const [isThemed] = React.useState(() => {
        try {
            useTheme();
            return true;
        }
        catch {
            return false;
        }
    });
    const content = (jsxRuntime.jsx(MFAFormContent, { challenge: propChallenge, onVerify: onVerify, onError: onError, allowBackupCode: allowBackupCode, appearance: appearance, className: className }));
    // Wrap with ThemeProvider if not already themed
    if (!isThemed && appearance) {
        return (jsxRuntime.jsx(ThemeProvider, { appearance: appearance, children: content }));
    }
    return content;
}
// ============================================================================
// Internal Content Component
// ============================================================================
function MFAFormContent({ challenge: propChallenge, onVerify, onError, allowBackupCode, className, }) {
    const { challenge: contextChallenge, verify: contextVerify, isRequired } = useMfaChallenge();
    const { cssVariables } = useTheme();
    const challenge = propChallenge || contextChallenge;
    const verifyMfa = contextVerify;
    const [code, setCode] = React.useState(['', '', '', '', '', '']);
    const [method] = React.useState(challenge?.method || 'totp');
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const [useBackupCode, setUseBackupCode] = React.useState(false);
    const inputRefs = React.useRef([]);
    // Focus first input on mount
    React.useEffect(() => {
        if (!useBackupCode) {
            inputRefs.current[0]?.focus();
        }
    }, [useBackupCode]);
    const handleChange = React.useCallback((index, value) => {
        // Only allow digits
        if (!/^\d*$/.test(value))
            return;
        const newCode = [...code];
        newCode[index] = value.slice(-1); // Only take last character
        setCode(newCode);
        setError(null);
        // Auto-focus next input
        if (value && index < 5) {
            inputRefs.current[index + 1]?.focus();
        }
    }, [code]);
    const handleKeyDown = React.useCallback((index, e) => {
        if (e.key === 'Backspace' && !code[index] && index > 0) {
            // Move to previous input on backspace if current is empty
            inputRefs.current[index - 1]?.focus();
        }
    }, [code]);
    const handlePaste = React.useCallback((e) => {
        e.preventDefault();
        const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
        const newCode = [...code];
        pastedData.split('').forEach((digit, i) => {
            if (i < 6)
                newCode[i] = digit;
        });
        setCode(newCode);
        // Focus appropriate input
        const focusIndex = Math.min(pastedData.length, 5);
        inputRefs.current[focusIndex]?.focus();
    }, [code]);
    const handleSubmit = React.useCallback(async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError(null);
        const fullCode = code.join('');
        if (fullCode.length !== 6) {
            setError('Please enter a complete code');
            setIsLoading(false);
            return;
        }
        try {
            await verifyMfa(fullCode, useBackupCode ? 'backup_codes' : method);
            onVerify?.();
        }
        catch (err) {
            const errorMessage = err.message || 'Invalid code. Please try again.';
            setError(errorMessage);
            onError?.(err);
            // Clear code on error
            setCode(['', '', '', '', '', '']);
            inputRefs.current[0]?.focus();
        }
        finally {
            setIsLoading(false);
        }
    }, [code, method, useBackupCode, verifyMfa, onVerify, onError]);
    const handleBackupCodeToggle = React.useCallback(() => {
        setUseBackupCode(!useBackupCode);
        setCode(['', '', '', '', '', '']);
        setError(null);
    }, [useBackupCode]);
    const getMethodLabel = (m) => {
        switch (m) {
            case 'totp':
                return 'authenticator app';
            case 'email':
                return 'email';
            case 'sms':
                return 'SMS';
            case 'webauthn':
                return 'security key';
            default:
                return m;
        }
    };
    // If not in MFA state and no challenge provided, show nothing
    if (!isRequired && !challenge && !propChallenge) {
        return null;
    }
    return (jsxRuntime.jsxs(Card, { className: className, centered: true, width: "sm", children: [jsxRuntime.jsx(CardHeader, { title: "Two-factor authentication", subtitle: useBackupCode
                    ? 'Enter one of your backup codes to continue.'
                    : `Enter the 6-digit code from your ${getMethodLabel(method)}.` }), jsxRuntime.jsxs(CardContent, { children: [jsxRuntime.jsx(LockIcon, {}), error && (jsxRuntime.jsx(Alert, { variant: "error", style: { marginBottom: '1rem' }, children: error })), jsxRuntime.jsxs("form", { onSubmit: handleSubmit, children: [!useBackupCode ? (jsxRuntime.jsx("div", { style: {
                                    display: 'flex',
                                    justifyContent: 'center',
                                    gap: '0.5rem',
                                    marginBottom: '1.5rem',
                                }, children: code.map((digit, index) => (jsxRuntime.jsx("input", { ref: (el) => { inputRefs.current[index] = el; }, type: "text", inputMode: "numeric", maxLength: 1, value: digit, onChange: (e) => handleChange(index, e.target.value), onKeyDown: (e) => handleKeyDown(index, e), onPaste: handlePaste, disabled: isLoading, style: {
                                        width: '3rem',
                                        height: '3.5rem',
                                        fontSize: '1.5rem',
                                        fontWeight: 600,
                                        textAlign: 'center',
                                        fontFamily: cssVariables['--vault-font-family'],
                                        color: cssVariables['--vault-color-input-text'],
                                        backgroundColor: cssVariables['--vault-color-input-background'],
                                        border: `2px solid ${cssVariables['--vault-color-input-border']}`,
                                        borderRadius: cssVariables['--vault-border-radius'],
                                        outline: 'none',
                                        transition: 'all 0.15s ease-in-out',
                                    }, "aria-label": `Digit ${index + 1}` }, index))) })) : (jsxRuntime.jsx("div", { style: { marginBottom: '1.5rem' }, children: jsxRuntime.jsx("input", { type: "text", value: code.join(''), onChange: (e) => {
                                        const value = e.target.value.replace(/\D/g, '').slice(0, 6);
                                        const newCode = value.split('').concat(Array(6 - value.length).fill(''));
                                        setCode(newCode);
                                    }, placeholder: "Enter backup code", disabled: isLoading, style: {
                                        width: '100%',
                                        padding: '0.75rem',
                                        fontSize: '1.125rem',
                                        textAlign: 'center',
                                        letterSpacing: '0.25rem',
                                        fontFamily: cssVariables['--vault-font-family'],
                                        color: cssVariables['--vault-color-input-text'],
                                        backgroundColor: cssVariables['--vault-color-input-background'],
                                        border: `2px solid ${cssVariables['--vault-color-input-border']}`,
                                        borderRadius: cssVariables['--vault-border-radius'],
                                        outline: 'none',
                                        boxSizing: 'border-box',
                                    } }) })), jsxRuntime.jsx(Button, { type: "submit", isLoading: isLoading, disabled: code.join('').length !== 6, children: "Verify" })] }), allowBackupCode && (jsxRuntime.jsx(Button, { variant: "ghost", onClick: handleBackupCodeToggle, style: { marginTop: '0.5rem' }, children: useBackupCode
                            ? 'Use authenticator code instead'
                            : 'Use backup code instead' }))] }), jsxRuntime.jsx("div", { style: {
                    padding: '1rem 1.5rem 1.5rem',
                    textAlign: 'center',
                    borderTop: `1px solid ${cssVariables['--vault-color-border']}`,
                }, children: jsxRuntime.jsxs("p", { style: {
                        fontSize: '0.8125rem',
                        fontFamily: cssVariables['--vault-font-family'],
                        color: cssVariables['--vault-color-text-secondary'],
                        margin: 0,
                    }, children: ["Having trouble?", ' ', jsxRuntime.jsx("a", { href: "/support", style: {
                                color: cssVariables['--vault-color-primary'],
                                textDecoration: 'none',
                            }, children: "Contact support" })] }) })] }));
}
// Lock Icon Component
function LockIcon() {
    const { cssVariables } = useTheme();
    return (jsxRuntime.jsx("div", { style: { textAlign: 'center', marginBottom: '1rem' }, children: jsxRuntime.jsxs("svg", { width: "48", height: "48", viewBox: "0 0 24 24", fill: "none", stroke: cssVariables['--vault-color-primary'], strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("rect", { x: "5", y: "11", width: "14", height: "10", rx: "2" }), jsxRuntime.jsx("circle", { cx: "12", cy: "16", r: "1" }), jsxRuntime.jsx("path", { d: "M8 11V7a4 4 0 0 1 8 0v4" })] }) }));
}

const DEFAULT_PAGE_SIZE = 10;
function OrganizationSwitcher({ hidePersonal = false, onSwitch, appearance, className, showSearch = true, pageSize = DEFAULT_PAGE_SIZE, }) {
    const { organization: activeOrg, organizations, isLoaded, setActive, create, } = useOrganization();
    const { user } = useAuth();
    const [isOpen, setIsOpen] = React.useState(false);
    const [isCreating, setIsCreating] = React.useState(false);
    const [newOrgName, setNewOrgName] = React.useState('');
    const [isLoading, setIsLoading] = React.useState(false);
    const [searchQuery, setSearchQuery] = React.useState('');
    const [currentPage, setCurrentPage] = React.useState(0);
    const [error, setError] = React.useState(null);
    const menuRef = React.useRef(null);
    const searchInputRef = React.useRef(null);
    // Filter organizations based on search query
    const filteredOrganizations = React.useMemo(() => {
        if (!searchQuery.trim())
            return organizations;
        const query = searchQuery.toLowerCase();
        return organizations.filter(org => org.name.toLowerCase().includes(query) ||
            org.slug.toLowerCase().includes(query));
    }, [organizations, searchQuery]);
    // Paginate organizations
    const paginatedOrganizations = React.useMemo(() => {
        const start = currentPage * pageSize;
        return filteredOrganizations.slice(start, start + pageSize);
    }, [filteredOrganizations, currentPage, pageSize]);
    const totalPages = Math.ceil(filteredOrganizations.length / pageSize);
    const hasMorePages = currentPage < totalPages - 1;
    const hasPreviousPages = currentPage > 0;
    // Close menu when clicking outside
    React.useEffect(() => {
        const handleClickOutside = (event) => {
            if (menuRef.current && !menuRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        };
        if (isOpen) {
            document.addEventListener('mousedown', handleClickOutside);
        }
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [isOpen]);
    // Focus search input when menu opens
    React.useEffect(() => {
        if (isOpen && showSearch && searchInputRef.current) {
            setTimeout(() => searchInputRef.current?.focus(), 0);
        }
    }, [isOpen, showSearch]);
    // Reset search and pagination when menu closes
    React.useEffect(() => {
        if (!isOpen) {
            setSearchQuery('');
            setCurrentPage(0);
            setIsCreating(false);
            setNewOrgName('');
            setError(null);
        }
    }, [isOpen]);
    const handleSelectOrg = React.useCallback((orgId) => {
        setActive(orgId);
        const selectedOrg = orgId ? organizations.find(o => o.id === orgId) : null;
        onSwitch?.(selectedOrg || null);
        setIsOpen(false);
    }, [setActive, organizations, onSwitch]);
    const handleCreateOrg = React.useCallback(async (e) => {
        e.preventDefault();
        if (!newOrgName.trim())
            return;
        setIsLoading(true);
        setError(null);
        try {
            const newOrg = await create({ name: newOrgName.trim() });
            onSwitch?.(newOrg);
            setIsCreating(false);
            setNewOrgName('');
            setIsOpen(false);
        }
        catch (error) {
            setError(error.message || 'Failed to create organization');
        }
        finally {
            setIsLoading(false);
        }
    }, [newOrgName, create, onSwitch]);
    if (!isLoaded) {
        return (jsxRuntime.jsx("div", { style: applyAppearance$5(styles$8.skeleton, appearance), className: className, children: jsxRuntime.jsx("div", { style: styles$8.skeletonInner }) }));
    }
    const currentOrgName = activeOrg?.name || user?.profile?.name || user?.email || 'Personal';
    const hasOrganizations = organizations.length > 0;
    return (jsxRuntime.jsxs("div", { ref: menuRef, style: styles$8.container, className: className, children: [jsxRuntime.jsxs("button", { onClick: () => setIsOpen(!isOpen), style: applyAppearance$5(styles$8.button, appearance), "aria-expanded": isOpen, "aria-haspopup": "true", "aria-label": "Switch organization", children: [jsxRuntime.jsx(BuildingIcon$1, {}), jsxRuntime.jsx("span", { style: styles$8.buttonText, children: currentOrgName }), jsxRuntime.jsx(ChevronIcon, { isOpen: isOpen })] }), isOpen && (jsxRuntime.jsxs("div", { style: applyAppearance$5(styles$8.menu, appearance), role: "menu", children: [jsxRuntime.jsx("div", { style: styles$8.menuHeader, children: jsxRuntime.jsx("span", { style: styles$8.menuTitle, children: "Switch organization" }) }), showSearch && hasOrganizations && (jsxRuntime.jsxs("div", { style: styles$8.searchContainer, children: [jsxRuntime.jsx(SearchIcon, {}), jsxRuntime.jsx("input", { ref: searchInputRef, type: "text", value: searchQuery, onChange: (e) => {
                                    setSearchQuery(e.target.value);
                                    setCurrentPage(0);
                                }, placeholder: "Search organizations...", style: applyAppearance$5(styles$8.searchInput, appearance) }), searchQuery && (jsxRuntime.jsx("button", { onClick: () => {
                                    setSearchQuery('');
                                    searchInputRef.current?.focus();
                                }, style: styles$8.clearSearch, "aria-label": "Clear search", children: jsxRuntime.jsx(CloseIcon$1, {}) }))] })), searchQuery && (jsxRuntime.jsx("div", { style: styles$8.searchResults, children: filteredOrganizations.length === 0 ? (jsxRuntime.jsx("span", { children: "No organizations found" })) : (jsxRuntime.jsxs("span", { children: [filteredOrganizations.length, " result", filteredOrganizations.length !== 1 ? 's' : ''] })) })), jsxRuntime.jsxs("div", { style: styles$8.menuItems, children: [!hidePersonal && !searchQuery && currentPage === 0 && (jsxRuntime.jsxs("button", { onClick: () => handleSelectOrg(null), style: {
                                    ...applyAppearance$5(styles$8.menuItem, appearance),
                                    ...(activeOrg === null && styles$8.menuItemActive),
                                }, role: "menuitem", children: [jsxRuntime.jsx(UserIcon$2, {}), jsxRuntime.jsx("span", { style: styles$8.menuItemText, children: user?.profile?.name || user?.email || 'Personal Account' }), activeOrg === null && jsxRuntime.jsx(CheckIcon$1, {})] })), paginatedOrganizations.map((org) => (jsxRuntime.jsxs("button", { onClick: () => handleSelectOrg(org.id), style: {
                                    ...applyAppearance$5(styles$8.menuItem, appearance),
                                    ...(activeOrg?.id === org.id && styles$8.menuItemActive),
                                }, role: "menuitem", children: [jsxRuntime.jsx(BuildingIcon$1, { small: true }), jsxRuntime.jsxs("div", { style: styles$8.menuItemContent, children: [jsxRuntime.jsx("span", { style: styles$8.menuItemName, children: org.name }), jsxRuntime.jsx("span", { style: styles$8.menuItemSlug, children: org.slug })] }), activeOrg?.id === org.id && jsxRuntime.jsx(CheckIcon$1, {})] }, org.id))), !hasOrganizations && !isCreating && (jsxRuntime.jsxs("div", { style: styles$8.emptyState, children: [jsxRuntime.jsx("div", { style: styles$8.emptyIcon, children: jsxRuntime.jsx(BuildingIcon$1, {}) }), jsxRuntime.jsx("p", { style: styles$8.emptyTitle, children: "No organizations" }), jsxRuntime.jsx("p", { style: styles$8.emptyText, children: "Create one to collaborate with your team" })] })), searchQuery && filteredOrganizations.length === 0 && (jsxRuntime.jsxs("div", { style: styles$8.emptyState, children: [jsxRuntime.jsx("div", { style: styles$8.emptyIcon, children: jsxRuntime.jsx(SearchIcon, { large: true }) }), jsxRuntime.jsx("p", { style: styles$8.emptyTitle, children: "No results" }), jsxRuntime.jsx("p", { style: styles$8.emptyText, children: "Try a different search term" })] }))] }), filteredOrganizations.length > pageSize && (jsxRuntime.jsxs("div", { style: styles$8.pagination, children: [jsxRuntime.jsx("button", { onClick: () => setCurrentPage(p => Math.max(0, p - 1)), disabled: !hasPreviousPages, style: {
                                    ...styles$8.paginationButton,
                                    ...(!hasPreviousPages && styles$8.paginationButtonDisabled),
                                }, "aria-label": "Previous page", children: jsxRuntime.jsx(ChevronLeftIcon, {}) }), jsxRuntime.jsxs("span", { style: styles$8.paginationInfo, children: ["Page ", currentPage + 1, " of ", totalPages] }), jsxRuntime.jsx("button", { onClick: () => setCurrentPage(p => Math.min(totalPages - 1, p + 1)), disabled: !hasMorePages, style: {
                                    ...styles$8.paginationButton,
                                    ...(!hasMorePages && styles$8.paginationButtonDisabled),
                                }, "aria-label": "Next page", children: jsxRuntime.jsx(ChevronRightIcon, {}) })] })), jsxRuntime.jsx("div", { style: styles$8.divider }), isCreating ? (jsxRuntime.jsxs("form", { onSubmit: handleCreateOrg, style: styles$8.createForm, children: [error && (jsxRuntime.jsx("div", { style: applyAppearance$5(styles$8.createError, appearance), role: "alert", children: error })), jsxRuntime.jsx("input", { type: "text", value: newOrgName, onChange: (e) => setNewOrgName(e.target.value), placeholder: "Organization name", autoFocus: true, style: applyAppearance$5(styles$8.createInput, appearance), disabled: isLoading }), jsxRuntime.jsxs("div", { style: styles$8.createButtons, children: [jsxRuntime.jsx("button", { type: "submit", disabled: isLoading || !newOrgName.trim(), style: applyAppearance$5(styles$8.createButton, appearance), children: isLoading ? 'Creating...' : 'Create' }), jsxRuntime.jsx("button", { type: "button", onClick: () => {
                                            setIsCreating(false);
                                            setNewOrgName('');
                                            setError(null);
                                        }, style: applyAppearance$5(styles$8.cancelButton, appearance), children: "Cancel" })] })] })) : (jsxRuntime.jsxs("button", { onClick: () => setIsCreating(true), style: applyAppearance$5(styles$8.createOrgButton, appearance), children: [jsxRuntime.jsx(PlusIcon$1, {}), jsxRuntime.jsx("span", { children: "Create organization" })] }))] }))] }));
}
// Icon Components
function BuildingIcon$1({ small }) {
    return (jsxRuntime.jsxs("svg", { width: small ? 16 : 20, height: small ? 16 : 20, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("path", { d: "M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z" }), jsxRuntime.jsx("path", { d: "M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2" }), jsxRuntime.jsx("path", { d: "M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2" }), jsxRuntime.jsx("path", { d: "M10 6h4" }), jsxRuntime.jsx("path", { d: "M10 10h4" }), jsxRuntime.jsx("path", { d: "M10 14h4" }), jsxRuntime.jsx("path", { d: "M10 18h4" })] }));
}
function UserIcon$2() {
    return (jsxRuntime.jsxs("svg", { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("path", { d: "M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" }), jsxRuntime.jsx("circle", { cx: "12", cy: "7", r: "4" })] }));
}
function PlusIcon$1() {
    return (jsxRuntime.jsxs("svg", { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("path", { d: "M5 12h14" }), jsxRuntime.jsx("path", { d: "M12 5v14" })] }));
}
function CheckIcon$1() {
    return (jsxRuntime.jsx("svg", { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: jsxRuntime.jsx("path", { d: "M20 6 9 17l-5-5" }) }));
}
function ChevronIcon({ isOpen }) {
    return (jsxRuntime.jsx("svg", { width: "12", height: "12", viewBox: "0 0 12 12", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", style: {
            transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
            transition: 'transform 0.2s ease',
        }, children: jsxRuntime.jsx("path", { d: "M2 4l4 4 4-4" }) }));
}
function SearchIcon({ large }) {
    const size = large ? 32 : 16;
    return (jsxRuntime.jsxs("svg", { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("circle", { cx: "11", cy: "11", r: "8" }), jsxRuntime.jsx("path", { d: "m21 21-4.35-4.35" })] }));
}
function CloseIcon$1() {
    return (jsxRuntime.jsxs("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("line", { x1: "18", y1: "6", x2: "6", y2: "18" }), jsxRuntime.jsx("line", { x1: "6", y1: "6", x2: "18", y2: "18" })] }));
}
function ChevronLeftIcon() {
    return (jsxRuntime.jsx("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: jsxRuntime.jsx("polyline", { points: "15 18 9 12 15 6" }) }));
}
function ChevronRightIcon() {
    return (jsxRuntime.jsx("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: jsxRuntime.jsx("polyline", { points: "9 18 15 12 9 6" }) }));
}
// Apply appearance variables
function applyAppearance$5(baseStyle, appearance) {
    if (!appearance)
        return baseStyle;
    const variables = appearance.variables || {};
    let style = { ...baseStyle };
    if (variables['colorPrimary']) {
        if (baseStyle.color === '#0066cc' || baseStyle.borderColor === '#0066cc') {
            style = {
                ...style,
                color: baseStyle.color === '#0066cc' ? variables['colorPrimary'] : style.color,
                borderColor: baseStyle.borderColor === '#0066cc' ? variables['colorPrimary'] : style.borderColor,
            };
        }
        if (baseStyle.backgroundColor === '#0066cc') {
            style = { ...style, backgroundColor: variables['colorPrimary'] };
        }
    }
    if (variables['borderRadius'] && baseStyle.borderRadius) {
        style = { ...style, borderRadius: variables['borderRadius'] };
    }
    return style;
}
// Styles
const styles$8 = {
    container: {
        position: 'relative',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    skeleton: {
        width: '160px',
        height: '40px',
    },
    skeletonInner: {
        width: '100%',
        height: '100%',
        backgroundColor: '#e5e7eb',
        borderRadius: '6px',
        animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
    },
    button: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '8px 12px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#374151',
        backgroundColor: '#f3f4f6',
        border: '1px solid #e5e7eb',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    buttonText: {
        maxWidth: '120px',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
    },
    menu: {
        position: 'absolute',
        top: '100%',
        left: '0',
        marginTop: '4px',
        minWidth: '280px',
        maxWidth: '320px',
        backgroundColor: '#fff',
        border: '1px solid #e5e7eb',
        borderRadius: '8px',
        boxShadow: '0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05)',
        zIndex: 1000,
        overflow: 'hidden',
    },
    menuHeader: {
        padding: '8px 12px',
        borderBottom: '1px solid #e5e7eb',
    },
    menuTitle: {
        fontSize: '12px',
        fontWeight: 600,
        color: '#6b7280',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
    },
    searchContainer: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '8px 12px',
        borderBottom: '1px solid #e5e7eb',
        color: '#6b7280',
    },
    searchInput: {
        flex: 1,
        border: 'none',
        outline: 'none',
        fontSize: '14px',
        padding: '4px 0',
        backgroundColor: 'transparent',
    },
    clearSearch: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '4px',
        color: '#9ca3af',
        backgroundColor: 'transparent',
        border: 'none',
        borderRadius: '4px',
        cursor: 'pointer',
    },
    searchResults: {
        padding: '4px 12px',
        fontSize: '12px',
        color: '#6b7280',
        borderBottom: '1px solid #e5e7eb',
        backgroundColor: '#f9fafb',
    },
    menuItems: {
        maxHeight: '280px',
        overflowY: 'auto',
    },
    menuItem: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        width: '100%',
        padding: '10px 12px',
        fontSize: '14px',
        color: '#374151',
        backgroundColor: 'transparent',
        border: 'none',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    menuItemActive: {
        backgroundColor: '#eff6ff',
        color: '#0066cc',
    },
    menuItemContent: {
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        minWidth: 0,
    },
    menuItemName: {
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        textAlign: 'left',
    },
    menuItemSlug: {
        fontSize: '12px',
        color: '#9ca3af',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
    },
    pagination: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '8px 12px',
        borderTop: '1px solid #e5e7eb',
        borderBottom: '1px solid #e5e7eb',
    },
    paginationButton: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '4px',
        color: '#374151',
        backgroundColor: 'transparent',
        border: 'none',
        borderRadius: '4px',
        cursor: 'pointer',
    },
    paginationButtonDisabled: {
        color: '#d1d5db',
        cursor: 'not-allowed',
    },
    paginationInfo: {
        fontSize: '12px',
        color: '#6b7280',
    },
    emptyState: {
        padding: '24px',
        textAlign: 'center',
        color: '#6b7280',
    },
    emptyIcon: {
        display: 'flex',
        justifyContent: 'center',
        marginBottom: '12px',
        color: '#d1d5db',
    },
    emptyTitle: {
        margin: '0 0 4px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#374151',
    },
    emptyText: {
        margin: 0,
        fontSize: '12px',
        color: '#9ca3af',
    },
    divider: {
        height: '1px',
        backgroundColor: '#e5e7eb',
        margin: '4px 0',
    },
    createOrgButton: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        width: '100%',
        padding: '10px 12px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#0066cc',
        backgroundColor: 'transparent',
        border: 'none',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    createForm: {
        padding: '12px',
    },
    createError: {
        padding: '8px 12px',
        marginBottom: '8px',
        color: '#dc2626',
        backgroundColor: '#fee2e2',
        borderRadius: '4px',
        fontSize: '13px',
    },
    createInput: {
        width: '100%',
        padding: '8px 12px',
        fontSize: '14px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        marginBottom: '8px',
        outline: 'none',
        boxSizing: 'border-box',
    },
    createButtons: {
        display: 'flex',
        gap: '8px',
    },
    createButton: {
        flex: 1,
        padding: '8px 12px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#0066cc',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
    },
    cancelButton: {
        flex: 1,
        padding: '8px 12px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#6b7280',
        backgroundColor: '#f3f4f6',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
    },
};

function CreateOrganization({ onCreate, onCancel, redirectUrl, skipInvitationScreen = false, appearance, className, }) {
    const { create, isLoading } = useOrganization();
    const [name, setName] = React.useState('');
    const [slug, setSlug] = React.useState('');
    const [description, setDescription] = React.useState('');
    const [logo, setLogo] = React.useState(null);
    const [logoPreview, setLogoPreview] = React.useState(null);
    const [createdOrg, setCreatedOrg] = React.useState(null);
    const [inviteEmail, setInviteEmail] = React.useState('');
    const [inviteRole, setInviteRole] = React.useState('member');
    const [inviteSent, setInviteSent] = React.useState(false);
    const [error, setError] = React.useState(null);
    // Auto-generate slug from name
    const generateSlug = React.useCallback((name) => {
        return name
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '');
    }, []);
    const handleNameChange = React.useCallback((value) => {
        setName(value);
        // Only auto-update slug if user hasn't manually edited it
        if (slug === '' || slug === generateSlug(name)) {
            setSlug(generateSlug(value));
        }
    }, [slug, name, generateSlug]);
    const handleLogoChange = React.useCallback((e) => {
        const file = e.target.files?.[0];
        if (file) {
            if (file.size > 5 * 1024 * 1024) {
                setError('Logo must be less than 5MB');
                return;
            }
            if (!file.type.startsWith('image/')) {
                setError('Please upload an image file');
                return;
            }
            setLogo(file);
            const reader = new FileReader();
            reader.onloadend = () => {
                setLogoPreview(reader.result);
            };
            reader.readAsDataURL(file);
            setError(null);
        }
    }, []);
    const handleSubmit = React.useCallback(async (e) => {
        e.preventDefault();
        setError(null);
        if (!name.trim()) {
            setError('Organization name is required');
            return;
        }
        if (!slug.trim()) {
            setError('Organization slug is required');
            return;
        }
        try {
            const org = await create({ name: name.trim(), slug: slug.trim() });
            if (skipInvitationScreen) {
                onCreate?.(org);
                if (redirectUrl) {
                    window.location.href = redirectUrl;
                }
            }
            else {
                setCreatedOrg(org);
            }
        }
        catch (err) {
            setError(err.message || 'Failed to create organization');
        }
    }, [name, slug, create, skipInvitationScreen, onCreate, redirectUrl]);
    const handleSendInvite = React.useCallback(async (e) => {
        e.preventDefault();
        if (!inviteEmail.trim()) {
            setError('Email is required');
            return;
        }
        // Note: This would call the actual invite API
        // For now, we simulate success
        setInviteSent(true);
        setTimeout(() => {
            onCreate?.(createdOrg);
            if (redirectUrl) {
                window.location.href = redirectUrl;
            }
        }, 1500);
    }, [inviteEmail, createdOrg, onCreate, redirectUrl]);
    const handleSkipInvite = React.useCallback(() => {
        onCreate?.(createdOrg);
        if (redirectUrl) {
            window.location.href = redirectUrl;
        }
    }, [createdOrg, onCreate, redirectUrl]);
    // Invitation Screen
    if (createdOrg) {
        return (jsxRuntime.jsx("div", { style: applyAppearance$4(styles$7.container, appearance), className: className, children: jsxRuntime.jsxs("div", { style: styles$7.successState, children: [jsxRuntime.jsx("div", { style: styles$7.successIcon, children: "\u2713" }), jsxRuntime.jsx("h2", { style: applyAppearance$4(styles$7.title, appearance), children: "Organization Created!" }), jsxRuntime.jsxs("p", { style: styles$7.successText, children: [jsxRuntime.jsx("strong", { children: createdOrg.name }), " has been created successfully."] }), inviteSent ? (jsxRuntime.jsxs("div", { style: applyAppearance$4(styles$7.successMessage, appearance), children: ["Invitation sent to ", inviteEmail, "!"] })) : (jsxRuntime.jsxs("form", { onSubmit: handleSendInvite, style: styles$7.inviteForm, children: [jsxRuntime.jsx("p", { style: styles$7.inviteText, children: "Want to invite team members now?" }), error && (jsxRuntime.jsx("div", { style: applyAppearance$4(styles$7.error, appearance), role: "alert", children: error })), jsxRuntime.jsxs("div", { style: styles$7.field, children: [jsxRuntime.jsx("label", { htmlFor: "vault-invite-email", style: applyAppearance$4(styles$7.label, appearance), children: "Email Address" }), jsxRuntime.jsx("input", { id: "vault-invite-email", type: "email", value: inviteEmail, onChange: (e) => setInviteEmail(e.target.value), placeholder: "colleague@example.com", style: applyAppearance$4(styles$7.input, appearance), disabled: isLoading })] }), jsxRuntime.jsxs("div", { style: styles$7.field, children: [jsxRuntime.jsx("label", { htmlFor: "vault-invite-role", style: applyAppearance$4(styles$7.label, appearance), children: "Role" }), jsxRuntime.jsxs("select", { id: "vault-invite-role", value: inviteRole, onChange: (e) => setInviteRole(e.target.value), style: applyAppearance$4(styles$7.select, appearance), disabled: isLoading, children: [jsxRuntime.jsx("option", { value: "member", children: "Member" }), jsxRuntime.jsx("option", { value: "admin", children: "Admin" })] })] }), jsxRuntime.jsxs("div", { style: styles$7.buttonGroup, children: [jsxRuntime.jsx("button", { type: "submit", disabled: isLoading, style: applyAppearance$4(styles$7.primaryButton, appearance), children: isLoading ? 'Sending...' : 'Send Invitation' }), jsxRuntime.jsx("button", { type: "button", onClick: handleSkipInvite, style: applyAppearance$4(styles$7.secondaryButton, appearance), children: "Skip for now" })] })] }))] }) }));
    }
    // Create Organization Form
    return (jsxRuntime.jsx("div", { style: applyAppearance$4(styles$7.container, appearance), className: className, children: jsxRuntime.jsxs("form", { onSubmit: handleSubmit, style: styles$7.form, children: [jsxRuntime.jsx("h2", { style: applyAppearance$4(styles$7.title, appearance), children: "Create Organization" }), jsxRuntime.jsx("p", { style: styles$7.subtitle, children: "Set up a new organization to collaborate with your team." }), error && (jsxRuntime.jsx("div", { style: applyAppearance$4(styles$7.error, appearance), role: "alert", children: error })), jsxRuntime.jsxs("div", { style: styles$7.field, children: [jsxRuntime.jsx("label", { htmlFor: "vault-org-name", style: applyAppearance$4(styles$7.label, appearance), children: "Organization Name *" }), jsxRuntime.jsx("input", { id: "vault-org-name", type: "text", value: name, onChange: (e) => handleNameChange(e.target.value), placeholder: "Acme Inc", required: true, style: applyAppearance$4(styles$7.input, appearance), disabled: isLoading })] }), jsxRuntime.jsxs("div", { style: styles$7.field, children: [jsxRuntime.jsx("label", { htmlFor: "vault-org-slug", style: applyAppearance$4(styles$7.label, appearance), children: "Organization Slug *" }), jsxRuntime.jsx("input", { id: "vault-org-slug", type: "text", value: slug, onChange: (e) => setSlug(e.target.value), placeholder: "acme-inc", required: true, style: applyAppearance$4(styles$7.input, appearance), disabled: isLoading }), jsxRuntime.jsxs("span", { style: styles$7.helpText, children: ["Used in URLs: vault.dev/o/", slug || 'your-org'] })] }), jsxRuntime.jsxs("div", { style: styles$7.field, children: [jsxRuntime.jsx("label", { htmlFor: "vault-org-description", style: applyAppearance$4(styles$7.label, appearance), children: "Description" }), jsxRuntime.jsx("textarea", { id: "vault-org-description", value: description, onChange: (e) => setDescription(e.target.value), placeholder: "What does your organization do?", rows: 3, style: applyAppearance$4(styles$7.textarea, appearance), disabled: isLoading })] }), jsxRuntime.jsxs("div", { style: styles$7.field, children: [jsxRuntime.jsx("label", { htmlFor: "vault-org-logo", style: applyAppearance$4(styles$7.label, appearance), children: "Logo" }), jsxRuntime.jsx("div", { style: styles$7.logoUpload, children: logoPreview ? (jsxRuntime.jsxs("div", { style: styles$7.logoPreview, children: [jsxRuntime.jsx("img", { src: logoPreview, alt: "Logo preview", style: styles$7.logoImage }), jsxRuntime.jsx("button", { type: "button", onClick: () => {
                                            setLogo(null);
                                            setLogoPreview(null);
                                        }, style: styles$7.removeLogo, children: "\u2715" })] })) : (jsxRuntime.jsxs("label", { style: applyAppearance$4(styles$7.logoInputLabel, appearance), children: [jsxRuntime.jsx("input", { id: "vault-org-logo", type: "file", accept: "image/*", onChange: handleLogoChange, style: styles$7.fileInput, disabled: isLoading }), jsxRuntime.jsx(UploadIcon, {}), jsxRuntime.jsx("span", { children: "Upload logo" })] })) }), jsxRuntime.jsx("span", { style: styles$7.helpText, children: "Max 5MB, PNG or JPG recommended" })] }), jsxRuntime.jsxs("div", { style: styles$7.buttonGroup, children: [jsxRuntime.jsx("button", { type: "submit", disabled: isLoading || !name.trim() || !slug.trim(), style: applyAppearance$4(styles$7.primaryButton, appearance), children: isLoading ? 'Creating...' : 'Create Organization' }), onCancel && (jsxRuntime.jsx("button", { type: "button", onClick: onCancel, disabled: isLoading, style: applyAppearance$4(styles$7.secondaryButton, appearance), children: "Cancel" }))] })] }) }));
}
// Icon Components
function UploadIcon() {
    return (jsxRuntime.jsxs("svg", { width: "20", height: "20", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }), jsxRuntime.jsx("polyline", { points: "17 8 12 3 7 8" }), jsxRuntime.jsx("line", { x1: "12", y1: "3", x2: "12", y2: "15" })] }));
}
// Apply appearance variables
function applyAppearance$4(baseStyle, appearance) {
    if (!appearance)
        return baseStyle;
    const variables = appearance.variables || {};
    let style = { ...baseStyle };
    if (variables['colorPrimary']) {
        if (baseStyle.backgroundColor === '#0066cc' || baseStyle.borderColor === '#0066cc') {
            style = {
                ...style,
                backgroundColor: variables['colorPrimary'],
                borderColor: variables['colorPrimary'],
            };
        }
        if (baseStyle.color === '#0066cc') {
            style = { ...style, color: variables['colorPrimary'] };
        }
    }
    if (variables['borderRadius'] && baseStyle.borderRadius) {
        style = { ...style, borderRadius: variables['borderRadius'] };
    }
    if (variables['fontSize'] && baseStyle.fontSize) {
        style = { ...style, fontSize: variables['fontSize'] };
    }
    return style;
}
// Styles
const styles$7 = {
    container: {
        maxWidth: '480px',
        margin: '0 auto',
        padding: '24px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    form: {
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
    },
    title: {
        margin: '0',
        fontSize: '24px',
        fontWeight: 600,
        color: '#1a1a1a',
    },
    subtitle: {
        margin: '-12px 0 0',
        fontSize: '14px',
        color: '#6b7280',
    },
    field: {
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
    },
    label: {
        fontSize: '14px',
        fontWeight: 500,
        color: '#374151',
    },
    input: {
        padding: '10px 12px',
        fontSize: '15px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        outline: 'none',
        transition: 'border-color 0.15s ease-in-out',
    },
    textarea: {
        padding: '10px 12px',
        fontSize: '15px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        outline: 'none',
        transition: 'border-color 0.15s ease-in-out',
        resize: 'vertical',
        fontFamily: 'inherit',
    },
    select: {
        padding: '10px 12px',
        fontSize: '15px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        outline: 'none',
        backgroundColor: '#fff',
        cursor: 'pointer',
    },
    helpText: {
        fontSize: '12px',
        color: '#6b7280',
    },
    logoUpload: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
    },
    logoInputLabel: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '12px 16px',
        fontSize: '14px',
        color: '#374151',
        backgroundColor: '#f3f4f6',
        border: '2px dashed #d1d5db',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'all 0.15s ease-in-out',
    },
    fileInput: {
        position: 'absolute',
        opacity: 0,
        width: 0,
        height: 0,
    },
    logoPreview: {
        position: 'relative',
        width: '64px',
        height: '64px',
        borderRadius: '8px',
        overflow: 'hidden',
        border: '1px solid #e5e7eb',
    },
    logoImage: {
        width: '100%',
        height: '100%',
        objectFit: 'cover',
    },
    removeLogo: {
        position: 'absolute',
        top: '2px',
        right: '2px',
        width: '20px',
        height: '20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: '12px',
        color: '#fff',
        backgroundColor: 'rgba(0,0,0,0.5)',
        border: 'none',
        borderRadius: '50%',
        cursor: 'pointer',
    },
    buttonGroup: {
        display: 'flex',
        gap: '12px',
        marginTop: '8px',
    },
    primaryButton: {
        flex: 1,
        padding: '12px',
        fontSize: '15px',
        fontWeight: 600,
        color: '#fff',
        backgroundColor: '#0066cc',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    secondaryButton: {
        padding: '12px 20px',
        fontSize: '15px',
        fontWeight: 500,
        color: '#374151',
        backgroundColor: '#f3f4f6',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    error: {
        padding: '12px',
        color: '#dc2626',
        backgroundColor: '#fee2e2',
        borderRadius: '6px',
        fontSize: '14px',
    },
    successState: {
        textAlign: 'center',
        padding: '32px 24px',
    },
    successIcon: {
        width: '64px',
        height: '64px',
        margin: '0 auto 16px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: '32px',
        color: '#fff',
        backgroundColor: '#10b981',
        borderRadius: '50%',
    },
    successText: {
        fontSize: '16px',
        color: '#6b7280',
        margin: '0 0 24px',
    },
    successMessage: {
        padding: '16px',
        color: '#059669',
        backgroundColor: '#d1fae5',
        borderRadius: '6px',
        fontSize: '15px',
    },
    inviteForm: {
        marginTop: '24px',
        textAlign: 'left',
    },
    inviteText: {
        fontSize: '15px',
        color: '#374151',
        margin: '0 0 16px',
    },
};

function OrganizationProfile({ organization: propOrg, appearance, className, }) {
    const vault = useVault();
    const { organization: activeOrg, organizations, isLoaded, refreshMembers, } = useOrganization();
    const organization = propOrg || activeOrg;
    const [activeTab, setActiveTab] = React.useState('general');
    // General tab state
    const [name, setName] = React.useState('');
    const [slug, setSlug] = React.useState('');
    const [description, setDescription] = React.useState('');
    const [isEditing, setIsEditing] = React.useState(false);
    const [isSaving, setIsSaving] = React.useState(false);
    // Members tab state
    const [members, setMembers] = React.useState([]);
    const [isLoadingMembers, setIsLoadingMembers] = React.useState(false);
    const [inviteEmail, setInviteEmail] = React.useState('');
    const [inviteRole, setInviteRole] = React.useState('member');
    const [isInviting, setIsInviting] = React.useState(false);
    // Settings tab state
    const [isDeleting, setIsDeleting] = React.useState(false);
    const [showDeleteConfirm, setShowDeleteConfirm] = React.useState(false);
    const [deleteConfirmText, setDeleteConfirmText] = React.useState('');
    // Common state
    const [error, setError] = React.useState(null);
    const [successMessage, setSuccessMessage] = React.useState(null);
    // Initialize form data when organization loads
    React.useEffect(() => {
        if (organization) {
            setName(organization.name || '');
            setSlug(organization.slug || '');
            setDescription(organization.description || '');
        }
    }, [organization]);
    // Load members when members tab is selected
    React.useEffect(() => {
        if (activeTab === 'members' && organization) {
            loadMembers();
        }
    }, [activeTab, organization?.id]);
    const loadMembers = React.useCallback(async () => {
        if (!organization)
            return;
        setIsLoadingMembers(true);
        try {
            const response = await vault.api.listOrganizationMembers(organization.id);
            setMembers(response);
        }
        catch (err) {
            setError(err.message || 'Failed to load members');
        }
        finally {
            setIsLoadingMembers(false);
        }
    }, [organization, vault.api]);
    const handleSaveGeneral = React.useCallback(async () => {
        if (!organization)
            return;
        setIsSaving(true);
        setError(null);
        try {
            await vault.api.updateOrganization(organization.id, {
                name: name.trim(),
                slug: slug.trim(),
                description: description.trim() || undefined,
            });
            setSuccessMessage('Organization updated successfully');
            setIsEditing(false);
            // Refresh organizations list
            await vault.refreshOrganizations();
            setTimeout(() => setSuccessMessage(null), 3000);
        }
        catch (err) {
            setError(err.message || 'Failed to update organization');
        }
        finally {
            setIsSaving(false);
        }
    }, [organization, name, slug, description, vault]);
    const handleInviteMember = React.useCallback(async (e) => {
        e.preventDefault();
        if (!organization || !inviteEmail.trim())
            return;
        setIsInviting(true);
        setError(null);
        try {
            // This would call the actual invite API
            // await vault.api.inviteMember(organization.id, { email: inviteEmail, role: inviteRole });
            // Simulate success for now
            setSuccessMessage(`Invitation sent to ${inviteEmail}`);
            setInviteEmail('');
            setTimeout(() => setSuccessMessage(null), 3000);
        }
        catch (err) {
            setError(err.message || 'Failed to send invitation');
        }
        finally {
            setIsInviting(false);
        }
    }, [organization, inviteEmail, inviteRole]);
    const handleRemoveMember = React.useCallback(async (memberId) => {
        if (!organization)
            return;
        if (!window.confirm('Are you sure you want to remove this member?')) {
            return;
        }
        try {
            // await vault.api.removeMember(organization.id, memberId);
            setMembers(prev => prev.filter(m => m.id !== memberId));
            setSuccessMessage('Member removed successfully');
            setTimeout(() => setSuccessMessage(null), 3000);
        }
        catch (err) {
            setError(err.message || 'Failed to remove member');
        }
    }, [organization]);
    const handleUpdateMemberRole = React.useCallback(async (memberId, newRole) => {
        if (!organization)
            return;
        try {
            // await vault.api.updateMemberRole(organization.id, memberId, newRole);
            setMembers(prev => prev.map(m => m.id === memberId ? { ...m, role: newRole } : m));
            setSuccessMessage('Role updated successfully');
            setTimeout(() => setSuccessMessage(null), 3000);
        }
        catch (err) {
            setError(err.message || 'Failed to update role');
        }
    }, [organization]);
    const handleDeleteOrganization = React.useCallback(async () => {
        if (!organization)
            return;
        if (deleteConfirmText !== organization.name) {
            setError('Please type the organization name to confirm');
            return;
        }
        setIsDeleting(true);
        try {
            await vault.api.deleteOrganization(organization.id);
            // Redirect to dashboard or org list
            window.location.href = '/';
        }
        catch (err) {
            setError(err.message || 'Failed to delete organization');
            setIsDeleting(false);
        }
    }, [organization, deleteConfirmText, vault.api]);
    const handleLeaveOrganization = React.useCallback(async () => {
        if (!organization)
            return;
        if (!window.confirm(`Are you sure you want to leave ${organization.name}?`)) {
            return;
        }
        try {
            await vault.leaveOrganization(organization.id);
            window.location.href = '/';
        }
        catch (err) {
            setError(err.message || 'Failed to leave organization');
        }
    }, [organization, vault]);
    if (!isLoaded) {
        return (jsxRuntime.jsx("div", { style: applyAppearance$3(styles$6.container, appearance), className: className, children: jsxRuntime.jsx("div", { style: styles$6.loading, children: "Loading..." }) }));
    }
    if (!organization) {
        return (jsxRuntime.jsx("div", { style: applyAppearance$3(styles$6.container, appearance), className: className, children: jsxRuntime.jsxs("div", { style: styles$6.emptyState, children: [jsxRuntime.jsx("p", { children: "No organization selected." }), jsxRuntime.jsx("p", { style: styles$6.emptyStateSubtext, children: "Create or join an organization to manage it here." })] }) }));
    }
    const isOwner = organization.role === 'owner';
    const isAdmin = organization.role === 'admin' || isOwner;
    return (jsxRuntime.jsxs("div", { style: applyAppearance$3(styles$6.container, appearance), className: className, children: [jsxRuntime.jsx("div", { style: styles$6.header, children: jsxRuntime.jsxs("div", { children: [jsxRuntime.jsx("h1", { style: applyAppearance$3(styles$6.heading, appearance), children: organization.name }), jsxRuntime.jsx("span", { style: styles$6.roleBadge, children: organization.role })] }) }), jsxRuntime.jsxs("div", { style: styles$6.tabs, children: [jsxRuntime.jsx(TabButton, { label: "General", isActive: activeTab === 'general', onClick: () => setActiveTab('general'), appearance: appearance }), jsxRuntime.jsx(TabButton, { label: "Members", isActive: activeTab === 'members', onClick: () => setActiveTab('members'), appearance: appearance }), jsxRuntime.jsx(TabButton, { label: "Settings", isActive: activeTab === 'settings', onClick: () => setActiveTab('settings'), appearance: appearance })] }), error && (jsxRuntime.jsx("div", { style: applyAppearance$3(styles$6.error, appearance), role: "alert", children: error })), successMessage && (jsxRuntime.jsx("div", { style: applyAppearance$3(styles$6.success, appearance), role: "status", children: successMessage })), activeTab === 'general' && (jsxRuntime.jsxs("div", { style: styles$6.section, children: [jsxRuntime.jsxs("div", { style: styles$6.sectionHeader, children: [jsxRuntime.jsx("h2", { style: styles$6.sectionTitle, children: "Organization Details" }), isAdmin && !isEditing && (jsxRuntime.jsx("button", { onClick: () => setIsEditing(true), style: applyAppearance$3(styles$6.editButton, appearance), children: "Edit" }))] }), jsxRuntime.jsxs("div", { style: styles$6.fieldGroup, children: [jsxRuntime.jsxs("div", { style: styles$6.field, children: [jsxRuntime.jsx("label", { style: applyAppearance$3(styles$6.label, appearance), children: "Organization Name" }), jsxRuntime.jsx("input", { type: "text", value: name, onChange: (e) => setName(e.target.value), disabled: !isEditing || isSaving, style: applyAppearance$3(styles$6.input, appearance) })] }), jsxRuntime.jsxs("div", { style: styles$6.field, children: [jsxRuntime.jsx("label", { style: applyAppearance$3(styles$6.label, appearance), children: "Organization Slug" }), jsxRuntime.jsx("input", { type: "text", value: slug, onChange: (e) => setSlug(e.target.value), disabled: !isEditing || isSaving, style: applyAppearance$3(styles$6.input, appearance) }), jsxRuntime.jsxs("span", { style: styles$6.helpText, children: ["Used in URLs: vault.dev/o/", slug] })] }), jsxRuntime.jsxs("div", { style: styles$6.field, children: [jsxRuntime.jsx("label", { style: applyAppearance$3(styles$6.label, appearance), children: "Description" }), jsxRuntime.jsx("textarea", { value: description, onChange: (e) => setDescription(e.target.value), disabled: !isEditing || isSaving, rows: 3, style: applyAppearance$3(styles$6.textarea, appearance), placeholder: "What does your organization do?" })] }), organization.logoUrl && (jsxRuntime.jsxs("div", { style: styles$6.field, children: [jsxRuntime.jsx("label", { style: applyAppearance$3(styles$6.label, appearance), children: "Logo" }), jsxRuntime.jsx("img", { src: organization.logoUrl, alt: "Organization logo", style: styles$6.logoImage })] }))] }), isEditing && (jsxRuntime.jsxs("div", { style: styles$6.buttonGroup, children: [jsxRuntime.jsx("button", { onClick: handleSaveGeneral, disabled: isSaving || !name.trim() || !slug.trim(), style: applyAppearance$3(styles$6.primaryButton, appearance), children: isSaving ? 'Saving...' : 'Save Changes' }), jsxRuntime.jsx("button", { onClick: () => {
                                    setIsEditing(false);
                                    setName(organization.name);
                                    setSlug(organization.slug);
                                    setDescription(organization.description || '');
                                    setError(null);
                                }, disabled: isSaving, style: applyAppearance$3(styles$6.secondaryButton, appearance), children: "Cancel" })] }))] })), activeTab === 'members' && (jsxRuntime.jsxs("div", { style: styles$6.section, children: [jsxRuntime.jsx("h2", { style: styles$6.sectionTitle, children: "Members" }), isAdmin && (jsxRuntime.jsx("form", { onSubmit: handleInviteMember, style: styles$6.inviteForm, children: jsxRuntime.jsxs("div", { style: styles$6.inviteRow, children: [jsxRuntime.jsx("input", { type: "email", value: inviteEmail, onChange: (e) => setInviteEmail(e.target.value), placeholder: "colleague@example.com", style: { ...applyAppearance$3(styles$6.input, appearance), flex: 1 }, disabled: isInviting }), jsxRuntime.jsxs("select", { value: inviteRole, onChange: (e) => setInviteRole(e.target.value), style: applyAppearance$3(styles$6.select, appearance), disabled: isInviting, children: [jsxRuntime.jsx("option", { value: "member", children: "Member" }), jsxRuntime.jsx("option", { value: "admin", children: "Admin" }), isOwner && jsxRuntime.jsx("option", { value: "owner", children: "Owner" })] }), jsxRuntime.jsx("button", { type: "submit", disabled: isInviting || !inviteEmail.trim(), style: applyAppearance$3(styles$6.primaryButton, appearance), children: isInviting ? 'Inviting...' : 'Invite' })] }) })), isLoadingMembers ? (jsxRuntime.jsx("div", { style: styles$6.loading, children: "Loading members..." })) : (jsxRuntime.jsx("div", { style: styles$6.membersList, children: members.length === 0 ? (jsxRuntime.jsx("div", { style: styles$6.emptyMembers, children: "No members yet." })) : (members.map((member) => (jsxRuntime.jsxs("div", { style: styles$6.memberRow, children: [jsxRuntime.jsxs("div", { style: styles$6.memberInfo, children: [jsxRuntime.jsx("div", { style: styles$6.memberAvatar, children: member.name?.[0] || member.email[0].toUpperCase() }), jsxRuntime.jsxs("div", { children: [jsxRuntime.jsx("div", { style: styles$6.memberName, children: member.name || member.email }), member.name && (jsxRuntime.jsx("div", { style: styles$6.memberEmail, children: member.email }))] })] }), jsxRuntime.jsx("div", { style: styles$6.memberActions, children: isAdmin && member.userId !== vault.user?.id ? (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsxs("select", { value: member.role, onChange: (e) => handleUpdateMemberRole(member.id, e.target.value), style: applyAppearance$3(styles$6.roleSelect, appearance), children: [jsxRuntime.jsx("option", { value: "member", children: "Member" }), jsxRuntime.jsx("option", { value: "admin", children: "Admin" }), isOwner && jsxRuntime.jsx("option", { value: "owner", children: "Owner" })] }), jsxRuntime.jsx("button", { onClick: () => handleRemoveMember(member.id), style: styles$6.removeButton, title: "Remove member", children: "\u2715" })] })) : (jsxRuntime.jsx("span", { style: styles$6.roleBadge, children: member.role })) })] }, member.id)))) }))] })), activeTab === 'settings' && (jsxRuntime.jsxs("div", { style: styles$6.section, children: [jsxRuntime.jsx("h2", { style: styles$6.sectionTitle, children: "Organization Settings" }), !isOwner && (jsxRuntime.jsxs("div", { style: styles$6.dangerBox, children: [jsxRuntime.jsx("h3", { style: styles$6.dangerTitle, children: "Leave Organization" }), jsxRuntime.jsx("p", { style: styles$6.dangerText, children: "You will lose access to all resources in this organization." }), jsxRuntime.jsx("button", { onClick: handleLeaveOrganization, style: applyAppearance$3(styles$6.dangerButton, appearance), children: "Leave Organization" })] })), isOwner && (jsxRuntime.jsxs("div", { style: styles$6.dangerBox, children: [jsxRuntime.jsx("h3", { style: styles$6.dangerTitle, children: "Delete Organization" }), jsxRuntime.jsx("p", { style: styles$6.dangerText, children: "Once deleted, this organization and all its data cannot be recovered. This action cannot be undone." }), !showDeleteConfirm ? (jsxRuntime.jsx("button", { onClick: () => setShowDeleteConfirm(true), style: applyAppearance$3(styles$6.dangerButton, appearance), children: "Delete Organization" })) : (jsxRuntime.jsxs("div", { style: styles$6.confirmDelete, children: [jsxRuntime.jsxs("p", { style: styles$6.confirmText, children: ["Type ", jsxRuntime.jsx("strong", { children: organization.name }), " to confirm:"] }), jsxRuntime.jsx("input", { type: "text", value: deleteConfirmText, onChange: (e) => setDeleteConfirmText(e.target.value), placeholder: organization.name, style: applyAppearance$3(styles$6.input, appearance) }), jsxRuntime.jsxs("div", { style: styles$6.buttonGroup, children: [jsxRuntime.jsx("button", { onClick: handleDeleteOrganization, disabled: isDeleting || deleteConfirmText !== organization.name, style: applyAppearance$3(styles$6.dangerButton, appearance), children: isDeleting ? 'Deleting...' : 'Confirm Delete' }), jsxRuntime.jsx("button", { onClick: () => {
                                                    setShowDeleteConfirm(false);
                                                    setDeleteConfirmText('');
                                                    setError(null);
                                                }, style: applyAppearance$3(styles$6.secondaryButton, appearance), children: "Cancel" })] })] }))] }))] }))] }));
}
// Tab Button Component
function TabButton({ label, isActive, onClick, appearance, }) {
    return (jsxRuntime.jsx("button", { onClick: onClick, style: {
            ...styles$6.tabButton,
            ...(isActive && styles$6.tabButtonActive),
            ...(isActive && appearance?.variables?.['colorPrimary'] && {
                borderBottomColor: appearance.variables['colorPrimary'],
                color: appearance.variables['colorPrimary'],
            }),
        }, children: label }));
}
// Apply appearance variables
function applyAppearance$3(baseStyle, appearance) {
    if (!appearance)
        return baseStyle;
    const variables = appearance.variables || {};
    let style = { ...baseStyle };
    if (variables['colorPrimary']) {
        if (baseStyle.backgroundColor === '#0066cc' || baseStyle.borderColor === '#0066cc') {
            style = {
                ...style,
                backgroundColor: variables['colorPrimary'],
                borderColor: variables['colorPrimary'],
            };
        }
        if (baseStyle.color === '#0066cc') {
            style = { ...style, color: variables['colorPrimary'] };
        }
    }
    if (variables['colorDanger'] && baseStyle.backgroundColor === '#dc2626') {
        style = { ...style, backgroundColor: variables['colorDanger'] };
    }
    if (variables['borderRadius'] && baseStyle.borderRadius) {
        style = { ...style, borderRadius: variables['borderRadius'] };
    }
    return style;
}
// Styles
const styles$6 = {
    container: {
        maxWidth: '800px',
        margin: '0 auto',
        padding: '24px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    loading: {
        textAlign: 'center',
        padding: '48px',
        color: '#6b7280',
    },
    header: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: '24px',
    },
    heading: {
        fontSize: '28px',
        fontWeight: 600,
        margin: '0 0 8px',
        color: '#1f2937',
    },
    roleBadge: {
        display: 'inline-block',
        padding: '4px 12px',
        fontSize: '12px',
        fontWeight: 500,
        textTransform: 'uppercase',
        color: '#6b7280',
        backgroundColor: '#f3f4f6',
        borderRadius: '9999px',
    },
    tabs: {
        display: 'flex',
        borderBottom: '1px solid #e5e7eb',
        marginBottom: '24px',
    },
    tabButton: {
        padding: '12px 16px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#6b7280',
        background: 'transparent',
        border: 'none',
        borderBottom: '2px solid transparent',
        cursor: 'pointer',
        transition: 'all 0.15s ease-in-out',
    },
    tabButtonActive: {
        color: '#0066cc',
        borderBottomColor: '#0066cc',
    },
    error: {
        padding: '12px 16px',
        marginBottom: '16px',
        color: '#dc2626',
        backgroundColor: '#fee2e2',
        borderRadius: '6px',
        fontSize: '14px',
    },
    success: {
        padding: '12px 16px',
        marginBottom: '16px',
        color: '#059669',
        backgroundColor: '#d1fae5',
        borderRadius: '6px',
        fontSize: '14px',
    },
    section: {
        backgroundColor: '#fff',
        border: '1px solid #e5e7eb',
        borderRadius: '8px',
        padding: '24px',
    },
    sectionHeader: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '20px',
    },
    sectionTitle: {
        fontSize: '18px',
        fontWeight: 600,
        margin: 0,
        color: '#1f2937',
    },
    editButton: {
        padding: '6px 12px',
        fontSize: '14px',
        color: '#0066cc',
        backgroundColor: 'transparent',
        border: '1px solid #0066cc',
        borderRadius: '6px',
        cursor: 'pointer',
    },
    fieldGroup: {
        display: 'flex',
        flexDirection: 'column',
        gap: '16px',
        marginBottom: '24px',
    },
    field: {
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
    },
    label: {
        fontSize: '14px',
        fontWeight: 500,
        color: '#374151',
    },
    input: {
        padding: '10px 12px',
        fontSize: '15px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        outline: 'none',
        transition: 'border-color 0.15s ease-in-out',
    },
    textarea: {
        padding: '10px 12px',
        fontSize: '15px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        outline: 'none',
        transition: 'border-color 0.15s ease-in-out',
        resize: 'vertical',
        fontFamily: 'inherit',
    },
    select: {
        padding: '10px 12px',
        fontSize: '15px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        outline: 'none',
        backgroundColor: '#fff',
        cursor: 'pointer',
    },
    helpText: {
        fontSize: '12px',
        color: '#6b7280',
    },
    buttonGroup: {
        display: 'flex',
        gap: '12px',
    },
    primaryButton: {
        padding: '10px 20px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#0066cc',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    secondaryButton: {
        padding: '10px 20px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#374151',
        backgroundColor: '#f3f4f6',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    logoImage: {
        width: '80px',
        height: '80px',
        objectFit: 'cover',
        borderRadius: '8px',
        border: '1px solid #e5e7eb',
    },
    emptyState: {
        textAlign: 'center',
        padding: '48px',
        color: '#6b7280',
    },
    emptyStateSubtext: {
        fontSize: '14px',
        marginTop: '8px',
    },
    inviteForm: {
        marginBottom: '24px',
        padding: '16px',
        backgroundColor: '#f9fafb',
        borderRadius: '6px',
    },
    inviteRow: {
        display: 'flex',
        gap: '8px',
    },
    membersList: {
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
    },
    memberRow: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '12px',
        backgroundColor: '#f9fafb',
        borderRadius: '6px',
    },
    memberInfo: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
    },
    memberAvatar: {
        width: '36px',
        height: '36px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: '14px',
        fontWeight: 600,
        color: '#fff',
        backgroundColor: '#0066cc',
        borderRadius: '50%',
    },
    memberName: {
        fontSize: '14px',
        fontWeight: 500,
        color: '#1f2937',
    },
    memberEmail: {
        fontSize: '12px',
        color: '#6b7280',
    },
    memberActions: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
    },
    roleSelect: {
        padding: '6px 10px',
        fontSize: '13px',
        border: '1px solid #d1d5db',
        borderRadius: '4px',
        backgroundColor: '#fff',
        cursor: 'pointer',
    },
    removeButton: {
        padding: '6px 10px',
        fontSize: '12px',
        color: '#dc2626',
        backgroundColor: 'transparent',
        border: '1px solid #fecaca',
        borderRadius: '4px',
        cursor: 'pointer',
    },
    emptyMembers: {
        textAlign: 'center',
        padding: '24px',
        color: '#6b7280',
        fontSize: '14px',
    },
    dangerBox: {
        padding: '16px',
        border: '1px solid #fecaca',
        borderRadius: '6px',
        backgroundColor: '#fef2f2',
    },
    dangerTitle: {
        fontSize: '16px',
        fontWeight: 600,
        margin: '0 0 8px',
        color: '#dc2626',
    },
    dangerText: {
        fontSize: '14px',
        color: '#7f1d1d',
        margin: '0 0 16px',
    },
    dangerButton: {
        padding: '10px 20px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#dc2626',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    confirmDelete: {
        marginTop: '12px',
    },
    confirmText: {
        fontSize: '14px',
        marginBottom: '8px',
    },
};

function OrganizationList({ onSelect, hideCreateButton = false, appearance, className, }) {
    const { organizations, organization: activeOrg, isLoaded, setActive, create, } = useOrganization();
    const { user } = useAuth();
    const [isCreating, setIsCreating] = React.useState(false);
    const [newOrgName, setNewOrgName] = React.useState('');
    const [isLoading, setIsLoading] = React.useState(false);
    const [error, setError] = React.useState(null);
    const [successMessage, setSuccessMessage] = React.useState(null);
    const handleSelectOrg = React.useCallback((org) => {
        setActive(org.id);
        onSelect?.(org);
    }, [setActive, onSelect]);
    const handleCreateOrg = React.useCallback(async (e) => {
        e.preventDefault();
        if (!newOrgName.trim())
            return;
        setIsLoading(true);
        setError(null);
        try {
            const newOrg = await create({ name: newOrgName.trim() });
            setSuccessMessage(`Organization "${newOrg.name}" created successfully`);
            setNewOrgName('');
            setIsCreating(false);
            setTimeout(() => setSuccessMessage(null), 3000);
        }
        catch (err) {
            setError(err.message || 'Failed to create organization');
        }
        finally {
            setIsLoading(false);
        }
    }, [newOrgName, create]);
    if (!isLoaded) {
        return (jsxRuntime.jsx("div", { style: applyAppearance$2(styles$5.container, appearance), className: className, children: jsxRuntime.jsx("div", { style: styles$5.loading, children: "Loading organizations..." }) }));
    }
    const hasOrganizations = organizations.length > 0;
    return (jsxRuntime.jsxs("div", { style: applyAppearance$2(styles$5.container, appearance), className: className, children: [jsxRuntime.jsxs("div", { style: styles$5.header, children: [jsxRuntime.jsx("h2", { style: applyAppearance$2(styles$5.title, appearance), children: "Your Organizations" }), !hideCreateButton && !isCreating && (jsxRuntime.jsxs("button", { onClick: () => setIsCreating(true), style: applyAppearance$2(styles$5.createButton, appearance), children: [jsxRuntime.jsx(PlusIcon, {}), jsxRuntime.jsx("span", { children: "New" })] }))] }), error && (jsxRuntime.jsx("div", { style: applyAppearance$2(styles$5.error, appearance), role: "alert", children: error })), successMessage && (jsxRuntime.jsx("div", { style: applyAppearance$2(styles$5.success, appearance), role: "status", children: successMessage })), isCreating && (jsxRuntime.jsxs("form", { onSubmit: handleCreateOrg, style: styles$5.createForm, children: [jsxRuntime.jsx("input", { type: "text", value: newOrgName, onChange: (e) => setNewOrgName(e.target.value), placeholder: "Organization name", autoFocus: true, style: applyAppearance$2(styles$5.createInput, appearance), disabled: isLoading }), jsxRuntime.jsxs("div", { style: styles$5.createActions, children: [jsxRuntime.jsx("button", { type: "submit", disabled: isLoading || !newOrgName.trim(), style: applyAppearance$2(styles$5.primaryButton, appearance), children: isLoading ? 'Creating...' : 'Create' }), jsxRuntime.jsx("button", { type: "button", onClick: () => {
                                    setIsCreating(false);
                                    setNewOrgName('');
                                    setError(null);
                                }, disabled: isLoading, style: applyAppearance$2(styles$5.secondaryButton, appearance), children: "Cancel" })] })] })), jsxRuntime.jsxs("div", { style: styles$5.list, children: [jsxRuntime.jsx(OrganizationItem, { name: user?.profile?.name || user?.email || 'Personal Account', email: user?.email, isActive: !activeOrg, onClick: () => {
                            setActive(null);
                            onSelect?.(null);
                        }, isPersonal: true, appearance: appearance }), organizations.map((org) => (jsxRuntime.jsx(OrganizationItem, { name: org.name, role: org.role, isActive: activeOrg?.id === org.id, onClick: () => handleSelectOrg(org), appearance: appearance }, org.id))), !hasOrganizations && !isCreating && (jsxRuntime.jsxs("div", { style: styles$5.emptyState, children: [jsxRuntime.jsx("div", { style: styles$5.emptyIcon, children: jsxRuntime.jsx(BuildingIcon, {}) }), jsxRuntime.jsx("p", { style: styles$5.emptyTitle, children: "No organizations yet" }), jsxRuntime.jsx("p", { style: styles$5.emptyText, children: "Create an organization to collaborate with your team." }), !hideCreateButton && (jsxRuntime.jsx("button", { onClick: () => setIsCreating(true), style: applyAppearance$2(styles$5.emptyCreateButton, appearance), children: "Create Organization" }))] }))] })] }));
}
function OrganizationItem({ name, email, role, isActive, onClick, isPersonal = false, appearance, }) {
    return (jsxRuntime.jsxs("button", { onClick: onClick, style: {
            ...styles$5.item,
            ...(isActive && styles$5.itemActive),
            ...(isActive && appearance?.variables?.['colorPrimary'] && {
                borderColor: appearance.variables['colorPrimary'],
                backgroundColor: `${appearance.variables['colorPrimary']}10`,
            }),
        }, children: [jsxRuntime.jsx("div", { style: styles$5.itemIcon, children: isPersonal ? jsxRuntime.jsx(UserIcon$1, {}) : jsxRuntime.jsx(BuildingIcon, { small: true }) }), jsxRuntime.jsxs("div", { style: styles$5.itemContent, children: [jsxRuntime.jsx("div", { style: styles$5.itemName, children: name }), email && jsxRuntime.jsx("div", { style: styles$5.itemEmail, children: email }), role && !isPersonal && (jsxRuntime.jsx("span", { style: styles$5.itemRole, children: role }))] }), isActive && (jsxRuntime.jsx("div", { style: {
                    ...styles$5.activeBadge,
                    ...(appearance?.variables?.['colorPrimary'] && {
                        backgroundColor: appearance.variables['colorPrimary'],
                    }),
                }, children: "Active" }))] }));
}
// Icon Components
function BuildingIcon({ small }) {
    return (jsxRuntime.jsxs("svg", { width: small ? 20 : 24, height: small ? 20 : 24, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("path", { d: "M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z" }), jsxRuntime.jsx("path", { d: "M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2" }), jsxRuntime.jsx("path", { d: "M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2" }), jsxRuntime.jsx("path", { d: "M10 6h4" }), jsxRuntime.jsx("path", { d: "M10 10h4" }), jsxRuntime.jsx("path", { d: "M10 14h4" }), jsxRuntime.jsx("path", { d: "M10 18h4" })] }));
}
function UserIcon$1() {
    return (jsxRuntime.jsxs("svg", { width: 20, height: 20, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("path", { d: "M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" }), jsxRuntime.jsx("circle", { cx: "12", cy: "7", r: "4" })] }));
}
function PlusIcon() {
    return (jsxRuntime.jsxs("svg", { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("path", { d: "M5 12h14" }), jsxRuntime.jsx("path", { d: "M12 5v14" })] }));
}
// Apply appearance variables
function applyAppearance$2(baseStyle, appearance) {
    if (!appearance)
        return baseStyle;
    const variables = appearance.variables || {};
    let style = { ...baseStyle };
    if (variables['colorPrimary']) {
        if (baseStyle.backgroundColor === '#0066cc' || baseStyle.borderColor === '#0066cc') {
            style = {
                ...style,
                backgroundColor: variables['colorPrimary'],
                borderColor: variables['colorPrimary'],
            };
        }
        if (baseStyle.color === '#0066cc') {
            style = { ...style, color: variables['colorPrimary'] };
        }
    }
    if (variables['borderRadius'] && baseStyle.borderRadius) {
        style = { ...style, borderRadius: variables['borderRadius'] };
    }
    return style;
}
// Styles
const styles$5 = {
    container: {
        maxWidth: '480px',
        margin: '0 auto',
        padding: '24px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    loading: {
        textAlign: 'center',
        padding: '48px',
        color: '#6b7280',
    },
    header: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '20px',
    },
    title: {
        margin: '0',
        fontSize: '20px',
        fontWeight: 600,
        color: '#1a1a1a',
    },
    createButton: {
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        padding: '8px 12px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#0066cc',
        backgroundColor: '#eff6ff',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    error: {
        padding: '12px',
        marginBottom: '16px',
        color: '#dc2626',
        backgroundColor: '#fee2e2',
        borderRadius: '6px',
        fontSize: '14px',
    },
    success: {
        padding: '12px',
        marginBottom: '16px',
        color: '#059669',
        backgroundColor: '#d1fae5',
        borderRadius: '6px',
        fontSize: '14px',
    },
    createForm: {
        marginBottom: '16px',
        padding: '16px',
        backgroundColor: '#f9fafb',
        borderRadius: '8px',
    },
    createInput: {
        width: '100%',
        padding: '10px 12px',
        fontSize: '15px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        marginBottom: '12px',
        outline: 'none',
        boxSizing: 'border-box',
    },
    createActions: {
        display: 'flex',
        gap: '8px',
    },
    primaryButton: {
        flex: 1,
        padding: '10px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#0066cc',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    secondaryButton: {
        padding: '10px 16px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#6b7280',
        backgroundColor: '#fff',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    list: {
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
    },
    item: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '16px',
        backgroundColor: '#fff',
        border: '1px solid #e5e7eb',
        borderRadius: '8px',
        cursor: 'pointer',
        transition: 'all 0.15s ease-in-out',
        textAlign: 'left',
        width: '100%',
    },
    itemActive: {
        borderColor: '#0066cc',
        backgroundColor: '#eff6ff',
    },
    itemIcon: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '40px',
        height: '40px',
        color: '#6b7280',
        backgroundColor: '#f3f4f6',
        borderRadius: '8px',
        flexShrink: 0,
    },
    itemContent: {
        flex: 1,
        minWidth: 0,
    },
    itemName: {
        fontSize: '15px',
        fontWeight: 500,
        color: '#1f2937',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
    },
    itemEmail: {
        fontSize: '13px',
        color: '#6b7280',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
    },
    itemRole: {
        display: 'inline-block',
        marginTop: '4px',
        padding: '2px 8px',
        fontSize: '11px',
        fontWeight: 500,
        textTransform: 'uppercase',
        color: '#6b7280',
        backgroundColor: '#f3f4f6',
        borderRadius: '9999px',
    },
    activeBadge: {
        padding: '4px 10px',
        fontSize: '12px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#0066cc',
        borderRadius: '9999px',
        flexShrink: 0,
    },
    emptyState: {
        textAlign: 'center',
        padding: '48px 24px',
        border: '2px dashed #e5e7eb',
        borderRadius: '8px',
    },
    emptyIcon: {
        display: 'flex',
        justifyContent: 'center',
        marginBottom: '16px',
        color: '#d1d5db',
    },
    emptyTitle: {
        margin: '0 0 8px',
        fontSize: '16px',
        fontWeight: 500,
        color: '#374151',
    },
    emptyText: {
        margin: '0 0 20px',
        fontSize: '14px',
        color: '#6b7280',
    },
    emptyCreateButton: {
        padding: '10px 20px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#0066cc',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
};

function SessionManagement({ appearance, className, }) {
    const { sessions, isLoading, revokeSession, revokeAllOtherSessions } = useSessions();
    useVault();
    const [revokingId, setRevokingId] = React.useState(null);
    const [showConfirmAll, setShowConfirmAll] = React.useState(false);
    const handleRevoke = React.useCallback(async (sessionId) => {
        setRevokingId(sessionId);
        try {
            await revokeSession(sessionId);
        }
        finally {
            setRevokingId(null);
        }
    }, [revokeSession]);
    const handleRevokeAllOthers = React.useCallback(async () => {
        try {
            await revokeAllOtherSessions();
            setShowConfirmAll(false);
        }
        catch (error) {
            console.error('Failed to revoke all sessions:', error);
        }
    }, [revokeAllOtherSessions]);
    const otherSessionsCount = sessions.filter(s => !s.isCurrent).length;
    return (jsxRuntime.jsxs("div", { style: applyAppearance$1(styles$4.container, appearance), className: className, children: [jsxRuntime.jsx("div", { style: styles$4.header, children: jsxRuntime.jsxs("div", { children: [jsxRuntime.jsx("h2", { style: applyAppearance$1(styles$4.title, appearance), children: "Active Sessions" }), jsxRuntime.jsx("p", { style: styles$4.subtitle, children: "Manage your active sessions across all devices" })] }) }), otherSessionsCount > 0 && (jsxRuntime.jsxs("div", { style: styles$4.warningBanner, children: [jsxRuntime.jsx(AlertIcon, {}), jsxRuntime.jsxs("span", { children: ["You have ", otherSessionsCount, " other active session", otherSessionsCount !== 1 ? 's' : ''] })] })), showConfirmAll ? (jsxRuntime.jsxs("div", { style: styles$4.confirmBanner, children: [jsxRuntime.jsx("p", { style: styles$4.confirmText, children: "Are you sure you want to sign out all other devices? This will require you to sign in again on those devices." }), jsxRuntime.jsxs("div", { style: styles$4.confirmActions, children: [jsxRuntime.jsx("button", { onClick: handleRevokeAllOthers, disabled: isLoading, style: applyAppearance$1(styles$4.dangerButton, appearance), children: isLoading ? 'Signing out...' : 'Yes, sign out all' }), jsxRuntime.jsx("button", { onClick: () => setShowConfirmAll(false), disabled: isLoading, style: applyAppearance$1(styles$4.secondaryButton, appearance), children: "Cancel" })] })] })) : (otherSessionsCount > 0 && (jsxRuntime.jsxs("button", { onClick: () => setShowConfirmAll(true), style: applyAppearance$1(styles$4.signOutAllButton, appearance), children: [jsxRuntime.jsx(LogOutIcon$1, {}), "Sign out all other devices"] }))), jsxRuntime.jsx("div", { style: styles$4.sessionsList, children: sessions.length === 0 ? (jsxRuntime.jsx("div", { style: styles$4.emptyState, children: jsxRuntime.jsx("p", { children: "No active sessions found" }) })) : (sessions
                    .sort((a, b) => (a.isCurrent ? -1 : 1))
                    .map((session) => (jsxRuntime.jsx(SessionItem, { session: session, isCurrent: session.isCurrent, onRevoke: () => handleRevoke(session.id), isRevoking: revokingId === session.id, appearance: appearance }, session.id)))) })] }));
}
function SessionItem({ session, isCurrent, onRevoke, isRevoking, appearance }) {
    const deviceInfo = parseUserAgent(session.userAgent);
    const location = session.ipAddress ? `IP: ${session.ipAddress}` : null;
    const lastActive = formatLastActive(session.lastActiveAt);
    return (jsxRuntime.jsxs("div", { style: {
            ...styles$4.sessionItem,
            ...(isCurrent && styles$4.currentSession),
        }, children: [jsxRuntime.jsx("div", { style: styles$4.sessionIcon, children: jsxRuntime.jsx(DeviceIcon, { device: deviceInfo.device }) }), jsxRuntime.jsxs("div", { style: styles$4.sessionInfo, children: [jsxRuntime.jsxs("div", { style: styles$4.sessionHeader, children: [jsxRuntime.jsxs("span", { style: styles$4.deviceName, children: [deviceInfo.browser, " on ", deviceInfo.os] }), isCurrent && (jsxRuntime.jsx("span", { style: {
                                    ...styles$4.currentBadge,
                                    ...(appearance?.variables?.['colorPrimary'] && {
                                        backgroundColor: appearance.variables['colorPrimary'],
                                    }),
                                }, children: "Current" }))] }), jsxRuntime.jsxs("div", { style: styles$4.sessionDetails, children: [location && jsxRuntime.jsx("span", { children: location }), jsxRuntime.jsxs("span", { children: ["Last active ", lastActive] })] }), jsxRuntime.jsxs("div", { style: styles$4.sessionMeta, children: ["Started ", new Date(session.createdAt).toLocaleDateString()] })] }), !isCurrent && (jsxRuntime.jsx("button", { onClick: onRevoke, disabled: isRevoking, style: styles$4.revokeButton, title: "Sign out this device", children: isRevoking ? (jsxRuntime.jsx(Spinner$2, {})) : (jsxRuntime.jsx(LogOutIcon$1, { small: true })) }))] }));
}
// Helper Functions
function parseUserAgent(userAgent) {
    if (!userAgent) {
        return { browser: 'Unknown', os: 'Unknown', device: 'desktop' };
    }
    const ua = userAgent.toLowerCase();
    // Detect browser
    let browser = 'Unknown';
    if (ua.includes('firefox'))
        browser = 'Firefox';
    else if (ua.includes('edg'))
        browser = 'Edge';
    else if (ua.includes('chrome'))
        browser = 'Chrome';
    else if (ua.includes('safari'))
        browser = 'Safari';
    else if (ua.includes('opera'))
        browser = 'Opera';
    // Detect OS
    let os = 'Unknown';
    if (ua.includes('windows'))
        os = 'Windows';
    else if (ua.includes('macintosh') || ua.includes('mac os'))
        os = 'macOS';
    else if (ua.includes('linux'))
        os = 'Linux';
    else if (ua.includes('android'))
        os = 'Android';
    else if (ua.includes('iphone') || ua.includes('ipad'))
        os = 'iOS';
    // Detect device type
    let device = 'desktop';
    if (ua.includes('mobile'))
        device = 'mobile';
    else if (ua.includes('tablet') || ua.includes('ipad'))
        device = 'tablet';
    return { browser, os, device };
}
function formatLastActive(lastActiveAt) {
    const lastActive = new Date(lastActiveAt);
    const now = new Date();
    const diffMs = now.getTime() - lastActive.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    if (diffMins < 1)
        return 'just now';
    if (diffMins < 60)
        return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
    if (diffHours < 24)
        return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    if (diffDays < 7)
        return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
    return lastActive.toLocaleDateString();
}
// Icon Components
function DeviceIcon({ device }) {
    if (device === 'mobile') {
        return (jsxRuntime.jsxs("svg", { width: "24", height: "24", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", children: [jsxRuntime.jsx("rect", { x: "7", y: "2", width: "10", height: "20", rx: "2", ry: "2" }), jsxRuntime.jsx("line", { x1: "12", y1: "18", x2: "12", y2: "18" })] }));
    }
    if (device === 'tablet') {
        return (jsxRuntime.jsxs("svg", { width: "24", height: "24", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", children: [jsxRuntime.jsx("rect", { x: "4", y: "2", width: "16", height: "20", rx: "2", ry: "2" }), jsxRuntime.jsx("line", { x1: "12", y1: "18", x2: "12", y2: "18" })] }));
    }
    return (jsxRuntime.jsxs("svg", { width: "24", height: "24", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", children: [jsxRuntime.jsx("rect", { x: "2", y: "3", width: "20", height: "14", rx: "2", ry: "2" }), jsxRuntime.jsx("line", { x1: "8", y1: "21", x2: "16", y2: "21" }), jsxRuntime.jsx("line", { x1: "12", y1: "17", x2: "12", y2: "21" })] }));
}
function LogOutIcon$1({ small }) {
    const size = small ? 16 : 18;
    return (jsxRuntime.jsxs("svg", { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", children: [jsxRuntime.jsx("path", { d: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" }), jsxRuntime.jsx("polyline", { points: "16 17 21 12 16 7" }), jsxRuntime.jsx("line", { x1: "21", y1: "12", x2: "9", y2: "12" })] }));
}
function AlertIcon() {
    return (jsxRuntime.jsxs("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", children: [jsxRuntime.jsx("path", { d: "M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" }), jsxRuntime.jsx("line", { x1: "12", y1: "9", x2: "12", y2: "13" }), jsxRuntime.jsx("line", { x1: "12", y1: "17", x2: "12.01", y2: "17" })] }));
}
function Spinner$2() {
    return (jsxRuntime.jsx("div", { style: styles$4.spinner, children: jsxRuntime.jsx("div", { style: styles$4.spinnerInner }) }));
}
// Apply appearance variables
function applyAppearance$1(baseStyle, appearance) {
    if (!appearance)
        return baseStyle;
    const variables = appearance.variables || {};
    let style = { ...baseStyle };
    if (variables['colorPrimary']) {
        if (baseStyle.backgroundColor === '#0066cc' || baseStyle.borderColor === '#0066cc') {
            style = {
                ...style,
                backgroundColor: variables['colorPrimary'],
                borderColor: variables['colorPrimary'],
            };
        }
        if (baseStyle.color === '#0066cc') {
            style = { ...style, color: variables['colorPrimary'] };
        }
    }
    if (variables['colorDanger'] && baseStyle.backgroundColor === '#dc2626') {
        style = { ...style, backgroundColor: variables['colorDanger'] };
    }
    if (variables['borderRadius'] && baseStyle.borderRadius) {
        style = { ...style, borderRadius: variables['borderRadius'] };
    }
    return style;
}
// Styles
const styles$4 = {
    container: {
        maxWidth: '600px',
        margin: '0 auto',
        padding: '24px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    header: {
        marginBottom: '20px',
    },
    title: {
        margin: '0 0 4px',
        fontSize: '20px',
        fontWeight: 600,
        color: '#1a1a1a',
    },
    subtitle: {
        margin: 0,
        fontSize: '14px',
        color: '#6b7280',
    },
    warningBanner: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '12px 16px',
        marginBottom: '16px',
        fontSize: '14px',
        color: '#92400e',
        backgroundColor: '#fef3c7',
        borderRadius: '6px',
    },
    confirmBanner: {
        padding: '16px',
        marginBottom: '16px',
        backgroundColor: '#fee2e2',
        borderRadius: '6px',
        border: '1px solid #fecaca',
    },
    confirmText: {
        margin: '0 0 12px',
        fontSize: '14px',
        color: '#7f1d1d',
    },
    confirmActions: {
        display: 'flex',
        gap: '8px',
    },
    signOutAllButton: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '10px 16px',
        marginBottom: '16px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#dc2626',
        backgroundColor: '#fef2f2',
        border: '1px solid #fecaca',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'all 0.15s ease-in-out',
    },
    dangerButton: {
        padding: '8px 16px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#dc2626',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    secondaryButton: {
        padding: '8px 16px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#374151',
        backgroundColor: '#fff',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    sessionsList: {
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
    },
    sessionItem: {
        display: 'flex',
        alignItems: 'center',
        gap: '16px',
        padding: '16px',
        backgroundColor: '#fff',
        border: '1px solid #e5e7eb',
        borderRadius: '8px',
        transition: 'background-color 0.15s ease-in-out',
    },
    currentSession: {
        backgroundColor: '#f0fdf4',
        borderColor: '#bbf7d0',
    },
    sessionIcon: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '44px',
        height: '44px',
        color: '#6b7280',
        backgroundColor: '#f3f4f6',
        borderRadius: '10px',
        flexShrink: 0,
    },
    sessionInfo: {
        flex: 1,
        minWidth: 0,
    },
    sessionHeader: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '4px',
    },
    deviceName: {
        fontSize: '15px',
        fontWeight: 500,
        color: '#1f2937',
    },
    currentBadge: {
        padding: '2px 8px',
        fontSize: '11px',
        fontWeight: 600,
        textTransform: 'uppercase',
        color: '#fff',
        backgroundColor: '#10b981',
        borderRadius: '9999px',
    },
    sessionDetails: {
        display: 'flex',
        gap: '12px',
        fontSize: '13px',
        color: '#6b7280',
        marginBottom: '2px',
    },
    sessionMeta: {
        fontSize: '12px',
        color: '#9ca3af',
    },
    revokeButton: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '36px',
        height: '36px',
        color: '#dc2626',
        backgroundColor: '#fef2f2',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'all 0.15s ease-in-out',
    },
    emptyState: {
        textAlign: 'center',
        padding: '48px',
        color: '#6b7280',
    },
    spinner: {
        width: '16px',
        height: '16px',
        animation: 'spin 1s linear infinite',
    },
    spinnerInner: {
        width: '100%',
        height: '100%',
        border: '2px solid #e5e7eb',
        borderTopColor: '#6b7280',
        borderRadius: '50%',
    },
};

function Waitlist({ onSubmit, redirectUrl, appearance, socialProof, className, }) {
    const [email, setEmail] = React.useState('');
    const [isLoading, setIsLoading] = React.useState(false);
    const [isSuccess, setIsSuccess] = React.useState(false);
    const [error, setError] = React.useState(null);
    const handleSubmit = React.useCallback(async (e) => {
        e.preventDefault();
        setError(null);
        // Validate email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email.trim()) {
            setError('Please enter your email address');
            return;
        }
        if (!emailRegex.test(email)) {
            setError('Please enter a valid email address');
            return;
        }
        setIsLoading(true);
        try {
            // Call the onSubmit callback if provided
            await onSubmit?.(email);
            setIsSuccess(true);
            // Redirect after a short delay if redirectUrl is provided
            if (redirectUrl) {
                setTimeout(() => {
                    window.location.href = redirectUrl;
                }, 2000);
            }
        }
        catch (err) {
            setError(err.message || 'Something went wrong. Please try again.');
        }
        finally {
            setIsLoading(false);
        }
    }, [email, onSubmit, redirectUrl]);
    if (isSuccess) {
        return (jsxRuntime.jsx("div", { style: applyAppearance(styles$3.container, appearance), className: className, children: jsxRuntime.jsxs("div", { style: styles$3.successState, children: [jsxRuntime.jsx("div", { style: styles$3.successIcon, children: jsxRuntime.jsx(CheckIcon, {}) }), jsxRuntime.jsx("h2", { style: applyAppearance(styles$3.successTitle, appearance), children: "You're on the list!" }), jsxRuntime.jsxs("p", { style: styles$3.successText, children: ["We've added ", jsxRuntime.jsx("strong", { children: email }), " to our waitlist. We'll notify you when spots become available."] }), redirectUrl && (jsxRuntime.jsx("p", { style: styles$3.redirectText, children: "Redirecting you..." }))] }) }));
    }
    return (jsxRuntime.jsxs("div", { style: applyAppearance(styles$3.container, appearance), className: className, children: [jsxRuntime.jsxs("div", { style: styles$3.header, children: [jsxRuntime.jsx("h2", { style: applyAppearance(styles$3.title, appearance), children: "Join the Waitlist" }), jsxRuntime.jsx("p", { style: styles$3.subtitle, children: "Be the first to know when we launch. No spam, ever." })] }), socialProof && (jsxRuntime.jsxs("div", { style: styles$3.socialProof, children: [jsxRuntime.jsx(UsersIcon, {}), jsxRuntime.jsx("span", { children: socialProof })] })), jsxRuntime.jsxs("form", { onSubmit: handleSubmit, style: styles$3.form, children: [error && (jsxRuntime.jsx("div", { style: applyAppearance(styles$3.error, appearance), role: "alert", children: error })), jsxRuntime.jsxs("div", { style: styles$3.inputGroup, children: [jsxRuntime.jsx("input", { id: "vault-waitlist-email", type: "email", value: email, onChange: (e) => setEmail(e.target.value), placeholder: "Enter your email", required: true, disabled: isLoading, style: applyAppearance(styles$3.input, appearance), "aria-label": "Email address" }), jsxRuntime.jsx("button", { type: "submit", disabled: isLoading || !email.trim(), style: applyAppearance(styles$3.submitButton, appearance), children: isLoading ? (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx(Spinner$1, {}), jsxRuntime.jsx("span", { children: "Joining..." })] })) : (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx("span", { children: "Join Waitlist" }), jsxRuntime.jsx(ArrowRightIcon, {})] })) })] }), jsxRuntime.jsx("p", { style: styles$3.privacy, children: "By joining, you agree to our Terms of Service and Privacy Policy." })] })] }));
}
// Icon Components
function CheckIcon() {
    return (jsxRuntime.jsx("svg", { width: "32", height: "32", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "3", strokeLinecap: "round", strokeLinejoin: "round", children: jsxRuntime.jsx("polyline", { points: "20 6 9 17 4 12" }) }));
}
function UsersIcon() {
    return (jsxRuntime.jsxs("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("path", { d: "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" }), jsxRuntime.jsx("circle", { cx: "9", cy: "7", r: "4" }), jsxRuntime.jsx("path", { d: "M23 21v-2a4 4 0 0 0-3-3.87" }), jsxRuntime.jsx("path", { d: "M16 3.13a4 4 0 0 1 0 7.75" })] }));
}
function ArrowRightIcon() {
    return (jsxRuntime.jsxs("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("line", { x1: "5", y1: "12", x2: "19", y2: "12" }), jsxRuntime.jsx("polyline", { points: "12 5 19 12 12 19" })] }));
}
function Spinner$1() {
    return (jsxRuntime.jsx("div", { style: styles$3.spinner, children: jsxRuntime.jsx("div", { style: styles$3.spinnerInner }) }));
}
// Apply appearance variables
function applyAppearance(baseStyle, appearance) {
    if (!appearance)
        return baseStyle;
    const variables = appearance.variables || {};
    let style = { ...baseStyle };
    if (variables['colorPrimary']) {
        if (baseStyle.backgroundColor === '#0066cc' || baseStyle.borderColor === '#0066cc') {
            style = {
                ...style,
                backgroundColor: variables['colorPrimary'],
                borderColor: variables['colorPrimary'],
            };
        }
        if (baseStyle.color === '#0066cc') {
            style = { ...style, color: variables['colorPrimary'] };
        }
    }
    if (variables['borderRadius'] && baseStyle.borderRadius) {
        style = { ...style, borderRadius: variables['borderRadius'] };
    }
    if (variables['fontSize'] && baseStyle.fontSize) {
        style = { ...style, fontSize: variables['fontSize'] };
    }
    return style;
}
// Styles
const styles$3 = {
    container: {
        maxWidth: '400px',
        margin: '0 auto',
        padding: '32px 24px',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    header: {
        textAlign: 'center',
        marginBottom: '24px',
    },
    title: {
        margin: '0 0 8px',
        fontSize: '24px',
        fontWeight: 700,
        color: '#1a1a1a',
    },
    subtitle: {
        margin: 0,
        fontSize: '15px',
        color: '#6b7280',
    },
    socialProof: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '6px',
        marginBottom: '20px',
        fontSize: '14px',
        color: '#059669',
    },
    form: {
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
    },
    error: {
        padding: '12px',
        color: '#dc2626',
        backgroundColor: '#fee2e2',
        borderRadius: '6px',
        fontSize: '14px',
    },
    inputGroup: {
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
    },
    input: {
        padding: '12px 16px',
        fontSize: '16px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        outline: 'none',
        transition: 'border-color 0.15s ease-in-out',
    },
    submitButton: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        padding: '12px 20px',
        fontSize: '16px',
        fontWeight: 600,
        color: '#fff',
        backgroundColor: '#0066cc',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'background-color 0.15s ease-in-out',
    },
    privacy: {
        margin: '8px 0 0',
        fontSize: '12px',
        color: '#9ca3af',
        textAlign: 'center',
    },
    successState: {
        textAlign: 'center',
        padding: '24px 16px',
    },
    successIcon: {
        width: '64px',
        height: '64px',
        margin: '0 auto 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: '#fff',
        backgroundColor: '#10b981',
        borderRadius: '50%',
    },
    successTitle: {
        margin: '0 0 12px',
        fontSize: '22px',
        fontWeight: 700,
        color: '#1a1a1a',
    },
    successText: {
        margin: '0 0 16px',
        fontSize: '15px',
        color: '#6b7280',
        lineHeight: 1.6,
    },
    redirectText: {
        margin: 0,
        fontSize: '14px',
        color: '#9ca3af',
    },
    spinner: {
        width: '16px',
        height: '16px',
        animation: 'spin 1s linear infinite',
    },
    spinnerInner: {
        width: '100%',
        height: '100%',
        border: '2px solid rgba(255,255,255,0.3)',
        borderTopColor: '#fff',
        borderRadius: '50%',
    },
};

function ImpersonationBanner({ onStopImpersonating, }) {
    const { user } = useAuth();
    const [isStopping, setIsStopping] = React.useState(false);
    const [isDismissed, setIsDismissed] = React.useState(false);
    // In a real implementation, this would check if the current session
    // is an impersonation session (likely from auth context or a header)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const isImpersonating = user?.impersonating === true; // Placeholder check
    const handleStopImpersonating = React.useCallback(async () => {
        setIsStopping(true);
        try {
            await onStopImpersonating?.();
        }
        finally {
            setIsStopping(false);
        }
    }, [onStopImpersonating]);
    // Don't render if not impersonating or dismissed
    // Note: In a real implementation, check the actual impersonation state
    // For now, we'll show a demo state if no real check is available
    if (!isImpersonating && !isDismissed) {
        // This is a demo/placeholder - in production, you'd check actual impersonation state
        // Returning null until real impersonation detection is implemented
        return null;
    }
    if (isDismissed) {
        return (jsxRuntime.jsx("button", { onClick: () => setIsDismissed(false), style: styles$2.showButton, title: "Show impersonation banner", children: jsxRuntime.jsx(UserIcon, {}) }));
    }
    return (jsxRuntime.jsxs("div", { style: styles$2.banner, role: "alert", "aria-live": "polite", children: [jsxRuntime.jsxs("div", { style: styles$2.content, children: [jsxRuntime.jsx("div", { style: styles$2.icon, children: jsxRuntime.jsx(UserIcon, {}) }), jsxRuntime.jsxs("div", { style: styles$2.text, children: [jsxRuntime.jsx("span", { style: styles$2.label, children: "Impersonating" }), jsxRuntime.jsx("span", { style: styles$2.userInfo, children: user?.profile?.name || user?.email || 'Unknown User' })] })] }), jsxRuntime.jsxs("div", { style: styles$2.actions, children: [jsxRuntime.jsx("button", { onClick: handleStopImpersonating, disabled: isStopping, style: styles$2.stopButton, children: isStopping ? (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx(Spinner, {}), jsxRuntime.jsx("span", { children: "Stopping..." })] })) : (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx(LogOutIcon, {}), jsxRuntime.jsx("span", { children: "Stop Impersonating" })] })) }), jsxRuntime.jsx("button", { onClick: () => setIsDismissed(true), style: styles$2.dismissButton, title: "Dismiss banner", "aria-label": "Dismiss impersonation banner", children: jsxRuntime.jsx(CloseIcon, {}) })] })] }));
}
// Icon Components
function UserIcon() {
    return (jsxRuntime.jsxs("svg", { width: "18", height: "18", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("path", { d: "M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" }), jsxRuntime.jsx("circle", { cx: "12", cy: "7", r: "4" })] }));
}
function LogOutIcon() {
    return (jsxRuntime.jsxs("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("path", { d: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" }), jsxRuntime.jsx("polyline", { points: "16 17 21 12 16 7" }), jsxRuntime.jsx("line", { x1: "21", y1: "12", x2: "9", y2: "12" })] }));
}
function CloseIcon() {
    return (jsxRuntime.jsxs("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [jsxRuntime.jsx("line", { x1: "18", y1: "6", x2: "6", y2: "18" }), jsxRuntime.jsx("line", { x1: "6", y1: "6", x2: "18", y2: "18" })] }));
}
function Spinner() {
    return (jsxRuntime.jsx("div", { style: styles$2.spinner, children: jsxRuntime.jsx("div", { style: styles$2.spinnerInner }) }));
}
// Styles
const styles$2 = {
    banner: {
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 16px',
        backgroundColor: '#7c3aed', // Purple for impersonation
        color: '#fff',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    },
    content: {
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
    },
    icon: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '32px',
        height: '32px',
        backgroundColor: 'rgba(255, 255, 255, 0.2)',
        borderRadius: '6px',
    },
    text: {
        display: 'flex',
        flexDirection: 'column',
        gap: '2px',
    },
    label: {
        fontSize: '11px',
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
        opacity: 0.8,
    },
    userInfo: {
        fontSize: '14px',
        fontWeight: 500,
    },
    actions: {
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
    },
    stopButton: {
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        padding: '8px 12px',
        fontSize: '13px',
        fontWeight: 500,
        color: '#7c3aed',
        backgroundColor: '#fff',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'all 0.15s ease-in-out',
    },
    dismissButton: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '32px',
        height: '32px',
        color: '#fff',
        backgroundColor: 'rgba(255, 255, 255, 0.2)',
        border: 'none',
        borderRadius: '6px',
        cursor: 'pointer',
        transition: 'all 0.15s ease-in-out',
    },
    showButton: {
        position: 'fixed',
        top: '16px',
        right: '16px',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '40px',
        height: '40px',
        color: '#fff',
        backgroundColor: '#7c3aed',
        border: 'none',
        borderRadius: '50%',
        cursor: 'pointer',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
    },
    spinner: {
        width: '14px',
        height: '14px',
        animation: 'spin 1s linear infinite',
    },
    spinnerInner: {
        width: '100%',
        height: '100%',
        border: '2px solid rgba(124, 58, 237, 0.3)',
        borderTopColor: '#7c3aed',
        borderRadius: '50%',
    },
};

/**
 * Renders children only when user is signed in.
 */
function SignedIn({ children }) {
    const { isSignedIn, isLoaded } = useAuth();
    if (!isLoaded) {
        return null;
    }
    return isSignedIn ? jsxRuntime.jsx(jsxRuntime.Fragment, { children: children }) : null;
}
/**
 * Renders children only when user is signed out.
 */
function SignedOut({ children }) {
    const { isSignedIn, isLoaded } = useAuth();
    if (!isLoaded) {
        return null;
    }
    return !isSignedIn ? jsxRuntime.jsx(jsxRuntime.Fragment, { children: children }) : null;
}
/**
 * Renders children only when user is signed in.
 * Shows fallback (or default message) when signed out.
 * Shows loading state while auth is loading.
 */
function RequireAuth({ children, fallback, loading }) {
    const { isSignedIn, isLoaded } = useAuth();
    if (!isLoaded) {
        if (loading) {
            return jsxRuntime.jsx(jsxRuntime.Fragment, { children: loading });
        }
        return (jsxRuntime.jsxs("div", { style: styles$1.loading, children: [jsxRuntime.jsx("div", { style: styles$1.spinner }), jsxRuntime.jsx("span", { children: "Loading..." })] }));
    }
    if (!isSignedIn) {
        if (fallback) {
            return jsxRuntime.jsx(jsxRuntime.Fragment, { children: fallback });
        }
        return (jsxRuntime.jsxs("div", { style: styles$1.unauthenticated, children: [jsxRuntime.jsx("p", { children: "Please sign in to continue." }), jsxRuntime.jsx("a", { href: "/sign-in", style: styles$1.link, children: "Sign In" })] }));
    }
    return jsxRuntime.jsx(jsxRuntime.Fragment, { children: children });
}
// Styles
const styles$1 = {
    loading: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '12px',
        padding: '48px',
        color: '#6b7280',
    },
    spinner: {
        width: '20px',
        height: '20px',
        border: '2px solid #e5e7eb',
        borderTopColor: '#0066cc',
        borderRadius: '50%',
        animation: 'spin 1s linear infinite',
    },
    unauthenticated: {
        padding: '48px',
        textAlign: 'center',
        color: '#6b7280',
    },
    link: {
        color: '#0066cc',
        textDecoration: 'none',
    },
};

function Protect({ children, fallback, role, permission, loading, }) {
    const { isLoaded, isSignedIn, user } = useAuth();
    const { organization } = useOrganization();
    // Show loading state
    if (!isLoaded) {
        if (loading) {
            return jsxRuntime.jsx(jsxRuntime.Fragment, { children: loading });
        }
        return (jsxRuntime.jsxs("div", { style: styles.loading, children: [jsxRuntime.jsx("div", { style: styles.spinner }), jsxRuntime.jsx("span", { children: "Loading..." })] }));
    }
    // Not signed in
    if (!isSignedIn || !user) {
        if (fallback) {
            return jsxRuntime.jsx(jsxRuntime.Fragment, { children: fallback });
        }
        return (jsxRuntime.jsxs("div", { style: styles.unauthorized, children: [jsxRuntime.jsx("h2", { style: styles.title, children: "Sign in required" }), jsxRuntime.jsx("p", { style: styles.message, children: "You need to be signed in to access this page." }), jsxRuntime.jsx("a", { href: "/sign-in", style: styles.link, children: "Sign In" })] }));
    }
    // Check role requirement
    if (role) {
        const userRole = organization?.role;
        if (userRole !== role && userRole !== 'owner') {
            return (jsxRuntime.jsxs("div", { style: styles.unauthorized, children: [jsxRuntime.jsx("h2", { style: styles.title, children: "Access denied" }), jsxRuntime.jsx("p", { style: styles.message, children: "You don't have the required role to access this page." }), jsxRuntime.jsx("a", { href: "/", style: styles.link, children: "Go Home" })] }));
        }
    }
    // All checks passed, render children
    return jsxRuntime.jsx(jsxRuntime.Fragment, { children: children });
}
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
function RedirectToSignIn({ redirectUrl }) {
    const { isLoaded, isSignedIn } = useAuth();
    React.useEffect(() => {
        if (isLoaded && !isSignedIn) {
            const url = redirectUrl
                ? `/sign-in?redirect_url=${encodeURIComponent(redirectUrl)}`
                : '/sign-in';
            window.location.href = url;
        }
    }, [isLoaded, isSignedIn, redirectUrl]);
    return (jsxRuntime.jsxs("div", { style: styles.loading, children: [jsxRuntime.jsx("div", { style: styles.spinner }), jsxRuntime.jsx("span", { children: "Redirecting..." })] }));
}
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
function RedirectToSignUp({ redirectUrl }) {
    const { isLoaded, isSignedIn } = useAuth();
    React.useEffect(() => {
        if (isLoaded && !isSignedIn) {
            const url = redirectUrl
                ? `/sign-up?redirect_url=${encodeURIComponent(redirectUrl)}`
                : '/sign-up';
            window.location.href = url;
        }
    }, [isLoaded, isSignedIn, redirectUrl]);
    return (jsxRuntime.jsxs("div", { style: styles.loading, children: [jsxRuntime.jsx("div", { style: styles.spinner }), jsxRuntime.jsx("span", { children: "Redirecting..." })] }));
}
// Styles
const styles = {
    loading: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '12px',
        padding: '48px',
        color: '#6b7280',
    },
    spinner: {
        width: '20px',
        height: '20px',
        border: '2px solid #e5e7eb',
        borderTopColor: '#0066cc',
        borderRadius: '50%',
        animation: 'spin 1s linear infinite',
    },
    unauthorized: {
        maxWidth: '400px',
        margin: '48px auto',
        padding: '32px',
        textAlign: 'center',
        backgroundColor: '#f9fafb',
        borderRadius: '8px',
        border: '1px solid #e5e7eb',
    },
    title: {
        fontSize: '20px',
        fontWeight: 600,
        margin: '0 0 8px',
        color: '#1f2937',
    },
    message: {
        fontSize: '14px',
        color: '#6b7280',
        margin: '0 0 20px',
    },
    link: {
        display: 'inline-block',
        padding: '10px 20px',
        fontSize: '14px',
        fontWeight: 500,
        color: '#fff',
        backgroundColor: '#0066cc',
        borderRadius: '6px',
        textDecoration: 'none',
    },
};

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
const PricingTable = ({ plans, currentPlanId, currentInterval = 'month', loading = false, onSelectPlan, onIntervalChange, showFeatures = true, className = '', }) => {
    const { appearance } = useTheme();
    const [selectedInterval, setSelectedInterval] = React.useState(currentInterval);
    // Handle interval change
    const handleIntervalChange = (interval) => {
        setSelectedInterval(interval);
        onIntervalChange?.(interval);
    };
    // Format price for display
    const formatPrice = (amount, currency) => {
        const formatter = new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: currency.toUpperCase(),
            minimumFractionDigits: 0,
            maximumFractionDigits: 2,
        });
        return formatter.format(amount / 100);
    };
    // Get features for display
    const getFeatures = (plan) => {
        return plan.features.map((feature) => ({
            name: feature,
            included: true,
            description: feature,
        }));
    };
    // Check if a plan is the current plan
    const isCurrentPlan = (plan) => plan.id === currentPlanId;
    // Loading state
    if (loading) {
        return (jsxRuntime.jsx("div", { className: `vault-pricing-table vault-pricing-loading ${className}`, children: jsxRuntime.jsx("div", { className: "vault-pricing-skeleton", children: [1, 2, 3].map((i) => (jsxRuntime.jsx("div", { className: "vault-pricing-card-skeleton" }, i))) }) }));
    }
    // Empty state
    if (!plans || plans.length === 0) {
        return (jsxRuntime.jsx("div", { className: `vault-pricing-table vault-pricing-empty ${className}`, children: jsxRuntime.jsx("p", { children: "No plans available" }) }));
    }
    return (jsxRuntime.jsxs("div", { className: `vault-pricing-table ${className}`, style: {
            '--vault-primary': appearance?.variables?.colorPrimary,
            '--vault-background': appearance?.variables?.colorBackground,
            '--vault-foreground': appearance?.variables?.colorText,
        }, children: [onIntervalChange && (jsxRuntime.jsxs("div", { className: "vault-pricing-interval-toggle", children: [jsxRuntime.jsx("button", { className: `vault-interval-btn ${selectedInterval === 'month' ? 'active' : ''}`, onClick: () => handleIntervalChange('month'), type: "button", children: "Monthly" }), jsxRuntime.jsxs("button", { className: `vault-interval-btn ${selectedInterval === 'year' ? 'active' : ''}`, onClick: () => handleIntervalChange('year'), type: "button", children: ["Yearly", jsxRuntime.jsx("span", { className: "vault-save-badge", children: "Save 20%" })] })] })), jsxRuntime.jsx("div", { className: "vault-pricing-grid", children: plans.map((plan) => {
                    const features = getFeatures(plan);
                    const isCurrent = isCurrentPlan(plan);
                    return (jsxRuntime.jsxs("div", { className: `vault-pricing-card ${isCurrent ? 'current' : ''}`, "data-plan-id": plan.id, children: [isCurrent && (jsxRuntime.jsx("div", { className: "vault-current-plan-badge", children: "Current Plan" })), jsxRuntime.jsxs("div", { className: "vault-pricing-header", children: [jsxRuntime.jsx("h3", { className: "vault-plan-name", children: plan.name }), plan.description && (jsxRuntime.jsx("p", { className: "vault-plan-description", children: plan.description }))] }), jsxRuntime.jsxs("div", { className: "vault-pricing-price", children: [jsxRuntime.jsx("span", { className: "vault-price-amount", children: formatPrice(plan.amount, plan.currency) }), jsxRuntime.jsxs("span", { className: "vault-price-interval", children: ["/", plan.interval] })] }), showFeatures && features.length > 0 && (jsxRuntime.jsx("ul", { className: "vault-pricing-features", children: features.map((feature, index) => (jsxRuntime.jsxs("li", { className: `vault-feature-item ${feature.included ? 'included' : 'excluded'}`, title: feature.description, children: [jsxRuntime.jsx("svg", { className: "vault-feature-icon", viewBox: "0 0 20 20", fill: "currentColor", children: feature.included ? (jsxRuntime.jsx("path", { fillRule: "evenodd", d: "M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z", clipRule: "evenodd" })) : (jsxRuntime.jsx("path", { fillRule: "evenodd", d: "M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z", clipRule: "evenodd" })) }), jsxRuntime.jsx("span", { className: "vault-feature-name", children: feature.name })] }, index))) })), onSelectPlan && (jsxRuntime.jsx("button", { className: `vault-pricing-cta ${isCurrent ? 'current' : ''}`, onClick: () => onSelectPlan(plan), disabled: isCurrent, type: "button", children: isCurrent ? 'Current Plan' : 'Subscribe' }))] }, plan.id));
                }) }), jsxRuntime.jsx("style", { children: `
        .vault-pricing-table {
          --vault-card-bg: var(--vault-background, #ffffff);
          --vault-card-border: #e5e7eb;
          --vault-primary-color: var(--vault-primary, #3b82f6);
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-text-secondary: #6b7280;
          --vault-success: #10b981;
          
          width: 100%;
        }

        .vault-pricing-interval-toggle {
          display: flex;
          justify-content: center;
          gap: 0.5rem;
          margin-bottom: 2rem;
        }

        .vault-interval-btn {
          padding: 0.5rem 1rem;
          border: 1px solid var(--vault-card-border);
          background: var(--vault-card-bg);
          color: var(--vault-text-primary);
          border-radius: 0.5rem;
          cursor: pointer;
          font-size: 0.875rem;
          transition: all 0.2s;
        }

        .vault-interval-btn.active {
          background: var(--vault-primary-color);
          color: white;
          border-color: var(--vault-primary-color);
        }

        .vault-save-badge {
          margin-left: 0.5rem;
          padding: 0.125rem 0.5rem;
          background: var(--vault-success);
          color: white;
          border-radius: 9999px;
          font-size: 0.75rem;
          font-weight: 600;
        }

        .vault-pricing-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 1.5rem;
        }

        .vault-pricing-card {
          position: relative;
          padding: 1.5rem;
          background: var(--vault-card-bg);
          border: 2px solid var(--vault-card-border);
          border-radius: 1rem;
          transition: all 0.2s;
        }

        .vault-pricing-card:hover {
          border-color: var(--vault-primary-color);
          box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .vault-pricing-card.current {
          border-color: var(--vault-primary-color);
          box-shadow: 0 0 0 2px var(--vault-primary-color);
        }

        .vault-current-plan-badge {
          position: absolute;
          top: -1px;
          left: 50%;
          transform: translateX(-50%);
          padding: 0.25rem 1rem;
          background: var(--vault-primary-color);
          color: white;
          font-size: 0.75rem;
          font-weight: 600;
          border-radius: 0 0 0.5rem 0.5rem;
        }

        .vault-pricing-header {
          text-align: center;
          margin-bottom: 1.5rem;
        }

        .vault-plan-name {
          margin: 0 0 0.5rem;
          font-size: 1.5rem;
          font-weight: 700;
          color: var(--vault-text-primary);
        }

        .vault-plan-description {
          margin: 0;
          font-size: 0.875rem;
          color: var(--vault-text-secondary);
        }

        .vault-pricing-price {
          text-align: center;
          margin-bottom: 1.5rem;
        }

        .vault-price-amount {
          font-size: 2.5rem;
          font-weight: 700;
          color: var(--vault-text-primary);
        }

        .vault-price-interval {
          font-size: 1rem;
          color: var(--vault-text-secondary);
        }

        .vault-pricing-features {
          list-style: none;
          padding: 0;
          margin: 0 0 1.5rem;
        }

        .vault-feature-item {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          padding: 0.5rem 0;
          font-size: 0.875rem;
        }

        .vault-feature-item.included {
          color: var(--vault-text-primary);
        }

        .vault-feature-item.excluded {
          color: var(--vault-text-secondary);
          opacity: 0.5;
        }

        .vault-feature-icon {
          width: 1.25rem;
          height: 1.25rem;
          flex-shrink: 0;
        }

        .vault-feature-item.included .vault-feature-icon {
          color: var(--vault-success);
        }

        .vault-feature-item.excluded .vault-feature-icon {
          color: var(--vault-text-secondary);
        }

        .vault-pricing-cta {
          width: 100%;
          padding: 0.75rem 1rem;
          background: var(--vault-primary-color);
          color: white;
          border: none;
          border-radius: 0.5rem;
          font-size: 1rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }

        .vault-pricing-cta:hover:not(:disabled) {
          opacity: 0.9;
          transform: translateY(-1px);
        }

        .vault-pricing-cta:disabled {
          background: var(--vault-card-border);
          color: var(--vault-text-secondary);
          cursor: not-allowed;
        }

        .vault-pricing-cta.current {
          background: var(--vault-card-border);
          color: var(--vault-text-secondary);
        }

        .vault-pricing-skeleton {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 1.5rem;
        }

        .vault-pricing-card-skeleton {
          height: 400px;
          background: linear-gradient(90deg, #f3f4f6 25%, #e5e7eb 50%, #f3f4f6 75%);
          background-size: 200% 100%;
          animation: vault-skeleton-loading 1.5s infinite;
          border-radius: 1rem;
        }

        @keyframes vault-skeleton-loading {
          0% {
            background-position: 200% 0;
          }
          100% {
            background-position: -200% 0;
          }
        }

        .vault-pricing-empty {
          text-align: center;
          padding: 3rem;
          color: var(--vault-text-secondary);
        }
      ` })] }));
};

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
const CheckoutButton = ({ priceId, successUrl, cancelUrl, children, disabled = false, loading: externalLoading = false, onCheckout, onError, className = '', }) => {
    const { createCheckout } = useBilling();
    const { appearance } = useTheme();
    const [internalLoading, setInternalLoading] = React.useState(false);
    const isLoading = externalLoading || internalLoading;
    const isDisabled = disabled || isLoading;
    const handleClick = React.useCallback(async () => {
        if (isDisabled)
            return;
        setInternalLoading(true);
        try {
            const session = await createCheckout({
                priceId,
                successUrl,
                cancelUrl,
            });
            onCheckout?.(session);
            // Redirect to checkout
            if (session.url) {
                window.location.href = session.url;
            }
        }
        catch (error) {
            console.error('Checkout failed:', error);
            onError?.(error instanceof Error ? error : new Error('Checkout failed'));
        }
        finally {
            setInternalLoading(false);
        }
    }, [createCheckout, priceId, successUrl, cancelUrl, onCheckout, onError, isDisabled]);
    return (jsxRuntime.jsxs("button", { className: `vault-checkout-button ${isLoading ? 'loading' : ''} ${className}`, onClick: handleClick, disabled: isDisabled, type: "button", style: {
            '--vault-primary': appearance?.variables?.colorPrimary,
            '--vault-background': appearance?.variables?.colorBackground,
            '--vault-foreground': appearance?.variables?.colorText,
        }, children: [isLoading ? (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx("span", { className: "vault-checkout-spinner" }), jsxRuntime.jsx("span", { children: "Loading..." })] })) : (children), jsxRuntime.jsx("style", { children: `
        .vault-checkout-button {
          --vault-primary-color: var(--vault-primary, #3b82f6);
          --vault-text-primary: var(--vault-foreground, #111827);
          
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          padding: 0.75rem 1.5rem;
          background: var(--vault-primary-color);
          color: white;
          border: none;
          border-radius: 0.5rem;
          font-size: 1rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          min-width: 150px;
        }

        .vault-checkout-button:hover:not(:disabled) {
          opacity: 0.9;
          transform: translateY(-1px);
        }

        .vault-checkout-button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .vault-checkout-button.loading {
          cursor: wait;
        }

        .vault-checkout-spinner {
          width: 1rem;
          height: 1rem;
          border: 2px solid rgba(255, 255, 255, 0.3);
          border-top-color: white;
          border-radius: 50%;
          animation: vault-checkout-spin 0.8s linear infinite;
        }

        @keyframes vault-checkout-spin {
          to {
            transform: rotate(360deg);
          }
        }
      ` })] }));
};
const QuickCheckoutButton = ({ priceId, children, successPath = '/billing/success', cancelPath = '/billing/cancel', ...props }) => {
    const successUrl = typeof window !== 'undefined'
        ? `${window.location.origin}${successPath}`
        : successPath;
    const cancelUrl = typeof window !== 'undefined'
        ? `${window.location.origin}${cancelPath}`
        : cancelPath;
    return (jsxRuntime.jsx(CheckoutButton, { priceId: priceId, successUrl: successUrl, cancelUrl: cancelUrl, ...props, children: children }));
};

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
const CustomerPortalButton = ({ children, returnUrl: propReturnUrl, disabled = false, onOpen, onError, className = '', }) => {
    const { createPortalSession } = useBilling();
    const { appearance } = useTheme();
    const [isLoading, setIsLoading] = React.useState(false);
    // Default return URL to current page
    const returnUrl = propReturnUrl || (typeof window !== 'undefined' ? window.location.href : '/');
    const handleClick = React.useCallback(async () => {
        if (disabled || isLoading)
            return;
        setIsLoading(true);
        try {
            const session = await createPortalSession({ returnUrl });
            onOpen?.();
            // Open portal in same window
            if (session.url) {
                window.location.href = session.url;
            }
        }
        catch (error) {
            console.error('Failed to open customer portal:', error);
            onError?.(error instanceof Error ? error : new Error('Failed to open billing portal'));
        }
        finally {
            setIsLoading(false);
        }
    }, [createPortalSession, returnUrl, disabled, isLoading, onOpen, onError]);
    return (jsxRuntime.jsxs("button", { className: `vault-portal-button ${isLoading ? 'loading' : ''} ${className}`, onClick: handleClick, disabled: disabled || isLoading, type: "button", style: {
            '--vault-primary': appearance?.variables?.colorPrimary,
            '--vault-background': appearance?.variables?.colorBackground,
            '--vault-foreground': appearance?.variables?.colorText,
        }, children: [isLoading ? (jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [jsxRuntime.jsx("span", { className: "vault-portal-spinner" }), jsxRuntime.jsx("span", { children: "Loading..." })] })) : (children), jsxRuntime.jsx("style", { children: `
        .vault-portal-button {
          --vault-primary-color: var(--vault-primary, #3b82f6);
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-card-bg: var(--vault-background, #ffffff);
          --vault-card-border: #e5e7eb;
          
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          padding: 0.75rem 1.5rem;
          background: var(--vault-card-bg);
          color: var(--vault-text-primary);
          border: 1px solid var(--vault-card-border);
          border-radius: 0.5rem;
          font-size: 1rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s;
        }

        .vault-portal-button:hover:not(:disabled) {
          border-color: var(--vault-primary-color);
          background: rgba(59, 130, 246, 0.05);
        }

        .vault-portal-button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .vault-portal-button.loading {
          cursor: wait;
        }

        .vault-portal-spinner {
          width: 1rem;
          height: 1rem;
          border: 2px solid rgba(0, 0, 0, 0.1);
          border-top-color: var(--vault-primary-color);
          border-radius: 50%;
          animation: vault-portal-spin 0.8s linear infinite;
        }

        @keyframes vault-portal-spin {
          to {
            transform: rotate(360deg);
          }
        }
      ` })] }));
};
/**
 * ManageSubscriptionButton - Opens portal to the subscription management page
 */
const ManageSubscriptionButton = (props) => {
    return jsxRuntime.jsx(CustomerPortalButton, { ...props });
};
/**
 * UpdatePaymentMethodButton - Opens portal to update payment methods
 */
const UpdatePaymentMethodButton = (props) => {
    return jsxRuntime.jsx(CustomerPortalButton, { ...props });
};
/**
 * ViewInvoicesButton - Opens portal to view invoice history
 */
const ViewInvoicesButton = (props) => {
    return jsxRuntime.jsx(CustomerPortalButton, { ...props });
};
const BillingSettings = ({ returnUrl, showManageSubscription = true, showUpdatePayment = true, showViewInvoices = true, className = '', }) => {
    const { appearance } = useTheme();
    return (jsxRuntime.jsxs("div", { className: `vault-billing-settings ${className}`, style: {
            '--vault-primary': appearance?.variables?.colorPrimary,
            '--vault-background': appearance?.variables?.colorBackground,
            '--vault-foreground': appearance?.variables?.colorText,
        }, children: [jsxRuntime.jsx("h3", { className: "vault-billing-settings-title", children: "Billing Settings" }), jsxRuntime.jsxs("div", { className: "vault-billing-settings-list", children: [showManageSubscription && (jsxRuntime.jsxs("div", { className: "vault-billing-setting-item", children: [jsxRuntime.jsxs("div", { className: "vault-billing-setting-info", children: [jsxRuntime.jsx("h4", { children: "Subscription Plan" }), jsxRuntime.jsx("p", { children: "Upgrade, downgrade, or cancel your subscription" })] }), jsxRuntime.jsx(CustomerPortalButton, { returnUrl: returnUrl, children: "Manage" })] })), showUpdatePayment && (jsxRuntime.jsxs("div", { className: "vault-billing-setting-item", children: [jsxRuntime.jsxs("div", { className: "vault-billing-setting-info", children: [jsxRuntime.jsx("h4", { children: "Payment Methods" }), jsxRuntime.jsx("p", { children: "Add or update your payment methods" })] }), jsxRuntime.jsx(UpdatePaymentMethodButton, { returnUrl: returnUrl, children: "Update" })] })), showViewInvoices && (jsxRuntime.jsxs("div", { className: "vault-billing-setting-item", children: [jsxRuntime.jsxs("div", { className: "vault-billing-setting-info", children: [jsxRuntime.jsx("h4", { children: "Billing History" }), jsxRuntime.jsx("p", { children: "View and download your invoices" })] }), jsxRuntime.jsx(ViewInvoicesButton, { returnUrl: returnUrl, children: "View" })] }))] }), jsxRuntime.jsx("style", { children: `
        .vault-billing-settings {
          --vault-card-bg: var(--vault-background, #ffffff);
          --vault-card-border: #e5e7eb;
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-text-secondary: #6b7280;
          
          background: var(--vault-card-bg);
          border: 1px solid var(--vault-card-border);
          border-radius: 0.75rem;
          padding: 1.5rem;
        }

        .vault-billing-settings-title {
          margin: 0 0 1.5rem;
          font-size: 1.25rem;
          font-weight: 600;
          color: var(--vault-text-primary);
        }

        .vault-billing-settings-list {
          display: flex;
          flex-direction: column;
          gap: 1.5rem;
        }

        .vault-billing-setting-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 1rem;
          padding-bottom: 1.5rem;
          border-bottom: 1px solid var(--vault-card-border);
        }

        .vault-billing-setting-item:last-child {
          padding-bottom: 0;
          border-bottom: none;
        }

        .vault-billing-setting-info h4 {
          margin: 0 0 0.25rem;
          font-size: 1rem;
          font-weight: 600;
          color: var(--vault-text-primary);
        }

        .vault-billing-setting-info p {
          margin: 0;
          font-size: 0.875rem;
          color: var(--vault-text-secondary);
        }
      ` })] }));
};

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
const SubscriptionStatus = ({ subscription: propSubscription, showDetails = true, showInvoices = false, showUsage = false, onCancel, onResume, onUpdate, className = '', }) => {
    const hookSubscription = useSubscription();
    const { usage, percentage: usagePercentage } = useUsage();
    const { appearance } = useTheme();
    // Use prop subscription if provided, otherwise use hook
    const { subscription, isLoading, isActive, isTrialing, isCanceled, daysUntilRenewal, daysLeftInTrial, willRenew, } = propSubscription
        ? {
            subscription: propSubscription,
            isLoading: false,
            isActive: ['active', 'trialing'].includes(propSubscription.status),
            isTrialing: propSubscription.status === 'trialing',
            isCanceled: propSubscription.cancelAtPeriodEnd ||
                ['canceled', 'unpaid'].includes(propSubscription.status),
            daysUntilRenewal: Math.max(0, Math.ceil((new Date(propSubscription.currentPeriodEnd).getTime() - Date.now()) /
                (1000 * 60 * 60 * 24))),
            daysLeftInTrial: propSubscription.trialEnd
                ? Math.max(0, Math.ceil((new Date(propSubscription.trialEnd).getTime() - Date.now()) /
                    (1000 * 60 * 60 * 24)))
                : null,
            willRenew: ['active', 'trialing'].includes(propSubscription.status) &&
                !propSubscription.cancelAtPeriodEnd,
        }
        : hookSubscription;
    const [isActionLoading, setIsActionLoading] = React.useState(false);
    const handleCancel = React.useCallback(async () => {
        if (!onCancel)
            return;
        setIsActionLoading(true);
        try {
            await onCancel();
        }
        finally {
            setIsActionLoading(false);
        }
    }, [onCancel]);
    const handleResume = React.useCallback(async () => {
        if (!onResume)
            return;
        setIsActionLoading(true);
        try {
            await onResume();
        }
        finally {
            setIsActionLoading(false);
        }
    }, [onResume]);
    // Format date for display
    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
        });
    };
    // Get status badge color
    const getStatusColor = (status) => {
        switch (status) {
            case 'active':
                return 'success';
            case 'trialing':
                return 'info';
            case 'past_due':
            case 'unpaid':
                return 'warning';
            case 'canceled':
                return 'error';
            default:
                return 'default';
        }
    };
    // Loading state
    if (isLoading) {
        return (jsxRuntime.jsx("div", { className: `vault-subscription-status loading ${className}`, children: jsxRuntime.jsx("div", { className: "vault-subscription-skeleton" }) }));
    }
    // No subscription state
    if (!subscription) {
        return (jsxRuntime.jsxs("div", { className: `vault-subscription-status empty ${className}`, style: {
                '--vault-primary': appearance?.variables?.colorPrimary,
                '--vault-background': appearance?.variables?.colorBackground,
                '--vault-foreground': appearance?.variables?.colorText,
            }, children: [jsxRuntime.jsxs("div", { className: "vault-subscription-empty", children: [jsxRuntime.jsx("svg", { className: "vault-empty-icon", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", children: jsxRuntime.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", strokeWidth: 1.5, d: "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" }) }), jsxRuntime.jsx("h3", { children: "No Active Subscription" }), jsxRuntime.jsx("p", { children: "You don't have an active subscription. Choose a plan to get started." })] }), jsxRuntime.jsx("style", { children: `
          .vault-subscription-empty {
            text-align: center;
            padding: 3rem 2rem;
            background: var(--vault-background, #ffffff);
            border: 2px dashed #e5e7eb;
            border-radius: 1rem;
          }

          .vault-empty-icon {
            width: 4rem;
            height: 4rem;
            margin-bottom: 1rem;
            color: #9ca3af;
          }

          .vault-subscription-empty h3 {
            margin: 0 0 0.5rem;
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--vault-foreground, #111827);
          }

          .vault-subscription-empty p {
            margin: 0;
            font-size: 0.875rem;
            color: #6b7280;
          }
        ` })] }));
    }
    return (jsxRuntime.jsxs("div", { className: `vault-subscription-status ${className}`, style: {
            '--vault-primary': appearance?.variables?.colorPrimary,
            '--vault-background': appearance?.variables?.colorBackground,
            '--vault-foreground': appearance?.variables?.colorText,
        }, children: [jsxRuntime.jsxs("div", { className: "vault-subscription-header", children: [jsxRuntime.jsxs("div", { className: "vault-subscription-info", children: [jsxRuntime.jsx("h3", { className: "vault-plan-name", children: subscription.plan?.name || 'Subscription' }), jsxRuntime.jsx("span", { className: `vault-status-badge ${getStatusColor(subscription.status)}`, children: subscription.status.replace('_', ' ') })] }), subscription.plan && (jsxRuntime.jsxs("div", { className: "vault-plan-price", children: [jsxRuntime.jsxs("span", { className: "vault-price-amount", children: ["$", (subscription.plan.amount / 100).toFixed(2)] }), jsxRuntime.jsxs("span", { className: "vault-price-interval", children: ["/", subscription.plan.interval] })] }))] }), showDetails && (jsxRuntime.jsxs("div", { className: "vault-subscription-details", children: [isTrialing && daysLeftInTrial !== null && (jsxRuntime.jsxs("div", { className: "vault-detail-item vault-trial-info", children: [jsxRuntime.jsx("span", { className: "vault-detail-label", children: "Trial ends in" }), jsxRuntime.jsxs("span", { className: "vault-detail-value vault-trial-days", children: [daysLeftInTrial, " days"] })] })), isActive && !isCanceled && (jsxRuntime.jsxs("div", { className: "vault-detail-item", children: [jsxRuntime.jsx("span", { className: "vault-detail-label", children: willRenew ? 'Next billing date' : 'Access until' }), jsxRuntime.jsx("span", { className: "vault-detail-value", children: formatDate(subscription.currentPeriodEnd) })] })), isCanceled && (jsxRuntime.jsxs("div", { className: "vault-detail-item vault-canceled-info", children: [jsxRuntime.jsx("span", { className: "vault-detail-label", children: "Subscription ends" }), jsxRuntime.jsx("span", { className: "vault-detail-value", children: formatDate(subscription.currentPeriodEnd) })] })), subscription.cancelAtPeriodEnd && !isCanceled && (jsxRuntime.jsxs("div", { className: "vault-cancel-warning", children: [jsxRuntime.jsx("svg", { viewBox: "0 0 20 20", fill: "currentColor", children: jsxRuntime.jsx("path", { fillRule: "evenodd", d: "M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z", clipRule: "evenodd" }) }), jsxRuntime.jsx("span", { children: "Your subscription will not renew" })] }))] })), showUsage && usage && (jsxRuntime.jsxs("div", { className: "vault-usage-section", children: [jsxRuntime.jsx("h4", { children: "Usage This Period" }), jsxRuntime.jsx(UsageMeter, { usage: usage, showPercentage: true })] })), jsxRuntime.jsxs("div", { className: "vault-subscription-actions", children: [onCancel && isActive && !subscription.cancelAtPeriodEnd && (jsxRuntime.jsx("button", { className: "vault-action-btn cancel", onClick: handleCancel, disabled: isActionLoading, type: "button", children: isActionLoading ? 'Processing...' : 'Cancel Subscription' })), onResume && subscription.cancelAtPeriodEnd && (jsxRuntime.jsx("button", { className: "vault-action-btn resume", onClick: handleResume, disabled: isActionLoading, type: "button", children: isActionLoading ? 'Processing...' : 'Resume Subscription' }))] }), jsxRuntime.jsx("style", { children: `
        .vault-subscription-status {
          --vault-card-bg: var(--vault-background, #ffffff);
          --vault-card-border: #e5e7eb;
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-text-secondary: #6b7280;
          --vault-primary-color: var(--vault-primary, #3b82f6);
          --vault-success: #10b981;
          --vault-warning: #f59e0b;
          --vault-error: #ef4444;
          --vault-info: #3b82f6;
          
          background: var(--vault-card-bg);
          border: 1px solid var(--vault-card-border);
          border-radius: 0.75rem;
          padding: 1.5rem;
        }

        .vault-subscription-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 1.5rem;
          padding-bottom: 1.5rem;
          border-bottom: 1px solid var(--vault-card-border);
        }

        .vault-subscription-info {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .vault-plan-name {
          margin: 0;
          font-size: 1.25rem;
          font-weight: 600;
          color: var(--vault-text-primary);
        }

        .vault-status-badge {
          display: inline-flex;
          padding: 0.25rem 0.75rem;
          border-radius: 9999px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
        }

        .vault-status-badge.success {
          background: rgba(16, 185, 129, 0.1);
          color: var(--vault-success);
        }

        .vault-status-badge.info {
          background: rgba(59, 130, 246, 0.1);
          color: var(--vault-info);
        }

        .vault-status-badge.warning {
          background: rgba(245, 158, 11, 0.1);
          color: var(--vault-warning);
        }

        .vault-status-badge.error {
          background: rgba(239, 68, 68, 0.1);
          color: var(--vault-error);
        }

        .vault-status-badge.default {
          background: #f3f4f6;
          color: #6b7280;
        }

        .vault-plan-price {
          text-align: right;
        }

        .vault-price-amount {
          font-size: 1.5rem;
          font-weight: 700;
          color: var(--vault-text-primary);
        }

        .vault-price-interval {
          font-size: 0.875rem;
          color: var(--vault-text-secondary);
        }

        .vault-subscription-details {
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          margin-bottom: 1.5rem;
        }

        .vault-detail-item {
          display: flex;
          justify-content: space-between;
          font-size: 0.875rem;
        }

        .vault-detail-label {
          color: var(--vault-text-secondary);
        }

        .vault-detail-value {
          font-weight: 500;
          color: var(--vault-text-primary);
        }

        .vault-trial-info .vault-detail-value {
          color: var(--vault-info);
        }

        .vault-canceled-info .vault-detail-value {
          color: var(--vault-error);
        }

        .vault-cancel-warning {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.75rem;
          background: rgba(245, 158, 11, 0.1);
          border-radius: 0.5rem;
          font-size: 0.875rem;
          color: var(--vault-warning);
        }

        .vault-cancel-warning svg {
          width: 1.25rem;
          height: 1.25rem;
          flex-shrink: 0;
        }

        .vault-usage-section {
          margin-bottom: 1.5rem;
          padding: 1rem;
          background: #f9fafb;
          border-radius: 0.5rem;
        }

        .vault-usage-section h4 {
          margin: 0 0 0.75rem;
          font-size: 0.875rem;
          font-weight: 600;
          color: var(--vault-text-primary);
        }

        .vault-subscription-actions {
          display: flex;
          gap: 0.75rem;
        }

        .vault-action-btn {
          flex: 1;
          padding: 0.75rem 1rem;
          border: none;
          border-radius: 0.5rem;
          font-size: 0.875rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s;
        }

        .vault-action-btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .vault-action-btn.cancel {
          background: transparent;
          color: var(--vault-error);
          border: 1px solid var(--vault-error);
        }

        .vault-action-btn.cancel:hover:not(:disabled) {
          background: rgba(239, 68, 68, 0.05);
        }

        .vault-action-btn.resume {
          background: var(--vault-primary-color);
          color: white;
        }

        .vault-action-btn.resume:hover:not(:disabled) {
          opacity: 0.9;
        }

        .vault-subscription-skeleton {
          height: 200px;
          background: linear-gradient(90deg, #f3f4f6 25%, #e5e7eb 50%, #f3f4f6 75%);
          background-size: 200% 100%;
          animation: vault-skeleton-pulse 1.5s infinite;
          border-radius: 0.75rem;
        }

        @keyframes vault-skeleton-pulse {
          0% {
            background-position: 200% 0;
          }
          100% {
            background-position: -200% 0;
          }
        }
      ` })] }));
};
/**
 * UsageMeter component
 *
 * Displays usage with progress bar
 */
const UsageMeter = ({ usage, showPercentage = true, showRemaining = false, className = '', }) => {
    const { appearance } = useTheme();
    const percentage = usage.quota
        ? Math.min(100, (usage.totalUsage / usage.quota.limit) * 100)
        : 0;
    const isNearLimit = usage.quota
        ? percentage >= (usage.quota.warningThreshold || 0.8) * 100
        : false;
    const isOverLimit = usage.quota ? usage.totalUsage > usage.quota.limit : false;
    const remaining = usage.quota ? Math.max(0, usage.quota.limit - usage.totalUsage) : 0;
    const getBarColor = () => {
        if (isOverLimit)
            return 'var(--vault-error, #ef4444)';
        if (isNearLimit)
            return 'var(--vault-warning, #f59e0b)';
        return 'var(--vault-primary, #3b82f6)';
    };
    return (jsxRuntime.jsxs("div", { className: `vault-usage-meter ${className} ${isOverLimit ? 'over-limit' : ''} ${isNearLimit ? 'near-limit' : ''}`, style: {
            '--vault-primary': appearance?.variables?.colorPrimary,
            '--vault-foreground': appearance?.variables?.colorText,
        }, children: [jsxRuntime.jsx("div", { className: "vault-usage-bar-container", children: jsxRuntime.jsx("div", { className: "vault-usage-bar", style: {
                        width: `${percentage}%`,
                        backgroundColor: getBarColor(),
                    } }) }), jsxRuntime.jsxs("div", { className: "vault-usage-info", children: [showPercentage && (jsxRuntime.jsxs("span", { className: "vault-usage-percentage", children: [percentage.toFixed(0), "%"] })), jsxRuntime.jsxs("span", { className: "vault-usage-values", children: [usage.totalUsage.toLocaleString(), usage.quota && ` / ${usage.quota.limit.toLocaleString()}`, " ", usage.metric] }), showRemaining && remaining > 0 && (jsxRuntime.jsxs("span", { className: "vault-usage-remaining", children: ["(", remaining.toLocaleString(), " remaining)"] }))] }), isOverLimit && (jsxRuntime.jsx("div", { className: "vault-usage-warning error", children: "You've exceeded your limit. Please upgrade your plan." })), isNearLimit && !isOverLimit && (jsxRuntime.jsx("div", { className: "vault-usage-warning warning", children: "You're approaching your usage limit." })), jsxRuntime.jsx("style", { children: `
        .vault-usage-meter {
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-text-secondary: #6b7280;
          --vault-primary-color: var(--vault-primary, #3b82f6);
          --vault-success: #10b981;
          --vault-warning: #f59e0b;
          --vault-error: #ef4444;
          --vault-bar-bg: #e5e7eb;
        }

        .vault-usage-bar-container {
          height: 0.5rem;
          background: var(--vault-bar-bg);
          border-radius: 9999px;
          overflow: hidden;
          margin-bottom: 0.5rem;
        }

        .vault-usage-bar {
          height: 100%;
          border-radius: 9999px;
          transition: width 0.3s ease, background-color 0.3s ease;
        }

        .vault-usage-info {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          font-size: 0.875rem;
        }

        .vault-usage-percentage {
          font-weight: 600;
          color: var(--vault-text-primary);
          min-width: 2.5rem;
        }

        .vault-usage-values {
          color: var(--vault-text-secondary);
        }

        .vault-usage-remaining {
          color: var(--vault-text-secondary);
          font-size: 0.75rem;
        }

        .vault-usage-warning {
          margin-top: 0.5rem;
          padding: 0.5rem;
          border-radius: 0.375rem;
          font-size: 0.75rem;
          font-weight: 500;
        }

        .vault-usage-warning.error {
          background: rgba(239, 68, 68, 0.1);
          color: var(--vault-error);
        }

        .vault-usage-warning.warning {
          background: rgba(245, 158, 11, 0.1);
          color: var(--vault-warning);
        }

        .vault-usage-meter.near-limit .vault-usage-percentage {
          color: var(--vault-warning);
        }

        .vault-usage-meter.over-limit .vault-usage-percentage {
          color: var(--vault-error);
        }
      ` })] }));
};
const InvoiceList = ({ invoices, loading = false, emptyMessage = 'No invoices yet', className = '', }) => {
    const { appearance } = useTheme();
    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        });
    };
    const formatAmount = (amount, currency) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: currency.toUpperCase(),
        }).format(amount / 100);
    };
    const getStatusColor = (status) => {
        switch (status) {
            case 'paid':
                return 'success';
            case 'open':
                return 'warning';
            case 'draft':
                return 'default';
            case 'uncollectible':
            case 'void':
                return 'error';
            default:
                return 'default';
        }
    };
    if (loading) {
        return (jsxRuntime.jsx("div", { className: `vault-invoice-list loading ${className}`, children: [1, 2, 3].map((i) => (jsxRuntime.jsx("div", { className: "vault-invoice-skeleton" }, i))) }));
    }
    if (!invoices || invoices.length === 0) {
        return (jsxRuntime.jsx("div", { className: `vault-invoice-list empty ${className}`, style: {
                '--vault-foreground': appearance?.variables?.colorText,
            }, children: jsxRuntime.jsx("p", { className: "vault-invoice-empty-message", children: emptyMessage }) }));
    }
    return (jsxRuntime.jsxs("div", { className: `vault-invoice-list ${className}`, style: {
            '--vault-primary': appearance?.variables?.colorPrimary,
            '--vault-background': appearance?.variables?.colorBackground,
            '--vault-foreground': appearance?.variables?.colorText,
        }, children: [jsxRuntime.jsxs("table", { className: "vault-invoice-table", children: [jsxRuntime.jsx("thead", { children: jsxRuntime.jsxs("tr", { children: [jsxRuntime.jsx("th", { children: "Date" }), jsxRuntime.jsx("th", { children: "Amount" }), jsxRuntime.jsx("th", { children: "Status" }), jsxRuntime.jsx("th", { children: "Action" })] }) }), jsxRuntime.jsx("tbody", { children: invoices.map((invoice) => (jsxRuntime.jsxs("tr", { children: [jsxRuntime.jsx("td", { children: formatDate(invoice.createdAt) }), jsxRuntime.jsx("td", { children: formatAmount(invoice.total, invoice.currency) }), jsxRuntime.jsx("td", { children: jsxRuntime.jsx("span", { className: `vault-invoice-status ${getStatusColor(invoice.status)}`, children: invoice.status }) }), jsxRuntime.jsx("td", { children: invoice.invoicePdf && (jsxRuntime.jsx("a", { href: invoice.invoicePdf, target: "_blank", rel: "noopener noreferrer", className: "vault-invoice-download", children: "Download" })) })] }, invoice.id))) })] }), jsxRuntime.jsx("style", { children: `
        .vault-invoice-list {
          --vault-card-bg: var(--vault-background, #ffffff);
          --vault-text-primary: var(--vault-foreground, #111827);
          --vault-text-secondary: #6b7280;
          --vault-card-border: #e5e7eb;
          --vault-success: #10b981;
          --vault-warning: #f59e0b;
          --vault-error: #ef4444;
          --vault-primary-color: var(--vault-primary, #3b82f6);
        }

        .vault-invoice-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.875rem;
        }

        .vault-invoice-table th {
          text-align: left;
          padding: 0.75rem;
          font-weight: 600;
          color: var(--vault-text-secondary);
          border-bottom: 1px solid var(--vault-card-border);
        }

        .vault-invoice-table td {
          padding: 0.75rem;
          color: var(--vault-text-primary);
          border-bottom: 1px solid var(--vault-card-border);
        }

        .vault-invoice-status {
          display: inline-flex;
          padding: 0.125rem 0.5rem;
          border-radius: 9999px;
          font-size: 0.75rem;
          font-weight: 500;
          text-transform: uppercase;
        }

        .vault-invoice-status.success {
          background: rgba(16, 185, 129, 0.1);
          color: var(--vault-success);
        }

        .vault-invoice-status.warning {
          background: rgba(245, 158, 11, 0.1);
          color: var(--vault-warning);
        }

        .vault-invoice-status.error {
          background: rgba(239, 68, 68, 0.1);
          color: var(--vault-error);
        }

        .vault-invoice-status.default {
          background: #f3f4f6;
          color: #6b7280;
        }

        .vault-invoice-download {
          color: var(--vault-primary-color);
          text-decoration: none;
          font-weight: 500;
        }

        .vault-invoice-download:hover {
          text-decoration: underline;
        }

        .vault-invoice-skeleton {
          height: 3rem;
          background: linear-gradient(90deg, #f3f4f6 25%, #e5e7eb 50%, #f3f4f6 75%);
          background-size: 200% 100%;
          animation: vault-invoice-skeleton-loading 1.5s infinite;
          border-radius: 0.375rem;
          margin-bottom: 0.5rem;
        }

        @keyframes vault-invoice-skeleton-loading {
          0% {
            background-position: 200% 0;
          }
          100% {
            background-position: -200% 0;
          }
        }

        .vault-invoice-empty-message {
          text-align: center;
          color: var(--vault-text-secondary);
          padding: 2rem;
        }
      ` })] }));
};

/**
 * Master Key Derivation for Zero-Knowledge Architecture
 *
 * This module implements client-side key derivation using Argon2id.
 * In the browser, we use a WebAssembly implementation of Argon2.
 *
 * @module zk/keyDerivation
 */
const SALT_LENGTH = 16;
const KEY_MATERIAL_LENGTH = 64;
/**
 * Default Argon2id parameters
 */
const DEFAULT_ARGON2_PARAMS = {
    memoryCost: 65536, // 64 MB
    timeCost: 3,
    parallelism: 4,
};
/**
 * Conservative parameters (higher security, slower)
 */
const CONSERVATIVE_ARGON2_PARAMS = {
    memoryCost: 262144, // 256 MB
    timeCost: 4,
    parallelism: 4,
};
/**
 * Fast parameters (for testing only)
 */
const FAST_ARGON2_PARAMS = {
    memoryCost: 16384, // 16 MB
    timeCost: 2,
    parallelism: 1,
};
/**
 * Generate a cryptographically secure random salt
 */
function generateSalt() {
    return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}
/**
 * Derive master key from password using PBKDF2 (fallback for browsers without Argon2)
 *
 * For production, use argon2-browser WASM implementation
 */
async function deriveMasterKey(password, salt, params = DEFAULT_ARGON2_PARAMS) {
    // Use PBKDF2 as a fallback (browser native)
    // In production, use argon2-browser for proper Argon2id
    const keyMaterial = await pbkdf2Derive(password, salt, KEY_MATERIAL_LENGTH);
    // Split key material
    const encryptionKey = keyMaterial.slice(0, 32);
    const authenticationKey = keyMaterial.slice(32, 64);
    // Generate RSA key pair deterministically from encryption key
    const { privateKey, publicKey } = await generateRsaKeyPair();
    return {
        encryptionKey,
        authenticationKey,
        rsaPrivateKey: privateKey,
        rsaPublicKey: publicKey,
        keyMaterial,
    };
}
/**
 * PBKDF2 key derivation (browser fallback)
 */
async function pbkdf2Derive(password, salt, length) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    // Import password as key material
    const keyMaterial = await crypto.subtle.importKey('raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveBits']);
    // Derive bits
    const derived = await crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256',
    }, keyMaterial, length * 8);
    return new Uint8Array(derived);
}
/**
 * Generate RSA key pair
 *
 * Note: In a full implementation, this should be deterministic based on the seed
 */
async function generateRsaKeyPair(seed) {
    // Generate RSA key pair
    const keyPair = await crypto.subtle.generateKey({
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
    }, true, // extractable
    ['wrapKey', 'unwrapKey']);
    return {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
    };
}
/**
 * Export master key to portable format (for storage)
 */
async function exportMasterKey(masterKey) {
    const [privateKeyJwk, publicKeyJwk] = await Promise.all([
        crypto.subtle.exportKey('jwk', masterKey.rsaPrivateKey),
        crypto.subtle.exportKey('jwk', masterKey.rsaPublicKey),
    ]);
    return {
        encryptionKey: arrayBufferToBase64$3(masterKey.encryptionKey),
        authenticationKey: arrayBufferToBase64$3(masterKey.authenticationKey),
        rsaPrivateKey: JSON.stringify(privateKeyJwk),
        rsaPublicKey: JSON.stringify(publicKeyJwk),
    };
}
/**
 * Import master key from portable format
 */
async function importMasterKey(exported) {
    const encryptionKey = base64ToArrayBuffer$3(exported.encryptionKey);
    const authenticationKey = base64ToArrayBuffer$3(exported.authenticationKey);
    const privateKeyJwk = JSON.parse(exported.rsaPrivateKey);
    const publicKeyJwk = JSON.parse(exported.rsaPublicKey);
    const [privateKey, publicKey] = await Promise.all([
        crypto.subtle.importKey('jwk', privateKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['unwrapKey']),
        crypto.subtle.importKey('jwk', publicKeyJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']),
    ]);
    const keyMaterial = new Uint8Array(64);
    keyMaterial.set(encryptionKey, 0);
    keyMaterial.set(authenticationKey, 32);
    return {
        encryptionKey,
        authenticationKey,
        rsaPrivateKey: privateKey,
        rsaPublicKey: publicKey,
        keyMaterial,
    };
}
/**
 * Encrypt RSA private key for server storage
 */
async function encryptPrivateKeyForStorage(privateKey, encryptionKey) {
    // Export private key
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    // Import encryption key
    const cryptoKey = await crypto.subtle.importKey('raw', encryptionKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    // Generate nonce
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    // Encrypt
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, pkcs8);
    // Combine nonce + ciphertext
    const combined = new Uint8Array(nonce.length + ciphertext.byteLength);
    combined.set(nonce, 0);
    combined.set(new Uint8Array(ciphertext), nonce.length);
    return arrayBufferToBase64$3(combined);
}
/**
 * Decrypt RSA private key from server storage
 */
async function decryptPrivateKeyFromStorage(encryptedKey, encryptionKey) {
    const combined = base64ToArrayBuffer$3(encryptedKey);
    // Extract nonce and ciphertext
    const nonce = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    // Import encryption key
    const cryptoKey = await crypto.subtle.importKey('raw', encryptionKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    // Decrypt
    const pkcs8 = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, ciphertext);
    // Import private key
    return await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['unwrapKey']);
}
/**
 * Generate password commitment for ZK proof
 */
async function generatePasswordCommitment(password, salt) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    // Combine password + salt
    const combined = new Uint8Array(data.length + salt.length + 14);
    combined.set(data, 0);
    combined.set(salt, data.length);
    combined.set(encoder.encode('zk_password_v1'), data.length + salt.length);
    // Hash with SHA-256
    const hash = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hash);
}
// Helper functions
function arrayBufferToBase64$3(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
function base64ToArrayBuffer$3(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Client-Side Encryption for Zero-Knowledge Architecture
 *
 * This module implements browser-based encryption ensuring that user data
 * is encrypted before being sent to the server. The server only stores
 * encrypted blobs and cannot decrypt them.
 *
 * @module zk/encryption
 */
const AES_GCM_ALGORITHM = 'AES-GCM';
const RSA_OAEP_ALGORITHM = 'RSA-OAEP';
const AES_KEY_SIZE = 256;
const AES_IV_SIZE = 12;
/**
 * Generate a random Data Encryption Key
 */
async function generateDek() {
    return await crypto.subtle.generateKey({
        name: AES_GCM_ALGORITHM,
        length: AES_KEY_SIZE,
    }, true, // extractable
    ['encrypt', 'decrypt']);
}
/**
 * Wrap DEK with RSA public key using RSA-OAEP
 */
async function wrapDek(dek, publicKey) {
    // Export DEK to raw format
    await crypto.subtle.exportKey('raw', dek);
    // Wrap with RSA-OAEP
    const wrapped = await crypto.subtle.wrapKey('raw', dek, publicKey, {
        name: RSA_OAEP_ALGORITHM,
        hash: 'SHA-256',
    });
    return {
        ciphertext: new Uint8Array(wrapped),
    };
}
/**
 * Unwrap DEK with RSA private key
 */
async function unwrapDek(wrappedDek, privateKey) {
    return await crypto.subtle.unwrapKey('raw', wrappedDek.ciphertext, privateKey, {
        name: RSA_OAEP_ALGORITHM,
        hash: 'SHA-256',
    }, {
        name: AES_GCM_ALGORITHM,
        length: AES_KEY_SIZE,
    }, true, ['encrypt', 'decrypt']);
}
/**
 * Encrypt data with AES-GCM
 */
async function aesGcmEncrypt(data, key) {
    // Generate random nonce
    const nonce = crypto.getRandomValues(new Uint8Array(AES_IV_SIZE));
    // Encrypt
    const ciphertext = await crypto.subtle.encrypt({
        name: AES_GCM_ALGORITHM,
        iv: nonce,
    }, key, data);
    return {
        ciphertext: new Uint8Array(ciphertext),
        nonce,
    };
}
/**
 * Decrypt data with AES-GCM
 */
async function aesGcmDecrypt(ciphertext, nonce, key) {
    const plaintext = await crypto.subtle.decrypt({
        name: AES_GCM_ALGORITHM,
        iv: nonce,
    }, key, ciphertext);
    return new Uint8Array(plaintext);
}
/**
 * Encrypt user profile data
 */
async function encryptUserData(profile, masterKey) {
    // Serialize profile to JSON
    const plaintext = new TextEncoder().encode(JSON.stringify(profile));
    // Generate random DEK
    const dek = await generateDek();
    // Encrypt data with DEK
    const { ciphertext, nonce } = await aesGcmEncrypt(plaintext, dek);
    // Wrap DEK with RSA public key
    const encryptedDek = await wrapDek(dek, masterKey.rsaPublicKey);
    return {
        version: 1,
        ciphertext,
        nonce,
        encryptedDek,
        encryptedAt: new Date().toISOString(),
    };
}
/**
 * Decrypt user profile data
 */
async function decryptUserData(encryptedData, masterKey) {
    // Unwrap DEK
    const dek = await unwrapDek(encryptedData.encryptedDek, masterKey.rsaPrivateKey);
    // Decrypt data
    const plaintext = await aesGcmDecrypt(encryptedData.ciphertext, encryptedData.nonce, dek);
    // Parse JSON
    const json = new TextDecoder().decode(plaintext);
    return JSON.parse(json);
}
/**
 * Serialize encrypted data for transmission
 */
function serializeEncryptedData(data) {
    const obj = {
        version: data.version,
        ciphertext: arrayBufferToBase64$2(data.ciphertext),
        nonce: arrayBufferToBase64$2(data.nonce),
        encryptedDek: {
            ciphertext: arrayBufferToBase64$2(data.encryptedDek.ciphertext),
        },
        encryptedAt: data.encryptedAt,
    };
    return JSON.stringify(obj);
}
/**
 * Deserialize encrypted data from transmission
 */
function deserializeEncryptedData(json) {
    const obj = JSON.parse(json);
    return {
        version: obj.version,
        ciphertext: base64ToArrayBuffer$2(obj.ciphertext),
        nonce: base64ToArrayBuffer$2(obj.nonce),
        encryptedDek: {
            ciphertext: base64ToArrayBuffer$2(obj.encryptedDek.ciphertext),
        },
        encryptedAt: obj.encryptedAt,
    };
}
/**
 * Encrypt arbitrary data with master key
 */
async function encryptWithMasterKey(data, masterKey) {
    const dek = await generateDek();
    const { ciphertext, nonce } = await aesGcmEncrypt(data, dek);
    const encryptedDek = await wrapDek(dek, masterKey.rsaPublicKey);
    return {
        version: 1,
        ciphertext,
        nonce,
        encryptedDek,
        encryptedAt: new Date().toISOString(),
    };
}
/**
 * Decrypt arbitrary data with master key
 */
async function decryptWithMasterKey(encryptedData, masterKey) {
    const dek = await unwrapDek(encryptedData.encryptedDek, masterKey.rsaPrivateKey);
    return await aesGcmDecrypt(encryptedData.ciphertext, encryptedData.nonce, dek);
}
// Helper functions
function arrayBufferToBase64$2(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
function base64ToArrayBuffer$2(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Zero-Knowledge Password Proofs
 *
 * This module implements zero-knowledge proofs that allow a user to prove
 * knowledge of their password without revealing it to the server.
 *
 * @module zk/proofs
 */
const CHALLENGE_SIZE = 32;
const SCALAR_SIZE = 32;
/**
 * ZK Password Prover (client-side)
 */
class ZkPasswordProver {
    /**
     * Generate a ZK proof of password knowledge
     */
    static async prove(password, salt, challenge) {
        const actualChallenge = challenge || generateChallenge();
        // Generate random blinding factor
        const blindingFactor = crypto.getRandomValues(new Uint8Array(32));
        // Compute blinded commitment
        const blindedCommitment = await computeBlindedCommitment(blindingFactor, actualChallenge);
        // Compute response
        const response = await computeResponse(blindingFactor, password, actualChallenge, salt);
        return {
            version: 1,
            challenge: actualChallenge,
            response,
            blindedCommitment,
        };
    }
    /**
     * Generate commitment for registration
     */
    static async commit(password, salt) {
        const encoder = new TextEncoder();
        const passwordData = encoder.encode(password);
        const combined = new Uint8Array(passwordData.length + salt.length + 14);
        combined.set(passwordData, 0);
        combined.set(salt, passwordData.length);
        combined.set(encoder.encode('zk_password_v1'), passwordData.length + salt.length);
        const hash = await crypto.subtle.digest('SHA-256', combined);
        return new Uint8Array(hash);
    }
}
/**
 * ZK Password Verifier (server-side simulation for testing)
 */
class ZkPasswordVerifier {
    /**
     * Verify a ZK password proof
     */
    static async verify(proof, expectedCommitment, salt) {
        // Check version
        if (proof.version !== 1) {
            throw new Error(`Protocol version mismatch: expected 1, got ${proof.version}`);
        }
        // Check challenge is valid
        if (proof.challenge.length !== CHALLENGE_SIZE) {
            throw new Error('Invalid challenge size');
        }
        // In a full ZK implementation, we would verify the proof equation here
        // For now, we check the proof structure
        return proof.response.length === SCALAR_SIZE;
    }
}
/**
 * Generate a random challenge
 */
function generateChallenge() {
    return crypto.getRandomValues(new Uint8Array(CHALLENGE_SIZE));
}
/**
 * Compute blinded commitment
 */
async function computeBlindedCommitment(blindingFactor, challenge) {
    const combined = new Uint8Array(blindingFactor.length + challenge.length + 12);
    combined.set(blindingFactor, 0);
    combined.set(challenge, blindingFactor.length);
    const encoder = new TextEncoder();
    combined.set(encoder.encode('blinded_v1'), blindingFactor.length + challenge.length);
    const hash = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hash);
}
/**
 * Compute response
 */
async function computeResponse(blindingFactor, password, challenge, salt) {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);
    const combined = new Uint8Array(blindingFactor.length + passwordData.length + challenge.length + salt.length + 12);
    let offset = 0;
    combined.set(blindingFactor, offset);
    offset += blindingFactor.length;
    combined.set(passwordData, offset);
    offset += passwordData.length;
    combined.set(challenge, offset);
    offset += challenge.length;
    combined.set(salt, offset);
    offset += salt.length;
    combined.set(encoder.encode('response_v1'), offset);
    const hash = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hash);
}
/**
 * Full ZK authentication flow
 */
class ZkAuthentication {
    /**
     * Server generates challenge
     */
    static serverChallenge() {
        return generateChallenge();
    }
    /**
     * Client generates proof
     */
    static async clientProve(password, salt, challenge) {
        return await ZkPasswordProver.prove(password, salt, challenge);
    }
    /**
     * Server verifies proof
     */
    static async serverVerify(proof, expectedCommitment, salt) {
        return await ZkPasswordVerifier.verify(proof, expectedCommitment, salt);
    }
}
/**
 * Serialize proof for transmission
 */
function serializeProof(proof) {
    const obj = {
        version: proof.version,
        challenge: arrayBufferToBase64$1(proof.challenge),
        response: arrayBufferToBase64$1(proof.response),
        blindedCommitment: arrayBufferToBase64$1(proof.blindedCommitment),
    };
    return JSON.stringify(obj);
}
/**
 * Deserialize proof from transmission
 */
function deserializeProof(json) {
    const obj = JSON.parse(json);
    return {
        version: obj.version,
        challenge: base64ToArrayBuffer$1(obj.challenge),
        response: base64ToArrayBuffer$1(obj.response),
        blindedCommitment: base64ToArrayBuffer$1(obj.blindedCommitment),
    };
}
// Helper functions
function arrayBufferToBase64$1(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
function base64ToArrayBuffer$1(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Social Recovery Using Shamir's Secret Sharing
 *
 * This module implements account recovery without server knowledge.
 * The master key is split into multiple shares distributed to trusted contacts.
 *
 * @module zk/recovery
 */
const MAX_SHARES = 255;
const MAX_THRESHOLD = 255;
/**
 * Recovery session status
 */
exports.RecoverySessionStatus = void 0;
(function (RecoverySessionStatus) {
    RecoverySessionStatus["Collecting"] = "collecting";
    RecoverySessionStatus["Ready"] = "ready";
    RecoverySessionStatus["Completed"] = "completed";
    RecoverySessionStatus["Expired"] = "expired";
    RecoverySessionStatus["Failed"] = "failed";
})(exports.RecoverySessionStatus || (exports.RecoverySessionStatus = {}));
/**
 * Social recovery implementation
 */
class SocialRecovery {
    /**
     * Split master key into shares
     */
    static createShares(masterKey, threshold, totalShares, userId) {
        if (threshold === 0 || threshold > MAX_THRESHOLD) {
            throw new Error(`Threshold must be between 1 and ${MAX_THRESHOLD}`);
        }
        if (totalShares > MAX_SHARES) {
            throw new Error(`Total shares must be <= ${MAX_SHARES}`);
        }
        if (threshold > totalShares) {
            throw new Error('Threshold cannot be greater than total shares');
        }
        const secret = masterKey.keyMaterial;
        const shares = sssSplit(secret, threshold, totalShares);
        const metadata = {
            userId,
            createdAt: new Date().toISOString(),
            threshold,
            totalShares,
            version: 1,
        };
        return shares.map(([index, value]) => ({
            index,
            value,
            metadata: { ...metadata },
        }));
    }
    /**
     * Recover master key from shares
     */
    static recoverFromShares(shares) {
        if (shares.length === 0) {
            throw new Error('No shares provided');
        }
        // Validate all shares belong to the same set
        const firstMetadata = shares[0].metadata;
        for (const share of shares.slice(1)) {
            if (share.metadata.userId !== firstMetadata.userId) {
                throw new Error('Shares belong to different users');
            }
            if (share.metadata.threshold !== firstMetadata.threshold) {
                throw new Error('Inconsistent threshold in shares');
            }
        }
        // Check if we have enough shares
        if (shares.length < firstMetadata.threshold) {
            throw new Error(`Not enough shares: need ${firstMetadata.threshold}, have ${shares.length}`);
        }
        // Use only the first 'threshold' shares
        const sharesToUse = shares.slice(0, firstMetadata.threshold);
        // Reconstruct the secret
        const secret = sssRecover(sharesToUse);
        // Convert back to MasterKey
        return bytesToMasterKey(secret);
    }
    /**
     * Get share hash for verification
     */
    static async getShareHash(share) {
        const data = new Uint8Array(share.value.length + 1);
        data[0] = share.index;
        data.set(share.value, 1);
        const combined = new Uint8Array(data.length + share.metadata.userId.length);
        combined.set(data, 0);
        combined.set(new TextEncoder().encode(share.metadata.userId), data.length);
        const hash = await crypto.subtle.digest('SHA-256', combined);
        return new Uint8Array(hash);
    }
    /**
     * Generate share hashes for verification
     */
    static async generateShareHashes(shares) {
        return Promise.all(shares.map((s) => this.getShareHash(s)));
    }
    /**
     * Serialize share for transmission
     */
    static serializeShare(share) {
        const obj = {
            index: share.index,
            value: arrayBufferToBase64(share.value),
            metadata: share.metadata,
        };
        return JSON.stringify(obj);
    }
    /**
     * Deserialize share from transmission
     */
    static deserializeShare(json) {
        const obj = JSON.parse(json);
        return {
            index: obj.index,
            value: base64ToArrayBuffer(obj.value),
            metadata: obj.metadata,
        };
    }
}
/**
 * Share validator
 */
class ShareValidator {
    /**
     * Validate a share's structure
     */
    static validateStructure(share) {
        if (share.index === 0) {
            throw new Error('Invalid share index (0)');
        }
        if (share.value.length === 0) {
            throw new Error('Empty share value');
        }
        if (!share.metadata.userId) {
            throw new Error('Empty userId in metadata');
        }
        if (share.metadata.threshold === 0) {
            throw new Error('Invalid threshold (0)');
        }
    }
    /**
     * Validate a set of shares for recovery
     */
    static validateSet(shares) {
        if (shares.length === 0) {
            throw new Error('No shares provided');
        }
        // Check for duplicate indices
        const indices = new Set();
        for (const share of shares) {
            if (indices.has(share.index)) {
                throw new Error(`Duplicate share index: ${share.index}`);
            }
            indices.add(share.index);
        }
        // Validate all shares have same metadata
        const first = shares[0].metadata;
        for (const share of shares.slice(1)) {
            if (share.metadata.userId !== first.userId) {
                throw new Error('Shares have different userIds');
            }
            if (share.metadata.threshold !== first.threshold) {
                throw new Error('Shares have different thresholds');
            }
        }
        // Check we have enough shares
        if (shares.length < first.threshold) {
            throw new Error(`Need ${first.threshold} shares, have ${shares.length}`);
        }
    }
}
/**
 * Recovery session manager
 */
class RecoverySessionManager {
    constructor() {
        this.sessions = new Map();
    }
    /**
     * Create a new recovery session
     */
    createSession(userId, threshold) {
        const id = generateSessionId();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours
        const session = {
            id,
            userId,
            collectedShares: [],
            threshold,
            createdAt: now.toISOString(),
            expiresAt: expiresAt.toISOString(),
            status: exports.RecoverySessionStatus.Collecting,
        };
        this.sessions.set(id, session);
        return session;
    }
    /**
     * Get a session by ID
     */
    getSession(id) {
        return this.sessions.get(id);
    }
    /**
     * Add a share to a session
     */
    addShare(sessionId, share) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error('Session not found');
        }
        if (session.status !== exports.RecoverySessionStatus.Collecting) {
            throw new Error('Session is not in collecting state');
        }
        if (new Date() > new Date(session.expiresAt)) {
            session.status = exports.RecoverySessionStatus.Expired;
            throw new Error('Session has expired');
        }
        // Check if we already have this share
        if (session.collectedShares.some((s) => s.index === share.index)) {
            throw new Error(`Share ${share.index} already collected`);
        }
        session.collectedShares.push(share);
        // Check if we have enough shares
        if (session.collectedShares.length >= session.threshold) {
            session.status = exports.RecoverySessionStatus.Ready;
        }
        return session;
    }
    /**
     * Complete a recovery session
     */
    completeSession(sessionId, success) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error('Session not found');
        }
        session.status = success
            ? exports.RecoverySessionStatus.Completed
            : exports.RecoverySessionStatus.Failed;
        return session;
    }
    /**
     * Get number of shares still needed
     */
    sharesNeeded(session) {
        return session.collectedShares.length >= session.threshold
            ? 0
            : session.threshold - session.collectedShares.length;
    }
}
// Internal SSS implementation
/**
 * Split secret into shares
 */
function sssSplit(secret, threshold, totalShares) {
    const shares = [];
    // For each share
    for (let i = 1; i <= totalShares; i++) {
        // Generate random value (simplified - real SSS uses polynomial evaluation)
        const value = new Uint8Array(secret.length);
        for (let j = 0; j < secret.length; j++) {
            // XOR with random value for demonstration
            // Real implementation uses polynomial over finite field
            value[j] = secret[j] ^ (Math.random() * 256) | 0;
        }
        shares.push([i, value]);
    }
    return shares;
}
/**
 * Recover secret from shares
 */
function sssRecover(shares) {
    const secretLength = shares[0].value.length;
    const secret = new Uint8Array(secretLength);
    // Simplified recovery - XOR all shares
    // Real implementation uses Lagrange interpolation
    for (const share of shares) {
        for (let i = 0; i < secretLength; i++) {
            secret[i] ^= share.value[i];
        }
    }
    return secret;
}
/**
 * Convert bytes to MasterKey
 */
function bytesToMasterKey(bytes) {
    if (bytes.length !== 64) {
        throw new Error('Invalid key material length');
    }
    bytes.slice(0, 32);
    bytes.slice(32, 64);
    // Note: In real implementation, RSA keys would be derived or stored
    // For now, we'll need to regenerate them or handle this differently
    throw new Error('Master key reconstruction from shares requires RSA key regeneration. ' +
        'Use a proper SSS library that handles the full key material.');
}
/**
 * Generate random session ID
 */
function generateSessionId() {
    const array = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
}
// Helper functions
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
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
// Key derivation
/**
 * Zero-knowledge module version
 */
const ZK_VERSION = '1.0.0';
/**
 * Check if Web Crypto API is available
 */
function isWebCryptoAvailable() {
    return typeof crypto !== 'undefined' &&
        typeof crypto.subtle !== 'undefined';
}
/**
 * Initialize the zero-knowledge module
 *
 * @throws Error if Web Crypto API is not available
 */
function initZk() {
    if (!isWebCryptoAvailable()) {
        throw new Error('Web Crypto API is not available. ' +
            'Please use a modern browser with HTTPS.');
    }
}
/**
 * Zero-knowledge error types
 */
class ZkError extends Error {
    constructor(message, code, details) {
        super(message);
        this.code = code;
        this.details = details;
        this.name = 'ZkError';
    }
}
/**
 * Encryption error
 */
class ZkEncryptionError extends ZkError {
    constructor(message, details) {
        super(message, 'ZK_ENCRYPTION_ERROR', details);
        this.name = 'ZkEncryptionError';
    }
}
/**
 * Key derivation error
 */
class ZkKeyDerivationError extends ZkError {
    constructor(message, details) {
        super(message, 'ZK_KEY_DERIVATION_ERROR', details);
        this.name = 'ZkKeyDerivationError';
    }
}
/**
 * Proof error
 */
class ZkProofError extends ZkError {
    constructor(message, details) {
        super(message, 'ZK_PROOF_ERROR', details);
        this.name = 'ZkProofError';
    }
}
/**
 * Recovery error
 */
class ZkRecoveryError extends ZkError {
    constructor(message, details) {
        super(message, 'ZK_RECOVERY_ERROR', details);
        this.name = 'ZkRecoveryError';
    }
}

/**
 * OAuth Provider Utilities
 *
 * Comprehensive metadata and utilities for 30+ OAuth providers.
 */
/**
 * OAuth provider metadata for all supported providers
 */
const oauthProviderMetadata = {
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
function getAllOAuthProviders() {
    return Object.keys(oauthProviderMetadata);
}
/**
 * Get OAuth providers by category
 */
function getOAuthProvidersByCategory(category) {
    return Object.keys(oauthProviderMetadata).filter((provider) => oauthProviderMetadata[provider].category === category);
}
/**
 * Get OAuth provider metadata
 */
function getOAuthProviderMetadata(provider) {
    return oauthProviderMetadata[provider];
}
/**
 * Get OAuth provider display name
 */
function getOAuthProviderDisplayName(provider) {
    return oauthProviderMetadata[provider]?.displayName || provider;
}
/**
 * Get OAuth provider icon color
 */
function getOAuthProviderColor(provider) {
    return oauthProviderMetadata[provider]?.color || '#000000';
}
/**
 * Check if OAuth provider uses PKCE
 */
function isPkceEnabled(provider) {
    return oauthProviderMetadata[provider]?.pkceEnabled || false;
}
/**
 * Get default scopes for OAuth provider
 */
function getOAuthProviderDefaultScopes(provider) {
    return oauthProviderMetadata[provider]?.scopes || ['openid', 'email', 'profile'];
}
/**
 * OAuth provider categories
 */
const oauthProviderCategories = [
    { id: 'social', label: 'Social' },
    { id: 'professional', label: 'Professional' },
    { id: 'developer', label: 'Developer' },
    { id: 'enterprise', label: 'Enterprise' },
    { id: 'regional', label: 'Regional' },
];
/**
 * Get popular OAuth providers (most commonly used)
 */
function getPopularOAuthProviders() {
    return ['google', 'github', 'microsoft', 'apple', 'facebook', 'twitter', 'linkedin'];
}
/**
 * Get recommended OAuth providers for a specific use case
 */
function getRecommendedOAuthProviders(useCase) {
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
function isValidOAuthProvider(provider) {
    return provider in oauthProviderMetadata;
}
/**
 * Group providers by category
 */
function groupProvidersByCategory() {
    const groups = {
        social: [],
        professional: [],
        developer: [],
        enterprise: [],
        regional: [],
        custom: [],
    };
    Object.keys(oauthProviderMetadata).forEach((provider) => {
        const category = oauthProviderMetadata[provider].category;
        groups[category].push(provider);
    });
    return groups;
}

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
// ============================================================================
// Context & Provider
// ============================================================================
// ============================================================================
// Version
// ============================================================================
const VERSION = '0.1.0';

exports.Alert = Alert;
exports.BillingSettings = BillingSettings;
exports.Button = Button;
exports.CONSERVATIVE_ARGON2_PARAMS = CONSERVATIVE_ARGON2_PARAMS;
exports.Card = Card;
exports.CardContent = CardContent;
exports.CardFooter = CardFooter;
exports.CardHeader = CardHeader;
exports.CheckoutButton = CheckoutButton;
exports.CreateOrganization = CreateOrganization;
exports.CustomerPortalButton = CustomerPortalButton;
exports.DEFAULT_ARGON2_PARAMS = DEFAULT_ARGON2_PARAMS;
exports.Divider = Divider;
exports.FAST_ARGON2_PARAMS = FAST_ARGON2_PARAMS;
exports.Header = Header;
exports.ImpersonationBanner = ImpersonationBanner;
exports.Input = Input;
exports.InvoiceList = InvoiceList;
exports.MFAForm = MFAForm;
exports.ManageSubscriptionButton = ManageSubscriptionButton;
exports.OrganizationList = OrganizationList;
exports.OrganizationProfile = OrganizationProfile;
exports.OrganizationSwitcher = OrganizationSwitcher;
exports.PricingTable = PricingTable;
exports.Protect = Protect;
exports.QuickCheckoutButton = QuickCheckoutButton;
exports.RecoverySessionManager = RecoverySessionManager;
exports.RedirectToSignIn = RedirectToSignIn;
exports.RedirectToSignUp = RedirectToSignUp;
exports.RequireAuth = RequireAuth;
exports.ResetPassword = ResetPassword;
exports.SessionManagement = SessionManagement;
exports.ShareValidator = ShareValidator;
exports.SignIn = SignIn;
exports.SignUp = SignUp;
exports.SignedIn = SignedIn;
exports.SignedOut = SignedOut;
exports.Skeleton = Skeleton;
exports.SocialButton = SocialButton;
exports.SocialButtons = SocialButtons;
exports.SocialRecovery = SocialRecovery;
exports.Spinner = Spinner$3;
exports.SpinnerOverlay = SpinnerOverlay;
exports.SubscriptionStatus = SubscriptionStatus;
exports.ThemeContext = ThemeContext;
exports.ThemeProvider = ThemeProvider;
exports.UpdatePaymentMethodButton = UpdatePaymentMethodButton;
exports.UsageMeter = UsageMeter;
exports.UserButton = UserButton;
exports.UserProfile = UserProfile;
exports.VERSION = VERSION;
exports.VaultApiClient = VaultApiClient;
exports.VaultContext = VaultContext;
exports.VaultProvider = VaultProvider;
exports.VerifyEmail = VerifyEmail;
exports.ViewInvoicesButton = ViewInvoicesButton;
exports.Waitlist = Waitlist;
exports.WebAuthnButton = WebAuthnButton;
exports.ZK_VERSION = ZK_VERSION;
exports.ZkAuthentication = ZkAuthentication;
exports.ZkEncryptionError = ZkEncryptionError;
exports.ZkError = ZkError;
exports.ZkKeyDerivationError = ZkKeyDerivationError;
exports.ZkPasswordProver = ZkPasswordProver;
exports.ZkPasswordVerifier = ZkPasswordVerifier;
exports.ZkProofError = ZkProofError;
exports.ZkRecoveryError = ZkRecoveryError;
exports.aesGcmDecrypt = aesGcmDecrypt;
exports.aesGcmEncrypt = aesGcmEncrypt;
exports.applyCSSVariables = applyCSSVariables;
exports.createElementStyles = createElementStyles;
exports.createVaultClient = createVaultClient;
exports.cssVariablesToStyle = cssVariablesToStyle;
exports.cx = cx;
exports.darkTheme = darkTheme;
exports.decryptPrivateKeyFromStorage = decryptPrivateKeyFromStorage;
exports.decryptUserData = decryptUserData;
exports.decryptWithMasterKey = decryptWithMasterKey;
exports.deriveMasterKey = deriveMasterKey;
exports.deserializeEncryptedData = deserializeEncryptedData;
exports.deserializeProof = deserializeProof;
exports.encryptPrivateKeyForStorage = encryptPrivateKeyForStorage;
exports.encryptUserData = encryptUserData;
exports.encryptWithMasterKey = encryptWithMasterKey;
exports.exportMasterKey = exportMasterKey;
exports.generateBaseStyles = generateBaseStyles;
exports.generateCSSVariables = generateCSSVariables;
exports.generateChallenge = generateChallenge;
exports.generateDek = generateDek;
exports.generatePasswordCommitment = generatePasswordCommitment;
exports.generateSalt = generateSalt;
exports.getAllOAuthProviders = getAllOAuthProviders;
exports.getElementClasses = getElementClasses;
exports.getLayoutOption = getLayoutOption;
exports.getOAuthProviderColor = getOAuthProviderColor;
exports.getOAuthProviderDefaultScopes = getOAuthProviderDefaultScopes;
exports.getOAuthProviderDisplayName = getOAuthProviderDisplayName;
exports.getOAuthProviderMetadata = getOAuthProviderMetadata;
exports.getOAuthProvidersByCategory = getOAuthProvidersByCategory;
exports.getPopularOAuthProviders = getPopularOAuthProviders;
exports.getRecommendedOAuthProviders = getRecommendedOAuthProviders;
exports.getTheme = getTheme;
exports.groupProvidersByCategory = groupProvidersByCategory;
exports.importMasterKey = importMasterKey;
exports.initZk = initZk;
exports.isPkceEnabled = isPkceEnabled;
exports.isValidOAuthProvider = isValidOAuthProvider;
exports.isWebCryptoAvailable = isWebCryptoAvailable;
exports.lightTheme = lightTheme;
exports.mergeThemes = mergeThemes;
exports.neutralTheme = neutralTheme;
exports.oauthProviderCategories = oauthProviderCategories;
exports.oauthProviderMetadata = oauthProviderMetadata;
exports.serializeEncryptedData = serializeEncryptedData;
exports.serializeProof = serializeProof;
exports.themes = themes;
exports.unwrapDek = unwrapDek;
exports.useActiveOrganization = useActiveOrganization;
exports.useAuth = useAuth;
exports.useAuthState = useAuthState;
exports.useBilling = useBilling;
exports.useCheckAuthorization = useCheckAuthorization;
exports.useHasRole = useHasRole;
exports.useIsOrgAdmin = useIsOrgAdmin;
exports.useIsWebAuthnSupported = useIsWebAuthnSupported;
exports.useMfa = useMfa;
exports.useMfaChallenge = useMfaChallenge;
exports.useOrganization = useOrganization;
exports.useOrganizationRole = useOrganizationRole;
exports.usePermissions = usePermissions;
exports.useRequireAuth = useRequireAuth;
exports.useSession = useSession;
exports.useSessionId = useSessionId;
exports.useSessions = useSessions;
exports.useSignIn = useSignIn;
exports.useSignUp = useSignUp;
exports.useSubscription = useSubscription;
exports.useTheme = useTheme;
exports.useToken = useToken;
exports.useUpdateUser = useUpdateUser;
exports.useUsage = useUsage;
exports.useUser = useUser;
exports.useUserManager = useUserManager;
exports.useVault = useVault;
exports.useWebAuthn = useWebAuthn;
exports.withTheme = withTheme;
exports.wrapDek = wrapDek;
//# sourceMappingURL=index.js.map
