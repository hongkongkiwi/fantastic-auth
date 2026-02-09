<template>
  <div class="vault-sign-in" :class="props.class">
    <div v-if="magicLinkSent" class="vault-magic-link-sent">
      <div class="vault-card vault-card-centered">
        <div class="vault-card-header">
          <h2 class="vault-title">Check your email</h2>
          <p class="vault-subtitle">We've sent a magic link to {{ email }}</p>
        </div>
        <div class="vault-card-content">
          <p class="vault-text-center vault-text-secondary">
            Click the link in the email to sign in.
          </p>
          <button
            type="button"
            class="vault-btn vault-btn-ghost"
            @click="resetMagicLink"
          >
            Back to sign in
          </button>
        </div>
      </div>
    </div>

    <div v-else class="vault-card vault-card-centered">
      <div class="vault-card-header">
        <h2 class="vault-title">Sign In</h2>
      </div>

      <div class="vault-card-content">
        <div v-if="displayError" class="vault-alert vault-alert-error" style="margin-bottom: 1rem;">
          {{ displayError }}
        </div>

        <div v-if="socialButtonsPlacement === 'top' && hasOAuthProviders" class="vault-social-section">
          <slot name="oauth-buttons" :providers="oauthProviders" :handle-o-auth="handleOAuth">
            <div class="vault-social-buttons">
              <button
                v-for="provider in oauthProviders"
                :key="provider"
                type="button"
                class="vault-btn vault-btn-social"
                :disabled="isLoading"
                @click="handleOAuth(provider)"
              >
                <span class="vault-social-icon">{{ getProviderIcon(provider) }}</span>
                <span>Continue with {{ capitalize(provider) }}</span>
              </button>
            </div>
            <div class="vault-divider">
              <span class="vault-divider-text">or</span>
            </div>
          </slot>
        </div>

        <form @submit.prevent="handleSubmit">
          <div class="vault-form-group">
            <label class="vault-label" for="vault-email">Email</label>
            <input
              id="vault-email"
              v-model="email"
              type="email"
              class="vault-input"
              placeholder="you@example.com"
              required
              autocomplete="email"
              :disabled="isLoading"
            />
          </div>

          <div v-if="!useMagicLink" class="vault-form-group vault-form-group-relative">
            <label class="vault-label" for="vault-password">Password</label>
            <input
              id="vault-password"
              v-model="password"
              type="password"
              class="vault-input"
              placeholder="••••••••"
              required
              autocomplete="current-password"
              :disabled="isLoading"
            />
            <button
              v-if="showForgotPassword"
              type="button"
              class="vault-link vault-link-small vault-link-absolute"
              @click="handleForgotPassword"
            >
              Forgot password?
            </button>
          </div>

          <button
            type="submit"
            class="vault-btn vault-btn-primary vault-btn-full"
            style="margin-top: 0.5rem;"
            :disabled="isLoading"
          >
            <span v-if="isLoading" class="vault-spinner vault-spinner-small vault-spinner-inline"></span>
            {{ useMagicLink ? 'Send Magic Link' : 'Sign In' }}
          </button>
        </form>

        <button
          v-if="showMagicLink"
          type="button"
          class="vault-btn vault-btn-ghost vault-btn-full"
          @click="toggleMagicLink"
        >
          {{ useMagicLink ? 'Use password instead' : 'Use magic link instead' }}
        </button>

        <div v-if="showWebAuthn && isWebAuthnSupported" class="vault-webauthn-section">
          <div class="vault-divider">
            <span class="vault-divider-text">or</span>
          </div>
          <button
            type="button"
            class="vault-btn vault-btn-secondary vault-btn-full"
            :disabled="isLoading"
            @click="handleWebAuthn"
          >
            <span class="vault-icon">🔐</span>
            Sign in with Passkey
          </button>
        </div>

        <div v-if="socialButtonsPlacement === 'bottom' && hasOAuthProviders" class="vault-social-section">
          <div class="vault-divider">
            <span class="vault-divider-text">or</span>
          </div>
          <slot name="oauth-buttons" :providers="oauthProviders" :handle-o-auth="handleOAuth">
            <div class="vault-social-buttons">
              <button
                v-for="provider in oauthProviders"
                :key="provider"
                type="button"
                class="vault-btn vault-btn-social"
                :disabled="isLoading"
                @click="handleOAuth(provider)"
              >
                <span class="vault-social-icon">{{ getProviderIcon(provider) }}</span>
                <span>Continue with {{ capitalize(provider) }}</span>
              </button>
            </div>
          </slot>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { useSignIn, useWebAuthn } from '../composables';
import type { SignInProps, ApiError } from '../types';

/**
 * Props definition with defaults
 */
const props = withDefaults(defineProps<SignInProps>(), {
  showMagicLink: true,
  showForgotPassword: true,
  oauthProviders: () => [],
  showWebAuthn: false,
});

/**
 * Emits definition
 */
const emit = defineEmits<{
  (e: 'success'): void;
  (e: 'error', error: ApiError): void;
}>();

/**
 * Local state
 */
const email = ref('');
const password = ref('');
const useMagicLink = ref(false);
const magicLinkSent = ref(false);
const localError = ref<string | null>(null);

/**
 * Composables
 */
const { signIn, signInWithMagicLink, signInWithOAuth, isLoading, error, resetError } = useSignIn();
const { isSupported: isWebAuthnSupported, authenticate: authenticateWithWebAuthn } = useWebAuthn();

/**
 * Computed
 */
const displayError = computed(() => localError.value || error.value?.message);
const hasOAuthProviders = computed(() => props.oauthProviders && props.oauthProviders.length > 0);
const socialButtonsPlacement = computed(() => props.appearance?.layout?.socialButtonsPlacement || 'top');

/**
 * Form submission handler
 */
async function handleSubmit() {
  resetError();
  localError.value = null;

  try {
    if (useMagicLink.value) {
      await signInWithMagicLink({ email: email.value, redirectUrl: props.redirectUrl });
      magicLinkSent.value = true;
    } else {
      await signIn({ email: email.value, password: password.value });
      emit('success');
      if (props.redirectUrl) {
        window.location.href = props.redirectUrl;
      }
    }
  } catch (err: any) {
    const errorMessage = err.message || 'Failed to sign in';
    localError.value = errorMessage;
    emit('error', err as ApiError);
  }
}

/**
 * OAuth sign in handler
 */
async function handleOAuth(provider: 'google' | 'github' | 'microsoft') {
  resetError();
  localError.value = null;
  try {
    await signInWithOAuth({ provider, redirectUrl: props.redirectUrl });
  } catch (err: any) {
    localError.value = err.message || 'Failed to sign in';
    emit('error', err as ApiError);
  }
}

/**
 * WebAuthn sign in handler
 */
async function handleWebAuthn() {
  resetError();
  localError.value = null;
  try {
    await authenticateWithWebAuthn();
    emit('success');
    if (props.redirectUrl) {
      window.location.href = props.redirectUrl;
    }
  } catch (err: any) {
    localError.value = err.message || 'Passkey authentication failed';
    emit('error', err as ApiError);
  }
}

/**
 * Forgot password handler
 */
function handleForgotPassword() {
  window.location.href = `/forgot-password?email=${encodeURIComponent(email.value)}`;
}

/**
 * Toggle magic link mode
 */
function toggleMagicLink() {
  useMagicLink.value = !useMagicLink.value;
  resetError();
  localError.value = null;
}

/**
 * Reset magic link state
 */
function resetMagicLink() {
  magicLinkSent.value = false;
  email.value = '';
}

/**
 * Get OAuth provider icon
 */
function getProviderIcon(provider: string): string {
  const icons: Record<string, string> = {
    google: '🔍',
    github: '🐙',
    microsoft: '🪟',
  };
  return icons[provider] || '🔑';
}

/**
 * Capitalize first letter
 */
function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}
</script>

<style scoped>
.vault-sign-in {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

.vault-card {
  background: white;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  border: 1px solid #e5e7eb;
  max-width: 400px;
  width: 100%;
}

.vault-card-centered {
  margin: 0 auto;
}

.vault-card-header {
  padding: 1.5rem 1.5rem 0.5rem;
  text-align: center;
}

.vault-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #111827;
  margin: 0;
}

.vault-subtitle {
  font-size: 0.875rem;
  color: #6b7280;
  margin: 0.5rem 0 0;
}

.vault-card-content {
  padding: 1rem 1.5rem 1.5rem;
}

.vault-form-group {
  margin-bottom: 1rem;
}

.vault-form-group-relative {
  position: relative;
}

.vault-label {
  display: block;
  font-size: 0.875rem;
  font-weight: 500;
  color: #374151;
  margin-bottom: 0.25rem;
}

.vault-input {
  width: 100%;
  padding: 0.5rem 0.75rem;
  font-size: 0.875rem;
  line-height: 1.5;
  color: #111827;
  background-color: white;
  border: 1px solid #d1d5db;
  border-radius: 0.375rem;
  box-sizing: border-box;
  transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
}

.vault-input:focus {
  outline: none;
  border-color: #3b82f6;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.vault-input:disabled {
  background-color: #f3f4f6;
  cursor: not-allowed;
}

.vault-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  font-size: 0.875rem;
  font-weight: 500;
  line-height: 1.5;
  text-align: center;
  white-space: nowrap;
  vertical-align: middle;
  cursor: pointer;
  user-select: none;
  border: 1px solid transparent;
  border-radius: 0.375rem;
  transition: all 0.15s ease-in-out;
  background: transparent;
}

.vault-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.vault-btn-primary {
  color: white;
  background-color: #0066cc;
  border-color: #0066cc;
}

.vault-btn-primary:hover:not(:disabled) {
  background-color: #0052a3;
  border-color: #0052a3;
}

.vault-btn-secondary {
  color: #374151;
  background-color: #f3f4f6;
  border-color: #d1d5db;
}

.vault-btn-secondary:hover:not(:disabled) {
  background-color: #e5e7eb;
}

.vault-btn-ghost {
  color: #6b7280;
  background: transparent;
}

.vault-btn-ghost:hover:not(:disabled) {
  color: #374151;
  background-color: #f3f4f6;
}

.vault-btn-social {
  width: 100%;
  color: #374151;
  background-color: white;
  border-color: #d1d5db;
}

.vault-btn-social:hover:not(:disabled) {
  background-color: #f9fafb;
}

.vault-btn-full {
  width: 100%;
  margin-top: 0.75rem;
}

.vault-link {
  color: #0066cc;
  text-decoration: none;
  background: none;
  border: none;
  cursor: pointer;
}

.vault-link:hover {
  text-decoration: underline;
}

.vault-link-small {
  font-size: 0.75rem;
}

.vault-link-absolute {
  position: absolute;
  right: 0;
  top: 0;
}

.vault-alert {
  padding: 0.75rem 1rem;
  border-radius: 0.375rem;
  font-size: 0.875rem;
}

.vault-alert-error {
  color: #991b1b;
  background-color: #fef2f2;
  border: 1px solid #fecaca;
}

.vault-divider {
  display: flex;
  align-items: center;
  margin: 1rem 0;
}

.vault-divider::before,
.vault-divider::after {
  content: '';
  flex: 1;
  border-top: 1px solid #e5e7eb;
}

.vault-divider-text {
  padding: 0 1rem;
  font-size: 0.75rem;
  color: #6b7280;
  text-transform: uppercase;
}

.vault-social-buttons {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.vault-social-icon {
  font-size: 1.125rem;
}

.vault-webauthn-section {
  margin-top: 0.5rem;
}

.vault-text-center {
  text-align: center;
}

.vault-text-secondary {
  color: #6b7280;
}

.vault-spinner {
  display: inline-block;
  border: 2px solid #e5e7eb;
  border-top-color: currentColor;
  border-radius: 50%;
  animation: vault-spin 1s linear infinite;
}

.vault-spinner-small {
  width: 1rem;
  height: 1rem;
}

.vault-spinner-inline {
  margin-right: 0.5rem;
}

@keyframes vault-spin {
  to {
    transform: rotate(360deg);
  }
}

.vault-icon {
  font-size: 1rem;
}
</style>
