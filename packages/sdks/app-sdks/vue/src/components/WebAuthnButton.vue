<template>
  <button
    type="button"
    class="vault-webauthn-btn"
    :class="[
      `vault-webauthn-btn-${props.mode}`,
      props.class,
      { 'vault-webauthn-btn-loading': isLoading }
    ]"
    :disabled="isDisabled"
    @click="handleClick"
  >
    <span v-if="isLoading" class="vault-spinner vault-spinner-small vault-spinner-inline"></span>
    <span v-else class="vault-webauthn-icon">
      <svg v-if="props.mode === 'signin'" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
      <svg v-else-if="props.mode === 'signup'" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="12" y1="8" x2="12" y2="16"/>
        <line x1="8" y1="12" x2="16" y2="12"/>
      </svg>
      <svg v-else xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="M12 8v4"/>
        <path d="M12 16h.01"/>
      </svg>
    </span>
    <span class="vault-webauthn-label">{{ displayLabel }}</span>
  </button>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useWebAuthn } from '../composables';
import type { WebAuthnButtonProps, ApiError } from '../types';

/**
 * Props definition with defaults
 */
const props = withDefaults(defineProps<WebAuthnButtonProps>(), {
  mode: 'signin',
});

/**
 * Emits definition
 */
const emit = defineEmits<{
  (e: 'success'): void;
  (e: 'error', error: ApiError): void;
}>();

/**
 * Composables
 */
const {
  isSupported,
  isLoading,
  error,
  register,
  authenticate,
  resetError,
} = useWebAuthn();

/**
 * Computed
 */
const isDisabled = computed(() => {
  return !isSupported.value || isLoading.value;
});

const displayLabel = computed(() => {
  if (props.label) return props.label;

  const labels: Record<string, string> = {
    signin: 'Sign in with Passkey',
    signup: 'Register Passkey',
    link: 'Link Passkey',
  };

  return labels[props.mode] || 'Passkey';
});

/**
 * Handle button click
 */
async function handleClick() {
  resetError();

  try {
    if (props.mode === 'signin') {
      await authenticate();
    } else if (props.mode === 'signup' || props.mode === 'link') {
      await register();
    }

    emit('success');
  } catch (err) {
    emit('error', err as ApiError);
  }
}
</script>

<style scoped>
.vault-webauthn-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.625rem 1rem;
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

.vault-webauthn-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.vault-webauthn-btn-signin {
  color: #374151;
  background-color: white;
  border-color: #d1d5db;
}

.vault-webauthn-btn-signin:hover:not(:disabled) {
  background-color: #f9fafb;
  border-color: #9ca3af;
}

.vault-webauthn-btn-signup {
  color: white;
  background-color: #0066cc;
  border-color: #0066cc;
}

.vault-webauthn-btn-signup:hover:not(:disabled) {
  background-color: #0052a3;
  border-color: #0052a3;
}

.vault-webauthn-btn-link {
  color: #0066cc;
  background-color: #eff6ff;
  border-color: #bfdbfe;
}

.vault-webauthn-btn-link:hover:not(:disabled) {
  background-color: #dbeafe;
  border-color: #93c5fd;
}

.vault-webauthn-icon {
  width: 1.25rem;
  height: 1.25rem;
  flex-shrink: 0;
}

.vault-webauthn-icon svg {
  width: 100%;
  height: 100%;
}

.vault-webauthn-label {
  flex: 1;
}

.vault-spinner {
  display: inline-block;
  border: 2px solid currentColor;
  border-top-color: transparent;
  border-radius: 50%;
  animation: vault-spin 1s linear infinite;
}

.vault-spinner-small {
  width: 1rem;
  height: 1rem;
}

.vault-spinner-inline {
  margin-right: 0.25rem;
}

@keyframes vault-spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
