<template>
  <div v-if="!isLoaded" class="vault-protect-loading">
    <slot name="loading">
      <div class="vault-loading">
        <div class="vault-spinner"></div>
        <span>Loading...</span>
      </div>
    </slot>
  </div>

  <div v-else-if="!isAuthorized" class="vault-protect-unauthorized">
    <slot name="fallback">
      <div class="vault-unauthorized">
        <h2 class="vault-unauthorized-title">
          {{ unauthorizedTitle }}
        </h2>
        <p class="vault-unauthorized-message">
          {{ unauthorizedMessage }}
        </p>
        <a href="/sign-in" class="vault-btn vault-btn-primary">
          Sign In
        </a>
      </div>
    </slot>
  </div>

  <div v-else class="vault-protect-content">
    <slot />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useAuth, useOrganization, usePermissions } from '../composables';
import type { ProtectProps } from '../types';

/**
 * Props definition
 */
const props = defineProps<ProtectProps>();

/**
 * Composables
 */
const { isLoaded, isSignedIn } = useAuth();
const { organization } = useOrganization();
const { hasRole } = usePermissions();

/**
 * Computed
 */
const isAuthorized = computed(() => {
  // Check if signed in
  if (!isSignedIn.value) {
    return false;
  }

  // Check role requirement
  if (props.role) {
    const userRole = organization.value?.role;
    if (userRole !== props.role && userRole !== 'owner') {
      return false;
    }
  }

  // Check permission requirement
  if (props.permission) {
    // This would check user permissions
    // For now, we'll just pass through
  }

  // All checks passed
  return true;
});

const unauthorizedTitle = computed(() => {
  if (!isSignedIn.value) {
    return 'Sign in required';
  }
  if (props.role || props.permission) {
    return 'Access denied';
  }
  return 'Unauthorized';
});

const unauthorizedMessage = computed(() => {
  if (!isSignedIn.value) {
    return 'You need to be signed in to access this page.';
  }
  if (props.role) {
    return "You don't have the required role to access this page.";
  }
  if (props.permission) {
    return "You don't have the required permission to access this page.";
  }
  return 'You are not authorized to view this content.';
});
</script>

<style scoped>
.vault-protect-loading,
.vault-protect-unauthorized {
  width: 100%;
}

.vault-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 48px;
  color: #6b7280;
}

.vault-spinner {
  width: 20px;
  height: 20px;
  border: 2px solid #e5e7eb;
  border-top-color: #0066cc;
  border-radius: 50%;
  animation: vault-spin 1s linear infinite;
}

@keyframes vault-spin {
  to {
    transform: rotate(360deg);
  }
}

.vault-unauthorized {
  max-width: 400px;
  margin: 48px auto;
  padding: 32px;
  text-align: center;
  background-color: #f9fafb;
  border-radius: 8px;
  border: 1px solid #e5e7eb;
}

.vault-unauthorized-title {
  font-size: 20px;
  font-weight: 600;
  margin: 0 0 8px;
  color: #1f2937;
}

.vault-unauthorized-message {
  font-size: 14px;
  color: #6b7280;
  margin: 0 0 20px;
}

.vault-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.625rem 1.25rem;
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
  text-decoration: none;
  transition: all 0.15s ease-in-out;
}

.vault-btn-primary {
  color: #fff;
  background-color: #0066cc;
}

.vault-btn-primary:hover {
  background-color: #0052a3;
}

.vault-protect-content {
  width: 100%;
}
</style>
