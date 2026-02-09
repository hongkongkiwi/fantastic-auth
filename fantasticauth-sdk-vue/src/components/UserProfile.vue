<template>
  <div class="vault-user-profile" :class="props.class">
    <div class="vault-card">
      <div class="vault-card-header">
        <h2 class="vault-title">Profile</h2>
      </div>

      <div class="vault-card-content">
        <div v-if="isLoading" class="vault-loading">
          <div class="vault-spinner vault-spinner-large"></div>
        </div>

        <template v-else-if="user">
          <div class="vault-profile-header">
            <div class="vault-avatar-container">
              <img
                v-if="user.profile?.picture"
                :src="user.profile.picture"
                :alt="user.name || user.email"
                class="vault-avatar vault-avatar-large"
              />
              <div v-else class="vault-avatar vault-avatar-large vault-avatar-placeholder">
                {{ initials }}
              </div>
              <button
                type="button"
                class="vault-avatar-edit"
                @click="triggerFileInput"
              >
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z" />
                </svg>
              </button>
              <input
                ref="fileInput"
                type="file"
                accept="image/*"
                class="vault-file-input"
                @change="handleFileChange"
              />
            </div>
            <div class="vault-profile-info">
              <h3 class="vault-profile-name">{{ user.name || 'No name set' }}</h3>
              <p class="vault-profile-email">{{ user.email }}</p>
              <span
                class="vault-badge"
                :class="user.emailVerified ? 'vault-badge-success' : 'vault-badge-warning'"
              >
                {{ user.emailVerified ? 'Verified' : 'Unverified' }}
              </span>
            </div>
          </div>

          <div class="vault-divider"></div>

          <form @submit.prevent="handleUpdateProfile" class="vault-form">
            <div class="vault-form-row">
              <div class="vault-form-group">
                <label class="vault-label" for="vault-first-name">First Name</label>
                <input
                  id="vault-first-name"
                  v-model="form.givenName"
                  type="text"
                  class="vault-input"
                  :disabled="isUpdating"
                />
              </div>
              <div class="vault-form-group">
                <label class="vault-label" for="vault-last-name">Last Name</label>
                <input
                  id="vault-last-name"
                  v-model="form.familyName"
                  type="text"
                  class="vault-input"
                  :disabled="isUpdating"
                />
              </div>
            </div>

            <div class="vault-form-group">
              <label class="vault-label" for="vault-display-name">Display Name</label>
              <input
                id="vault-display-name"
                v-model="form.name"
                type="text"
                class="vault-input"
                :disabled="isUpdating"
              />
            </div>

            <div class="vault-form-group">
              <label class="vault-label" for="vault-phone">Phone Number</label>
              <input
                id="vault-phone"
                v-model="form.phoneNumber"
                type="tel"
                class="vault-input"
                :disabled="isUpdating"
              />
            </div>

            <div v-if="updateError" class="vault-alert vault-alert-error">
              {{ updateError }}
            </div>

            <div v-if="updateSuccess" class="vault-alert vault-alert-success">
              Profile updated successfully!
            </div>

            <div class="vault-form-actions">
              <button
                type="submit"
                class="vault-btn vault-btn-primary"
                :disabled="isUpdating || !hasChanges"
              >
                <span v-if="isUpdating" class="vault-spinner vault-spinner-small vault-spinner-inline"></span>
                {{ isUpdating ? 'Saving...' : 'Save Changes' }}
              </button>
            </div>
          </form>
        </template>

        <div v-else class="vault-empty">
          <p>Not signed in</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useUser, useUpdateUser } from '../composables';
import type { UserProfileProps } from '../types';

/**
 * Props definition
 */
const props = defineProps<UserProfileProps>();

/**
 * Emits definition
 */
const emit = defineEmits<{
  (e: 'update', user: NonNullable<ReturnType<typeof useUser>>['value']): void;
}>();

/**
 * Local state
 */
const fileInput = ref<HTMLInputElement | null>(null);
const form = ref({
  name: '',
  givenName: '',
  familyName: '',
  phoneNumber: '',
});
const updateSuccess = ref(false);

/**
 * Composables
 */
const user = useUser();
const { updateUser, isLoading: isUpdating, error: updateError } = useUpdateUser();

/**
 * Computed
 */
const isLoading = computed(() => !user.value);

const initials = computed(() => {
  const name = user.value?.name || user.value?.email || '';
  return name
    .split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);
});

const hasChanges = computed(() => {
  if (!user.value) return false;
  return (
    form.value.name !== (user.value.name || '') ||
    form.value.givenName !== (user.value.profile?.givenName || '') ||
    form.value.familyName !== (user.value.profile?.familyName || '') ||
    form.value.phoneNumber !== (user.value.profile?.phoneNumber || '')
  );
});

/**
 * Watch for user changes and update form
 */
watch(
  () => user.value,
  (newUser) => {
    if (newUser) {
      form.value = {
        name: newUser.name || '',
        givenName: newUser.profile?.givenName || '',
        familyName: newUser.profile?.familyName || '',
        phoneNumber: newUser.profile?.phoneNumber || '',
      };
    }
  },
  { immediate: true }
);

/**
 * Trigger file input click
 */
function triggerFileInput() {
  fileInput.value?.click();
}

/**
 * Handle file change for avatar upload
 */
async function handleFileChange(event: Event) {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];

  if (!file) return;

  // This would typically upload the file
  // For now, we'll just create a data URL for preview
  const reader = new FileReader();
  reader.onload = (e) => {
    const result = e.target?.result as string;
    // Update user profile with new avatar URL
    updateUser({
      profile: {
        ...user.value?.profile,
        picture: result,
      },
    }).catch(() => {
      // Error is handled by composable
    });
  };
  reader.readAsDataURL(file);
}

/**
 * Handle profile update
 */
async function handleUpdateProfile() {
  updateSuccess.value = false;

  try {
    await updateUser({
      name: form.value.name,
      profile: {
        givenName: form.value.givenName,
        familyName: form.value.familyName,
        phoneNumber: form.value.phoneNumber,
      },
    });

    updateSuccess.value = true;
    emit('update', user.value!);

    // Hide success message after 3 seconds
    setTimeout(() => {
      updateSuccess.value = false;
    }, 3000);
  } catch {
    // Error is handled by composable
  }
}
</script>

<style scoped>
.vault-user-profile {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

.vault-card {
  background: white;
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  border: 1px solid #e5e7eb;
  max-width: 600px;
  width: 100%;
}

.vault-card-header {
  padding: 1.5rem;
  border-bottom: 1px solid #e5e7eb;
}

.vault-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #111827;
  margin: 0;
}

.vault-card-content {
  padding: 1.5rem;
}

.vault-loading {
  display: flex;
  justify-content: center;
  padding: 3rem;
}

.vault-spinner {
  display: inline-block;
  border: 2px solid #e5e7eb;
  border-top-color: #0066cc;
  border-radius: 50%;
  animation: vault-spin 1s linear infinite;
}

.vault-spinner-large {
  width: 2rem;
  height: 2rem;
  border-width: 3px;
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

.vault-profile-header {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.vault-avatar-container {
  position: relative;
}

.vault-avatar {
  border-radius: 50%;
  object-fit: cover;
}

.vault-avatar-large {
  width: 5rem;
  height: 5rem;
}

.vault-avatar-placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  font-size: 1.5rem;
  font-weight: 600;
}

.vault-avatar-edit {
  position: absolute;
  bottom: 0;
  right: 0;
  width: 2rem;
  height: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
  background: white;
  border: 2px solid #e5e7eb;
  border-radius: 50%;
  cursor: pointer;
  transition: all 0.15s ease;
}

.vault-avatar-edit:hover {
  background: #f3f4f6;
  border-color: #d1d5db;
}

.vault-avatar-edit svg {
  width: 1rem;
  height: 1rem;
  color: #6b7280;
}

.vault-file-input {
  display: none;
}

.vault-profile-info {
  flex: 1;
}

.vault-profile-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #111827;
  margin: 0 0 0.25rem;
}

.vault-profile-email {
  font-size: 0.875rem;
  color: #6b7280;
  margin: 0 0 0.5rem;
}

.vault-badge {
  display: inline-flex;
  align-items: center;
  padding: 0.25rem 0.5rem;
  font-size: 0.75rem;
  font-weight: 500;
  border-radius: 9999px;
}

.vault-badge-success {
  color: #166534;
  background-color: #dcfce7;
}

.vault-badge-warning {
  color: #92400e;
  background-color: #fef3c7;
}

.vault-divider {
  height: 1px;
  background-color: #e5e7eb;
  margin: 1.5rem 0;
}

.vault-form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.vault-form-group {
  margin-bottom: 1rem;
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

.vault-form-actions {
  display: flex;
  justify-content: flex-end;
  margin-top: 1.5rem;
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

.vault-alert {
  padding: 0.75rem 1rem;
  border-radius: 0.375rem;
  font-size: 0.875rem;
  margin-bottom: 1rem;
}

.vault-alert-error {
  color: #991b1b;
  background-color: #fef2f2;
  border: 1px solid #fecaca;
}

.vault-alert-success {
  color: #166534;
  background-color: #dcfce7;
  border: 1px solid #86efac;
}

.vault-empty {
  text-align: center;
  padding: 3rem;
  color: #6b7280;
}

@media (max-width: 640px) {
  .vault-form-row {
    grid-template-columns: 1fr;
  }
}
</style>
