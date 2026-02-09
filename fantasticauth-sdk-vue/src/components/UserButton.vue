<template>
  <div ref="buttonRef" class="vault-user-button">
    <button
      type="button"
      class="vault-user-button-trigger"
      :class="{ 'vault-user-button-open': isOpen }"
      @click="toggleDropdown"
    >
      <img
        v-if="displayAvatarUrl"
        :src="displayAvatarUrl"
        :alt="user?.name || user?.email"
        class="vault-avatar"
      />
      <div v-else class="vault-avatar vault-avatar-placeholder">
        {{ initials }}
      </div>
      <span v-if="showName" class="vault-user-name">
        {{ user?.name || user?.email }}
      </span>
      <svg
        class="vault-chevron"
        :class="{ 'vault-chevron-open': isOpen }"
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 20 20"
        fill="currentColor"
      >
        <path
          fill-rule="evenodd"
          d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z"
          clip-rule="evenodd"
        />
      </svg>
    </button>

    <Transition name="vault-dropdown">
      <div
        v-if="isOpen"
        class="vault-dropdown"
        :class="dropdownPosition"
      >
        <div class="vault-dropdown-header">
          <p class="vault-dropdown-email">{{ user?.email }}</p>
          <p v-if="organization" class="vault-dropdown-org">
            {{ organization.name }}
            <span class="vault-dropdown-role">({{ organization.role }})</span>
          </p>
        </div>

        <div class="vault-dropdown-divider"></div>

        <div class="vault-dropdown-items">
          <a
            v-if="showManageAccount"
            href="/account"
            class="vault-dropdown-item"
            @click="closeDropdown"
          >
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="vault-icon">
              <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd" />
            </svg>
            Manage account
          </a>

          <slot name="menu-items" :close="closeDropdown">
            <template v-if="customMenuItems.length > 0">
              <a
                v-for="(item, index) in customMenuItems"
                :key="index"
                href="#"
                class="vault-dropdown-item"
                @click.prevent="handleCustomItem(item)"
              >
                {{ item.label }}
              </a>
            </template>
          </slot>
        </div>

        <div class="vault-dropdown-divider"></div>

        <button
          type="button"
          class="vault-dropdown-item vault-dropdown-item-danger"
          @click="handleSignOut"
        >
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="vault-icon">
            <path fill-rule="evenodd" d="M3 3a1 1 0 00-1 1v12a1 1 0 102 0V4a1 1 0 00-1-1zm10.293 9.293a1 1 0 001.414 1.414l3-3a1 1 0 000-1.414l-3-3a1 1 0 10-1.414 1.414L14.586 9H7a1 1 0 100 2h7.586l-1.293 1.293z" clip-rule="evenodd" />
          </svg>
          Sign out
        </button>
      </div>
    </Transition>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useAuth, useUser, useOrganization } from '../composables';
import type { UserButtonProps } from '../types';

/**
 * Props definition with defaults
 */
const props = withDefaults(defineProps<UserButtonProps>(), {
  showName: false,
  showManageAccount: true,
  menuItems: () => [],
});

/**
 * Emits definition
 */
const emit = defineEmits<{
  (e: 'signOut'): void;
}>();

/**
 * Local state
 */
const isOpen = ref(false);
const buttonRef = ref<HTMLElement | null>(null);
const dropdownPosition = ref('vault-dropdown-bottom-right');

/**
 * Composables
 */
const { signOut } = useAuth();
const user = useUser();
const { organization } = useOrganization();

/**
 * Computed
 */
const initials = computed(() => {
  const name = user.value?.name || user.value?.email || '';
  return name
    .split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);
});

const displayAvatarUrl = computed(() => {
  return props.avatarUrl || user.value?.profile?.picture;
});

const customMenuItems = computed(() => props.menuItems || []);

/**
 * Toggle dropdown
 */
function toggleDropdown() {
  isOpen.value = !isOpen.value;
  if (isOpen.value) {
    calculatePosition();
  }
}

/**
 * Close dropdown
 */
function closeDropdown() {
  isOpen.value = false;
}

/**
 * Calculate dropdown position based on viewport
 */
function calculatePosition() {
  if (!buttonRef.value) return;

  const rect = buttonRef.value.getBoundingClientRect();
  const spaceBelow = window.innerHeight - rect.bottom;
  const spaceRight = window.innerWidth - rect.right;

  // Default to bottom-right
  let position = 'vault-dropdown-bottom-right';

  // If not enough space below, show above
  if (spaceBelow < 300) {
    position = 'vault-dropdown-top-right';
  }

  // If not enough space on right, show on left
  if (spaceRight < 200) {
    position = position.replace('right', 'left');
  }

  dropdownPosition.value = position;
}

/**
 * Handle sign out
 */
async function handleSignOut() {
  closeDropdown();
  await signOut();
  emit('signOut');
}

/**
 * Handle custom menu item click
 */
function handleCustomItem(item: { label: string; onClick: () => void }) {
  closeDropdown();
  item.onClick();
}

/**
 * Handle click outside to close dropdown
 */
function handleClickOutside(event: MouseEvent) {
  if (buttonRef.value && !buttonRef.value.contains(event.target as Node)) {
    closeDropdown();
  }
}

/**
 * Handle escape key to close dropdown
 */
function handleEscape(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    closeDropdown();
  }
}

/**
 * Lifecycle hooks
 */
onMounted(() => {
  document.addEventListener('click', handleClickOutside);
  document.addEventListener('keydown', handleEscape);
});

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside);
  document.removeEventListener('keydown', handleEscape);
});
</script>

<style scoped>
.vault-user-button {
  position: relative;
  display: inline-block;
}

.vault-user-button-trigger {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.375rem 0.75rem;
  background: transparent;
  border: 1px solid transparent;
  border-radius: 0.5rem;
  cursor: pointer;
  transition: all 0.15s ease;
}

.vault-user-button-trigger:hover {
  background-color: #f3f4f6;
}

.vault-user-button-open {
  background-color: #e5e7eb;
}

.vault-avatar {
  width: 2rem;
  height: 2rem;
  border-radius: 50%;
  object-fit: cover;
}

.vault-avatar-placeholder {
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  font-size: 0.75rem;
  font-weight: 600;
}

.vault-user-name {
  font-size: 0.875rem;
  font-weight: 500;
  color: #374151;
}

.vault-chevron {
  width: 1.25rem;
  height: 1.25rem;
  color: #6b7280;
  transition: transform 0.15s ease;
}

.vault-chevron-open {
  transform: rotate(180deg);
}

.vault-dropdown {
  position: absolute;
  z-index: 50;
  min-width: 240px;
  background: white;
  border: 1px solid #e5e7eb;
  border-radius: 0.5rem;
  box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
  margin-top: 0.5rem;
}

.vault-dropdown-top-right,
.vault-dropdown-top-left {
  bottom: 100%;
  margin-top: 0;
  margin-bottom: 0.5rem;
}

.vault-dropdown-bottom-right,
.vault-dropdown-top-right {
  right: 0;
}

.vault-dropdown-bottom-left,
.vault-dropdown-top-left {
  left: 0;
}

.vault-dropdown-header {
  padding: 0.75rem 1rem;
}

.vault-dropdown-email {
  font-size: 0.875rem;
  font-weight: 500;
  color: #111827;
  margin: 0;
}

.vault-dropdown-org {
  font-size: 0.75rem;
  color: #6b7280;
  margin: 0.25rem 0 0;
}

.vault-dropdown-role {
  text-transform: capitalize;
}

.vault-dropdown-divider {
  height: 1px;
  background-color: #e5e7eb;
  margin: 0.25rem 0;
}

.vault-dropdown-items {
  padding: 0.25rem 0;
}

.vault-dropdown-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
  padding: 0.5rem 1rem;
  font-size: 0.875rem;
  color: #374151;
  text-decoration: none;
  background: transparent;
  border: none;
  cursor: pointer;
  transition: background-color 0.15s ease;
}

.vault-dropdown-item:hover {
  background-color: #f3f4f6;
}

.vault-dropdown-item-danger {
  color: #dc2626;
}

.vault-dropdown-item-danger:hover {
  background-color: #fef2f2;
}

.vault-icon {
  width: 1.25rem;
  height: 1.25rem;
  flex-shrink: 0;
}

/* Transitions */
.vault-dropdown-enter-active,
.vault-dropdown-leave-active {
  transition: all 0.15s ease;
}

.vault-dropdown-enter-from,
.vault-dropdown-leave-to {
  opacity: 0;
  transform: scale(0.95);
}

.vault-dropdown-enter-to,
.vault-dropdown-leave-from {
  opacity: 1;
  transform: scale(1);
}
</style>
