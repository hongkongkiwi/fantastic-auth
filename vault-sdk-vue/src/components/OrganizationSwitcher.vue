<template>
  <div ref="switcherRef" class="vault-org-switcher">
    <button
      type="button"
      class="vault-org-trigger"
      :class="{ 'vault-org-trigger-open': isOpen }"
      @click="toggleDropdown"
    >
      <div class="vault-org-icon">
        {{ currentOrgInitials }}
      </div>
      <div class="vault-org-info">
        <span class="vault-org-name">{{ currentOrgName }}</span>
        <span class="vault-org-role">{{ currentOrgRole }}</span>
      </div>
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
      <div v-if="isOpen" class="vault-org-dropdown">
        <div class="vault-org-section">
          <span class="vault-org-section-title">Personal Account</span>
          <button
            type="button"
            class="vault-org-item"
            :class="{ 'vault-org-item-active': !organization }"
            @click="selectOrganization(null)"
          >
            <div class="vault-org-item-icon vault-org-item-icon-personal">
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="vault-org-item-info">
              <span class="vault-org-item-name">{{ user?.name || user?.email || 'Personal' }}</span>
            </div>
            <svg
              v-if="!organization"
              class="vault-org-check"
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 20 20"
              fill="currentColor"
            >
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
            </svg>
          </button>
        </div>

        <div v-if="organizations.length > 0" class="vault-org-section">
          <span class="vault-org-section-title">Organizations</span>
          <button
            v-for="org in organizations"
            :key="org.id"
            type="button"
            class="vault-org-item"
            :class="{ 'vault-org-item-active': organization?.id === org.id }"
            @click="selectOrganization(org)"
          >
            <div class="vault-org-item-icon">
              {{ getOrgInitials(org) }}
            </div>
            <div class="vault-org-item-info">
              <span class="vault-org-item-name">{{ org.name }}</span>
              <span class="vault-org-item-role">{{ org.role }}</span>
            </div>
            <svg
              v-if="organization?.id === org.id"
              class="vault-org-check"
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 20 20"
              fill="currentColor"
            >
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
            </svg>
          </button>
        </div>

        <div class="vault-org-divider"></div>

        <a href="/organizations/create" class="vault-org-item vault-org-item-action" @click="closeDropdown">
          <div class="vault-org-item-icon vault-org-item-icon-action">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" />
            </svg>
          </div>
          <span class="vault-org-item-name">Create Organization</span>
        </a>

        <a href="/organizations" class="vault-org-item vault-org-item-action" @click="closeDropdown">
          <div class="vault-org-item-icon vault-org-item-icon-action">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
              <path d="M13 6a3 3 0 11-6 0 3 3 0 016 0zM18 8a2 2 0 11-4 0 2 2 0 014 0zM14 15a4 4 0 00-8 0v3h8v-3zM6 8a2 2 0 11-4 0 2 2 0 014 0zM16 18v-3a5.972 5.972 0 00-.75-2.906A3.005 3.005 0 0119 15v3h-3zM4.75 12.094A5.973 5.973 0 004 15v3H1v-3a3 3 0 013.75-2.906z" />
            </svg>
          </div>
          <span class="vault-org-item-name">Manage Organizations</span>
        </a>
      </div>
    </Transition>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useUser, useOrganization } from '../composables';
import type { OrganizationSwitcherProps, Organization } from '../types';

/**
 * Props definition
 */
const props = defineProps<OrganizationSwitcherProps>();

/**
 * Emits definition
 */
const emit = defineEmits<{
  (e: 'switch', org: Organization | null): void;
}>();

/**
 * Local state
 */
const isOpen = ref(false);
const switcherRef = ref<HTMLElement | null>(null);

/**
 * Composables
 */
const user = useUser();
const { organization, organizations, setActiveOrganization } = useOrganization();

/**
 * Computed
 */
const currentOrgName = computed(() => {
  if (organization.value) {
    return organization.value.name;
  }
  return user.value?.name || user.value?.email || 'Personal';
});

const currentOrgRole = computed(() => {
  if (organization.value) {
    return capitalize(organization.value.role);
  }
  return 'Personal';
});

const currentOrgInitials = computed(() => {
  const name = currentOrgName.value;
  return name
    .split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);
});

/**
 * Toggle dropdown
 */
function toggleDropdown() {
  isOpen.value = !isOpen.value;
}

/**
 * Close dropdown
 */
function closeDropdown() {
  isOpen.value = false;
}

/**
 * Select organization
 */
async function selectOrganization(org: Organization | null) {
  closeDropdown();

  const orgId = org?.id || null;
  await setActiveOrganization(orgId);

  emit('switch', org);
}

/**
 * Get organization initials
 */
function getOrgInitials(org: Organization): string {
  return org.name
    .split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase()
    .slice(0, 2);
}

/**
 * Capitalize first letter
 */
function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Handle click outside
 */
function handleClickOutside(event: MouseEvent) {
  if (switcherRef.value && !switcherRef.value.contains(event.target as Node)) {
    closeDropdown();
  }
}

/**
 * Handle escape key
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
.vault-org-switcher {
  position: relative;
  display: inline-block;
}

.vault-org-trigger {
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 0.75rem;
  background: white;
  border: 1px solid #e5e7eb;
  border-radius: 0.5rem;
  cursor: pointer;
  transition: all 0.15s ease;
  min-width: 200px;
}

.vault-org-trigger:hover {
  border-color: #d1d5db;
  background-color: #f9fafb;
}

.vault-org-trigger-open {
  border-color: #3b82f6;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.vault-org-icon {
  width: 2rem;
  height: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  font-size: 0.75rem;
  font-weight: 600;
  border-radius: 0.375rem;
  flex-shrink: 0;
}

.vault-org-info {
  flex: 1;
  text-align: left;
  min-width: 0;
}

.vault-org-name {
  display: block;
  font-size: 0.875rem;
  font-weight: 500;
  color: #111827;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.vault-org-role {
  display: block;
  font-size: 0.75rem;
  color: #6b7280;
  text-transform: capitalize;
}

.vault-chevron {
  width: 1.25rem;
  height: 1.25rem;
  color: #6b7280;
  transition: transform 0.15s ease;
  flex-shrink: 0;
}

.vault-chevron-open {
  transform: rotate(180deg);
}

.vault-org-dropdown {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  z-index: 50;
  margin-top: 0.5rem;
  background: white;
  border: 1px solid #e5e7eb;
  border-radius: 0.5rem;
  box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
  min-width: 280px;
  max-height: 400px;
  overflow-y: auto;
}

.vault-org-section {
  padding: 0.5rem 0;
}

.vault-org-section-title {
  display: block;
  padding: 0.5rem 1rem;
  font-size: 0.75rem;
  font-weight: 600;
  color: #6b7280;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.vault-org-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
  padding: 0.625rem 1rem;
  text-align: left;
  background: transparent;
  border: none;
  cursor: pointer;
  text-decoration: none;
  transition: background-color 0.15s ease;
}

.vault-org-item:hover {
  background-color: #f3f4f6;
}

.vault-org-item-active {
  background-color: #eff6ff;
}

.vault-org-item-active:hover {
  background-color: #dbeafe;
}

.vault-org-item-icon {
  width: 2rem;
  height: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  font-size: 0.625rem;
  font-weight: 600;
  border-radius: 0.375rem;
  flex-shrink: 0;
}

.vault-org-item-icon-personal {
  background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
}

.vault-org-item-icon-personal svg {
  width: 1.25rem;
  height: 1.25rem;
}

.vault-org-item-icon-action {
  background: #f3f4f6;
  color: #6b7280;
}

.vault-org-item-icon-action svg {
  width: 1.25rem;
  height: 1.25rem;
}

.vault-org-item-info {
  flex: 1;
  min-width: 0;
}

.vault-org-item-name {
  display: block;
  font-size: 0.875rem;
  font-weight: 500;
  color: #111827;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.vault-org-item-role {
  display: block;
  font-size: 0.75rem;
  color: #6b7280;
  text-transform: capitalize;
}

.vault-org-check {
  width: 1.25rem;
  height: 1.25rem;
  color: #3b82f6;
  flex-shrink: 0;
}

.vault-org-divider {
  height: 1px;
  background-color: #e5e7eb;
  margin: 0.25rem 0;
}

.vault-org-item-action .vault-org-item-name {
  color: #374151;
}

/* Transitions */
.vault-dropdown-enter-active,
.vault-dropdown-leave-active {
  transition: all 0.15s ease;
}

.vault-dropdown-enter-from,
.vault-dropdown-leave-to {
  opacity: 0;
  transform: translateY(-0.5rem);
}

.vault-dropdown-enter-to,
.vault-dropdown-leave-from {
  opacity: 1;
  transform: translateY(0);
}
</style>
