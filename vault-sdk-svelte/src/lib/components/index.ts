/**
 * Vault Svelte Components
 * 
 * Pre-built components for authentication UI.
 * All components work with both Svelte 4 and Svelte 5.
 */

// Auth Components
export { default as SignIn } from './SignIn.svelte';
export { default as SignUp } from './SignUp.svelte';
export { default as UserButton } from './UserButton.svelte';
export { default as UserProfile } from './UserProfile.svelte';
export { default as WebAuthnButton } from './WebAuthnButton.svelte';

// Organization Components
export { default as OrganizationSwitcher } from './OrganizationSwitcher.svelte';

// Control Components
export { default as SignedIn } from './SignedIn.svelte';
export { default as SignedOut } from './SignedOut.svelte';
export { default as Protect } from './Protect.svelte';
