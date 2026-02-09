<script lang="ts">
  /**
   * SignedIn Component
   * 
   * Conditionally renders children only when user is signed in.
   * 
   * @example
   * ```svelte
   * <SignedIn>
   *   <UserNav />
   * </SignedIn>
   * ```
   */
  import { getVaultContext } from '../context.js';
  
  let { children }: { children: import('svelte').Snippet } = $props();
  
  const vault = getVaultContext();
  
  // Reactive state from store
  let isSignedIn = $state(false);
  vault.isSignedIn.subscribe(v => isSignedIn = v);
</script>

{#if isSignedIn}
  {@render children()}
{/if}
