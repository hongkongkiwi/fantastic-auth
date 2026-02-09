<script lang="ts">
  /**
   * SignedOut Component
   * 
   * Conditionally renders children only when user is signed out.
   * 
   * @example
   * ```svelte
   * <SignedOut>
   *   <LoginButton />
   * </SignedOut>
   * ```
   */
  import { getVaultContext } from '../context.js';
  
  let { children }: { children: import('svelte').Snippet } = $props();
  
  const vault = getVaultContext();
  
  // Reactive state from store
  let isSignedIn = $state(false);
  let isLoaded = $state(false);
  vault.isSignedIn.subscribe(v => isSignedIn = v);
  vault.isLoaded.subscribe(v => isLoaded = v);
</script>

{#if isLoaded && !isSignedIn}
  {@render children()}
{/if}
