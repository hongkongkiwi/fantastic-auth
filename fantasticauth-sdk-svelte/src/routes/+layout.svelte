<script lang="ts">
  /**
   * Example layout showing VaultProvider usage
   */
  import { VaultProvider } from '$lib/index.js';
  
  const config = {
    apiUrl: import.meta.env.VITE_VAULT_API_URL || 'https://api.vault.dev',
    tenantId: import.meta.env.VITE_VAULT_TENANT_ID || 'default',
    debug: import.meta.env.DEV
  };
</script>

<VaultProvider {config}>
  <slot />
</VaultProvider>
