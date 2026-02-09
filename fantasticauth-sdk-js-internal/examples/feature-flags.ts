/**
 * Example: Feature Flag Management
 * 
 * This example shows how to use feature flags for
 * gradual rollouts and tenant-specific features.
 */

import { VaultInternalClient, FeatureFlagManager } from '../src';

async function featureFlagExamples() {
  const client = new VaultInternalClient({
    baseUrl: process.env.VAULT_API_URL!,
    apiKey: process.env.VAULT_INTERNAL_API_KEY!
  });

  const features = new FeatureFlagManager(client);

  // ==========================================
  // 1. Create a new feature flag
  // ==========================================
  console.log('Creating feature flag...');
  await features.create('dark_mode', 'Dark Mode UI', {
    description: 'Enable dark mode across the application',
    enabled: false,
    rolloutPercentage: 0
  });

  // ==========================================
  // 2. Gradual rollout (10% → 50% → 100%)
  // ==========================================
  console.log('Starting gradual rollout...');
  
  // Phase 1: 10% of tenants
  await features.configureRollout('dark_mode', { percentage: 10 });
  await features.enable('dark_mode');
  console.log('✓ Phase 1: 10% rollout');

  // Monitor for errors, then increase
  // await wait('1d');
  await features.configureRollout('dark_mode', { percentage: 50 });
  console.log('✓ Phase 2: 50% rollout');

  // await wait('1d');
  await features.configureRollout('dark_mode', { percentage: 100 });
  console.log('✓ Phase 3: 100% rollout');

  // ==========================================
  // 3. Beta testing with specific tenants
  // ==========================================
  console.log('Setting up beta program...');
  
  await features.create('ai_assistant', 'AI Assistant', {
    description: 'AI-powered support assistant'
  });

  // Enable for beta tenants only
  await features.enableForTenants('ai_assistant', [
    'tenant-beta-1',
    'tenant-beta-2',
    'tenant-beta-3'
  ]);

  // ==========================================
  // 4. Check if feature is enabled (with caching)
  // ==========================================
  const tenantId = 'tenant-123';
  
  // This will cache results for 1 minute
  const isDarkModeEnabled = await features.isEnabled('dark_mode', tenantId);
  console.log(`Dark mode for ${tenantId}: ${isDarkModeEnabled}`);

  // Second call uses cache
  const isEnabledAgain = await features.isEnabled('dark_mode', tenantId);
  
  // Force refresh
  const isEnabledFresh = await features.get('dark_mode');

  // ==========================================
  // 5. Emergency disable
  // ==========================================
  console.log('Emergency disable...');
  await features.disable('ai_assistant');
  console.log('✓ Feature disabled globally');

  // ==========================================
  // 6. List all features
  // ==========================================
  const allFlags = await features.getAll();
  console.log('\nAll feature flags:');
  for (const flag of allFlags) {
    console.log(`  ${flag.key}: ${flag.enabled ? 'ON' : 'OFF'} (${flag.rolloutPercentage}%)`);
  }
}

// Run examples
featureFlagExamples().catch(console.error);
