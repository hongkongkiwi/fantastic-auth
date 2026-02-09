/**
 * Example: Tenant Signup Flow
 * 
 * This example shows how to use the Vault Internal SDK
 * to provision a new tenant during your SaaS signup process.
 */

import { VaultInternalClient, TenantManager, BillingManager } from '../src';

async function handleSignup(signupData: {
  companyName: string;
  email: string;
  plan: string;
}) {
  // Initialize client
  const client = new VaultInternalClient({
    baseUrl: process.env.VAULT_API_URL!,
    apiKey: process.env.VAULT_INTERNAL_API_KEY!
  });

  const tenants = new TenantManager(client);
  const billing = new BillingManager(client);

  try {
    // 1. Check if slug is available
    const slug = tenants['generateSlug'](signupData.companyName);
    const isAvailable = await tenants.isSlugAvailable(slug);
    
    if (!isAvailable) {
      throw new Error(`Slug "${slug}" is already taken`);
    }

    // 2. Provision the tenant
    console.log(`Provisioning tenant for ${signupData.companyName}...`);
    const { tenant, dashboardUrl } = await tenants.provision({
      name: signupData.companyName,
      slug,
      ownerEmail: signupData.email,
      plan: signupData.plan
    });

    console.log(`✓ Tenant created: ${tenant.id}`);
    console.log(`  Dashboard: ${dashboardUrl}`);

    // 3. For paid plans, create subscription
    if (signupData.plan !== 'free') {
      await billing.changePlan(tenant.id, {
        plan: signupData.plan,
        seats: 10, // Default starter seats
        interval: 'monthly'
      });
      console.log(`✓ Subscription created: ${signupData.plan}`);
    }

    // 4. Return onboarding info to the user
    return {
      success: true,
      tenantId: tenant.id,
      dashboardUrl,
      nextSteps: {
        verifyEmail: true,
        setupMfa: signupData.plan === 'enterprise'
      }
    };

  } catch (error) {
    console.error('Signup failed:', error);
    throw error;
  }
}

// Example usage
if (require.main === module) {
  handleSignup({
    companyName: 'Acme Corporation',
    email: 'admin@acme.com',
    plan: 'pro'
  }).then(result => {
    console.log('\nSignup complete:', result);
  });
}
