/**
 * Example: Bulk Operations
 * 
 * This example shows how to perform bulk operations
 * on users and organizations.
 */

import { TenantClient, UserManager, OrganizationManager } from '../src';

const client = new TenantClient({
  baseUrl: process.env.VAULT_API_URL!,
  token: process.env.TENANT_TOKEN!,
  tenantId: process.env.TENANT_ID!
});

const users = new UserManager(client);
const orgs = new OrganizationManager(client);

/**
 * Bulk deactivate inactive users
 */
export async function deactivateInactiveUsers(daysInactive: number = 90) {
  console.log(`Finding users inactive for ${daysInactive}+ days...`);
  
  const inactive = await users.getInactive(daysInactive);
  console.log(`Found ${inactive.length} inactive users`);

  if (inactive.length === 0) return { deactivated: 0, errors: [] };

  const errors: Array<{ userId: string; error: string }> = [];
  let deactivated = 0;

  // Process in batches of 10
  const batchSize = 10;
  for (let i = 0; i < inactive.length; i += batchSize) {
    const batch = inactive.slice(i, i + batchSize);
    
    await Promise.all(
      batch.map(async (user) => {
        try {
          await users.suspend(user.id, `Inactive for ${daysInactive}+ days`);
          deactivated++;
          console.log(`✓ Deactivated: ${user.email}`);
        } catch (error) {
          errors.push({ 
            userId: user.id, 
            error: error instanceof Error ? error.message : 'Unknown error'
          });
          console.error(`✗ Failed: ${user.email}`);
        }
      })
    );

    // Small delay between batches
    if (i + batchSize < inactive.length) {
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  return { deactivated, errors };
}

/**
 * Bulk update organization settings
 */
export async function bulkUpdateOrgSettings(
  updates: Partial<{
    maxMembers: number;
    ssoRequired: boolean;
  }>
) {
  console.log('Updating all organizations...');
  
  const allOrgs = await orgs.getAll();
  const results = await Promise.all(
    allOrgs.map(async (org) => {
      try {
        await orgs.update(org.id, updates);
        return { orgId: org.id, success: true };
      } catch (error) {
        return { 
          orgId: org.id, 
          success: false, 
          error: error instanceof Error ? error.message : 'Unknown error'
        };
      }
    })
  );

  const successful = results.filter(r => r.success).length;
  console.log(`Updated ${successful}/${allOrgs.length} organizations`);

  return results;
}

/**
 * Export user data for GDPR compliance
 */
export async function exportUserData(userId: string): Promise<{
  user: any;
  organizations: any[];
  auditLogs: any[];
  sessions: any[];
  exportedAt: string;
}> {
  console.log(`Exporting data for user ${userId}...`);

  const [user, sessions] = await Promise.all([
    client.getUser(userId),
    client.listUserSessions(userId)
  ]);

  // Get all orgs and filter by membership
  const allOrgs = await orgs.getAll();
  const userOrgs: any[] = [];
  
  for (const org of allOrgs) {
    const { members } = await orgs.getDetails(org.id);
    const member = members.find(m => m.userId === userId);
    if (member) {
      userOrgs.push({
        organization: org,
        membership: member
      });
    }
  }

  // Get audit logs for user
  const auditData = await client.getUserAuditLogs(userId, { perPage: 1000 });

  return {
    user,
    organizations: userOrgs,
    auditLogs: auditData.data,
    sessions,
    exportedAt: new Date().toISOString(),
  };
}

/**
 * Cleanup orphaned organizations
 */
export async function cleanupOrphanedOrgs(dryRun: boolean = true) {
  const orphaned = await orgs.getOrphaned();
  
  console.log(`Found ${orphaned.length} orphaned organizations`);
  
  if (dryRun) {
    console.log('Dry run mode - no changes made');
    return { wouldDelete: orphaned.length, deleted: 0 };
  }

  if (orphaned.length === 0) {
    return { wouldDelete: 0, deleted: 0 };
  }

  // Double-check before deletion
  const confirmed = orphaned.filter(o => {
    // Add any additional checks here
    const daysSinceCreation = (Date.now() - new Date(o.createdAt).getTime()) / (1000 * 60 * 60 * 24);
    return daysSinceCreation > 7; // Only delete if created more than 7 days ago
  });

  await orgs.bulkDelete(confirmed.map(o => o.id));
  
  return { wouldDelete: orphaned.length, deleted: confirmed.length };
}

// Example CLI interface
if (require.main === module) {
  const command = process.argv[2];

  switch (command) {
    case 'deactivate-inactive':
      const days = parseInt(process.argv[3]) || 90;
      deactivateInactiveUsers(days).then(result => {
        console.log(`\nDeactivated: ${result.deactivated}`);
        if (result.errors.length > 0) {
          console.log(`Errors: ${result.errors.length}`);
        }
      });
      break;

    case 'cleanup-orphans':
      const dryRun = process.argv[3] !== '--execute';
      cleanupOrphanedOrgs(dryRun).then(result => {
        console.log(`\nOrphaned orgs: ${result.wouldDelete}`);
        console.log(`Deleted: ${result.deleted}`);
      });
      break;

    case 'export-user':
      const userId = process.argv[3];
      if (!userId) {
        console.error('Usage: export-user <userId>');
        process.exit(1);
      }
      exportUserData(userId).then(data => {
        console.log(JSON.stringify(data, null, 2));
      });
      break;

    default:
      console.log('Usage:');
      console.log('  deactivate-inactive [days]');
      console.log('  cleanup-orphans [--execute]');
      console.log('  export-user <userId>');
  }
}
