/**
 * Example: Security Audit Dashboard Backend
 * 
 * This example shows how to build a security monitoring
 * dashboard using audit logs.
 */

import { VaultAdminClient, AuditManager, UserManager } from '../src';

const client = new VaultAdminClient({
  baseUrl: process.env.VAULT_API_URL!,
  token: process.env.ADMIN_TOKEN!,
  tenantId: process.env.TENANT_ID!
});

const audit = new AuditManager(client);
const users = new UserManager(client);

interface SecurityReport {
  generatedAt: string;
  period: { from: string; to: string };
  summary: {
    totalEvents: number;
    failedLogins: number;
    suspiciousActivities: number;
    lockedAccounts: number;
  };
  topThreats: Array<{
    userId: string;
    email?: string;
    threatLevel: 'high' | 'medium' | 'low';
    description: string;
    failedAttempts: number;
    ipAddresses: string[];
  }>;
  recommendations: string[];
}

/**
 * Generate a comprehensive security report
 */
export async function generateSecurityReport(days: number = 7): Promise<SecurityReport> {
  const from = new Date();
  from.setDate(from.getDate() - days);
  const to = new Date();

  console.log(`Generating security report for ${days} days...`);

  // Collect data
  const [
    actionSummary,
    failedLogins,
    suspiciousActivity,
    userStats
  ] = await Promise.all([
    audit.summarizeActions(days),
    audit.getFailedLogins(days),
    audit.detectSuspiciousActivity(5, 24),
    users.getStats()
  ]);

  // Calculate totals
  const totalEvents = actionSummary.reduce((sum, a) => sum + a.count, 0);
  const failedLoginCount = failedLogins.length;

  // Build threat list
  const topThreats = await Promise.all(
    suspiciousActivity.slice(0, 10).map(async (user) => {
      const userDetails = user.email 
        ? await users.findByEmail(user.email)
        : null;

      const threatLevel: 'high' | 'medium' | 'low' = 
        user.actionCount > 20 ? 'high' :
        user.actionCount > 10 ? 'medium' : 'low';

      return {
        userId: user.userId,
        email: user.email,
        threatLevel,
        description: `${user.actionCount} failed attempts from ${user.ipAddresses.length} IP(s)`,
        failedAttempts: user.actionCount,
        ipAddresses: user.ipAddresses,
      };
    })
  );

  // Generate recommendations
  const recommendations: string[] = [];
  
  if (failedLoginCount > 100) {
    recommendations.push('Consider implementing IP-based rate limiting');
  }
  
  if (suspiciousActivity.length > 5) {
    recommendations.push('Multiple accounts under attack - review security policies');
  }
  
  if (userStats.mfaEnabled / userStats.total < 0.5) {
    recommendations.push('MFA adoption is below 50% - consider requiring MFA');
  }

  const report: SecurityReport = {
    generatedAt: new Date().toISOString(),
    period: { from: from.toISOString(), to: to.toISOString() },
    summary: {
      totalEvents,
      failedLogins: failedLoginCount,
      suspiciousActivities: suspiciousActivity.length,
      lockedAccounts: userStats.suspended,
    },
    topThreats,
    recommendations,
  };

  return report;
}

/**
 * Monitor real-time security events
 */
export async function monitorSecurityEvents(callback: (event: any) => void) {
  let lastCheck = new Date();

  setInterval(async () => {
    try {
      const recent = await audit.getRecent(10);
      const newEvents = recent.filter(e => new Date(e.timestamp) > lastCheck);

      for (const event of newEvents) {
        // Alert on suspicious events
        if (event.action === 'user.login' && !event.success) {
          callback({
            type: 'failed_login',
            severity: 'warning',
            message: `Failed login for ${event.userEmail}`,
            ipAddress: event.ipAddress,
            timestamp: event.timestamp,
          });
        }

        // Alert on admin actions
        if (event.action.startsWith('admin.') && event.success) {
          callback({
            type: 'admin_action',
            severity: 'info',
            message: `Admin action: ${event.action}`,
            userId: event.userId,
            timestamp: event.timestamp,
          });
        }
      }

      lastCheck = new Date();
    } catch (error) {
      console.error('Security monitoring error:', error);
    }
  }, 30000); // Check every 30 seconds
}

// Example usage
if (require.main === module) {
  generateSecurityReport(7).then(report => {
    console.log('\n=== Security Report ===');
    console.log(`Period: ${report.period.from} to ${report.period.to}`);
    console.log(`\nSummary:`);
    console.log(`  Total events: ${report.summary.totalEvents}`);
    console.log(`  Failed logins: ${report.summary.failedLogins}`);
    console.log(`  Suspicious activities: ${report.summary.suspiciousActivities}`);
    
    console.log(`\nTop Threats:`);
    for (const threat of report.topThreats) {
      console.log(`  [${threat.threatLevel.toUpperCase()}] ${threat.email || threat.userId}: ${threat.description}`);
    }
    
    console.log(`\nRecommendations:`);
    for (const rec of report.recommendations) {
      console.log(`  • ${rec}`);
    }
  });
}
