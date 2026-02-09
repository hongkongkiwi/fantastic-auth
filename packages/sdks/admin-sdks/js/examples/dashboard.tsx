/**
 * Example: Admin Dashboard with React
 * 
 * This example shows how to build an admin dashboard
 * using the Vault Admin SDK.
 */

import React, { useEffect, useState } from 'react';
import { VaultAdminClient, UserManager } from '../src';

// Initialize client (in real app, get token from auth context)
const client = new VaultAdminClient({
  baseUrl: process.env.VAULT_API_URL!,
  token: getAdminToken(), // Your auth function
  tenantId: 'my-tenant'
});

const users = new UserManager(client);

function AdminDashboard() {
  const [stats, setStats] = useState<any>(null);
  const [recentUsers, setRecentUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  async function loadDashboardData() {
    try {
      setLoading(true);
      
      // Load in parallel
      const [dashboard, userStats, allUsers] = await Promise.all([
        client.getDashboard(),
        users.getStats(),
        users.getAll()
      ]);

      setStats({ ...dashboard, ...userStats });
      setRecentUsers(allUsers.slice(0, 10));
    } catch (error) {
      console.error('Failed to load dashboard:', error);
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <div>Loading...</div>;

  return (
    <div className="dashboard">
      <h1>Admin Dashboard</h1>
      
      {/* Stats Cards */}
      <div className="stats-grid">
        <StatCard 
          title="Total Users" 
          value={stats?.totalUsers} 
          trend="+5%"
        />
        <StatCard 
          title="Active Users" 
          value={stats?.activeUsers}
          subtitle="Last 30 days"
        />
        <StatCard 
          title="New Today" 
          value={stats?.newUsersToday}
        />
        <StatCard 
          title="MFA Enabled" 
          value={stats?.mfaEnabled}
          subtitle={`${Math.round((stats?.mfaEnabled / stats?.totalUsers) * 100)}%`}
        />
      </div>

      {/* Recent Users Table */}
      <div className="recent-users">
        <h2>Recent Users</h2>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {recentUsers.map(user => (
              <tr key={user.id}>
                <td>{user.name || 'N/A'}</td>
                <td>{user.email}</td>
                <td>
                  <StatusBadge status={user.status} />
                </td>
                <td>
                  <button onClick={() => handleSuspend(user.id)}>
                    Suspend
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatCard({ title, value, trend, subtitle }: any) {
  return (
    <div className="stat-card">
      <h3>{title}</h3>
      <div className="stat-value">{value}</div>
      {trend && <span className="trend">{trend}</span>}
      {subtitle && <span className="subtitle">{subtitle}</span>}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    active: 'green',
    suspended: 'red',
    pending: 'yellow',
    deactivated: 'gray'
  };
  
  return (
    <span style={{ color: colors[status] || 'black' }}>
      {status}
    </span>
  );
}

async function handleSuspend(userId: string) {
  if (confirm('Are you sure you want to suspend this user?')) {
    await users.suspend(userId, 'Suspended by admin');
    // Refresh data
  }
}

function getAdminToken(): string {
  // Get from your auth system
  return localStorage.getItem('admin_token') || '';
}

export default AdminDashboard;
