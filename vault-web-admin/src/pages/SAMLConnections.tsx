import { useNavigate } from 'react-router-dom'
import { Plus, Shield, CheckCircle, XCircle, Trash2, ExternalLink, Building2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useSAMLConnections, useDeleteSAMLConnection } from '@/hooks/useApi'

export function SAMLConnections() {
  const navigate = useNavigate()
  
  const { data: connections, isLoading } = useSAMLConnections()
  const deleteMutation = useDeleteSAMLConnection()

  const handleDelete = (id: string, name: string) => {
    if (confirm(`Are you sure you want to delete the SAML connection "${name}"?`)) {
      deleteMutation.mutate(id)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">SAML Connections</h1>
          <p className="text-muted-foreground">Manage SAML SSO connections for enterprise authentication</p>
        </div>
        <button
          onClick={() => navigate('/saml-connections/new')}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
        >
          <Plus className="w-4 h-4" />
          Add Connection
        </button>
      </div>

      {/* Connections List */}
      {isLoading ? (
        <div className="bg-card rounded-lg border border-border p-8">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto" />
        </div>
      ) : connections?.length === 0 ? (
        <div className="bg-card rounded-lg border border-border p-12 text-center">
          <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center mx-auto mb-4">
            <Shield className="w-8 h-8 text-muted-foreground" />
          </div>
          <h3 className="font-semibold mb-2">No SAML connections</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Add a SAML connection to enable single sign-on for your organization
          </p>
          <button
            onClick={() => navigate('/saml-connections/new')}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90"
          >
            Add Connection
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {connections?.map((connection) => (
            <div
              key={connection.id}
              className="bg-card rounded-lg border border-border p-6"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                      <Shield className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-semibold">{connection.name}</h3>
                      <p className="text-sm text-muted-foreground">{connection.provider}</p>
                    </div>
                    <span
                      className={cn(
                        "ml-2 px-2 py-0.5 rounded-full text-xs font-medium",
                        connection.active
                          ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                          : "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200"
                      )}
                    >
                      {connection.active ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                    <div>
                      <label className="text-xs text-muted-foreground uppercase tracking-wider">Entity ID</label>
                      <code className="block text-sm bg-muted px-2 py-1 rounded mt-1 truncate">
                        {connection.entityId}
                      </code>
                    </div>
                    <div>
                      <label className="text-xs text-muted-foreground uppercase tracking-wider">SSO URL</label>
                      <code className="block text-sm bg-muted px-2 py-1 rounded mt-1 truncate">
                        {connection.ssoUrl}
                      </code>
                    </div>
                  </div>

                  <div className="mt-4">
                    <label className="text-xs text-muted-foreground uppercase tracking-wider">Certificate</label>
                    <pre className="mt-1 p-3 bg-muted rounded text-xs overflow-x-auto">
                      {connection.certificate.slice(0, 100)}...
                    </pre>
                  </div>

                  <div className="mt-4 text-sm text-muted-foreground">
                    Created {new Date(connection.createdAt).toLocaleDateString()}
                  </div>
                </div>

                <div className="flex items-center gap-2 ml-4">
                  <button
                    onClick={() => navigate(`/saml-connections/${connection.id}/edit`)}
                    className="p-2 rounded-lg border border-border hover:bg-muted"
                    title="Edit connection"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(connection.id, connection.name)}
                    className="p-2 rounded-lg border border-border hover:bg-muted text-red-600"
                    title="Delete connection"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Configuration Info */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-card rounded-lg border border-border p-6">
          <h3 className="font-semibold mb-4">Vault SAML Settings</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Provide these values to your Identity Provider:
          </p>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-muted-foreground uppercase tracking-wider">ACS URL</label>
              <code className="block text-sm bg-muted px-3 py-2 rounded mt-1">
                https://your-domain.com/saml/acs
              </code>
            </div>
            <div>
              <label className="text-xs text-muted-foreground uppercase tracking-wider">Entity ID</label>
              <code className="block text-sm bg-muted px-3 py-2 rounded mt-1">
                https://your-domain.com/saml/metadata
              </code>
            </div>
            <div>
              <label className="text-xs text-muted-foreground uppercase tracking-wider">Single Logout URL</label>
              <code className="block text-sm bg-muted px-3 py-2 rounded mt-1">
                https://your-domain.com/saml/slo
              </code>
            </div>
          </div>
        </div>

        <div className="bg-card rounded-lg border border-border p-6">
          <h3 className="font-semibold mb-4">Supported Features</h3>
          <div className="space-y-2">
            {[
              'Identity Provider (IdP) initiated SSO',
              'Service Provider (SP) initiated SSO',
              'Just-In-Time (JIT) provisioning',
              'SAML attribute mapping',
              'Single Logout (SLO)',
              'Encrypted assertions',
            ].map((feature) => (
              <div key={feature} className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">{feature}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
