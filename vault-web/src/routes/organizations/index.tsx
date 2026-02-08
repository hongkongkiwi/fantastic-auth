import { createFileRoute, Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { 
  Building2, 
  Users, 
  Shield, 
  Plus,
  MoreHorizontal,
  ChevronRight
} from 'lucide-react'
import { motion } from 'framer-motion'
import { PageHeader } from '../../components/layout/Layout'
import { Card } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'
import { Badge } from '../../components/ui/Badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../components/ui/DropdownMenu'

export const Route = createFileRoute('/organizations/')({
  component: OrganizationsPage,
})

interface Organization {
  id: string
  name: string
  slug: string
  member_count: number
  role: 'owner' | 'admin' | 'member'
  sso_enabled: boolean
  created_at: string
}

function OrganizationsPage() {
  const { data: organizations, isLoading } = useQuery({
    queryKey: ['organizations'],
    queryFn: async () => {
      const res = await fetch('/api/v1/admin/organizations')
      if (!res.ok) throw new Error('Failed to load organizations')
      return res.json() as Promise<Organization[]>
    },
  })

  return (
    <div className="space-y-6">
      <PageHeader
        title="Organizations"
        description="Manage teams and organizations"
        actions={
          <Button>
            <Plus className="mr-2 h-4 w-4" />
            New Organization
          </Button>
        }
      />

      <div className="grid gap-4">
        {isLoading ? (
          <Card className="p-8 text-center">
            <div className="animate-pulse space-y-4">
              <div className="h-12 w-12 bg-muted rounded-full mx-auto" />
              <div className="h-4 w-48 bg-muted rounded mx-auto" />
            </div>
          </Card>
        ) : organizations?.length === 0 ? (
          <Card className="p-8 text-center">
            <Building2 className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
            <h3 className="text-lg font-medium">No organizations</h3>
            <p className="text-sm text-muted-foreground mt-1">
              Create an organization to start collaborating with your team
            </p>
            <Button className="mt-4">
              <Plus className="mr-2 h-4 w-4" />
              Create Organization
            </Button>
          </Card>
        ) : (
          organizations?.map((org, index) => (
            <motion.div
              key={org.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <Card className="p-6 hover:shadow-md transition-shadow">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
                      <Building2 className="h-6 w-6 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-semibold">{org.name}</h3>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="text-sm text-muted-foreground">@{org.slug}</span>
                        <Badge variant="secondary" className="gap-1">
                          <Users className="h-3 w-3" />
                          {org.member_count} members
                        </Badge>
                        {org.sso_enabled && (
                          <Badge variant="outline" className="gap-1">
                            <Shield className="h-3 w-3" />
                            SSO
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button variant="ghost" size="sm" asChild>
                      <Link to={`/organizations/${org.id}`}>
                        Manage
                        <ChevronRight className="ml-1 h-4 w-4" />
                      </Link>
                    </Button>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" aria-label="Open organization actions">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem asChild>
                          <Link to={`/organizations/${org.id}`}>View Settings</Link>
                        </DropdownMenuItem>
                        <DropdownMenuItem asChild>
                          <Link to={`/organizations/${org.id}`}>Manage Members</Link>
                        </DropdownMenuItem>
                        {org.role === 'owner' && (
                          <DropdownMenuItem className="text-destructive">
                            Delete Organization
                          </DropdownMenuItem>
                        )}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </div>
              </Card>
            </motion.div>
          ))
        )}
      </div>
    </div>
  )
}
