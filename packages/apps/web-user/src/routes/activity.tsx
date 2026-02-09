import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import {
  Activity,
  LogIn,
  LogOut,
  User,
  Shield,
  Smartphone,
  Key,
  AlertTriangle,
  Filter,
  ChevronLeft,
  ChevronRight,
  Download,
  Loader2,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Input } from '@/components/ui/Input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/Select'
import { FeatureUnavailable } from '@/components/FeatureUnavailable'
import { features } from '@/lib/features'
import { toast } from 'sonner'
import { formatDate, formatRelativeTime } from '@/lib/utils'
import { useActivityLog, type ActivityEntry } from '@/lib/api'

export const Route = createFileRoute('/activity')({
  component: ActivityPage,
})

const ITEMS_PER_PAGE = 10

function ActivityPage() {
  if (!features.activity) {
    return (
      <FeatureUnavailable
        title="Activity Log Disabled"
        description="Activity history is disabled until audit-event APIs are integrated for end users."
      />
    )
  }

  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [currentPage, setCurrentPage] = useState(1)

  const { data: activitiesData, isLoading, error } = useActivityLog({
    page: currentPage,
    limit: ITEMS_PER_PAGE,
    filter,
    search,
  })

  const activities = activitiesData?.activities || []
  const totalActivities = activitiesData?.total || 0
  const totalPages = Math.ceil(totalActivities / ITEMS_PER_PAGE)

  const filteredActivities = activities.filter((activity: ActivityEntry) => {
    const matchesFilter = filter === 'all' || activity.type === filter
    const matchesSearch =
      search === '' ||
      activity.action?.toLowerCase().includes(search.toLowerCase()) ||
      activity.description?.toLowerCase().includes(search.toLowerCase()) ||
      activity.location?.toLowerCase().includes(search.toLowerCase())
    return matchesFilter && matchesSearch
  })

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'login':
        return <LogIn className="h-4 w-4" aria-hidden="true" />
      case 'logout':
        return <LogOut className="h-4 w-4" aria-hidden="true" />
      case 'profile':
        return <User className="h-4 w-4" aria-hidden="true" />
      case 'security':
        return <Shield className="h-4 w-4" aria-hidden="true" />
      case 'device':
        return <Smartphone className="h-4 w-4" aria-hidden="true" />
      case 'session':
        return <Key className="h-4 w-4" aria-hidden="true" />
      default:
        return <Activity className="h-4 w-4" aria-hidden="true" />
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'success':
        return <Badge variant="success">Success</Badge>
      case 'failure':
        return <Badge variant="destructive">Failed</Badge>
      case 'blocked':
        return <Badge variant="warning">Blocked</Badge>
      default:
        return <Badge variant="secondary">{status}</Badge>
    }
  }

  const handleExport = () => {
    toast.success('Activity log export requested. You will receive an email when ready.')
  }

  if (error) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <AlertTriangle className="h-12 w-12 text-destructive mb-4" aria-hidden="true" />
          <CardTitle className="text-lg mb-2">Failed to Load Activity</CardTitle>
          <CardDescription>
            {error instanceof Error ? error.message : 'Please try again later'}
          </CardDescription>
          <Button 
            onClick={() => window.location.reload()} 
            variant="outline" 
            className="mt-4"
          >
            Retry
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Activity Log</h1>
        <p className="text-muted-foreground mt-2">
          Review your account activity and security events
        </p>
      </div>

      {/* Stats Overview */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">
              {isLoading ? '-' : totalActivities}
            </div>
            <p className="text-xs text-muted-foreground">Total Events</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold text-green-500">
              {isLoading ? '-' : activities.filter((a: ActivityEntry) => a.status === 'success').length}
            </div>
            <p className="text-xs text-muted-foreground">Successful</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold text-red-500">
              {isLoading ? '-' : activities.filter((a: ActivityEntry) => a.status === 'failure' || a.status === 'blocked').length}
            </div>
            <p className="text-xs text-muted-foreground">Failed/Blocked</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">
              {isLoading ? '-' : new Set(activities.map((a: ActivityEntry) => a.device)).size}
            </div>
            <p className="text-xs text-muted-foreground">Unique Devices</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <Input
                placeholder="Search activities..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                aria-label="Search activities"
              />
            </div>
            <div className="flex gap-2">
              <Select value={filter} onValueChange={setFilter}>
                <SelectTrigger className="w-[180px]" aria-label="Filter by type">
                  <Filter className="h-4 w-4 mr-2" aria-hidden="true" />
                  <SelectValue placeholder="Filter by type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Events</SelectItem>
                  <SelectItem value="login">Login</SelectItem>
                  <SelectItem value="profile">Profile</SelectItem>
                  <SelectItem value="security">Security</SelectItem>
                  <SelectItem value="device">Device</SelectItem>
                  <SelectItem value="session">Session</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" onClick={handleExport} aria-label="Export activity log">
                <Download className="h-4 w-4 mr-2" aria-hidden="true" />
                Export
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Activity List */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
          <CardDescription>
            {isLoading 
              ? 'Loading activities...' 
              : `Showing ${filteredActivities.length} of ${totalActivities} events`
            }
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" aria-hidden="true" />
            </div>
          ) : filteredActivities.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Activity className="h-12 w-12 mx-auto mb-3 opacity-50" aria-hidden="true" />
              <p>No activities found</p>
              <p className="text-sm">Try adjusting your filters</p>
            </div>
          ) : (
            <>
              <div className="space-y-4">
                {filteredActivities.map((activity: ActivityEntry) => (
                  <div
                    key={activity.id}
                    className="flex items-start gap-4 p-4 rounded-lg border hover:bg-muted/50 transition-colors"
                  >
                    <div
                      className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${
                        activity.status === 'success'
                          ? 'bg-green-100 text-green-600 dark:bg-green-900 dark:text-green-300'
                          : activity.status === 'failure'
                          ? 'bg-red-100 text-red-600 dark:bg-red-900 dark:text-red-300'
                          : 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900 dark:text-yellow-300'
                      }`}
                      aria-hidden="true"
                    >
                      {getActivityIcon(activity.type)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="font-medium">{activity.action}</p>
                        {getStatusBadge(activity.status)}
                        {activity.status === 'blocked' && (
                          <AlertTriangle className="h-4 w-4 text-yellow-500" aria-hidden="true" />
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground mt-0.5">
                        {activity.description}
                      </p>
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-xs text-muted-foreground">
                        <span>{formatDate(activity.timestamp)}</span>
                        <span aria-hidden="true">•</span>
                        <span>{activity.ip}</span>
                        <span aria-hidden="true">•</span>
                        <span>{activity.location}</span>
                        <span aria-hidden="true">•</span>
                        <span>{activity.device}</span>
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground shrink-0">
                      {formatRelativeTime(activity.timestamp)}
                    </div>
                  </div>
                ))}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between mt-6 pt-6 border-t">
                  <p className="text-sm text-muted-foreground">
                    Page {currentPage} of {totalPages}
                  </p>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                      disabled={currentPage === 1}
                      aria-label="Previous page"
                    >
                      <ChevronLeft className="h-4 w-4 mr-1" aria-hidden="true" />
                      Previous
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                      disabled={currentPage === totalPages}
                      aria-label="Next page"
                    >
                      Next
                      <ChevronRight className="h-4 w-4 ml-1" aria-hidden="true" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* Security Notice */}
      <div className="flex items-start gap-3 p-4 rounded-lg bg-muted">
        <Shield className="h-5 w-5 text-primary shrink-0 mt-0.5" aria-hidden="true" />
        <div>
          <p className="font-medium text-sm">Security Notice</p>
          <p className="text-sm text-muted-foreground mt-1">
            If you notice any suspicious activity that you don't recognize, immediately revoke the associated session and change your password. Contact support if you need assistance.
          </p>
        </div>
      </div>
    </div>
  )
}
