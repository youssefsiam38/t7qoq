import { Card, CardBody, PageLoading } from '@/components'
import { api } from '@/lib/api'
import { useApi } from '@/hooks/useApi'
import {
  UsersIcon,
  BuildingOfficeIcon,
  ComputerDesktopIcon,
  UserGroupIcon,
} from '@heroicons/react/24/outline'

const stats = [
  { name: 'Total Users', key: 'total_users', icon: UsersIcon },
  { name: 'Active Users', key: 'active_users', icon: UserGroupIcon },
  { name: 'Organizations', key: 'total_organizations', icon: BuildingOfficeIcon },
  { name: 'Active Sessions', key: 'total_sessions', icon: ComputerDesktopIcon },
]

export function Dashboard() {
  const { data, loading, error } = useApi(() => api.getStats(), [])

  if (loading) {
    return <PageLoading />
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-red-600">Failed to load stats: {error.message}</p>
      </div>
    )
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-1 text-sm text-gray-500">
          Overview of your authentication system
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <Card key={stat.key}>
            <CardBody>
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <stat.icon className="h-8 w-8 text-primary-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-500">{stat.name}</p>
                  <p className="text-2xl font-semibold text-gray-900">
                    {data?.[stat.key as keyof typeof data] ?? 0}
                  </p>
                </div>
              </div>
            </CardBody>
          </Card>
        ))}
      </div>

      <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardBody>
            <h3 className="text-lg font-medium text-gray-900 mb-4">Quick Actions</h3>
            <div className="space-y-3">
              <a
                href="/_t7qoq/users"
                className="block p-3 rounded-lg border border-gray-200 hover:border-primary-500 hover:bg-primary-50 transition-colors"
              >
                <p className="font-medium text-gray-900">Manage Users</p>
                <p className="text-sm text-gray-500">View and manage user accounts</p>
              </a>
              <a
                href="/_t7qoq/organizations"
                className="block p-3 rounded-lg border border-gray-200 hover:border-primary-500 hover:bg-primary-50 transition-colors"
              >
                <p className="font-medium text-gray-900">Manage Organizations</p>
                <p className="text-sm text-gray-500">View and manage organizations</p>
              </a>
              <a
                href="/_t7qoq/features"
                className="block p-3 rounded-lg border border-gray-200 hover:border-primary-500 hover:bg-primary-50 transition-colors"
              >
                <p className="font-medium text-gray-900">Feature Flags</p>
                <p className="text-sm text-gray-500">Control feature availability</p>
              </a>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <h3 className="text-lg font-medium text-gray-900 mb-4">System Status</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Authentication</span>
                <span className="flex items-center text-sm text-green-600">
                  <span className="h-2 w-2 rounded-full bg-green-500 mr-2" />
                  Active
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Email Service</span>
                <span className="flex items-center text-sm text-green-600">
                  <span className="h-2 w-2 rounded-full bg-green-500 mr-2" />
                  Connected
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Database</span>
                <span className="flex items-center text-sm text-green-600">
                  <span className="h-2 w-2 rounded-full bg-green-500 mr-2" />
                  Healthy
                </span>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
