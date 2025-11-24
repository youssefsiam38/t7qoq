import {
  Card,
  CardBody,
  CardHeader,
  Button,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Badge,
  PageLoading,
} from '@/components'
import { api } from '@/lib/api'
import { useApi } from '@/hooks/useApi'

export function Sessions() {
  const { data, loading, error, refetch } = useApi(() => api.getSessions(), [])

  const revokeSession = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this session?')) return

    try {
      await api.revokeSession(id)
      refetch()
    } catch (err) {
      console.error('Failed to revoke session:', err)
    }
  }

  if (loading) {
    return <PageLoading />
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-red-600">Failed to load sessions: {error.message}</p>
        <Button onClick={refetch} className="mt-4">
          Retry
        </Button>
      </div>
    )
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Sessions</h1>
        <p className="mt-1 text-sm text-gray-500">
          View and manage active user sessions
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-medium text-gray-900">Active Sessions</h3>
            <Badge variant="info">{data?.total ?? 0} total</Badge>
          </div>
        </CardHeader>
        <CardBody className="p-0">
          <Table>
            <TableHead>
              <TableRow>
                <TableCell header>Device</TableCell>
                <TableCell header>IP Address</TableCell>
                <TableCell header>Last Used</TableCell>
                <TableCell header>Expires</TableCell>
                <TableCell header>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data?.sessions && data.sessions.length > 0 ? (
                data.sessions.map((session) => (
                  <TableRow key={session.id}>
                    <TableCell>
                      <div>
                        <span className="font-medium text-gray-900">
                          {session.device_name || 'Unknown Device'}
                        </span>
                        <p className="text-sm text-gray-500">
                          {session.device_type || 'Unknown'}
                        </p>
                      </div>
                    </TableCell>
                    <TableCell>
                      <code className="text-sm bg-gray-100 px-2 py-1 rounded">
                        {session.ip_address || 'Unknown'}
                      </code>
                    </TableCell>
                    <TableCell>
                      {session.last_used_at
                        ? new Date(session.last_used_at).toLocaleString()
                        : 'Never'}
                    </TableCell>
                    <TableCell>
                      {new Date(session.expires_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => revokeSession(session.id)}
                      >
                        Revoke
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell className="text-center py-8" colSpan={5}>
                    No active sessions
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardBody>
      </Card>
    </div>
  )
}
