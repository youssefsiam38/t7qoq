import { useState } from 'react'
import {
  Card,
  CardBody,
  CardHeader,
  Button,
  Select,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Badge,
  Modal,
  PageLoading,
} from '@/components'
import { api } from '@/lib/api'
import { useApi } from '@/hooks/useApi'
import type { AuditLog } from '@/types'

export function Audit() {
  const [actionFilter, setActionFilter] = useState('')
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null)

  const { data, loading, error, refetch } = useApi(
    () => api.getAuditLogs({ action: actionFilter || undefined }),
    [actionFilter]
  )

  const getActionBadge = (action: string) => {
    if (action.includes('create') || action.includes('register')) {
      return <Badge variant="success">{action}</Badge>
    }
    if (action.includes('delete') || action.includes('revoke')) {
      return <Badge variant="danger">{action}</Badge>
    }
    if (action.includes('update') || action.includes('change')) {
      return <Badge variant="warning">{action}</Badge>
    }
    return <Badge variant="default">{action}</Badge>
  }

  if (loading) {
    return <PageLoading />
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-red-600">Failed to load audit logs: {error.message}</p>
        <Button onClick={refetch} className="mt-4">
          Retry
        </Button>
      </div>
    )
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Audit Logs</h1>
        <p className="mt-1 text-sm text-gray-500">
          View all system activity and changes
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <Select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              options={[
                { value: '', label: 'All Actions' },
                { value: 'user.login', label: 'User Login' },
                { value: 'user.register', label: 'User Register' },
                { value: 'user.update', label: 'User Update' },
                { value: 'user.password_change', label: 'Password Change' },
                { value: 'org.create', label: 'Org Create' },
                { value: 'org.update', label: 'Org Update' },
                { value: 'org.member_add', label: 'Member Add' },
                { value: 'org.member_remove', label: 'Member Remove' },
              ]}
              className="w-48"
            />
            <Badge variant="info">{data?.total ?? 0} total</Badge>
          </div>
        </CardHeader>
        <CardBody className="p-0">
          <Table>
            <TableHead>
              <TableRow>
                <TableCell header>Timestamp</TableCell>
                <TableCell header>Actor</TableCell>
                <TableCell header>Action</TableCell>
                <TableCell header>Resource</TableCell>
                <TableCell header>IP Address</TableCell>
                <TableCell header>Details</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data?.logs && data.logs.length > 0 ? (
                data.logs.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>
                      {new Date(log.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <div>
                        <span className="font-medium text-gray-900">
                          {log.actor_type}
                        </span>
                        {log.actor_id && (
                          <p className="text-xs text-gray-500 truncate max-w-[100px]">
                            {log.actor_id}
                          </p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>{getActionBadge(log.action)}</TableCell>
                    <TableCell>
                      <span className="text-gray-900">{log.resource_type}</span>
                      {log.resource_id && (
                        <p className="text-xs text-gray-500 truncate max-w-[100px]">
                          {log.resource_id}
                        </p>
                      )}
                    </TableCell>
                    <TableCell>
                      <code className="text-xs bg-gray-100 px-2 py-1 rounded">
                        {log.actor_ip || 'Unknown'}
                      </code>
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setSelectedLog(log)}
                      >
                        View
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell className="text-center py-8" colSpan={6}>
                    No audit logs found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardBody>
      </Card>

      <Modal
        open={!!selectedLog}
        onClose={() => setSelectedLog(null)}
        title="Audit Log Details"
        size="lg"
      >
        {selectedLog && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-gray-500">
                  Timestamp
                </label>
                <p className="text-gray-900">
                  {new Date(selectedLog.created_at).toLocaleString()}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">
                  Action
                </label>
                <p className="text-gray-900">{selectedLog.action}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">
                  Actor Type
                </label>
                <p className="text-gray-900">{selectedLog.actor_type}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">
                  Actor ID
                </label>
                <p className="text-gray-900 break-all">
                  {selectedLog.actor_id || '-'}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">
                  IP Address
                </label>
                <p className="text-gray-900">{selectedLog.actor_ip || '-'}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-500">
                  Resource
                </label>
                <p className="text-gray-900">
                  {selectedLog.resource_type}
                  {selectedLog.resource_id && ` (${selectedLog.resource_id})`}
                </p>
              </div>
            </div>

            {selectedLog.old_values && Object.keys(selectedLog.old_values).length > 0 && (
              <div>
                <label className="text-sm font-medium text-gray-500">
                  Old Values
                </label>
                <pre className="mt-1 p-3 bg-gray-50 rounded-lg text-sm overflow-auto">
                  {JSON.stringify(selectedLog.old_values, null, 2)}
                </pre>
              </div>
            )}

            {selectedLog.new_values && Object.keys(selectedLog.new_values).length > 0 && (
              <div>
                <label className="text-sm font-medium text-gray-500">
                  New Values
                </label>
                <pre className="mt-1 p-3 bg-gray-50 rounded-lg text-sm overflow-auto">
                  {JSON.stringify(selectedLog.new_values, null, 2)}
                </pre>
              </div>
            )}

            {selectedLog.metadata && Object.keys(selectedLog.metadata).length > 0 && (
              <div>
                <label className="text-sm font-medium text-gray-500">
                  Metadata
                </label>
                <pre className="mt-1 p-3 bg-gray-50 rounded-lg text-sm overflow-auto">
                  {JSON.stringify(selectedLog.metadata, null, 2)}
                </pre>
              </div>
            )}

            {selectedLog.actor_user_agent && (
              <div>
                <label className="text-sm font-medium text-gray-500">
                  User Agent
                </label>
                <p className="text-gray-900 text-sm break-all">
                  {selectedLog.actor_user_agent}
                </p>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}
