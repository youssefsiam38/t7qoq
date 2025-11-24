import { useState } from 'react'
import {
  Card,
  CardBody,
  CardHeader,
  Button,
  Input,
  Table,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  Badge,
  Modal,
  Select,
  PageLoading,
} from '@/components'
import { api } from '@/lib/api'
import { useApi } from '@/hooks/useApi'
import { PlusIcon } from '@heroicons/react/24/outline'

export function Roles() {
  const [createModalOpen, setCreateModalOpen] = useState(false)

  const { data, loading, error, refetch } = useApi(() => api.getRoles(), [])

  if (loading) {
    return <PageLoading />
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-red-600">Failed to load roles: {error.message}</p>
        <Button onClick={refetch} className="mt-4">
          Retry
        </Button>
      </div>
    )
  }

  return (
    <div>
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Roles</h1>
          <p className="mt-1 text-sm text-gray-500">
            Manage roles and their permissions
          </p>
        </div>
        <Button onClick={() => setCreateModalOpen(true)}>
          <PlusIcon className="h-4 w-4 mr-2" />
          Add Role
        </Button>
      </div>

      <Card>
        <CardHeader>
          <h3 className="text-lg font-medium text-gray-900">All Roles</h3>
        </CardHeader>
        <CardBody className="p-0">
          <Table>
            <TableHead>
              <TableRow>
                <TableCell header>Name</TableCell>
                <TableCell header>Description</TableCell>
                <TableCell header>Scope</TableCell>
                <TableCell header>Type</TableCell>
                <TableCell header>Created</TableCell>
                <TableCell header>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data?.roles && data.roles.length > 0 ? (
                data.roles.map((role) => (
                  <TableRow key={role.id}>
                    <TableCell>
                      <span className="font-medium text-gray-900">{role.name}</span>
                    </TableCell>
                    <TableCell>
                      <span className="text-gray-500">
                        {role.description || '-'}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={role.scope === 'system' ? 'info' : 'default'}
                      >
                        {role.scope}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {role.is_system ? (
                        <Badge variant="warning">System</Badge>
                      ) : (
                        <Badge variant="default">Custom</Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {new Date(role.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      {!role.is_system && (
                        <Button variant="ghost" size="sm">
                          Edit
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell className="text-center py-8" colSpan={6}>
                    No roles found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardBody>
      </Card>

      <CreateRoleModal
        open={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
        onSuccess={() => {
          setCreateModalOpen(false)
          refetch()
        }}
      />
    </div>
  )
}

interface CreateRoleModalProps {
  open: boolean
  onClose: () => void
  onSuccess: () => void
}

function CreateRoleModal({ open, onClose, onSuccess }: CreateRoleModalProps) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    scope: 'organization',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      await api.createRole(formData)
      onSuccess()
      setFormData({ name: '', description: '', scope: 'organization' })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create role')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Create Role">
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="p-3 bg-red-50 text-red-700 rounded-lg text-sm">
            {error}
          </div>
        )}
        <Input
          label="Name"
          required
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        />
        <Input
          label="Description"
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
        />
        <Select
          label="Scope"
          value={formData.scope}
          onChange={(e) => setFormData({ ...formData, scope: e.target.value })}
          options={[
            { value: 'organization', label: 'Organization' },
            { value: 'system', label: 'System' },
          ]}
        />
        <div className="flex justify-end gap-3 mt-6">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={loading}>
            Create Role
          </Button>
        </div>
      </form>
    </Modal>
  )
}
