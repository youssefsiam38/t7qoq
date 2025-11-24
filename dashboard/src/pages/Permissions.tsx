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
  PageLoading,
} from '@/components'
import { api } from '@/lib/api'
import { useApi } from '@/hooks/useApi'
import { PlusIcon } from '@heroicons/react/24/outline'

export function Permissions() {
  const [createModalOpen, setCreateModalOpen] = useState(false)

  const { data, loading, error, refetch } = useApi(() => api.getPermissions(), [])

  if (loading) {
    return <PageLoading />
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-red-600">Failed to load permissions: {error.message}</p>
        <Button onClick={refetch} className="mt-4">
          Retry
        </Button>
      </div>
    )
  }

  // Group permissions by category
  const groupedPermissions = data?.permissions?.reduce(
    (acc, perm) => {
      const category = perm.category || 'Other'
      if (!acc[category]) {
        acc[category] = []
      }
      acc[category].push(perm)
      return acc
    },
    {} as Record<string, typeof data.permissions>
  )

  return (
    <div>
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Permissions</h1>
          <p className="mt-1 text-sm text-gray-500">
            Manage system and organization permissions
          </p>
        </div>
        <Button onClick={() => setCreateModalOpen(true)}>
          <PlusIcon className="h-4 w-4 mr-2" />
          Add Permission
        </Button>
      </div>

      {groupedPermissions &&
        Object.entries(groupedPermissions).map(([category, permissions]) => (
          <Card key={category} className="mb-6">
            <CardHeader>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-medium text-gray-900 capitalize">
                  {category}
                </h3>
                <Badge variant="info">{permissions.length}</Badge>
              </div>
            </CardHeader>
            <CardBody className="p-0">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell header>Permission</TableCell>
                    <TableCell header>Description</TableCell>
                    <TableCell header>Created</TableCell>
                    <TableCell header>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {permissions.map((perm) => (
                    <TableRow key={perm.id}>
                      <TableCell>
                        <code className="text-sm bg-gray-100 px-2 py-1 rounded">
                          {perm.name}
                        </code>
                      </TableCell>
                      <TableCell>
                        <span className="text-gray-500">
                          {perm.description || '-'}
                        </span>
                      </TableCell>
                      <TableCell>
                        {new Date(perm.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        <Button variant="ghost" size="sm">
                          Edit
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardBody>
          </Card>
        ))}

      <CreatePermissionModal
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

interface CreatePermissionModalProps {
  open: boolean
  onClose: () => void
  onSuccess: () => void
}

function CreatePermissionModal({ open, onClose, onSuccess }: CreatePermissionModalProps) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    category: '',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      await api.createPermission(formData)
      onSuccess()
      setFormData({ name: '', description: '', category: '' })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create permission')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Create Permission">
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="p-3 bg-red-50 text-red-700 rounded-lg text-sm">
            {error}
          </div>
        )}
        <Input
          label="Name"
          required
          placeholder="e.g., users:read or billing:manage"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        />
        <Input
          label="Description"
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
        />
        <Input
          label="Category"
          placeholder="e.g., admin, org, billing"
          value={formData.category}
          onChange={(e) => setFormData({ ...formData, category: e.target.value })}
        />
        <div className="flex justify-end gap-3 mt-6">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={loading}>
            Create Permission
          </Button>
        </div>
      </form>
    </Modal>
  )
}
