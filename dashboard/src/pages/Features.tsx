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
import { Switch } from '@headlessui/react'
import { clsx } from 'clsx'

export function Features() {
  const [createModalOpen, setCreateModalOpen] = useState(false)

  const { data, loading, error, refetch } = useApi(() => api.getFeatures(), [])

  const toggleFeature = async (id: string, currentState: boolean) => {
    try {
      await api.updateFeature(id, { is_enabled: !currentState })
      refetch()
    } catch (err) {
      console.error('Failed to toggle feature:', err)
    }
  }

  if (loading) {
    return <PageLoading />
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-red-600">Failed to load features: {error.message}</p>
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
          <h1 className="text-2xl font-bold text-gray-900">Feature Flags</h1>
          <p className="mt-1 text-sm text-gray-500">
            Control feature availability across your application
          </p>
        </div>
        <Button onClick={() => setCreateModalOpen(true)}>
          <PlusIcon className="h-4 w-4 mr-2" />
          Add Feature
        </Button>
      </div>

      <Card>
        <CardHeader>
          <h3 className="text-lg font-medium text-gray-900">All Features</h3>
        </CardHeader>
        <CardBody className="p-0">
          <Table>
            <TableHead>
              <TableRow>
                <TableCell header>Feature</TableCell>
                <TableCell header>Key</TableCell>
                <TableCell header>Type</TableCell>
                <TableCell header>Status</TableCell>
                <TableCell header>Created</TableCell>
                <TableCell header>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data?.features && data.features.length > 0 ? (
                data.features.map((feature) => (
                  <TableRow key={feature.id}>
                    <TableCell>
                      <div>
                        <span className="font-medium text-gray-900">
                          {feature.name}
                        </span>
                        {feature.description && (
                          <p className="text-sm text-gray-500">
                            {feature.description}
                          </p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <code className="text-sm bg-gray-100 px-2 py-1 rounded">
                        {feature.key}
                      </code>
                    </TableCell>
                    <TableCell>
                      <Badge variant="default">{feature.flag_type}</Badge>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={feature.is_enabled}
                        onChange={() => toggleFeature(feature.id, feature.is_enabled)}
                        className={clsx(
                          feature.is_enabled ? 'bg-primary-600' : 'bg-gray-200',
                          'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2'
                        )}
                      >
                        <span
                          className={clsx(
                            feature.is_enabled ? 'translate-x-5' : 'translate-x-0',
                            'pointer-events-none relative inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out'
                          )}
                        />
                      </Switch>
                    </TableCell>
                    <TableCell>
                      {new Date(feature.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <Button variant="ghost" size="sm">
                        Edit
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell className="text-center py-8" colSpan={6}>
                    No features found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardBody>
      </Card>

      <CreateFeatureModal
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

interface CreateFeatureModalProps {
  open: boolean
  onClose: () => void
  onSuccess: () => void
}

function CreateFeatureModal({ open, onClose, onSuccess }: CreateFeatureModalProps) {
  const [formData, setFormData] = useState({
    key: '',
    name: '',
    description: '',
    flag_type: 'boolean',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      await api.createFeature(formData)
      onSuccess()
      setFormData({ key: '', name: '', description: '', flag_type: 'boolean' })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create feature')
    } finally {
      setLoading(false)
    }
  }

  const generateKey = (name: string) => {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '')
  }

  return (
    <Modal open={open} onClose={onClose} title="Create Feature Flag">
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
          onChange={(e) =>
            setFormData({
              ...formData,
              name: e.target.value,
              key: generateKey(e.target.value),
            })
          }
        />
        <Input
          label="Key"
          required
          value={formData.key}
          onChange={(e) => setFormData({ ...formData, key: e.target.value })}
        />
        <Input
          label="Description"
          value={formData.description}
          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
        />
        <Select
          label="Type"
          value={formData.flag_type}
          onChange={(e) => setFormData({ ...formData, flag_type: e.target.value })}
          options={[
            { value: 'boolean', label: 'Boolean' },
            { value: 'percentage', label: 'Percentage Rollout' },
            { value: 'variant', label: 'Variant' },
          ]}
        />
        <div className="flex justify-end gap-3 mt-6">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={loading}>
            Create Feature
          </Button>
        </div>
      </form>
    </Modal>
  )
}
