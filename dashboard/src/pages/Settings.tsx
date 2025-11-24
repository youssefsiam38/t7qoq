import { useState } from 'react'
import { Card, CardBody, CardHeader, Button, Input, PageLoading } from '@/components'
import { api } from '@/lib/api'
import { useApi } from '@/hooks/useApi'

export function Settings() {
  const { loading, error, refetch } = useApi(() => api.getSettings(), [])

  const [theme, setTheme] = useState({
    primary_color: '#0ea5e9',
    logo_url: '',
    app_name: 't7qoq',
  })

  const [smtp, setSmtp] = useState({
    host: '',
    port: '587',
    username: '',
    password: '',
    from_email: '',
    from_name: '',
  })

  const [saving, setSaving] = useState(false)

  const saveTheme = async () => {
    setSaving(true)
    try {
      await api.updateSettings({ theme })
      refetch()
    } catch (err) {
      console.error('Failed to save theme:', err)
    } finally {
      setSaving(false)
    }
  }

  const saveSmtp = async () => {
    setSaving(true)
    try {
      await api.updateSettings({ smtp })
      refetch()
    } catch (err) {
      console.error('Failed to save SMTP settings:', err)
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <PageLoading />
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-red-600">Failed to load settings: {error.message}</p>
        <Button onClick={refetch} className="mt-4">
          Retry
        </Button>
      </div>
    )
  }

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="mt-1 text-sm text-gray-500">
          Configure your authentication system
        </p>
      </div>

      <div className="space-y-6">
        {/* Theme Settings */}
        <Card>
          <CardHeader>
            <h3 className="text-lg font-medium text-gray-900">Appearance</h3>
            <p className="text-sm text-gray-500">
              Customize the look and feel of the auth pages
            </p>
          </CardHeader>
          <CardBody>
            <div className="space-y-4 max-w-md">
              <Input
                label="Application Name"
                value={theme.app_name}
                onChange={(e) => setTheme({ ...theme, app_name: e.target.value })}
              />
              <Input
                label="Logo URL"
                type="url"
                placeholder="https://example.com/logo.png"
                value={theme.logo_url}
                onChange={(e) => setTheme({ ...theme, logo_url: e.target.value })}
              />
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Primary Color
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="color"
                    value={theme.primary_color}
                    onChange={(e) =>
                      setTheme({ ...theme, primary_color: e.target.value })
                    }
                    className="h-10 w-20 rounded border border-gray-300 cursor-pointer"
                  />
                  <Input
                    value={theme.primary_color}
                    onChange={(e) =>
                      setTheme({ ...theme, primary_color: e.target.value })
                    }
                    className="w-32"
                  />
                </div>
              </div>
              <Button onClick={saveTheme} loading={saving}>
                Save Appearance
              </Button>
            </div>
          </CardBody>
        </Card>

        {/* SMTP Settings */}
        <Card>
          <CardHeader>
            <h3 className="text-lg font-medium text-gray-900">Email Settings</h3>
            <p className="text-sm text-gray-500">
              Configure SMTP settings for sending emails
            </p>
          </CardHeader>
          <CardBody>
            <div className="space-y-4 max-w-md">
              <div className="grid grid-cols-2 gap-4">
                <Input
                  label="SMTP Host"
                  placeholder="smtp.example.com"
                  value={smtp.host}
                  onChange={(e) => setSmtp({ ...smtp, host: e.target.value })}
                />
                <Input
                  label="SMTP Port"
                  placeholder="587"
                  value={smtp.port}
                  onChange={(e) => setSmtp({ ...smtp, port: e.target.value })}
                />
              </div>
              <Input
                label="Username"
                value={smtp.username}
                onChange={(e) => setSmtp({ ...smtp, username: e.target.value })}
              />
              <Input
                label="Password"
                type="password"
                value={smtp.password}
                onChange={(e) => setSmtp({ ...smtp, password: e.target.value })}
              />
              <div className="grid grid-cols-2 gap-4">
                <Input
                  label="From Email"
                  type="email"
                  placeholder="noreply@example.com"
                  value={smtp.from_email}
                  onChange={(e) => setSmtp({ ...smtp, from_email: e.target.value })}
                />
                <Input
                  label="From Name"
                  placeholder="My App"
                  value={smtp.from_name}
                  onChange={(e) => setSmtp({ ...smtp, from_name: e.target.value })}
                />
              </div>
              <div className="flex gap-3">
                <Button onClick={saveSmtp} loading={saving}>
                  Save Email Settings
                </Button>
                <Button variant="secondary">Test Connection</Button>
              </div>
            </div>
          </CardBody>
        </Card>

        {/* Danger Zone */}
        <Card className="border-red-200">
          <CardHeader>
            <h3 className="text-lg font-medium text-red-600">Danger Zone</h3>
            <p className="text-sm text-gray-500">
              Irreversible and destructive actions
            </p>
          </CardHeader>
          <CardBody>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 border border-red-200 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">
                    Delete All Sessions
                  </p>
                  <p className="text-sm text-gray-500">
                    Revoke all active user sessions
                  </p>
                </div>
                <Button variant="danger" size="sm">
                  Delete All
                </Button>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
