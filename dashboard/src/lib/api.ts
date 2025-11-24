const API_BASE = '/_t7qoq/api'

interface FetchOptions extends RequestInit {
  params?: Record<string, string | number | undefined>
}

class ApiError extends Error {
  status: number
  code?: string

  constructor(message: string, status: number, code?: string) {
    super(message)
    this.status = status
    this.code = code
    this.name = 'ApiError'
  }
}

async function fetchApi<T>(endpoint: string, options: FetchOptions = {}): Promise<T> {
  const { params, ...init } = options

  let url = `${API_BASE}${endpoint}`
  if (params) {
    const searchParams = new URLSearchParams()
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        searchParams.append(key, String(value))
      }
    })
    const queryString = searchParams.toString()
    if (queryString) {
      url += `?${queryString}`
    }
  }

  const token = localStorage.getItem('t7qoq_admin_token')

  const response = await fetch(url, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new ApiError(error.error || 'Request failed', response.status, error.code)
  }

  return response.json()
}

export const api = {
  // Stats
  getStats: () => fetchApi<{ total_users: number; active_users: number; total_organizations: number; total_sessions: number }>('/stats'),

  // Users
  getUsers: (params?: { page?: number; per_page?: number; search?: string; status?: string }) =>
    fetchApi<{ users: import('../types').User[]; total: number }>('/users', { params }),
  getUser: (id: string) => fetchApi<import('../types').User>(`/users/${id}`),
  createUser: (data: { email: string; password: string; first_name?: string; last_name?: string }) =>
    fetchApi<import('../types').User>('/users', { method: 'POST', body: JSON.stringify(data) }),
  updateUser: (id: string, data: Partial<import('../types').User>) =>
    fetchApi<import('../types').User>(`/users/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteUser: (id: string) => fetchApi<void>(`/users/${id}`, { method: 'DELETE' }),

  // Organizations
  getOrganizations: (params?: { page?: number; per_page?: number; search?: string }) =>
    fetchApi<{ organizations: import('../types').Organization[]; total: number }>('/organizations', { params }),
  getOrganization: (id: string) => fetchApi<import('../types').Organization>(`/organizations/${id}`),
  createOrganization: (data: { name: string; slug: string; description?: string }) =>
    fetchApi<import('../types').Organization>('/organizations', { method: 'POST', body: JSON.stringify(data) }),
  updateOrganization: (id: string, data: Partial<import('../types').Organization>) =>
    fetchApi<import('../types').Organization>(`/organizations/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteOrganization: (id: string) => fetchApi<void>(`/organizations/${id}`, { method: 'DELETE' }),
  getOrgMembers: (orgId: string) =>
    fetchApi<{ members: import('../types').OrgMember[] }>(`/organizations/${orgId}/members`),
  addOrgMember: (orgId: string, data: { user_id: string; role_id: string }) =>
    fetchApi<import('../types').OrgMember>(`/organizations/${orgId}/members`, { method: 'POST', body: JSON.stringify(data) }),
  removeOrgMember: (orgId: string, userId: string) =>
    fetchApi<void>(`/organizations/${orgId}/members/${userId}`, { method: 'DELETE' }),

  // Roles
  getRoles: (params?: { scope?: string }) =>
    fetchApi<{ roles: import('../types').Role[] }>('/roles', { params }),
  getRole: (id: string) => fetchApi<import('../types').Role>(`/roles/${id}`),
  createRole: (data: { name: string; description?: string; scope: string; permissions?: string[] }) =>
    fetchApi<import('../types').Role>('/roles', { method: 'POST', body: JSON.stringify(data) }),
  updateRole: (id: string, data: Partial<import('../types').Role> & { permissions?: string[] }) =>
    fetchApi<import('../types').Role>(`/roles/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteRole: (id: string) => fetchApi<void>(`/roles/${id}`, { method: 'DELETE' }),

  // Permissions
  getPermissions: () => fetchApi<{ permissions: import('../types').Permission[] }>('/permissions'),
  createPermission: (data: { name: string; description?: string; category?: string }) =>
    fetchApi<import('../types').Permission>('/permissions', { method: 'POST', body: JSON.stringify(data) }),
  updatePermission: (id: string, data: Partial<import('../types').Permission>) =>
    fetchApi<import('../types').Permission>(`/permissions/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deletePermission: (id: string) => fetchApi<void>(`/permissions/${id}`, { method: 'DELETE' }),

  // Feature Flags
  getFeatures: () => fetchApi<{ features: import('../types').FeatureFlag[] }>('/features'),
  getFeature: (id: string) => fetchApi<import('../types').FeatureFlag>(`/features/${id}`),
  createFeature: (data: { key: string; name: string; description?: string; flag_type: string }) =>
    fetchApi<import('../types').FeatureFlag>('/features', { method: 'POST', body: JSON.stringify(data) }),
  updateFeature: (id: string, data: Partial<import('../types').FeatureFlag>) =>
    fetchApi<import('../types').FeatureFlag>(`/features/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteFeature: (id: string) => fetchApi<void>(`/features/${id}`, { method: 'DELETE' }),

  // Audit Logs
  getAuditLogs: (params?: { page?: number; per_page?: number; action?: string; resource_type?: string }) =>
    fetchApi<{ logs: import('../types').AuditLog[]; total: number }>('/audit', { params }),
  getAuditLog: (id: string) => fetchApi<import('../types').AuditLog>(`/audit/${id}`),

  // Sessions
  getSessions: (params?: { page?: number; per_page?: number; user_id?: string }) =>
    fetchApi<{ sessions: import('../types').Session[]; total: number }>('/sessions', { params }),
  revokeSession: (id: string) => fetchApi<void>(`/sessions/${id}`, { method: 'DELETE' }),

  // Settings
  getSettings: () => fetchApi<{ theme: Record<string, unknown>; smtp: Record<string, unknown>; general: Record<string, unknown> }>('/settings'),
  updateSettings: (data: { theme?: Record<string, unknown>; smtp?: Record<string, unknown>; general?: Record<string, unknown> }) =>
    fetchApi<void>('/settings', { method: 'PUT', body: JSON.stringify(data) }),
}

export { ApiError }
