export interface User {
  id: string
  email: string
  first_name?: string
  last_name?: string
  avatar_url?: string
  phone?: string
  email_verified: boolean
  two_factor_enabled: boolean
  status: 'active' | 'pending' | 'suspended' | 'deleted'
  last_login_at?: string
  created_at: string
  updated_at: string
}

export interface Organization {
  id: string
  name: string
  slug: string
  description?: string
  logo_url?: string
  status: 'active' | 'suspended' | 'deleted'
  plan?: string
  created_at: string
  updated_at: string
}

export interface OrgMember {
  id: string
  organization_id: string
  user_id: string
  user_email: string
  user_first_name?: string
  user_last_name?: string
  user_avatar_url?: string
  role_id: string
  role_name: string
  status: string
  created_at: string
}

export interface Role {
  id: string
  name: string
  description?: string
  scope: 'system' | 'organization'
  organization_id?: string
  is_system: boolean
  created_at: string
  updated_at: string
}

export interface Permission {
  id: string
  name: string
  description?: string
  category?: string
  created_at: string
}

export interface FeatureFlag {
  id: string
  key: string
  name: string
  description?: string
  flag_type: 'boolean' | 'percentage' | 'variant'
  is_enabled: boolean
  percentage?: number
  created_at: string
  updated_at: string
}

export interface AuditLog {
  id: string
  actor_id?: string
  actor_type: string
  actor_ip?: string
  actor_user_agent?: string
  organization_id?: string
  action: string
  resource_type: string
  resource_id?: string
  old_values?: Record<string, unknown>
  new_values?: Record<string, unknown>
  metadata?: Record<string, unknown>
  created_at: string
}

export interface Session {
  id: string
  user_id: string
  device_name?: string
  device_type?: string
  ip_address?: string
  user_agent?: string
  last_used_at?: string
  expires_at: string
  created_at: string
}

export interface Stats {
  total_users: number
  active_users: number
  total_organizations: number
  total_sessions: number
  users_this_month: number
  orgs_this_month: number
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  per_page: number
}
