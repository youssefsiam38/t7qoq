-- +goose Up
-- +goose StatementBegin
CREATE TABLE t7qoq_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    category VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_t7qoq_permissions_name ON t7qoq_permissions(name);
CREATE INDEX idx_t7qoq_permissions_category ON t7qoq_permissions(category);

-- Seed default permissions for t7qoq internal use
-- System-level permissions (for admin panel)
INSERT INTO t7qoq_permissions (name, description, category) VALUES
    ('admin:*', 'Full system access (Super Admin)', 'admin'),
    ('users:read', 'View users', 'users'),
    ('users:manage', 'Create, update, delete users', 'users'),
    ('organizations:read', 'View organizations', 'organizations'),
    ('organizations:manage', 'Create, update, delete organizations', 'organizations'),
    ('roles:read', 'View roles', 'roles'),
    ('roles:manage', 'Create, update, delete roles', 'roles'),
    ('permissions:read', 'View permissions', 'permissions'),
    ('permissions:manage', 'Create, update, delete permissions', 'permissions'),
    ('features:read', 'View feature flags', 'features'),
    ('features:manage', 'Create, update, delete feature flags', 'features'),
    ('audit:read', 'View audit logs', 'audit'),
    ('settings:manage', 'Manage system settings', 'settings'),
    -- Organization-level permissions (for use within orgs)
    ('org:*', 'Full organization access', 'org'),
    ('org:read', 'View organization details', 'org'),
    ('org:update', 'Update organization settings', 'org'),
    ('org:delete', 'Delete organization', 'org'),
    ('org:members', 'Manage organization members', 'org'),
    ('org:invite', 'Invite users to organization', 'org'),
    ('org:roles', 'Manage organization roles', 'org');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS t7qoq_permissions;
-- +goose StatementEnd
