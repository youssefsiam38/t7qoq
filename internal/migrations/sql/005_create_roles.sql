-- +goose Up
-- +goose StatementBegin
CREATE TABLE t7qoq_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Scope: 'system' for global roles, 'organization' for org-specific
    scope VARCHAR(20) NOT NULL DEFAULT 'organization' CHECK (scope IN ('system', 'organization')),
    organization_id UUID REFERENCES t7qoq_organizations(id) ON DELETE CASCADE,

    -- Built-in roles cannot be deleted
    is_system BOOLEAN NOT NULL DEFAULT FALSE,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique role name per organization (or globally for system roles)
    UNIQUE(name, organization_id)
);

CREATE TABLE t7qoq_role_permissions (
    role_id UUID NOT NULL REFERENCES t7qoq_roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES t7qoq_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_t7qoq_roles_scope ON t7qoq_roles(scope);
CREATE INDEX idx_t7qoq_roles_org_id ON t7qoq_roles(organization_id);

-- Seed system roles
INSERT INTO t7qoq_roles (name, description, scope, is_system) VALUES
    ('Super Admin', 'Full system access', 'system', true),
    ('Admin', 'Administrative access', 'system', true);

-- Seed organization role templates (will be copied when org is created)
INSERT INTO t7qoq_roles (name, description, scope, is_system) VALUES
    ('Owner', 'Organization owner with full access', 'organization', true),
    ('Admin', 'Organization administrator', 'organization', true),
    ('Member', 'Standard organization member', 'organization', true),
    ('Viewer', 'Read-only access', 'organization', true);

-- Assign admin:* permission to Super Admin role
INSERT INTO t7qoq_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM t7qoq_roles r, t7qoq_permissions p
WHERE r.name = 'Super Admin' AND r.scope = 'system' AND p.name = 'admin:*';

-- Assign org:* to Owner role (full org access)
INSERT INTO t7qoq_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM t7qoq_roles r, t7qoq_permissions p
WHERE r.name = 'Owner' AND r.scope = 'organization' AND r.organization_id IS NULL AND p.name = 'org:*';

-- Assign permissions to Admin role (org-level admin, not owner)
INSERT INTO t7qoq_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM t7qoq_roles r, t7qoq_permissions p
WHERE r.name = 'Admin' AND r.scope = 'organization' AND r.organization_id IS NULL
    AND p.name IN ('org:read', 'org:update', 'org:members', 'org:invite', 'org:roles');

-- Assign permissions to Member role
INSERT INTO t7qoq_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM t7qoq_roles r, t7qoq_permissions p
WHERE r.name = 'Member' AND r.scope = 'organization' AND r.organization_id IS NULL
    AND p.name IN ('org:read', 'org:invite');

-- Assign permissions to Viewer role
INSERT INTO t7qoq_role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM t7qoq_roles r, t7qoq_permissions p
WHERE r.name = 'Viewer' AND r.scope = 'organization' AND r.organization_id IS NULL
    AND p.name = 'org:read';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS t7qoq_role_permissions;
DROP TABLE IF EXISTS t7qoq_roles;
-- +goose StatementEnd
