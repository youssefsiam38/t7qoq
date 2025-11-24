-- +goose Up
-- +goose StatementBegin
CREATE TABLE t7qoq_organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES t7qoq_organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES t7qoq_users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES t7qoq_roles(id),

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'invited', 'suspended')),
    invited_by UUID REFERENCES t7qoq_users(id),
    invited_at TIMESTAMPTZ,
    accepted_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(organization_id, user_id)
);

CREATE TABLE t7qoq_organization_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES t7qoq_organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role_id UUID NOT NULL REFERENCES t7qoq_roles(id),
    token VARCHAR(255) NOT NULL UNIQUE,
    invited_by UUID NOT NULL REFERENCES t7qoq_users(id),

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'expired', 'cancelled')),
    expires_at TIMESTAMPTZ NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE t7qoq_user_system_roles (
    user_id UUID NOT NULL REFERENCES t7qoq_users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES t7qoq_roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_t7qoq_org_members_org_id ON t7qoq_organization_members(organization_id);
CREATE INDEX idx_t7qoq_org_members_user_id ON t7qoq_organization_members(user_id);
CREATE INDEX idx_t7qoq_org_invites_token ON t7qoq_organization_invites(token);
CREATE INDEX idx_t7qoq_org_invites_email ON t7qoq_organization_invites(email);
CREATE INDEX idx_t7qoq_org_invites_org_id ON t7qoq_organization_invites(organization_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS t7qoq_user_system_roles;
DROP TABLE IF EXISTS t7qoq_organization_invites;
DROP TABLE IF EXISTS t7qoq_organization_members;
-- +goose StatementEnd
