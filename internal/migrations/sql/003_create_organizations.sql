-- +goose Up
-- +goose StatementBegin
CREATE TABLE t7qoq_organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    logo_url TEXT,

    -- Settings
    settings JSONB DEFAULT '{}',

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),

    -- Billing (optional)
    plan VARCHAR(50) DEFAULT 'free',
    trial_ends_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_t7qoq_organizations_slug ON t7qoq_organizations(slug);
CREATE INDEX idx_t7qoq_organizations_status ON t7qoq_organizations(status);
CREATE INDEX idx_t7qoq_organizations_deleted_at ON t7qoq_organizations(deleted_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS t7qoq_organizations;
-- +goose StatementEnd
