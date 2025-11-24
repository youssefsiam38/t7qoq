-- +goose Up
-- +goose StatementBegin
CREATE TABLE t7qoq_feature_flags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Type: boolean, percentage, variant
    flag_type VARCHAR(20) NOT NULL DEFAULT 'boolean' CHECK (flag_type IN ('boolean', 'percentage', 'variant')),

    -- Default value (JSON)
    default_value JSONB NOT NULL DEFAULT 'false',

    -- Variants (for variant type)
    variants JSONB DEFAULT '[]',

    -- Percentage (for percentage type, 0-100)
    percentage INT DEFAULT 0 CHECK (percentage >= 0 AND percentage <= 100),

    -- Status
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-user overrides
CREATE TABLE t7qoq_feature_flag_users (
    feature_flag_id UUID NOT NULL REFERENCES t7qoq_feature_flags(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES t7qoq_users(id) ON DELETE CASCADE,
    value JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (feature_flag_id, user_id)
);

-- Per-organization overrides
CREATE TABLE t7qoq_feature_flag_organizations (
    feature_flag_id UUID NOT NULL REFERENCES t7qoq_feature_flags(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES t7qoq_organizations(id) ON DELETE CASCADE,
    value JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (feature_flag_id, organization_id)
);

CREATE INDEX idx_t7qoq_feature_flags_key ON t7qoq_feature_flags(key);
CREATE INDEX idx_t7qoq_feature_flags_enabled ON t7qoq_feature_flags(is_enabled);
CREATE INDEX idx_t7qoq_feature_flag_users_user_id ON t7qoq_feature_flag_users(user_id);
CREATE INDEX idx_t7qoq_feature_flag_orgs_org_id ON t7qoq_feature_flag_organizations(organization_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS t7qoq_feature_flag_organizations;
DROP TABLE IF EXISTS t7qoq_feature_flag_users;
DROP TABLE IF EXISTS t7qoq_feature_flags;
-- +goose StatementEnd
