-- +goose Up
-- +goose StatementBegin
CREATE TABLE t7qoq_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Actor (who performed the action)
    actor_id UUID REFERENCES t7qoq_users(id) ON DELETE SET NULL,
    actor_type VARCHAR(20) NOT NULL CHECK (actor_type IN ('user', 'system')),
    actor_ip VARCHAR(45),
    actor_user_agent TEXT,

    -- Context
    organization_id UUID REFERENCES t7qoq_organizations(id) ON DELETE SET NULL,

    -- Action
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,

    -- Details
    old_values JSONB,
    new_values JSONB,
    metadata JSONB DEFAULT '{}',

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_t7qoq_audit_logs_actor_id ON t7qoq_audit_logs(actor_id);
CREATE INDEX idx_t7qoq_audit_logs_org_id ON t7qoq_audit_logs(organization_id);
CREATE INDEX idx_t7qoq_audit_logs_action ON t7qoq_audit_logs(action);
CREATE INDEX idx_t7qoq_audit_logs_resource ON t7qoq_audit_logs(resource_type, resource_id);
CREATE INDEX idx_t7qoq_audit_logs_created_at ON t7qoq_audit_logs(created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS t7qoq_audit_logs;
-- +goose StatementEnd
