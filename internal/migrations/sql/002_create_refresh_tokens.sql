-- +goose Up
-- +goose StatementBegin
CREATE TABLE t7qoq_refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES t7qoq_users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,

    -- Device info
    device_name VARCHAR(255),
    device_type VARCHAR(50),
    user_agent TEXT,
    ip_address VARCHAR(45),

    -- Status
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(100),

    -- Expiry
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_t7qoq_refresh_tokens_user_id ON t7qoq_refresh_tokens(user_id);
CREATE INDEX idx_t7qoq_refresh_tokens_token_hash ON t7qoq_refresh_tokens(token_hash);
CREATE INDEX idx_t7qoq_refresh_tokens_expires_at ON t7qoq_refresh_tokens(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS t7qoq_refresh_tokens;
-- +goose StatementEnd
