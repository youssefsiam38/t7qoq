-- +goose Up
-- +goose StatementBegin
CREATE TABLE t7qoq_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Settings scope
    scope VARCHAR(20) NOT NULL DEFAULT 'global' CHECK (scope IN ('global', 'organization')),
    organization_id UUID REFERENCES t7qoq_organizations(id) ON DELETE CASCADE,

    -- Theme settings
    theme JSONB DEFAULT '{
        "primaryColor": "#3B82F6",
        "secondaryColor": "#10B981",
        "accentColor": "#8B5CF6",
        "backgroundColor": "#FFFFFF",
        "textColor": "#1F2937",
        "logoUrl": null,
        "faviconUrl": null,
        "appName": "t7qoq"
    }',

    -- SMTP settings (global only)
    smtp_settings JSONB DEFAULT '{
        "host": "",
        "port": 587,
        "username": "",
        "password": "",
        "fromEmail": "",
        "fromName": "",
        "encryption": "tls"
    }',

    -- General settings
    general_settings JSONB DEFAULT '{
        "allowRegistration": true,
        "requireEmailVerification": true,
        "allowPasswordReset": true,
        "allowUserOrgCreation": true,
        "sessionLifetimeMinutes": 60,
        "refreshTokenLifetimeDays": 30,
        "maxLoginAttempts": 5,
        "lockoutDurationMinutes": 30,
        "twoFactorRequired": false
    }',

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(scope, organization_id)
);

-- Seed default global settings
INSERT INTO t7qoq_settings (scope) VALUES ('global');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS t7qoq_settings;
-- +goose StatementEnd
