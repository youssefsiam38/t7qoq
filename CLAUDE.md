# t7qoq - Enterprise Identity Infrastructure

## Project Overview

**t7qoq** is a stateful, opinionated authentication layer package for Go applications. It provides enterprise-ready identity infrastructure out of the box for any project using:

- **PostgreSQL** (database)
- **pgx** (Go PostgreSQL driver)
- **Gin** (HTTP framework)

## Key Features

### Authentication
- Email/Password authentication with JWT tokens (stateless)
- 1-hour access tokens, 30-day refresh tokens
- Two-Factor Authentication (TOTP)
- Email verification flow
- Password reset flow

### Multi-tenancy
- Organizations with membership management
- Users can belong to multiple organizations
- Per-organization roles and permissions
- Invitation system

### Permissions System
- **Generic/Dynamic permissions** - Admins create permissions via admin panel
- Developers use permissions in code with `RequirePermission("permission:name")`
- First registered user becomes Super Admin

### Admin Panel
- React SPA served at `/_t7qoq` endpoint
- User management, organizations, roles, permissions
- Feature flags management
- Audit logs viewer
- Theming (colors, logo URLs)

### Feature Flags
- Per-user and per-organization targeting
- Boolean, percentage, and variant types
- Accessible via `t7qoq.IsFeatureEnabled(c, "flag_key")`

## Project Structure

```
t7qoq/
├── dashboard/           # React SPA Admin Panel
├── templates/           # Embedded Auth UI (HTML + Tailwind)
├── static/css/          # Pre-compiled Tailwind
├── internal/
│   ├── database/        # DB connection & queries
│   ├── migrations/sql/  # SQL migration files (t7qoq_ prefix)
│   ├── jwt/             # JWT service
│   ├── email/           # SMTP service
│   ├── crypto/          # Password hashing
│   └── audit/           # Audit logging
├── pkg/t7qoq/
│   ├── types.go         # Public types
│   └── context.go       # Context helpers
├── middleware/          # All middlewares
├── handlers/            # HTTP handlers
├── t7qoq.go             # Main entry point
├── config.go            # Configuration
└── routes.go            # Route registration
```

## Database Tables (t7qoq_ prefix)

All tables are prefixed with `t7qoq_` and migrations run automatically on init:

1. `t7qoq_users` - User accounts
2. `t7qoq_refresh_tokens` - JWT refresh tokens
3. `t7qoq_organizations` - Multi-tenant organizations
4. `t7qoq_organization_members` - User-org membership
5. `t7qoq_organization_invites` - Pending invitations
6. `t7qoq_permissions` - Generic permissions
7. `t7qoq_roles` - System and org-level roles
8. `t7qoq_role_permissions` - Role-permission mappings
9. `t7qoq_user_system_roles` - User system role assignments
10. `t7qoq_feature_flags` - Feature flag definitions
11. `t7qoq_feature_flag_users` - Per-user flag overrides
12. `t7qoq_feature_flag_organizations` - Per-org flag overrides
13. `t7qoq_audit_logs` - Audit trail
14. `t7qoq_settings` - Theme and app settings

## Usage Pattern

```go
// Initialize
auth, err := t7qoq.New(t7qoq.Config{
    DB:        pool,
    JWTSecret: "secret",
})

// Register routes
auth.RegisterRoutes(router)

// Use middlewares
api.Use(auth.Middleware.RequireAuth())
route.DELETE("/users/:id", auth.Middleware.RequirePermission("users:delete"), handler)

// In handlers - use context (user/org populated by middleware)
user := t7qoq.GetUser(c)
org := t7qoq.GetOrganization(c)
enabled := t7qoq.IsFeatureEnabled(c, "beta_feature")

// ByID variants for checking other users
enabled := t7qoq.IsFeatureEnabledByID(c, "beta_feature", userID, orgID)
```

## Development Commands

```bash
make dev              # Hot reload development
make db-up            # Start PostgreSQL
make db-migrate       # Run migrations
make dashboard-dev    # React dev server
make dashboard-build  # Build React for embedding
make test             # Run tests
make release-local    # Test GoReleaser
```

## Configuration Decisions

- **First Admin**: First registered user becomes Super Admin
- **Organization Creation**: Configurable (default: users can create)
- **JWT Expiry**: 1 hour access, 30 days refresh
- **No API Keys**: Not required for this project
- **No Webhooks**: Not required for this project
