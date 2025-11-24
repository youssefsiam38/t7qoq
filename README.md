# t7qoq

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Enterprise-ready authentication & identity infrastructure for Go applications.**

t7qoq (pronounced "tahqeeq") provides a complete, drop-in authentication layer for Go applications using PostgreSQL and the Gin framework. It includes everything you need: user auth, multi-tenancy, RBAC, 2FA, feature flags, audit logging, and a React-based admin panel.

## Features

- **Complete Auth Flow** - Login, Register, Password Reset, Email Verification
- **JWT Tokens** - Access + Refresh tokens with secure session management
- **Multi-tenancy** - Organizations with members, roles, and invitations
- **RBAC** - Role-based access control with wildcard permissions (`admin:*`, `users:*`)
- **2FA** - TOTP-based two-factor authentication with backup codes
- **Feature Flags** - User/org targeting with percentage rollouts
- **Audit Logging** - Comprehensive activity tracking
- **Admin Panel** - React-based dashboard at `/_t7qoq`
- **Auth UI** - Pre-built login, register, reset pages with Tailwind CSS
- **Auto-migrations** - Database schema managed automatically

## Quick Start

### Installation

```bash
go get github.com/youssefsiam38/t7qoq
```

### Basic Usage

```go
package main

import (
    "os"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/youssefsiam38/t7qoq"
)

func main() {
    // Create database pool
    pool, _ := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))

    // Initialize t7qoq
    auth, err := t7qoq.New(t7qoq.Config{
        DB:        pool,
        JWTSecret: os.Getenv("JWT_SECRET"), // min 32 bytes
    })
    if err != nil {
        panic(err)
    }

    // Create Gin router
    router := gin.Default()

    // Register t7qoq routes
    auth.RegisterRoutes(router)

    // Your protected routes
    api := router.Group("/api")
    api.Use(auth.Middleware.RequireAuth())
    {
        api.GET("/profile", func(c *gin.Context) {
            user := t7qoq.GetUser(c)
            c.JSON(200, user)
        })
    }

    router.Run(":8080")
}
```

## Configuration

```go
t7qoq.Config{
    // Required
    DB:        pool,           // *pgxpool.Pool
    JWTSecret: "secret-key",   // min 32 bytes recommended

    // Application
    AppName: "My App",         // Default: "App"

    // Token expiry
    AccessTokenExpiry:  1 * time.Hour,   // Default: 1 hour
    RefreshTokenExpiry: 30 * 24 * time.Hour, // Default: 30 days

    // Route prefixes
    AuthRoutesPrefix:  "/auth",    // Default: /auth
    AdminRoutesPrefix: "/_t7qoq",  // Default: /_t7qoq

    // Feature toggles
    EnableRegistration:       true,  // Default: true
    RequireEmailVerification: true,  // Default: true
    Enable2FA:                true,  // Default: true
    EnableAdminPanel:         true,  // Default: true

    // Password policy
    PasswordMinLength:      8,     // Default: 8
    PasswordRequireUpper:   true,  // Default: true
    PasswordRequireLower:   true,  // Default: true
    PasswordRequireNumber:  true,  // Default: true
    PasswordRequireSpecial: false, // Default: false

    // Security
    MaxLoginAttempts:       5,   // Default: 5
    LockoutDurationMinutes: 30,  // Default: 30
    BCryptCost:             12,  // Default: 12

    // SMTP (optional)
    SMTP: &t7qoq.SMTPConfig{
        Host:       "smtp.example.com",
        Port:       587,
        Username:   "user",
        Password:   "pass",
        From:       "noreply@example.com",
        FromName:   "My App",
        Encryption: "tls",
    },
}
```

## Middlewares

| Middleware | Description |
|------------|-------------|
| `RequireAuth()` | Validates JWT access token, loads user into context |
| `OptionalAuth()` | Loads user if token present, continues if not |
| `RequireEmailVerified()` | Ensures user has verified their email |
| `RequireOrgContext()` | Loads organization from URL param (`:orgId` or `:orgSlug`), validates membership |
| `RequirePermission(perms...)` | Checks user has any of the specified permissions |
| `RequireAllPermissions(perms...)` | Checks user has all of the specified permissions |
| `RequireRole(roles...)` | Checks user has any of the specified roles (within org context) |
| `RequireAdmin()` | Checks for system admin role (`admin:*` permission) |
| `RequireFeature(key)` | Checks if feature flag is enabled for user/org |
| `RateLimit(opts)` | Rate limiting per IP/user |
| `CSRF()` | CSRF protection for forms |
| `AuditLog(action)` | Logs request to audit trail |

### Example Usage

```go
// Protected routes - require authentication
api := router.Group("/api")
api.Use(auth.Middleware.RequireAuth())

// Permission-based access control
api.DELETE("/users/:id",
    auth.Middleware.RequirePermission("users:delete"),
    deleteUserHandler)

// Organization routes - require membership
orgRoutes := api.Group("/orgs/:orgId")
orgRoutes.Use(auth.Middleware.RequireOrgContext())
{
    // Only org admins
    orgRoutes.PUT("/settings",
        auth.Middleware.RequireRole("Admin", "Owner"),
        updateSettingsHandler)
}

// Feature flag gating
api.GET("/beta-feature",
    auth.Middleware.RequireFeature("beta_feature"),
    betaHandler)
```

## Context Helpers

After middleware runs, you can access auth data from the Gin context:

```go
func myHandler(c *gin.Context) {
    // Get authenticated user
    user := t7qoq.GetUser(c)
    userID := t7qoq.GetUserID(c)

    // Get current organization (requires RequireOrgContext)
    org := t7qoq.GetOrganization(c)
    orgID := t7qoq.GetOrganizationID(c)

    // Get user's membership in current org
    membership := t7qoq.GetMembership(c)
    role := t7qoq.GetCurrentRole(c)

    // Get all permissions
    permissions := t7qoq.GetPermissions(c)

    // Check specific permission (supports wildcards)
    if t7qoq.HasPermission(c, "users:read") { ... }
    if t7qoq.HasAnyPermission(c, "users:read", "users:write") { ... }
    if t7qoq.HasAllPermissions(c, "users:read", "users:write") { ... }

    // Quick checks
    if t7qoq.IsAuthenticated(c) { ... }
    if t7qoq.IsAdmin(c) { ... }
    if t7qoq.IsEmailVerified(c) { ... }
    if t7qoq.IsMemberOfOrg(c) { ... }
}
```

## Auth Routes

t7qoq registers these routes automatically:

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/auth/login` | User login |
| POST | `/auth/register` | User registration |
| POST | `/auth/logout` | Logout (requires auth) |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/forgot-password` | Request password reset |
| POST | `/auth/reset-password` | Complete password reset |
| GET | `/auth/verify-email` | Verify email with token |
| POST | `/auth/2fa/verify` | Verify 2FA code during login |
| POST | `/auth/2fa/setup` | Setup 2FA (requires auth) |
| POST | `/auth/2fa/disable` | Disable 2FA (requires auth) |
| GET | `/auth/profile` | Get profile page (requires auth) |
| POST | `/auth/profile` | Update profile (requires auth) |
| POST | `/auth/change-password` | Change password (requires auth) |
| GET | `/auth/sessions` | List active sessions (requires auth) |
| DELETE | `/auth/sessions/:sessionId` | Revoke session (requires auth) |

### Organization Routes

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/auth/organizations` | List user's organizations |
| POST | `/auth/organizations` | Create organization |
| GET | `/auth/organizations/:orgId` | Get organization details |
| PUT | `/auth/organizations/:orgId` | Update organization |
| DELETE | `/auth/organizations/:orgId` | Delete organization |
| GET | `/auth/organizations/:orgId/members` | List members |
| POST | `/auth/organizations/:orgId/members/invite` | Invite member |
| DELETE | `/auth/organizations/:orgId/members/:memberId` | Remove member |
| GET | `/auth/invites` | List pending invites for current user |
| POST | `/auth/invites/accept` | Accept invitation |

## Admin Panel

Access the admin panel at `/_t7qoq` (requires Super Admin role).

**Features:**
- **Dashboard** - Stats overview, recent activity
- **Users** - User management, search, filters
- **Organizations** - Organization management
- **Permissions** - Create/manage permissions
- **Roles** - System & org roles, permission assignment
- **Sessions** - View and revoke active sessions
- **Feature Flags** - Manage feature flags and targeting
- **Audit Logs** - Search and filter activity logs
- **Settings** - Theme customization, SMTP configuration

The first user to register automatically becomes a Super Admin.

## Database

t7qoq uses PostgreSQL with automatic migrations. All tables are prefixed with `t7qoq_`:

- `t7qoq_users` - User accounts
- `t7qoq_refresh_tokens` - JWT refresh tokens/sessions
- `t7qoq_organizations` - Multi-tenant organizations
- `t7qoq_organization_members` - User-org memberships
- `t7qoq_organization_invites` - Pending invitations
- `t7qoq_permissions` - Permission definitions
- `t7qoq_roles` - System and org roles
- `t7qoq_role_permissions` - Role-permission mappings
- `t7qoq_user_system_roles` - User system role assignments
- `t7qoq_feature_flags` - Feature flag definitions
- `t7qoq_feature_flag_overrides` - User/org flag overrides
- `t7qoq_audit_logs` - Audit trail
- `t7qoq_settings` - Theme and app settings

Migrations run automatically when you call `t7qoq.New()`.

## Default Roles & Permissions

### System Roles
- **Super Admin** - Full system access (`admin:*`)
- **Admin** - Administrative access

### Organization Roles
- **Owner** - Full organization access
- **Admin** - Organization administration
- **Member** - Standard access
- **Viewer** - Read-only access

### Default Permissions
```
admin:*                  # Super admin wildcard
users:read, users:manage
organizations:read, organizations:manage
roles:read, roles:manage
permissions:read, permissions:manage
features:read, features:manage
audit:read
settings:manage
```

Custom permissions can be created via the admin panel and used in your code:

```go
// Admin creates "reports:generate" permission in /_t7qoq/permissions
// Developer uses it in code:
api.POST("/reports",
    auth.Middleware.RequirePermission("reports:generate"),
    generateReportHandler)
```

## Lifecycle Hooks

Customize behavior with hooks:

```go
auth, _ := t7qoq.New(t7qoq.Config{
    // ...
    Hooks: &t7qoq.Hooks{
        // User lifecycle
        OnUserCreated:     func(user *t7qoq.User) error { ... },
        OnUserUpdated:     func(user *t7qoq.User) error { ... },
        OnUserDeleted:     func(user *t7qoq.User) error { ... },

        // Auth events
        OnUserLoggedIn:    func(user *t7qoq.User, session *t7qoq.Session) error { ... },
        OnUserLoggedOut:   func(user *t7qoq.User, session *t7qoq.Session) error { ... },
        OnPasswordChanged: func(user *t7qoq.User) error { ... },
        OnEmailVerified:   func(user *t7qoq.User) error { ... },
        On2FAEnabled:      func(user *t7qoq.User) error { ... },
        On2FADisabled:     func(user *t7qoq.User) error { ... },

        // Organization events
        OnOrgCreated:    func(org *t7qoq.Organization) error { ... },
        OnUserJoinedOrg: func(user *t7qoq.User, org *t7qoq.Organization, role *t7qoq.Role) error { ... },
        OnUserLeftOrg:   func(user *t7qoq.User, org *t7qoq.Organization) error { ... },
    },
})
```

## Development

```bash
# Clone repository
git clone https://github.com/youssefsiam38/t7qoq.git
cd t7qoq

# Setup (starts PostgreSQL, installs deps)
make setup

# Start development server with hot reload
make dev

# Run tests
make test

# Run linter
make lint

# Build binary
make build

# Build with dashboard
make build-all
```

### Database Commands

```bash
make db-up       # Start PostgreSQL container
make db-down     # Stop PostgreSQL container
make db-restart  # Restart PostgreSQL
make db-shell    # Open psql shell
make db-migrate  # Run migrations manually
```

### Dashboard (Admin Panel)

```bash
make dashboard-install  # Install npm dependencies
make dashboard-dev      # Start React dev server
make dashboard-build    # Build for production (embeds into Go binary)
```

## Environment Variables

```bash
DATABASE_URL=postgres://user:pass@localhost:5432/dbname
JWT_SECRET=your-secret-key-min-32-bytes-long

# Optional SMTP
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user
SMTP_PASS=pass
SMTP_FROM=noreply@example.com
```

## License

MIT License - see [LICENSE](LICENSE) for details.
