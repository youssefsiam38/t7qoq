package t7qoq

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds the configuration for t7qoq
type Config struct {
	// Required: Database connection pool
	DB *pgxpool.Pool

	// Required: Secret key for JWT signing (min 32 bytes recommended)
	JWTSecret string

	// Application name (displayed in UI)
	AppName string // Default: "App"

	// Token expiry settings
	AccessTokenExpiry  time.Duration // Default: 1 hour
	RefreshTokenExpiry time.Duration // Default: 30 days

	// SMTP Configuration (optional - can be configured via admin panel)
	SMTP *SMTPConfig

	// Route prefixes
	AuthRoutesPrefix  string // Default: /auth
	AdminRoutesPrefix string // Default: /_t7qoq

	// Feature toggles
	EnableRegistration       bool // Default: true
	RequireEmailVerification bool // Default: true
	Enable2FA                bool // Default: true
	EnableAdminPanel         bool // Default: true

	// Password policy
	PasswordMinLength      int  // Default: 8
	PasswordRequireUpper   bool // Default: true
	PasswordRequireLower   bool // Default: true
	PasswordRequireNumber  bool // Default: true
	PasswordRequireSpecial bool // Default: false

	// Security
	MaxLoginAttempts       int // Default: 5
	LockoutDurationMinutes int // Default: 30
	BCryptCost             int // Default: 12

	// Hooks for custom logic
	Hooks *Hooks

	// Custom templates directory (optional - overrides embedded)
	CustomTemplatesDir string

	// Debug mode
	Debug bool
}

// SMTPConfig holds SMTP settings
type SMTPConfig struct {
	Host       string
	Port       int
	Username   string
	Password   string
	From       string
	FromName   string
	Encryption string // "tls", "ssl", "none"
}

// Hooks allows customizing behavior at various points
type Hooks struct {
	// User lifecycle
	BeforeUserCreate  func(email string) error
	OnUserCreated     func(user *User) error
	OnUserUpdated     func(user *User) error
	OnUserDeleted     func(user *User) error

	// Auth events
	OnUserLoggedIn    func(user *User, session *Session) error
	OnUserLoggedOut   func(user *User, session *Session) error
	OnPasswordChanged func(user *User) error
	OnEmailVerified   func(user *User) error
	On2FAEnabled      func(user *User) error
	On2FADisabled     func(user *User) error

	// Organization events
	OnOrgCreated    func(org *Organization) error
	OnUserJoinedOrg func(user *User, org *Organization, role *Role) error
	OnUserLeftOrg   func(user *User, org *Organization) error
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		AppName:                  "App",
		AccessTokenExpiry:        1 * time.Hour,
		RefreshTokenExpiry:       30 * 24 * time.Hour,
		AuthRoutesPrefix:         "/auth",
		AdminRoutesPrefix:        "/_t7qoq",
		EnableRegistration:       true,
		RequireEmailVerification: true,
		Enable2FA:                true,
		EnableAdminPanel:         true,
		PasswordMinLength:        8,
		PasswordRequireUpper:     true,
		PasswordRequireLower:     true,
		PasswordRequireNumber:    true,
		PasswordRequireSpecial:   false,
		MaxLoginAttempts:       5,
		LockoutDurationMinutes: 30,
		BCryptCost:             12,
	}
}

// Validate checks if the config is valid
func (c *Config) Validate() error {
	if c.DB == nil {
		return ErrDBRequired
	}
	if c.JWTSecret == "" {
		return ErrJWTSecretRequired
	}
	if len(c.JWTSecret) < 32 {
		return ErrJWTSecretTooShort
	}
	return nil
}

// applyDefaults fills in default values for empty fields
func (c *Config) applyDefaults() {
	defaults := DefaultConfig()

	if c.AppName == "" {
		c.AppName = defaults.AppName
	}
	if c.AccessTokenExpiry == 0 {
		c.AccessTokenExpiry = defaults.AccessTokenExpiry
	}
	if c.RefreshTokenExpiry == 0 {
		c.RefreshTokenExpiry = defaults.RefreshTokenExpiry
	}
	if c.AuthRoutesPrefix == "" {
		c.AuthRoutesPrefix = defaults.AuthRoutesPrefix
	}
	if c.AdminRoutesPrefix == "" {
		c.AdminRoutesPrefix = defaults.AdminRoutesPrefix
	}
	if c.PasswordMinLength == 0 {
		c.PasswordMinLength = defaults.PasswordMinLength
	}
	if c.MaxLoginAttempts == 0 {
		c.MaxLoginAttempts = defaults.MaxLoginAttempts
	}
	if c.LockoutDurationMinutes == 0 {
		c.LockoutDurationMinutes = defaults.LockoutDurationMinutes
	}
	if c.BCryptCost == 0 {
		c.BCryptCost = defaults.BCryptCost
	}
}
