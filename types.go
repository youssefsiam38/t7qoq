package t7qoq

// Types for the t7qoq authentication layer

import (
	"time"

	"github.com/google/uuid"
)

// UserStatus represents the status of a user
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusInactive  UserStatus = "inactive"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusPending   UserStatus = "pending"
)

// User represents an authenticated user
type User struct {
	ID               uuid.UUID  `json:"id"`
	Email            string     `json:"email"`
	EmailVerified    bool       `json:"email_verified"`
	FirstName        string     `json:"first_name,omitempty"`
	LastName         string     `json:"last_name,omitempty"`
	AvatarURL        string     `json:"avatar_url,omitempty"`
	Phone            string     `json:"phone,omitempty"`
	TwoFactorEnabled bool       `json:"two_factor_enabled"`
	Status           UserStatus `json:"status"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	Metadata         JSONMap    `json:"metadata,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// FullName returns the user's full name
func (u *User) FullName() string {
	if u.FirstName == "" && u.LastName == "" {
		return u.Email
	}
	if u.FirstName == "" {
		return u.LastName
	}
	if u.LastName == "" {
		return u.FirstName
	}
	return u.FirstName + " " + u.LastName
}

// OrgStatus represents the status of an organization
type OrgStatus string

const (
	OrgStatusActive    OrgStatus = "active"
	OrgStatusInactive  OrgStatus = "inactive"
	OrgStatusSuspended OrgStatus = "suspended"
)

// Organization represents a multi-tenant organization
type Organization struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description,omitempty"`
	LogoURL     string    `json:"logo_url,omitempty"`
	Status      OrgStatus `json:"status"`
	Plan        string    `json:"plan,omitempty"`
	Settings    JSONMap   `json:"settings,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// OrganizationMember represents a user's membership in an organization
type OrganizationMember struct {
	ID             uuid.UUID     `json:"id"`
	OrganizationID uuid.UUID     `json:"organization_id"`
	UserID         uuid.UUID     `json:"user_id"`
	RoleID         uuid.UUID     `json:"role_id"`
	Status         string        `json:"status"`
	User           *User         `json:"user,omitempty"`
	Role           *Role         `json:"role,omitempty"`
	Organization   *Organization `json:"organization,omitempty"`
	InvitedBy      *uuid.UUID    `json:"invited_by,omitempty"`
	InvitedAt      *time.Time    `json:"invited_at,omitempty"`
	AcceptedAt     *time.Time    `json:"accepted_at,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// Role represents a role with permissions
type Role struct {
	ID             uuid.UUID    `json:"id"`
	Name           string       `json:"name"`
	Description    string       `json:"description,omitempty"`
	Scope          string       `json:"scope"` // "system" or "organization"
	OrganizationID *uuid.UUID   `json:"organization_id,omitempty"`
	IsSystem       bool         `json:"is_system"`
	Permissions    []Permission `json:"permissions,omitempty"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// Permission represents a permission that can be assigned to roles
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Category    string    `json:"category,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Session represents an active user session (refresh token)
type Session struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	DeviceName string     `json:"device_name,omitempty"`
	DeviceType string     `json:"device_type,omitempty"`
	IPAddress  string     `json:"ip_address,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

// FeatureFlag represents a feature flag
type FeatureFlag struct {
	ID           uuid.UUID     `json:"id"`
	Key          string        `json:"key"`
	Name         string        `json:"name"`
	Description  string        `json:"description,omitempty"`
	FlagType     string        `json:"flag_type"` // boolean, percentage, variant
	DefaultValue any           `json:"default_value"`
	Variants     []FlagVariant `json:"variants,omitempty"`
	Percentage   int           `json:"percentage,omitempty"`
	IsEnabled    bool          `json:"is_enabled"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

// FlagVariant represents a variant for a feature flag
type FlagVariant struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID             uuid.UUID  `json:"id"`
	ActorID        *uuid.UUID `json:"actor_id,omitempty"`
	ActorType      string     `json:"actor_type"`
	ActorIP        string     `json:"actor_ip,omitempty"`
	ActorUserAgent string     `json:"actor_user_agent,omitempty"`
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`
	Action         string     `json:"action"`
	ResourceType   string     `json:"resource_type"`
	ResourceID     *uuid.UUID `json:"resource_id,omitempty"`
	OldValues      JSONMap    `json:"old_values,omitempty"`
	NewValues      JSONMap    `json:"new_values,omitempty"`
	Metadata       JSONMap    `json:"metadata,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Theme represents theming settings
type Theme struct {
	PrimaryColor    string `json:"primaryColor"`
	SecondaryColor  string `json:"secondaryColor"`
	AccentColor     string `json:"accentColor"`
	BackgroundColor string `json:"backgroundColor"`
	TextColor       string `json:"textColor"`
	LogoURL         string `json:"logoUrl,omitempty"`
	FaviconURL      string `json:"faviconUrl,omitempty"`
	AppName         string `json:"appName"`
}

// Settings represents system or organization settings
type Settings struct {
	ID              uuid.UUID        `json:"id"`
	Scope           string           `json:"scope"` // "global" or "organization"
	OrganizationID  *uuid.UUID       `json:"organization_id,omitempty"`
	Theme           Theme            `json:"theme"`
	SMTPSettings    SMTPSettings     `json:"smtp_settings,omitempty"`
	GeneralSettings GeneralSettings  `json:"general_settings"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// SMTPSettings represents SMTP configuration
type SMTPSettings struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	FromEmail  string `json:"fromEmail"`
	FromName   string `json:"fromName"`
	Encryption string `json:"encryption"` // tls, ssl, none
}

// GeneralSettings represents general system settings
type GeneralSettings struct {
	AllowRegistration        bool `json:"allowRegistration"`
	RequireEmailVerification bool `json:"requireEmailVerification"`
	AllowPasswordReset       bool `json:"allowPasswordReset"`
	AllowUserOrgCreation     bool `json:"allowUserOrgCreation"`
	SessionLifetimeMinutes   int  `json:"sessionLifetimeMinutes"`
	RefreshTokenLifetimeDays int  `json:"refreshTokenLifetimeDays"`
	MaxLoginAttempts         int  `json:"maxLoginAttempts"`
	LockoutDurationMinutes   int  `json:"lockoutDurationMinutes"`
	TwoFactorRequired        bool `json:"twoFactorRequired"`
}

// JSONMap is a type alias for JSON object storage
type JSONMap map[string]any

// OrganizationInvite represents a pending organization invitation
type OrganizationInvite struct {
	ID             uuid.UUID     `json:"id"`
	OrganizationID uuid.UUID     `json:"organization_id"`
	Organization   *Organization `json:"organization,omitempty"`
	Email          string        `json:"email"`
	RoleID         uuid.UUID     `json:"role_id"`
	Role           *Role         `json:"role,omitempty"`
	Token          string        `json:"-"` // Never expose token in JSON
	InvitedBy      uuid.UUID     `json:"invited_by"`
	InvitedByUser  *User         `json:"invited_by_user,omitempty"`
	Status         string        `json:"status"`
	ExpiresAt      time.Time     `json:"expires_at"`
	CreatedAt      time.Time     `json:"created_at"`
}

// TokenPair represents an access and refresh token pair
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// AuthResponse is returned after successful authentication
type AuthResponse struct {
	User   *User      `json:"user"`
	Tokens *TokenPair `json:"tokens"`
}
