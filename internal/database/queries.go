package database

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Common errors
var (
	ErrNotFound      = errors.New("record not found")
	ErrDuplicateKey  = errors.New("duplicate key")
	ErrInvalidInput  = errors.New("invalid input")
	ErrAlreadyExists = errors.New("already exists")
)

// =============================================================================
// User Types for Database
// =============================================================================

// UserRow represents a user row in the database
type UserRow struct {
	ID                        uuid.UUID
	Email                     string
	PasswordHash              string
	EmailVerified             bool
	EmailVerificationToken    *string
	EmailVerificationExpires  *time.Time
	PasswordResetToken        *string
	PasswordResetExpires      *time.Time
	FirstName                 *string
	LastName                  *string
	AvatarURL                 *string
	Phone                     *string
	TwoFactorEnabled          bool
	TwoFactorSecret           *string
	TwoFactorBackupCodes      []string
	Status                    string
	LastLoginAt               *time.Time
	LastLoginIP               *string
	FailedLoginAttempts       int
	LockedUntil               *time.Time
	Metadata                  []byte
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
}

// RefreshTokenRow represents a refresh token in the database
type RefreshTokenRow struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	DeviceName *string
	DeviceType *string
	IPAddress  *string
	UserAgent  *string
	LastUsedAt *time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// OrganizationRow represents an organization in the database
type OrganizationRow struct {
	ID          uuid.UUID
	Name        string
	Slug        string
	Description *string
	LogoURL     *string
	Status      string
	Plan        *string
	Settings    []byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// OrgMemberRow represents an organization membership
type OrgMemberRow struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	UserID         uuid.UUID
	RoleID         uuid.UUID
	Status         string
	InvitedBy      *uuid.UUID
	InvitedAt      *time.Time
	AcceptedAt     *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// RoleRow represents a role in the database
type RoleRow struct {
	ID             uuid.UUID
	Name           string
	Description    *string
	Scope          string
	OrganizationID *uuid.UUID
	IsSystem       bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// PermissionRow represents a permission in the database
type PermissionRow struct {
	ID          uuid.UUID
	Name        string
	Description *string
	Category    *string
	CreatedAt   time.Time
}

// FeatureFlagRow represents a feature flag in the database
type FeatureFlagRow struct {
	ID           uuid.UUID
	Key          string
	Name         string
	Description  *string
	FlagType     string
	DefaultValue []byte
	Variants     []byte
	Percentage   *int
	IsEnabled    bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// =============================================================================
// User Queries
// =============================================================================

// CreateUser creates a new user
func (db *DB) CreateUser(ctx context.Context, email, passwordHash string) (*UserRow, error) {
	var user UserRow
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO t7qoq_users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at, first_name, last_name, avatar_url, phone,
			two_factor_enabled, two_factor_secret, two_factor_backup_codes, status, last_login_at, last_login_ip,
			failed_login_attempts, locked_until, metadata, created_at, updated_at
	`, email, passwordHash).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpires,
		&user.PasswordResetToken, &user.PasswordResetExpires, &user.FirstName, &user.LastName, &user.AvatarURL, &user.Phone,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &user.TwoFactorBackupCodes, &user.Status, &user.LastLoginAt, &user.LastLoginIP,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if isDuplicateKeyError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByID retrieves a user by ID
func (db *DB) GetUserByID(ctx context.Context, id uuid.UUID) (*UserRow, error) {
	var user UserRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at, first_name, last_name, avatar_url, phone,
			two_factor_enabled, two_factor_secret, two_factor_backup_codes, status, last_login_at, last_login_ip,
			failed_login_attempts, locked_until, metadata, created_at, updated_at
		FROM t7qoq_users WHERE id = $1
	`, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpires,
		&user.PasswordResetToken, &user.PasswordResetExpires, &user.FirstName, &user.LastName, &user.AvatarURL, &user.Phone,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &user.TwoFactorBackupCodes, &user.Status, &user.LastLoginAt, &user.LastLoginIP,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (db *DB) GetUserByEmail(ctx context.Context, email string) (*UserRow, error) {
	var user UserRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at, first_name, last_name, avatar_url, phone,
			two_factor_enabled, two_factor_secret, two_factor_backup_codes, status, last_login_at, last_login_ip,
			failed_login_attempts, locked_until, metadata, created_at, updated_at
		FROM t7qoq_users WHERE email = $1
	`, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpires,
		&user.PasswordResetToken, &user.PasswordResetExpires, &user.FirstName, &user.LastName, &user.AvatarURL, &user.Phone,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &user.TwoFactorBackupCodes, &user.Status, &user.LastLoginAt, &user.LastLoginIP,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

// UpdateUserLastLogin updates the user's last login time
func (db *DB) UpdateUserLastLogin(ctx context.Context, userID uuid.UUID, ipAddress *string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users
		SET last_login_at = NOW(), last_login_ip = $2, failed_login_attempts = 0, locked_until = NULL, updated_at = NOW()
		WHERE id = $1
	`, userID, ipAddress)
	return err
}

// IncrementFailedLogin increments the failed login count
func (db *DB) IncrementFailedLogin(ctx context.Context, userID uuid.UUID, lockoutUntil *time.Time) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users
		SET failed_login_attempts = failed_login_attempts + 1, locked_until = $2, updated_at = NOW()
		WHERE id = $1
	`, userID, lockoutUntil)
	return err
}

// UpdateUserPassword updates the user's password
func (db *DB) UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users
		SET password_hash = $2, password_changed_at = NOW(), updated_at = NOW()
		WHERE id = $1
	`, userID, passwordHash)
	return err
}

// UpdateUserProfile updates user profile fields
func (db *DB) UpdateUserProfile(ctx context.Context, userID uuid.UUID, firstName, lastName, phone *string, avatarURL *string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users
		SET first_name = COALESCE($2, first_name),
			last_name = COALESCE($3, last_name),
			phone = COALESCE($4, phone),
			avatar_url = COALESCE($5, avatar_url),
			updated_at = NOW()
		WHERE id = $1
	`, userID, firstName, lastName, phone, avatarURL)
	return err
}

// VerifyUserEmail marks the user's email as verified
func (db *DB) VerifyUserEmail(ctx context.Context, token string) (*UserRow, error) {
	var user UserRow
	err := db.Pool.QueryRow(ctx, `
		UPDATE t7qoq_users
		SET email_verified = true, email_verification_token = NULL, email_verification_expires_at = NULL, status = 'active', updated_at = NOW()
		WHERE email_verification_token = $1 AND email_verified = false AND (email_verification_expires_at IS NULL OR email_verification_expires_at > NOW())
		RETURNING id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at, first_name, last_name, avatar_url, phone,
			two_factor_enabled, two_factor_secret, two_factor_backup_codes, status, last_login_at, last_login_ip,
			failed_login_attempts, locked_until, metadata, created_at, updated_at
	`, token).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.EmailVerificationToken, &user.EmailVerificationExpires,
		&user.PasswordResetToken, &user.PasswordResetExpires, &user.FirstName, &user.LastName, &user.AvatarURL, &user.Phone,
		&user.TwoFactorEnabled, &user.TwoFactorSecret, &user.TwoFactorBackupCodes, &user.Status, &user.LastLoginAt, &user.LastLoginIP,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

// SetEmailVerificationToken sets the email verification token
func (db *DB) SetEmailVerificationToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users SET email_verification_token = $2, email_verification_expires_at = $3, updated_at = NOW() WHERE id = $1
	`, userID, token, expiresAt)
	return err
}

// GetUserCount returns the total number of users
func (db *DB) GetUserCount(ctx context.Context) (int64, error) {
	var count int64
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM t7qoq_users`).Scan(&count)
	return count, err
}

// =============================================================================
// Refresh Token Queries
// =============================================================================

// CreateRefreshToken creates a new refresh token
func (db *DB) CreateRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time, deviceName, deviceType, ipAddress, userAgent *string) (*RefreshTokenRow, error) {
	var token RefreshTokenRow
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO t7qoq_refresh_tokens (user_id, token_hash, expires_at, device_name, device_type, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, user_id, token_hash, device_name, device_type, ip_address, user_agent, last_used_at, expires_at, revoked_at, created_at
	`, userID, tokenHash, expiresAt, deviceName, deviceType, ipAddress, userAgent).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.DeviceName, &token.DeviceType,
		&token.IPAddress, &token.UserAgent, &token.LastUsedAt, &token.ExpiresAt, &token.RevokedAt, &token.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetRefreshToken retrieves a refresh token by hash
func (db *DB) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshTokenRow, error) {
	var token RefreshTokenRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, device_name, device_type, ip_address, user_agent, last_used_at, expires_at, revoked_at, created_at
		FROM t7qoq_refresh_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
	`, tokenHash).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.DeviceName, &token.DeviceType,
		&token.IPAddress, &token.UserAgent, &token.LastUsedAt, &token.ExpiresAt, &token.RevokedAt, &token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &token, nil
}

// UpdateRefreshTokenLastUsed updates the last used time
func (db *DB) UpdateRefreshTokenLastUsed(ctx context.Context, tokenID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_refresh_tokens SET last_used_at = NOW() WHERE id = $1
	`, tokenID)
	return err
}

// RevokeRefreshToken revokes a refresh token
func (db *DB) RevokeRefreshToken(ctx context.Context, tokenID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_refresh_tokens SET revoked_at = NOW() WHERE id = $1
	`, tokenID)
	return err
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user
func (db *DB) RevokeAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL
	`, userID)
	return err
}

// GetUserSessions retrieves all active sessions for a user
func (db *DB) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]RefreshTokenRow, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, token_hash, device_name, device_type, ip_address, user_agent, last_used_at, expires_at, revoked_at, created_at
		FROM t7qoq_refresh_tokens
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY last_used_at DESC NULLS LAST
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []RefreshTokenRow
	for rows.Next() {
		var token RefreshTokenRow
		if err := rows.Scan(
			&token.ID, &token.UserID, &token.TokenHash, &token.DeviceName, &token.DeviceType,
			&token.IPAddress, &token.UserAgent, &token.LastUsedAt, &token.ExpiresAt, &token.RevokedAt, &token.CreatedAt,
		); err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

// =============================================================================
// Organization Queries
// =============================================================================

// CreateOrganization creates a new organization
func (db *DB) CreateOrganization(ctx context.Context, name, slug string, description *string) (*OrganizationRow, error) {
	var org OrganizationRow
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO t7qoq_organizations (name, slug, description)
		VALUES ($1, $2, $3)
		RETURNING id, name, slug, description, logo_url, status, plan, settings, created_at, updated_at
	`, name, slug, description).Scan(
		&org.ID, &org.Name, &org.Slug, &org.Description, &org.LogoURL,
		&org.Status, &org.Plan, &org.Settings, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		if isDuplicateKeyError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	return &org, nil
}

// GetOrganizationByID retrieves an organization by ID
func (db *DB) GetOrganizationByID(ctx context.Context, id uuid.UUID) (*OrganizationRow, error) {
	var org OrganizationRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, name, slug, description, logo_url, status, plan, settings, created_at, updated_at
		FROM t7qoq_organizations WHERE id = $1
	`, id).Scan(
		&org.ID, &org.Name, &org.Slug, &org.Description, &org.LogoURL,
		&org.Status, &org.Plan, &org.Settings, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &org, nil
}

// GetOrganizationBySlug retrieves an organization by slug
func (db *DB) GetOrganizationBySlug(ctx context.Context, slug string) (*OrganizationRow, error) {
	var org OrganizationRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, name, slug, description, logo_url, status, plan, settings, created_at, updated_at
		FROM t7qoq_organizations WHERE slug = $1
	`, slug).Scan(
		&org.ID, &org.Name, &org.Slug, &org.Description, &org.LogoURL,
		&org.Status, &org.Plan, &org.Settings, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &org, nil
}

// =============================================================================
// Organization Member Queries
// =============================================================================

// AddOrganizationMember adds a user to an organization
func (db *DB) AddOrganizationMember(ctx context.Context, orgID, userID, roleID uuid.UUID, invitedBy *uuid.UUID) (*OrgMemberRow, error) {
	var member OrgMemberRow
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO t7qoq_organization_members (organization_id, user_id, role_id, status, invited_by, accepted_at)
		VALUES ($1, $2, $3, 'active', $4, NOW())
		RETURNING id, organization_id, user_id, role_id, status, invited_by, invited_at, accepted_at, created_at, updated_at
	`, orgID, userID, roleID, invitedBy).Scan(
		&member.ID, &member.OrganizationID, &member.UserID, &member.RoleID, &member.Status,
		&member.InvitedBy, &member.InvitedAt, &member.AcceptedAt, &member.CreatedAt, &member.UpdatedAt,
	)
	if err != nil {
		if isDuplicateKeyError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	return &member, nil
}

// GetOrganizationMember retrieves a user's membership in an organization
func (db *DB) GetOrganizationMember(ctx context.Context, orgID, userID uuid.UUID) (*OrgMemberRow, error) {
	var member OrgMemberRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, organization_id, user_id, role_id, status, invited_by, invited_at, accepted_at, created_at, updated_at
		FROM t7qoq_organization_members
		WHERE organization_id = $1 AND user_id = $2
	`, orgID, userID).Scan(
		&member.ID, &member.OrganizationID, &member.UserID, &member.RoleID, &member.Status,
		&member.InvitedBy, &member.InvitedAt, &member.AcceptedAt, &member.CreatedAt, &member.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &member, nil
}

// =============================================================================
// Role and Permission Queries
// =============================================================================

// GetRoleByID retrieves a role by ID
func (db *DB) GetRoleByID(ctx context.Context, id uuid.UUID) (*RoleRow, error) {
	var role RoleRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, name, description, scope, organization_id, is_system, created_at, updated_at
		FROM t7qoq_roles WHERE id = $1
	`, id).Scan(
		&role.ID, &role.Name, &role.Description, &role.Scope, &role.OrganizationID,
		&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &role, nil
}

// GetRoleByName retrieves a role by name and scope
func (db *DB) GetRoleByName(ctx context.Context, name, scope string, orgID *uuid.UUID) (*RoleRow, error) {
	var role RoleRow
	var err error
	if orgID != nil {
		err = db.Pool.QueryRow(ctx, `
			SELECT id, name, description, scope, organization_id, is_system, created_at, updated_at
			FROM t7qoq_roles WHERE name = $1 AND scope = $2 AND organization_id = $3
		`, name, scope, orgID).Scan(
			&role.ID, &role.Name, &role.Description, &role.Scope, &role.OrganizationID,
			&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
		)
	} else {
		err = db.Pool.QueryRow(ctx, `
			SELECT id, name, description, scope, organization_id, is_system, created_at, updated_at
			FROM t7qoq_roles WHERE name = $1 AND scope = $2 AND organization_id IS NULL
		`, name, scope).Scan(
			&role.ID, &role.Name, &role.Description, &role.Scope, &role.OrganizationID,
			&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
		)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &role, nil
}

// GetRolePermissions retrieves all permissions for a role
func (db *DB) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]PermissionRow, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT p.id, p.name, p.description, p.category, p.created_at
		FROM t7qoq_permissions p
		JOIN t7qoq_role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.category, p.name
	`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []PermissionRow
	for rows.Next() {
		var perm PermissionRow
		if err := rows.Scan(&perm.ID, &perm.Name, &perm.Description, &perm.Category, &perm.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

// GetUserSystemPermissions retrieves all system-level permissions for a user
func (db *DB) GetUserSystemPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT DISTINCT p.name
		FROM t7qoq_permissions p
		JOIN t7qoq_role_permissions rp ON p.id = rp.permission_id
		JOIN t7qoq_user_system_roles usr ON rp.role_id = usr.role_id
		WHERE usr.user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, err
		}
		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

// GetUserOrgPermissions retrieves all organization-level permissions for a user in an org
func (db *DB) GetUserOrgPermissions(ctx context.Context, userID, orgID uuid.UUID) ([]string, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT DISTINCT p.name
		FROM t7qoq_permissions p
		JOIN t7qoq_role_permissions rp ON p.id = rp.permission_id
		JOIN t7qoq_organization_members om ON rp.role_id = om.role_id
		WHERE om.user_id = $1 AND om.organization_id = $2 AND om.status = 'active'
	`, userID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, err
		}
		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

// AssignSystemRole assigns a system role to a user
func (db *DB) AssignSystemRole(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO t7qoq_user_system_roles (user_id, role_id, assigned_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, userID, roleID, assignedBy)
	return err
}

// =============================================================================
// Feature Flag Queries
// =============================================================================

// GetFeatureFlag retrieves a feature flag by key
func (db *DB) GetFeatureFlag(ctx context.Context, key string) (*FeatureFlagRow, error) {
	var flag FeatureFlagRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, key, name, description, flag_type, default_value, variants, percentage, is_enabled, created_at, updated_at
		FROM t7qoq_feature_flags WHERE key = $1
	`, key).Scan(
		&flag.ID, &flag.Key, &flag.Name, &flag.Description, &flag.FlagType,
		&flag.DefaultValue, &flag.Variants, &flag.Percentage, &flag.IsEnabled, &flag.CreatedAt, &flag.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &flag, nil
}

// GetFeatureFlagOverride retrieves a feature flag override for user/org
func (db *DB) GetFeatureFlagOverride(ctx context.Context, flagID uuid.UUID, userID, orgID *uuid.UUID) (*bool, error) {
	var isEnabled bool
	var err error

	// Check user override first
	if userID != nil {
		err = db.Pool.QueryRow(ctx, `
			SELECT is_enabled FROM t7qoq_feature_flag_overrides
			WHERE flag_id = $1 AND user_id = $2
		`, flagID, userID).Scan(&isEnabled)
		if err == nil {
			return &isEnabled, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}

	// Check org override
	if orgID != nil {
		err = db.Pool.QueryRow(ctx, `
			SELECT is_enabled FROM t7qoq_feature_flag_overrides
			WHERE flag_id = $1 AND organization_id = $2 AND user_id IS NULL
		`, flagID, orgID).Scan(&isEnabled)
		if err == nil {
			return &isEnabled, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}

	return nil, nil // No override found
}

// =============================================================================
// Password Reset Queries
// =============================================================================

// SetPasswordResetToken sets the password reset token on a user
func (db *DB) SetPasswordResetToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users SET password_reset_token = $2, password_reset_expires_at = $3, updated_at = NOW()
		WHERE id = $1
	`, userID, token, expiresAt)
	return err
}

// GetPasswordResetToken retrieves and validates a password reset token
func (db *DB) GetPasswordResetToken(ctx context.Context, token string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := db.Pool.QueryRow(ctx, `
		SELECT id FROM t7qoq_users
		WHERE password_reset_token = $1 AND password_reset_expires_at > NOW()
	`, token).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, err
	}
	return userID, nil
}

// ClearPasswordResetToken clears the password reset token after use
func (db *DB) ClearPasswordResetToken(ctx context.Context, userID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users SET password_reset_token = NULL, password_reset_expires_at = NULL, updated_at = NOW()
		WHERE id = $1
	`, userID)
	return err
}

// =============================================================================
// Settings Queries
// =============================================================================

// GetGlobalSettings retrieves global settings
func (db *DB) GetGlobalSettings(ctx context.Context) ([]byte, []byte, []byte, error) {
	var theme, smtp, general []byte
	err := db.Pool.QueryRow(ctx, `
		SELECT theme, smtp_settings, general_settings
		FROM t7qoq_settings WHERE scope = 'global' AND organization_id IS NULL
	`).Scan(&theme, &smtp, &general)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, nil, ErrNotFound
		}
		return nil, nil, nil, err
	}
	return theme, smtp, general, nil
}

// UpsertGlobalSettings creates or updates global settings
func (db *DB) UpsertGlobalSettings(ctx context.Context, theme, smtpSettings, generalSettings []byte) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO t7qoq_settings (scope, theme, smtp_settings, general_settings)
		VALUES ('global', $1, $2, $3)
		ON CONFLICT (scope) WHERE organization_id IS NULL
		DO UPDATE SET
			theme = COALESCE(EXCLUDED.theme, t7qoq_settings.theme),
			smtp_settings = COALESCE(EXCLUDED.smtp_settings, t7qoq_settings.smtp_settings),
			general_settings = COALESCE(EXCLUDED.general_settings, t7qoq_settings.general_settings),
			updated_at = NOW()
	`, theme, smtpSettings, generalSettings)
	return err
}

// =============================================================================
// Extended Organization Queries
// =============================================================================

// UserOrganizationRow represents a user's organization membership with details
type UserOrganizationRow struct {
	OrganizationID uuid.UUID
	OrgName        string
	OrgSlug        string
	RoleID         uuid.UUID
	RoleName       string
	Status         string
	CreatedAt      time.Time
}

// GetUserOrganizations retrieves all organizations for a user with role info
func (db *DB) GetUserOrganizations(ctx context.Context, userID uuid.UUID) ([]UserOrganizationRow, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT o.id, o.name, o.slug, m.role_id, r.name, m.status, m.created_at
		FROM t7qoq_organizations o
		JOIN t7qoq_organization_members m ON o.id = m.organization_id
		JOIN t7qoq_roles r ON m.role_id = r.id
		WHERE m.user_id = $1 AND m.status = 'active' AND o.status = 'active'
		ORDER BY o.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []UserOrganizationRow
	for rows.Next() {
		var row UserOrganizationRow
		if err := rows.Scan(
			&row.OrganizationID, &row.OrgName, &row.OrgSlug,
			&row.RoleID, &row.RoleName, &row.Status, &row.CreatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// OrgMemberDetailRow represents a member with user details
type OrgMemberDetailRow struct {
	ID            uuid.UUID
	OrganizationID uuid.UUID
	UserID        uuid.UUID
	UserEmail     string
	UserFirstName *string
	UserLastName  *string
	UserAvatarURL *string
	RoleID        uuid.UUID
	RoleName      string
	Status        string
	CreatedAt     time.Time
}

// GetOrganizationMembers retrieves all members of an organization with user details
func (db *DB) GetOrganizationMembers(ctx context.Context, orgID uuid.UUID) ([]OrgMemberDetailRow, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT m.id, m.organization_id, m.user_id, u.email, u.first_name, u.last_name, u.avatar_url,
			m.role_id, r.name, m.status, m.created_at
		FROM t7qoq_organization_members m
		JOIN t7qoq_users u ON m.user_id = u.id
		JOIN t7qoq_roles r ON m.role_id = r.id
		WHERE m.organization_id = $1
		ORDER BY m.created_at
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []OrgMemberDetailRow
	for rows.Next() {
		var row OrgMemberDetailRow
		if err := rows.Scan(
			&row.ID, &row.OrganizationID, &row.UserID, &row.UserEmail,
			&row.UserFirstName, &row.UserLastName, &row.UserAvatarURL,
			&row.RoleID, &row.RoleName, &row.Status, &row.CreatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// GetOrganizationMemberByEmail retrieves a member by email
func (db *DB) GetOrganizationMemberByEmail(ctx context.Context, orgID uuid.UUID, email string) (*OrgMemberRow, error) {
	var member OrgMemberRow
	err := db.Pool.QueryRow(ctx, `
		SELECT m.id, m.organization_id, m.user_id, m.role_id, m.status, m.invited_by, m.invited_at, m.accepted_at, m.created_at, m.updated_at
		FROM t7qoq_organization_members m
		JOIN t7qoq_users u ON m.user_id = u.id
		WHERE m.organization_id = $1 AND u.email = $2
	`, orgID, email).Scan(
		&member.ID, &member.OrganizationID, &member.UserID, &member.RoleID, &member.Status,
		&member.InvitedBy, &member.InvitedAt, &member.AcceptedAt, &member.CreatedAt, &member.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &member, nil
}

// GetOrganizationMemberByID retrieves a member by ID
func (db *DB) GetOrganizationMemberByID(ctx context.Context, memberID uuid.UUID) (*OrgMemberRow, error) {
	var member OrgMemberRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, organization_id, user_id, role_id, status, invited_by, invited_at, accepted_at, created_at, updated_at
		FROM t7qoq_organization_members
		WHERE id = $1
	`, memberID).Scan(
		&member.ID, &member.OrganizationID, &member.UserID, &member.RoleID, &member.Status,
		&member.InvitedBy, &member.InvitedAt, &member.AcceptedAt, &member.CreatedAt, &member.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &member, nil
}

// RemoveOrganizationMember removes a member from an organization
func (db *DB) RemoveOrganizationMember(ctx context.Context, memberID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM t7qoq_organization_members WHERE id = $1`, memberID)
	return err
}

// UpdateOrganizationMemberRole updates a member's role
func (db *DB) UpdateOrganizationMemberRole(ctx context.Context, memberID, roleID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_organization_members SET role_id = $2, updated_at = NOW() WHERE id = $1
	`, memberID, roleID)
	return err
}

// UpdateOrganization updates an organization
func (db *DB) UpdateOrganization(ctx context.Context, orgID uuid.UUID, name, description, logoURL *string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_organizations
		SET name = COALESCE($2, name),
			description = COALESCE($3, description),
			logo_url = COALESCE($4, logo_url),
			updated_at = NOW()
		WHERE id = $1
	`, orgID, name, description, logoURL)
	return err
}

// DeleteOrganization deletes an organization
func (db *DB) DeleteOrganization(ctx context.Context, orgID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM t7qoq_organizations WHERE id = $1`, orgID)
	return err
}

// =============================================================================
// Organization Invite Queries
// =============================================================================

// OrgInviteRow represents an organization invitation
type OrgInviteRow struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Email          string
	RoleID         uuid.UUID
	Token          string
	InvitedBy      uuid.UUID
	Status         string
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

// CreateOrganizationInvite creates a new invitation
func (db *DB) CreateOrganizationInvite(ctx context.Context, orgID uuid.UUID, email string, roleID, invitedBy uuid.UUID, token string, expiresAt time.Time) (*OrgInviteRow, error) {
	var invite OrgInviteRow
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO t7qoq_organization_invites (organization_id, email, role_id, token, invited_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, organization_id, email, role_id, token, invited_by, status, expires_at, created_at
	`, orgID, email, roleID, token, invitedBy, expiresAt).Scan(
		&invite.ID, &invite.OrganizationID, &invite.Email, &invite.RoleID,
		&invite.Token, &invite.InvitedBy, &invite.Status, &invite.ExpiresAt, &invite.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &invite, nil
}

// GetPendingInviteByEmail retrieves a pending invite by email for an organization
func (db *DB) GetPendingInviteByEmail(ctx context.Context, orgID uuid.UUID, email string) (*OrgInviteRow, error) {
	var invite OrgInviteRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, organization_id, email, role_id, token, invited_by, status, expires_at, created_at
		FROM t7qoq_organization_invites
		WHERE organization_id = $1 AND email = $2 AND status = 'pending' AND expires_at > NOW()
	`, orgID, email).Scan(
		&invite.ID, &invite.OrganizationID, &invite.Email, &invite.RoleID,
		&invite.Token, &invite.InvitedBy, &invite.Status, &invite.ExpiresAt, &invite.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &invite, nil
}

// GetInviteByToken retrieves an invite by token
func (db *DB) GetInviteByToken(ctx context.Context, token string) (*OrgInviteRow, error) {
	var invite OrgInviteRow
	err := db.Pool.QueryRow(ctx, `
		SELECT id, organization_id, email, role_id, token, invited_by, status, expires_at, created_at
		FROM t7qoq_organization_invites
		WHERE token = $1 AND status = 'pending' AND expires_at > NOW()
	`, token).Scan(
		&invite.ID, &invite.OrganizationID, &invite.Email, &invite.RoleID,
		&invite.Token, &invite.InvitedBy, &invite.Status, &invite.ExpiresAt, &invite.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &invite, nil
}

// AcceptInvite marks an invite as accepted
func (db *DB) AcceptInvite(ctx context.Context, inviteID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_organization_invites SET status = 'accepted' WHERE id = $1
	`, inviteID)
	return err
}

// CancelInvite cancels a pending invite
func (db *DB) CancelInvite(ctx context.Context, inviteID, orgID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_organization_invites SET status = 'cancelled'
		WHERE id = $1 AND organization_id = $2 AND status = 'pending'
	`, inviteID, orgID)
	return err
}

// GetOrganizationInvites retrieves all pending invites for an organization
func (db *DB) GetOrganizationInvites(ctx context.Context, orgID uuid.UUID) ([]OrgInviteRow, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, organization_id, email, role_id, token, invited_by, status, expires_at, created_at
		FROM t7qoq_organization_invites
		WHERE organization_id = $1 AND status = 'pending' AND expires_at > NOW()
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []OrgInviteRow
	for rows.Next() {
		var invite OrgInviteRow
		if err := rows.Scan(
			&invite.ID, &invite.OrganizationID, &invite.Email, &invite.RoleID,
			&invite.Token, &invite.InvitedBy, &invite.Status, &invite.ExpiresAt, &invite.CreatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, invite)
	}
	return result, rows.Err()
}

// GetUserPendingInvites retrieves all pending invites for a user by email
func (db *DB) GetUserPendingInvites(ctx context.Context, email string) ([]OrgInviteRow, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, organization_id, email, role_id, token, invited_by, status, expires_at, created_at
		FROM t7qoq_organization_invites
		WHERE email = $1 AND status = 'pending' AND expires_at > NOW()
		ORDER BY created_at DESC
	`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []OrgInviteRow
	for rows.Next() {
		var invite OrgInviteRow
		if err := rows.Scan(
			&invite.ID, &invite.OrganizationID, &invite.Email, &invite.RoleID,
			&invite.Token, &invite.InvitedBy, &invite.Status, &invite.ExpiresAt, &invite.CreatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, invite)
	}
	return result, rows.Err()
}

// =============================================================================
// Extended Role Queries
// =============================================================================

// CreateRole creates a new role
func (db *DB) CreateRole(ctx context.Context, name, scope string, orgID *uuid.UUID, description string) (*RoleRow, error) {
	var role RoleRow
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO t7qoq_roles (name, scope, organization_id, description, is_system)
		VALUES ($1, $2, $3, $4, false)
		RETURNING id, name, description, scope, organization_id, is_system, created_at, updated_at
	`, name, scope, orgID, description).Scan(
		&role.ID, &role.Name, &role.Description, &role.Scope, &role.OrganizationID,
		&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// GetOrganizationRoles retrieves all roles available for an organization
func (db *DB) GetOrganizationRoles(ctx context.Context, orgID *uuid.UUID) ([]RoleRow, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, name, description, scope, organization_id, is_system, created_at, updated_at
		FROM t7qoq_roles
		WHERE scope = 'organization' AND (organization_id IS NULL OR organization_id = $1)
		ORDER BY is_system DESC, name
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []RoleRow
	for rows.Next() {
		var role RoleRow
		if err := rows.Scan(
			&role.ID, &role.Name, &role.Description, &role.Scope, &role.OrganizationID,
			&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, role)
	}
	return result, rows.Err()
}

// GetUserOrganizationPermissions retrieves all permissions for a user in an organization
func (db *DB) GetUserOrganizationPermissions(ctx context.Context, userID, orgID uuid.UUID) ([]string, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT DISTINCT p.name
		FROM t7qoq_permissions p
		JOIN t7qoq_role_permissions rp ON p.id = rp.permission_id
		JOIN t7qoq_organization_members om ON rp.role_id = om.role_id
		WHERE om.user_id = $1 AND om.organization_id = $2 AND om.status = 'active'
	`, userID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, err
		}
		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

// =============================================================================
// Audit Log Queries
// =============================================================================

// CreateAuditLog creates an audit log entry
func (db *DB) CreateAuditLog(ctx context.Context, actorID *uuid.UUID, actorType, actorIP, actorUserAgent string, orgID *uuid.UUID, action, resourceType string, resourceID *uuid.UUID, oldValues, newValues, metadata []byte) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO t7qoq_audit_logs (actor_id, actor_type, actor_ip, actor_user_agent, organization_id, action, resource_type, resource_id, old_values, new_values, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, actorID, actorType, actorIP, actorUserAgent, orgID, action, resourceType, resourceID, oldValues, newValues, metadata)
	return err
}

// AuditLogRow represents an audit log entry
type AuditLogRow struct {
	ID             uuid.UUID
	ActorID        *uuid.UUID
	ActorType      string
	ActorIP        *string
	ActorUserAgent *string
	OrganizationID *uuid.UUID
	Action         string
	ResourceType   string
	ResourceID     *uuid.UUID
	OldValues      []byte
	NewValues      []byte
	Metadata       []byte
	CreatedAt      time.Time
}

// GetAuditLogs retrieves audit logs with pagination
func (db *DB) GetAuditLogs(ctx context.Context, limit, offset int, actorID, orgID, resourceID *uuid.UUID, action, resourceType *string) ([]AuditLogRow, int64, error) {
	// Build dynamic query based on filters
	query := `
		SELECT id, actor_id, actor_type, actor_ip, actor_user_agent, organization_id, action, resource_type, resource_id, old_values, new_values, metadata, created_at
		FROM t7qoq_audit_logs
		WHERE 1=1
	`
	countQuery := `SELECT COUNT(*) FROM t7qoq_audit_logs WHERE 1=1`
	args := []any{}
	argNum := 1

	if actorID != nil {
		query += ` AND actor_id = $` + string(rune('0'+argNum))
		countQuery += ` AND actor_id = $` + string(rune('0'+argNum))
		args = append(args, actorID)
		argNum++
	}
	if orgID != nil {
		query += ` AND organization_id = $` + string(rune('0'+argNum))
		countQuery += ` AND organization_id = $` + string(rune('0'+argNum))
		args = append(args, orgID)
		argNum++
	}
	if resourceID != nil {
		query += ` AND resource_id = $` + string(rune('0'+argNum))
		countQuery += ` AND resource_id = $` + string(rune('0'+argNum))
		args = append(args, resourceID)
		argNum++
	}
	if action != nil && *action != "" {
		query += ` AND action = $` + string(rune('0'+argNum))
		countQuery += ` AND action = $` + string(rune('0'+argNum))
		args = append(args, *action)
		argNum++
	}
	if resourceType != nil && *resourceType != "" {
		query += ` AND resource_type = $` + string(rune('0'+argNum))
		countQuery += ` AND resource_type = $` + string(rune('0'+argNum))
		args = append(args, *resourceType)
		argNum++
	}

	query += ` ORDER BY created_at DESC LIMIT $` + string(rune('0'+argNum)) + ` OFFSET $` + string(rune('0'+argNum+1))
	args = append(args, limit, offset)

	// Get total count
	var total int64
	countArgs := args[:len(args)-2] // Remove limit and offset
	err := db.Pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get rows
	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []AuditLogRow
	for rows.Next() {
		var log AuditLogRow
		if err := rows.Scan(
			&log.ID, &log.ActorID, &log.ActorType, &log.ActorIP, &log.ActorUserAgent,
			&log.OrganizationID, &log.Action, &log.ResourceType, &log.ResourceID,
			&log.OldValues, &log.NewValues, &log.Metadata, &log.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		logs = append(logs, log)
	}

	return logs, total, rows.Err()
}

// =============================================================================
// Two-Factor Authentication Queries
// =============================================================================

// Set2FASecret stores the 2FA secret for a user (before enabling)
func (db *DB) Set2FASecret(ctx context.Context, userID uuid.UUID, secret string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users SET two_factor_secret = $2, updated_at = NOW() WHERE id = $1
	`, userID, secret)
	return err
}

// Enable2FA enables 2FA for a user and stores backup codes
func (db *DB) Enable2FA(ctx context.Context, userID uuid.UUID, backupCodes []string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users SET two_factor_enabled = true, two_factor_backup_codes = $2, updated_at = NOW() WHERE id = $1
	`, userID, backupCodes)
	return err
}

// Disable2FA disables 2FA for a user
func (db *DB) Disable2FA(ctx context.Context, userID uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users SET two_factor_enabled = false, two_factor_secret = NULL, two_factor_backup_codes = NULL, updated_at = NOW() WHERE id = $1
	`, userID)
	return err
}

// UseBackupCode marks a backup code as used by setting it to empty string
func (db *DB) UseBackupCode(ctx context.Context, userID uuid.UUID, codeIndex int) error {
	// Set the used code to empty string to mark it as used
	_, err := db.Pool.Exec(ctx, `
		UPDATE t7qoq_users SET two_factor_backup_codes[$2] = '', updated_at = NOW() WHERE id = $1
	`, userID, codeIndex+1) // PostgreSQL arrays are 1-indexed
	return err
}

// =============================================================================
// Helper Functions
// =============================================================================

// isDuplicateKeyError checks if an error is a duplicate key error
func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	// PostgreSQL unique violation error code is 23505
	return errors.Is(err, pgx.ErrNoRows) == false &&
		(contains(err.Error(), "duplicate key") || contains(err.Error(), "23505"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
