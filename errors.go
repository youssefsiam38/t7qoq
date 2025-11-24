package t7qoq

import "errors"

// Configuration errors
var (
	ErrDBRequired        = errors.New("t7qoq: database connection pool is required")
	ErrJWTSecretRequired = errors.New("t7qoq: JWT secret is required")
	ErrJWTSecretTooShort = errors.New("t7qoq: JWT secret must be at least 32 bytes")
)

// Authentication errors
var (
	ErrInvalidCredentials   = errors.New("invalid email or password")
	ErrUserNotFound         = errors.New("user not found")
	ErrUserAlreadyExists    = errors.New("user with this email already exists")
	ErrInvalidToken         = errors.New("invalid or expired token")
	ErrTokenExpired         = errors.New("token has expired")
	ErrEmailNotVerified     = errors.New("email not verified")
	ErrAccountLocked        = errors.New("account is locked due to too many failed login attempts")
	ErrAccountSuspended     = errors.New("account has been suspended")
	ErrAccountInactive      = errors.New("account is inactive")
	ErrInvalidPassword      = errors.New("password does not meet requirements")
	ErrPasswordMismatch     = errors.New("passwords do not match")
	Err2FARequired          = errors.New("two-factor authentication required")
	ErrInvalid2FACode       = errors.New("invalid two-factor authentication code")
	Err2FAAlreadyEnabled    = errors.New("two-factor authentication is already enabled")
	Err2FANotEnabled        = errors.New("two-factor authentication is not enabled")
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionRevoked       = errors.New("session has been revoked")
	ErrUnauthorized         = errors.New("unauthorized")
	ErrForbidden            = errors.New("forbidden")
	ErrRegistrationDisabled = errors.New("registration is disabled")
)

// Organization errors
var (
	ErrOrganizationNotFound     = errors.New("organization not found")
	ErrOrganizationAlreadyExists = errors.New("organization with this slug already exists")
	ErrNotMemberOfOrganization  = errors.New("user is not a member of this organization")
	ErrAlreadyMemberOfOrganization = errors.New("user is already a member of this organization")
	ErrCannotRemoveOwner        = errors.New("cannot remove the organization owner")
	ErrCannotLeaveAsOwner       = errors.New("cannot leave organization as owner, transfer ownership first")
	ErrInviteNotFound           = errors.New("invitation not found")
	ErrInviteExpired            = errors.New("invitation has expired")
	ErrInviteAlreadyAccepted    = errors.New("invitation has already been accepted")
	ErrOrgCreationDisabled      = errors.New("organization creation is disabled for users")
)

// Role and permission errors
var (
	ErrRoleNotFound           = errors.New("role not found")
	ErrRoleAlreadyExists      = errors.New("role with this name already exists")
	ErrCannotDeleteSystemRole = errors.New("cannot delete system role")
	ErrPermissionNotFound     = errors.New("permission not found")
	ErrPermissionAlreadyExists = errors.New("permission with this name already exists")
	ErrInsufficientPermissions = errors.New("insufficient permissions")
)

// Feature flag errors
var (
	ErrFeatureFlagNotFound     = errors.New("feature flag not found")
	ErrFeatureFlagAlreadyExists = errors.New("feature flag with this key already exists")
	ErrFeatureDisabled         = errors.New("feature is disabled")
)

// Validation errors
var (
	ErrInvalidEmail    = errors.New("invalid email address")
	ErrInvalidUUID     = errors.New("invalid UUID")
	ErrInvalidInput    = errors.New("invalid input")
	ErrRequiredField   = errors.New("required field is missing")
)

// APIError represents an error that can be returned in API responses
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	return e.Message
}

// NewAPIError creates a new API error
func NewAPIError(code, message string) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
	}
}

// NewFieldError creates a new field-specific API error
func NewFieldError(code, message, field string) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
		Field:   field,
	}
}

// Common API error codes
const (
	ErrCodeValidation       = "VALIDATION_ERROR"
	ErrCodeUnauthorized     = "UNAUTHORIZED"
	ErrCodeForbidden        = "FORBIDDEN"
	ErrCodeNotFound         = "NOT_FOUND"
	ErrCodeConflict         = "CONFLICT"
	ErrCodeInternalError    = "INTERNAL_ERROR"
	ErrCodeBadRequest       = "BAD_REQUEST"
	ErrCodeRateLimited      = "RATE_LIMITED"
	ErrCodeTooManyRequests  = "TOO_MANY_REQUESTS"
)
