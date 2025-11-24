package t7qoq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/youssefsiam38/t7qoq/internal/crypto"
	"github.com/youssefsiam38/t7qoq/internal/database"
	"github.com/youssefsiam38/t7qoq/internal/email"
	"github.com/youssefsiam38/t7qoq/internal/jwt"
	"github.com/youssefsiam38/t7qoq/internal/totp"
)

// =============================================================================
// Request/Response Types
// =============================================================================

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// ForgotPasswordRequest represents a forgot password request
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest represents a password reset request
type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

// ChangePasswordRequest represents a change password request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}

// UpdateProfileRequest represents a profile update request
type UpdateProfileRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Phone     string `json:"phone"`
	AvatarURL string `json:"avatar_url"`
}

// =============================================================================
// Auth Handlers
// =============================================================================

// handleLogin handles user login
func (t *T7qoq) handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	ctx := c.Request.Context()

	// Get user by email
	userRow, err := t.db.GetUserByEmail(ctx, strings.ToLower(req.Email))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid email or password",
				"code":  ErrCodeUnauthorized,
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Check if account is locked
	if userRow.LockedUntil != nil && userRow.LockedUntil.After(time.Now()) {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":        "account temporarily locked due to too many failed login attempts",
			"code":         ErrCodeTooManyRequests,
			"locked_until": userRow.LockedUntil,
		})
		return
	}

	// Check if account is active
	if userRow.Status != "active" && userRow.Status != "pending" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "account is " + userRow.Status,
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Verify password
	if !crypto.CheckPassword(req.Password, userRow.PasswordHash) {
		// Increment failed login attempts
		maxAttempts := t.config.MaxLoginAttempts
		if maxAttempts == 0 {
			maxAttempts = 5
		}

		var lockoutUntil *time.Time
		if userRow.FailedLoginAttempts+1 >= maxAttempts {
			lockoutDuration := time.Duration(t.config.LockoutDurationMinutes) * time.Minute
			if lockoutDuration == 0 {
				lockoutDuration = 15 * time.Minute
			}
			lockUntil := time.Now().Add(lockoutDuration)
			lockoutUntil = &lockUntil
		}
		t.db.IncrementFailedLogin(ctx, userRow.ID, lockoutUntil)

		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid email or password",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	// Check if 2FA is required
	if t.config.Enable2FA && userRow.TwoFactorEnabled {
		c.JSON(http.StatusOK, gin.H{
			"requires_2fa": true,
			"email":        userRow.Email,
			"message":      "Two-factor authentication required",
		})
		return
	}

	// Generate tokens
	tokens, err := t.jwt.GenerateTokenPair(userRow.ID, userRow.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to generate tokens",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Store refresh token in database
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	deviceName := parseDeviceName(userAgent)
	deviceType := parseDeviceType(userAgent)

	_, err = t.db.CreateRefreshToken(
		ctx,
		userRow.ID,
		jwt.HashToken(tokens.RefreshToken),
		time.Now().Add(t.config.RefreshTokenExpiry),
		&deviceName,
		&deviceType,
		&ipAddress,
		&userAgent,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create session",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Update last login
	t.db.UpdateUserLastLogin(ctx, userRow.ID, &ipAddress)

	// Build user response
	user := userRowToUser(userRow)

	// Check if this is the first user (make them super admin)
	if err := t.ensureFirstUserIsSuperAdmin(ctx, userRow.ID); err != nil {
		// Log error but don't fail login
	}

	c.JSON(http.StatusOK, AuthResponse{
		User: user,
		Tokens: &TokenPair{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			ExpiresAt:    tokens.ExpiresAt,
			TokenType:    "Bearer",
		},
	})
}

// handleRegister handles user registration
func (t *T7qoq) handleRegister(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	ctx := c.Request.Context()

	// Validate password strength
	passwordConfig := crypto.DefaultPasswordConfig()
	if err := crypto.ValidatePassword(req.Password, passwordConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  ErrCodeBadRequest,
		})
		return
	}

	// Hash password
	passwordHash, err := crypto.HashPassword(req.Password, passwordConfig.BCryptCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to process password",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Create user
	userRow, err := t.db.CreateUser(ctx, strings.ToLower(req.Email), passwordHash)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "email already registered",
				"code":  ErrCodeConflict,
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create user",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Update profile if provided
	if req.FirstName != "" || req.LastName != "" {
		var firstName, lastName *string
		if req.FirstName != "" {
			firstName = &req.FirstName
		}
		if req.LastName != "" {
			lastName = &req.LastName
		}
		t.db.UpdateUserProfile(ctx, userRow.ID, firstName, lastName, nil, nil)
	}

	// Generate email verification token if required
	var verificationToken string
	if t.config.RequireEmailVerification {
		token, err := crypto.GenerateToken()
		if err == nil {
			verificationToken = token
			expiresAt := time.Now().Add(24 * time.Hour)
			t.db.SetEmailVerificationToken(ctx, userRow.ID, token, expiresAt)
		}
	}

	// Send welcome email (with verification link if needed)
	userName := req.FirstName
	if userName == "" {
		userName = strings.Split(req.Email, "@")[0]
	}
	go t.sendWelcomeEmail(c.Copy(), req.Email, userName, verificationToken)

	// Generate tokens for immediate login
	tokens, err := t.jwt.GenerateTokenPair(userRow.ID, userRow.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to generate tokens",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Store refresh token
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	deviceName := parseDeviceName(userAgent)
	deviceType := parseDeviceType(userAgent)

	t.db.CreateRefreshToken(
		ctx,
		userRow.ID,
		jwt.HashToken(tokens.RefreshToken),
		time.Now().Add(t.config.RefreshTokenExpiry),
		&deviceName,
		&deviceType,
		&ipAddress,
		&userAgent,
	)

	// Check if first user and make super admin
	if err := t.ensureFirstUserIsSuperAdmin(ctx, userRow.ID); err != nil {
		// Log error but don't fail registration
	}

	// Reload user to get updated profile
	userRow, _ = t.db.GetUserByID(ctx, userRow.ID)
	user := userRowToUser(userRow)

	c.JSON(http.StatusCreated, AuthResponse{
		User: user,
		Tokens: &TokenPair{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			ExpiresAt:    tokens.ExpiresAt,
			TokenType:    "Bearer",
		},
	})
}

// handleRefresh handles token refresh
func (t *T7qoq) handleRefresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	ctx := c.Request.Context()

	// Validate refresh token
	claims, err := t.jwt.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid or expired refresh token",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	// Check if token exists in database and is not revoked
	tokenRow, err := t.db.GetRefreshToken(ctx, jwt.HashToken(req.RefreshToken))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid or expired refresh token",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	// Get user
	userRow, err := t.db.GetUserByID(ctx, claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "user not found",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	// Check user status
	if userRow.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "account is " + userRow.Status,
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Generate new access token
	accessToken, expiresAt, err := t.jwt.GenerateAccessToken(userRow.ID, userRow.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to generate token",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Update last used time for the refresh token
	t.db.UpdateRefreshTokenLastUsed(ctx, tokenRow.ID)

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"expires_at":   expiresAt,
		"token_type":   "Bearer",
	})
}

// handleLogout handles user logout
func (t *T7qoq) handleLogout(c *gin.Context) {
	ctx := c.Request.Context()

	// Get refresh token from request body or header
	var refreshToken string

	// Try to get from request body
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&req); err == nil && req.RefreshToken != "" {
		refreshToken = req.RefreshToken
	}

	if refreshToken != "" {
		// Revoke the specific refresh token
		tokenRow, err := t.db.GetRefreshToken(ctx, jwt.HashToken(refreshToken))
		if err == nil {
			t.db.RevokeRefreshToken(ctx, tokenRow.ID)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
}

// handleForgotPassword handles password reset request
func (t *T7qoq) handleForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	ctx := c.Request.Context()

	// Always return success to prevent email enumeration
	defer func() {
		c.JSON(http.StatusOK, gin.H{
			"message": "if an account with that email exists, a password reset link will be sent",
		})
	}()

	// Get user
	userRow, err := t.db.GetUserByEmail(ctx, strings.ToLower(req.Email))
	if err != nil {
		return
	}

	// Generate reset token
	token, err := crypto.GenerateToken()
	if err != nil {
		return
	}

	// Store token (expires in 1 hour)
	expiresAt := time.Now().Add(1 * time.Hour)
	t.db.SetPasswordResetToken(ctx, userRow.ID, token, expiresAt)

	// Send password reset email
	userName := ""
	if userRow.FirstName != nil {
		userName = *userRow.FirstName
	}
	go t.sendPasswordResetEmail(c.Copy(), userRow.Email, userName, token)
}

// handleResetPassword handles password reset
func (t *T7qoq) handleResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	ctx := c.Request.Context()

	// Validate password strength
	passwordConfig := crypto.DefaultPasswordConfig()
	if err := crypto.ValidatePassword(req.Password, passwordConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  ErrCodeBadRequest,
		})
		return
	}

	// Validate token
	userID, err := t.db.GetPasswordResetToken(ctx, req.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid or expired reset token",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	// Hash new password
	passwordHash, err := crypto.HashPassword(req.Password, passwordConfig.BCryptCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to process password",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Update password
	if err := t.db.UpdateUserPassword(ctx, userID, passwordHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to update password",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Clear reset token
	t.db.ClearPasswordResetToken(ctx, userID)

	// Revoke all refresh tokens for security
	t.db.RevokeAllUserRefreshTokens(ctx, userID)

	// Send password changed notification email
	userRow, err := t.db.GetUserByID(ctx, userID)
	if err == nil {
		userName := ""
		if userRow.FirstName != nil {
			userName = *userRow.FirstName
		}
		go t.sendPasswordChangedEmail(userRow.Email, userName)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "password reset successfully",
	})
}

// handleVerifyEmail handles email verification
func (t *T7qoq) handleVerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "missing verification token",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	ctx := c.Request.Context()

	userRow, err := t.db.VerifyUserEmail(ctx, token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid or expired verification token",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	user := userRowToUser(userRow)

	c.JSON(http.StatusOK, gin.H{
		"message": "email verified successfully",
		"user":    user,
	})
}

// handleUpdateProfile handles profile update
func (t *T7qoq) handleUpdateProfile(c *gin.Context) {
	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	user := GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	ctx := c.Request.Context()

	var firstName, lastName, phone, avatarURL *string
	if req.FirstName != "" {
		firstName = &req.FirstName
	}
	if req.LastName != "" {
		lastName = &req.LastName
	}
	if req.Phone != "" {
		phone = &req.Phone
	}
	if req.AvatarURL != "" {
		avatarURL = &req.AvatarURL
	}

	if err := t.db.UpdateUserProfile(ctx, user.ID, firstName, lastName, phone, avatarURL); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to update profile",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Get updated user
	userRow, err := t.db.GetUserByID(ctx, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get user",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, userRowToUser(userRow))
}

// handleChangePassword handles password change
func (t *T7qoq) handleChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	user := GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	ctx := c.Request.Context()

	// Get user to verify current password
	userRow, err := t.db.GetUserByID(ctx, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get user",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Verify current password
	if !crypto.CheckPassword(req.CurrentPassword, userRow.PasswordHash) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "current password is incorrect",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	// Validate new password
	passwordConfig := crypto.DefaultPasswordConfig()
	if err := crypto.ValidatePassword(req.NewPassword, passwordConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  ErrCodeBadRequest,
		})
		return
	}

	// Hash new password
	passwordHash, err := crypto.HashPassword(req.NewPassword, passwordConfig.BCryptCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to process password",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Update password
	if err := t.db.UpdateUserPassword(ctx, user.ID, passwordHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to update password",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Send password changed notification email
	userName := user.FirstName
	go t.sendPasswordChangedEmail(user.Email, userName)

	c.JSON(http.StatusOK, gin.H{
		"message": "password changed successfully",
	})
}

// TwoFactorSetupRequest represents a 2FA setup request
type TwoFactorSetupRequest struct {
	Code string `json:"code" binding:"required"`
}

// TwoFactorDisableRequest represents a 2FA disable request
type TwoFactorDisableRequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

// handle2FASetup handles 2FA setup - initiates or confirms setup
func (t *T7qoq) handle2FASetup(c *gin.Context) {
	user := GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	ctx := c.Request.Context()

	// Check if already enabled
	if user.TwoFactorEnabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "2FA is already enabled",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	// Check for POST body - if present, verify code and enable
	var req TwoFactorSetupRequest
	if err := c.ShouldBindJSON(&req); err == nil && req.Code != "" {
		// Get user with secret
		userRow, err := t.db.GetUserByID(ctx, user.ID)
		if err != nil || userRow.TwoFactorSecret == nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "2FA setup not initiated. Start setup first.",
				"code":  ErrCodeBadRequest,
			})
			return
		}

		// Validate code
		if !totp.ValidateCode(*userRow.TwoFactorSecret, req.Code) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid verification code",
				"code":  ErrCodeBadRequest,
			})
			return
		}

		// Generate backup codes
		backupCodes, err := totp.GenerateBackupCodes()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to generate backup codes",
				"code":  ErrCodeInternalError,
			})
			return
		}

		// Enable 2FA
		if err := t.db.Enable2FA(ctx, user.ID, backupCodes); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to enable 2FA",
				"code":  ErrCodeInternalError,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":      "2FA enabled successfully",
			"backup_codes": backupCodes,
		})
		return
	}

	// Generate new secret
	secret, err := totp.GenerateSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to generate 2FA secret",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Store secret temporarily (not enabled yet)
	if err := t.db.Set2FASecret(ctx, user.ID, secret); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to store 2FA secret",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Generate provisioning URI
	uri := totp.GenerateProvisioningURI(secret, t.config.AppName, user.Email)

	c.JSON(http.StatusOK, gin.H{
		"secret":           secret,
		"provisioning_uri": uri,
		"message":          "Scan the QR code with your authenticator app, then verify with a code",
	})
}

// handle2FAVerify handles 2FA verification during login
func (t *T7qoq) handle2FAVerify(c *gin.Context) {
	var req struct {
		Code     string `json:"code" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	ctx := c.Request.Context()

	// Get user
	userRow, err := t.db.GetUserByEmail(ctx, strings.ToLower(req.Email))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid credentials",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	// Verify password first (security: prevent bypassing password auth)
	if !crypto.CheckPassword(req.Password, userRow.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid credentials",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	if !userRow.TwoFactorEnabled || userRow.TwoFactorSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "2FA is not enabled for this account",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	// Try TOTP code first
	if totp.ValidateCode(*userRow.TwoFactorSecret, req.Code) {
		// Valid TOTP - generate tokens
		t.completeLogin(c, userRow)
		return
	}

	// Try backup code
	if userRow.TwoFactorBackupCodes != nil {
		idx := totp.ValidateBackupCode(req.Code, userRow.TwoFactorBackupCodes)
		if idx >= 0 {
			// Valid backup code - mark it as used
			t.db.UseBackupCode(ctx, userRow.ID, idx)
			t.completeLogin(c, userRow)
			return
		}
	}

	c.JSON(http.StatusUnauthorized, gin.H{
		"error": "invalid verification code",
		"code":  ErrCodeUnauthorized,
	})
}

// handle2FADisable handles 2FA disable
func (t *T7qoq) handle2FADisable(c *gin.Context) {
	var req TwoFactorDisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	user := GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	ctx := c.Request.Context()

	// Get user with password and 2FA secret
	userRow, err := t.db.GetUserByID(ctx, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get user",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Verify password
	if !crypto.CheckPassword(req.Password, userRow.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid password",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	// Verify 2FA code
	if userRow.TwoFactorSecret != nil && !totp.ValidateCode(*userRow.TwoFactorSecret, req.Code) {
		// Check backup codes
		if userRow.TwoFactorBackupCodes == nil || totp.ValidateBackupCode(req.Code, userRow.TwoFactorBackupCodes) < 0 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid verification code",
				"code":  ErrCodeUnauthorized,
			})
			return
		}
	}

	// Disable 2FA
	if err := t.db.Disable2FA(ctx, user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to disable 2FA",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "2FA disabled successfully",
	})
}

// completeLogin completes the login process and returns tokens
func (t *T7qoq) completeLogin(c *gin.Context, userRow *database.UserRow) {
	// Generate tokens
	tokens, err := t.jwt.GenerateTokenPair(userRow.ID, userRow.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to generate tokens",
			"code":  ErrCodeInternalError,
		})
		return
	}

	ctx := c.Request.Context()

	// Store refresh token in database
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	deviceName := parseDeviceName(userAgent)
	deviceType := parseDeviceType(userAgent)

	_, err = t.db.CreateRefreshToken(
		ctx,
		userRow.ID,
		jwt.HashToken(tokens.RefreshToken),
		time.Now().Add(t.config.RefreshTokenExpiry),
		&deviceName,
		&deviceType,
		&ipAddress,
		&userAgent,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create session",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Update last login
	t.db.UpdateUserLastLogin(ctx, userRow.ID, &ipAddress)

	// Build user response
	user := userRowToUser(userRow)

	c.JSON(http.StatusOK, AuthResponse{
		User: user,
		Tokens: &TokenPair{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			ExpiresAt:    tokens.ExpiresAt,
			TokenType:    "Bearer",
		},
	})
}

// handleListSessions lists user sessions
func (t *T7qoq) handleListSessions(c *gin.Context) {
	user := GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	ctx := c.Request.Context()

	sessions, err := t.db.GetUserSessions(ctx, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get sessions",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Convert to response format
	var result []Session
	for _, s := range sessions {
		session := Session{
			ID:        s.ID,
			UserID:    s.UserID,
			ExpiresAt: s.ExpiresAt,
			CreatedAt: s.CreatedAt,
		}
		if s.DeviceName != nil {
			session.DeviceName = *s.DeviceName
		}
		if s.DeviceType != nil {
			session.DeviceType = *s.DeviceType
		}
		if s.IPAddress != nil {
			session.IPAddress = *s.IPAddress
		}
		if s.UserAgent != nil {
			session.UserAgent = *s.UserAgent
		}
		if s.LastUsedAt != nil {
			session.LastUsedAt = s.LastUsedAt
		}
		result = append(result, session)
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": result,
	})
}

// handleRevokeSession revokes a session
func (t *T7qoq) handleRevokeSession(c *gin.Context) {
	user := GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "session ID required",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid session ID",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	ctx := c.Request.Context()

	// TODO: Verify session belongs to user before revoking
	if err := t.db.RevokeRefreshToken(ctx, sessionUUID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to revoke session",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "session revoked successfully",
	})
}

// =============================================================================
// Auth UI Page Renderers
// =============================================================================

// renderLoginPage renders the login page
func (t *T7qoq) renderLoginPage(c *gin.Context) {
	data := t.getTemplateData("Login")
	data.Error = c.Query("error")
	data.Success = c.Query("success")
	t.templateRenderer.render(c, "login.html", data)
}

// renderRegisterPage renders the registration page
func (t *T7qoq) renderRegisterPage(c *gin.Context) {
	data := t.getTemplateData("Register")
	data.Error = c.Query("error")
	t.templateRenderer.render(c, "register.html", data)
}

// renderForgotPasswordPage renders the forgot password page
func (t *T7qoq) renderForgotPasswordPage(c *gin.Context) {
	data := t.getTemplateData("Forgot Password")
	data.Error = c.Query("error")
	data.Success = c.Query("success")
	t.templateRenderer.render(c, "forgot-password.html", data)
}

// renderResetPasswordPage renders the reset password page
func (t *T7qoq) renderResetPasswordPage(c *gin.Context) {
	data := t.getTemplateData("Reset Password")
	data.Token = c.Query("token")
	data.Error = c.Query("error")
	t.templateRenderer.render(c, "reset-password.html", data)
}

// renderVerifyEmailSentPage renders the verify email sent page
func (t *T7qoq) renderVerifyEmailSentPage(c *gin.Context) {
	data := t.getTemplateData("Verify Email")
	data.Email = c.Query("email")
	t.templateRenderer.render(c, "verify-email-sent.html", data)
}

// renderProfilePage renders the profile page
func (t *T7qoq) renderProfilePage(c *gin.Context) {
	data := t.getTemplateData("Profile")
	data.User = GetUser(c)
	t.templateRenderer.render(c, "profile.html", data)
}

// render2FASetupPage renders the 2FA setup page
func (t *T7qoq) render2FASetupPage(c *gin.Context) {
	data := t.getTemplateData("Two-Factor Authentication")
	data.User = GetUser(c)
	t.templateRenderer.render(c, "two-factor-setup.html", data)
}

// =============================================================================
// Admin Handlers
// =============================================================================

// renderAdminLoginPage renders the admin login page
func (t *T7qoq) renderAdminLoginPage(c *gin.Context) {
	// TODO: Implement admin login page
	c.HTML(http.StatusOK, "admin-login.html", gin.H{})
}

// handleAdminLogin handles admin login
func (t *T7qoq) handleAdminLogin(c *gin.Context) {
	// TODO: Implement admin login
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// serveAdminPanel serves the React admin panel
func (t *T7qoq) serveAdminPanel(c *gin.Context) {
	// TODO: Serve embedded React app
	c.File("dashboard/dist/index.html")
}

// =============================================================================
// Admin API - Users
// =============================================================================

func (t *T7qoq) adminListUsers(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminGetUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminCreateUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminUpdateUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminDeleteUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// =============================================================================
// Admin API - Organizations
// =============================================================================

func (t *T7qoq) adminListOrganizations(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminGetOrganization(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminCreateOrganization(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminUpdateOrganization(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminDeleteOrganization(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminListOrgMembers(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminAddOrgMember(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminRemoveOrgMember(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// =============================================================================
// Admin API - Permissions
// =============================================================================

func (t *T7qoq) adminListPermissions(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminCreatePermission(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminUpdatePermission(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminDeletePermission(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// =============================================================================
// Admin API - Roles
// =============================================================================

func (t *T7qoq) adminListRoles(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminGetRole(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminCreateRole(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminUpdateRole(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminDeleteRole(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// =============================================================================
// Admin API - Sessions
// =============================================================================

func (t *T7qoq) adminListSessions(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminRevokeSession(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// =============================================================================
// Admin API - Feature Flags
// =============================================================================

func (t *T7qoq) adminListFeatures(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminGetFeature(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminCreateFeature(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminUpdateFeature(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminDeleteFeature(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// =============================================================================
// Admin API - Audit Logs
// =============================================================================

func (t *T7qoq) adminListAuditLogs(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (t *T7qoq) adminGetAuditLog(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// =============================================================================
// Admin API - Settings
// =============================================================================

func (t *T7qoq) adminGetSettings(c *gin.Context) {
	ctx := c.Request.Context()

	themeBytes, smtpBytes, generalBytes, err := t.db.GetGlobalSettings(ctx)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			// Return default settings when none exist
			c.JSON(http.StatusOK, Settings{
				Scope: "global",
				Theme: Theme{
					PrimaryColor:    "#3B82F6",
					SecondaryColor:  "#1E40AF",
					AccentColor:     "#F59E0B",
					BackgroundColor: "#F9FAFB",
					TextColor:       "#111827",
					AppName:         t.config.AppName,
				},
				GeneralSettings: GeneralSettings{
					AllowRegistration:        t.config.EnableRegistration,
					RequireEmailVerification: t.config.RequireEmailVerification,
					AllowPasswordReset:       true,
					AllowUserOrgCreation:     true,
					SessionLifetimeMinutes:   int(t.config.AccessTokenExpiry.Minutes()),
					RefreshTokenLifetimeDays: int(t.config.RefreshTokenExpiry.Hours() / 24),
					MaxLoginAttempts:         t.config.MaxLoginAttempts,
					LockoutDurationMinutes:   t.config.LockoutDurationMinutes,
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get settings",
			"code":  ErrCodeInternalError,
		})
		return
	}

	var settings Settings
	settings.Scope = "global"

	if themeBytes != nil {
		json.Unmarshal(themeBytes, &settings.Theme)
	}
	if smtpBytes != nil {
		json.Unmarshal(smtpBytes, &settings.SMTPSettings)
	}
	if generalBytes != nil {
		json.Unmarshal(generalBytes, &settings.GeneralSettings)
	}

	c.JSON(http.StatusOK, settings)
}

func (t *T7qoq) adminUpdateSettings(c *gin.Context) {
	var req struct {
		Theme           *Theme           `json:"theme"`
		SMTPSettings    *SMTPSettings    `json:"smtp_settings"`
		GeneralSettings *GeneralSettings `json:"general_settings"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	ctx := c.Request.Context()

	var themeBytes, smtpBytes, generalBytes []byte
	var err error

	if req.Theme != nil {
		themeBytes, err = json.Marshal(req.Theme)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid theme data",
				"code":  ErrCodeBadRequest,
			})
			return
		}
	}
	if req.SMTPSettings != nil {
		smtpBytes, err = json.Marshal(req.SMTPSettings)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid SMTP settings",
				"code":  ErrCodeBadRequest,
			})
			return
		}
	}
	if req.GeneralSettings != nil {
		generalBytes, err = json.Marshal(req.GeneralSettings)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid general settings",
				"code":  ErrCodeBadRequest,
			})
			return
		}
	}

	if err := t.db.UpsertGlobalSettings(ctx, themeBytes, smtpBytes, generalBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to update settings",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "settings updated successfully"})
}

// =============================================================================
// Admin API - Stats
// =============================================================================

func (t *T7qoq) adminGetStats(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// =============================================================================
// Helper Functions
// =============================================================================

// userRowToUser converts a database user row to the public User type
func userRowToUser(row *database.UserRow) *User {
	if row == nil {
		return nil
	}

	user := &User{
		ID:               row.ID,
		Email:            row.Email,
		EmailVerified:    row.EmailVerified,
		TwoFactorEnabled: row.TwoFactorEnabled,
		Status:           UserStatus(row.Status),
		LastLoginAt:      row.LastLoginAt,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}

	if row.FirstName != nil {
		user.FirstName = *row.FirstName
	}
	if row.LastName != nil {
		user.LastName = *row.LastName
	}
	if row.AvatarURL != nil {
		user.AvatarURL = *row.AvatarURL
	}
	if row.Phone != nil {
		user.Phone = *row.Phone
	}

	return user
}

// parseDeviceName extracts device name from user agent
func parseDeviceName(userAgent string) string {
	// Simple parsing - could be improved with a proper library
	if strings.Contains(userAgent, "Mobile") {
		return "Mobile Device"
	}
	if strings.Contains(userAgent, "Tablet") {
		return "Tablet"
	}
	return "Desktop"
}

// parseDeviceType extracts device type from user agent
func parseDeviceType(userAgent string) string {
	ua := strings.ToLower(userAgent)
	if strings.Contains(ua, "iphone") || strings.Contains(ua, "android") {
		return "mobile"
	}
	if strings.Contains(ua, "ipad") || strings.Contains(ua, "tablet") {
		return "tablet"
	}
	return "desktop"
}

// ensureFirstUserIsSuperAdmin makes the first registered user a super admin
func (t *T7qoq) ensureFirstUserIsSuperAdmin(ctx context.Context, userID uuid.UUID) error {
	// Check if this is the first user
	count, err := t.db.GetUserCount(ctx)
	if err != nil {
		return err
	}

	if count != 1 {
		return nil // Not the first user
	}

	// Get the "Super Admin" role
	role, err := t.db.GetRoleByName(ctx, "Super Admin", "system", nil)
	if err != nil {
		return err
	}

	// Assign the role to the user
	return t.db.AssignSystemRole(ctx, userID, role.ID, nil)
}

// getEmailData creates EmailData with common fields
func (t *T7qoq) getEmailData() email.EmailData {
	return email.EmailData{
		AppName: t.config.AppName,
		Year:    time.Now().Year(),
		// SupportURL could come from config or DB settings
	}
}

// buildURL constructs a URL for email links
func (t *T7qoq) buildURL(c *gin.Context, path string, queryParams map[string]string) string {
	scheme := "https"
	if c.Request.TLS == nil {
		// Check X-Forwarded-Proto header
		if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}

	host := c.Request.Host
	if forwardedHost := c.GetHeader("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}

	url := fmt.Sprintf("%s://%s%s", scheme, host, path)

	if len(queryParams) > 0 {
		url += "?"
		first := true
		for key, value := range queryParams {
			if !first {
				url += "&"
			}
			url += fmt.Sprintf("%s=%s", key, value)
			first = false
		}
	}

	return url
}

// sendVerificationEmail sends an email verification email
func (t *T7qoq) sendVerificationEmail(c *gin.Context, userEmail, userName, token string) error {
	if t.email == nil || !t.email.IsConfigured() {
		return nil // Email not configured, skip silently
	}

	verifyURL := t.buildURL(c, t.config.AuthRoutesPrefix+"/verify-email", map[string]string{
		"token": token,
	})

	data := t.getEmailData()
	return t.email.SendVerificationEmail(userEmail, userName, verifyURL, data)
}

// sendPasswordResetEmail sends a password reset email
func (t *T7qoq) sendPasswordResetEmail(c *gin.Context, userEmail, userName, token string) error {
	if t.email == nil || !t.email.IsConfigured() {
		return nil // Email not configured, skip silently
	}

	resetURL := t.buildURL(c, t.config.AuthRoutesPrefix+"/reset-password", map[string]string{
		"token": token,
	})

	data := t.getEmailData()
	return t.email.SendPasswordResetEmail(userEmail, userName, resetURL, data)
}

// sendPasswordChangedEmail sends a password changed notification email
func (t *T7qoq) sendPasswordChangedEmail(userEmail, userName string) error {
	if t.email == nil || !t.email.IsConfigured() {
		return nil // Email not configured, skip silently
	}

	data := t.getEmailData()
	return t.email.SendPasswordChangedEmail(userEmail, userName, data)
}

// sendWelcomeEmail sends a welcome email
func (t *T7qoq) sendWelcomeEmail(c *gin.Context, userEmail, userName, verifyToken string) error {
	if t.email == nil || !t.email.IsConfigured() {
		return nil // Email not configured, skip silently
	}

	var verifyURL string
	if verifyToken != "" {
		verifyURL = t.buildURL(c, t.config.AuthRoutesPrefix+"/verify-email", map[string]string{
			"token": verifyToken,
		})
	}

	data := t.getEmailData()
	return t.email.SendWelcomeEmail(userEmail, userName, verifyURL, data)
}
