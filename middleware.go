package t7qoq

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// =============================================================================
// Authentication Middlewares
// =============================================================================

// RequireAuth middleware validates JWT access token and loads user into context
func (m *MiddlewareGroup) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// Try to get from cookie
			authHeader, _ = c.Cookie("access_token")
		}

		// Remove "Bearer " prefix if present
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing access token",
				"code":  ErrCodeUnauthorized,
			})
			return
		}

		// Validate token
		claims, err := m.t.jwt.ValidateAccessToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
				"code":  ErrCodeUnauthorized,
			})
			return
		}

		ctx := c.Request.Context()

		// Load user from database
		userRow, err := m.t.db.GetUserByID(ctx, claims.UserID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "user not found",
				"code":  ErrCodeUnauthorized,
			})
			return
		}

		// Check if user is active
		if userRow.Status != "active" && userRow.Status != "pending" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "account is " + userRow.Status,
				"code":  ErrCodeForbidden,
			})
			return
		}

		// Convert to User type
		user := userRowToUser(userRow)

		// Set user in context
		setUser(c, user)

		// Load user's system permissions
		permissions, _ := m.t.db.GetUserSystemPermissions(ctx, user.ID)
		if permissions == nil {
			permissions = []string{}
		}
		setPermissions(c, permissions)

		c.Next()
	}
}

// OptionalAuth middleware loads user if token present, continues if not
func (m *MiddlewareGroup) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			authHeader, _ = c.Cookie("access_token")
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			c.Next()
			return
		}

		// Validate token
		claims, err := m.t.jwt.ValidateAccessToken(token)
		if err != nil {
			// Invalid token, continue without user
			c.Next()
			return
		}

		ctx := c.Request.Context()

		// Load user from database
		userRow, err := m.t.db.GetUserByID(ctx, claims.UserID)
		if err != nil {
			// User not found, continue without user
			c.Next()
			return
		}

		// Check if user is active
		if userRow.Status != "active" && userRow.Status != "pending" {
			// Inactive user, continue without user
			c.Next()
			return
		}

		user := userRowToUser(userRow)
		setUser(c, user)

		// Load permissions
		permissions, _ := m.t.db.GetUserSystemPermissions(ctx, user.ID)
		if permissions != nil {
			setPermissions(c, permissions)
		}

		c.Next()
	}
}

// RequireEmailVerified middleware ensures user has verified email
func (m *MiddlewareGroup) RequireEmailVerified() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
				"code":  ErrCodeUnauthorized,
			})
			return
		}

		if !user.EmailVerified {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "email verification required",
				"code":  ErrCodeForbidden,
			})
			return
		}

		c.Next()
	}
}

// =============================================================================
// Organization Middlewares
// =============================================================================

// RequireOrgContext middleware loads organization from URL param and validates membership
func (m *MiddlewareGroup) RequireOrgContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := GetUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
				"code":  ErrCodeUnauthorized,
			})
			return
		}

		// Get organization ID from URL param
		orgIDStr := c.Param("orgId")
		if orgIDStr == "" {
			orgIDStr = c.Param("orgSlug")
		}

		if orgIDStr == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "organization ID or slug required",
				"code":  ErrCodeBadRequest,
			})
			return
		}

		ctx := c.Request.Context()

		// Try to parse as UUID first, otherwise treat as slug
		var org *Organization
		var err error

		orgID, parseErr := parseUUID(orgIDStr)
		if parseErr == nil {
			// It's a UUID
			orgRow, err := m.t.db.GetOrganizationByID(ctx, orgID)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
					"error": "organization not found",
					"code":  ErrCodeNotFound,
				})
				return
			}
			org = orgRowToOrganization(orgRow)
		} else {
			// Treat as slug
			orgRow, err := m.t.db.GetOrganizationBySlug(ctx, orgIDStr)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
					"error": "organization not found",
					"code":  ErrCodeNotFound,
				})
				return
			}
			org = orgRowToOrganization(orgRow)
		}

		if org == nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "organization not found",
				"code":  ErrCodeNotFound,
			})
			return
		}

		// Check if organization is active
		if org.Status != OrgStatusActive {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "organization is not active",
				"code":  ErrCodeForbidden,
			})
			return
		}

		// Load user's membership in this org
		membership, err := m.t.db.GetOrganizationMember(ctx, org.ID, user.ID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "you are not a member of this organization",
				"code":  ErrCodeForbidden,
			})
			return
		}

		// Check membership status
		if membership.Status != "active" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "your membership is not active",
				"code":  ErrCodeForbidden,
			})
			return
		}

		// Load role
		role, _ := m.t.db.GetRoleByID(ctx, membership.RoleID)

		// Create OrganizationMember object
		orgMember := &OrganizationMember{
			ID:             membership.ID,
			OrganizationID: membership.OrganizationID,
			UserID:         membership.UserID,
			RoleID:         membership.RoleID,
			Status:         membership.Status,
			CreatedAt:      membership.CreatedAt,
			UpdatedAt:      membership.UpdatedAt,
		}
		if role != nil {
			orgMember.Role = &Role{
				ID:          role.ID,
				Name:        role.Name,
				Scope:       role.Scope,
				IsSystem:    role.IsSystem,
				CreatedAt:   role.CreatedAt,
				UpdatedAt:   role.UpdatedAt,
			}
			if role.Description != nil {
				orgMember.Role.Description = *role.Description
			}
		}
		orgMember.Organization = org

		// Load user's permissions for this org
		permissions, _ := m.t.db.GetUserOrganizationPermissions(ctx, user.ID, org.ID)
		if permissions == nil {
			permissions = []string{}
		}

		// Set in context
		setOrganization(c, org)
		setMembership(c, orgMember)
		setPermissions(c, permissions)

		c.Next()
	}
}

// parseUUID is a helper to parse UUID strings
func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// =============================================================================
// Permission Middlewares
// =============================================================================

// RequirePermission middleware checks if user has any of the specified permissions
func (m *MiddlewareGroup) RequirePermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(permissions) == 0 {
			c.Next()
			return
		}

		for _, perm := range permissions {
			if HasPermission(c, perm) {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "insufficient permissions",
			"code":  ErrCodeForbidden,
		})
	}
}

// RequireAllPermissions middleware checks if user has all of the specified permissions
func (m *MiddlewareGroup) RequireAllPermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, perm := range permissions {
			if !HasPermission(c, perm) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "insufficient permissions",
					"code":  ErrCodeForbidden,
				})
				return
			}
		}
		c.Next()
	}
}

// =============================================================================
// Role Middlewares
// =============================================================================

// RequireRole middleware checks if user has any of the specified roles
func (m *MiddlewareGroup) RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		membership := GetMembership(c)
		if membership == nil || membership.Role == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "access denied",
				"code":  ErrCodeForbidden,
			})
			return
		}

		for _, role := range roles {
			if membership.Role.Name == role {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "role required",
			"code":  ErrCodeForbidden,
		})
	}
}

// RequireAdmin middleware checks for system admin role
func (m *MiddlewareGroup) RequireAdmin() gin.HandlerFunc {
	return m.RequirePermission("admin:*")
}

// =============================================================================
// Feature Flag Middlewares
// =============================================================================

// RequireFeature middleware checks if feature flag is enabled for user/org
func (m *MiddlewareGroup) RequireFeature(key string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !IsFeatureEnabled(c, key) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "feature not available",
				"code":  ErrCodeForbidden,
			})
			return
		}
		c.Next()
	}
}

// =============================================================================
// Rate Limiting Middleware
// =============================================================================

// RateLimitOptions configures rate limiting
type RateLimitOptions struct {
	RequestsPerMinute int
	ByIP              bool
	ByUser            bool
}

// RateLimit middleware limits requests
func (m *MiddlewareGroup) RateLimit(opts RateLimitOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement rate limiting
		c.Next()
	}
}

// =============================================================================
// CSRF Middleware
// =============================================================================

// CSRF middleware provides CSRF protection for form submissions
func (m *MiddlewareGroup) CSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip for GET, HEAD, OPTIONS
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// TODO: Validate CSRF token
		c.Next()
	}
}

// =============================================================================
// Audit Log Middleware
// =============================================================================

// AuditLog middleware logs requests to audit log
func (m *MiddlewareGroup) AuditLog(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// After handler completes, log the action
		// TODO: Implement audit logging
	}
}
