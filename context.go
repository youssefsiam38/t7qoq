package t7qoq

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Context keys for storing auth data
const (
	ContextKeyUser         = "t7qoq_user"
	ContextKeyOrganization = "t7qoq_organization"
	ContextKeyMembership   = "t7qoq_membership"
	ContextKeyPermissions  = "t7qoq_permissions"
	ContextKeySession      = "t7qoq_session"
	ContextKeyT7qoq        = "t7qoq_instance"
)

// GetUser retrieves the authenticated user from context
func GetUser(c *gin.Context) *User {
	if user, ok := c.Get(ContextKeyUser); ok {
		if u, ok := user.(*User); ok {
			return u
		}
	}
	return nil
}

// GetUserID retrieves the authenticated user's ID from context
func GetUserID(c *gin.Context) *uuid.UUID {
	user := GetUser(c)
	if user == nil {
		return nil
	}
	return &user.ID
}

// GetOrganization retrieves the current organization from context
func GetOrganization(c *gin.Context) *Organization {
	if org, ok := c.Get(ContextKeyOrganization); ok {
		if o, ok := org.(*Organization); ok {
			return o
		}
	}
	return nil
}

// GetOrganizationID retrieves the current organization's ID from context
func GetOrganizationID(c *gin.Context) *uuid.UUID {
	org := GetOrganization(c)
	if org == nil {
		return nil
	}
	return &org.ID
}

// GetMembership retrieves the user's membership in the current organization
func GetMembership(c *gin.Context) *OrganizationMember {
	if m, ok := c.Get(ContextKeyMembership); ok {
		if membership, ok := m.(*OrganizationMember); ok {
			return membership
		}
	}
	return nil
}

// GetPermissions retrieves the user's permissions for the current context
func GetPermissions(c *gin.Context) []string {
	if perms, ok := c.Get(ContextKeyPermissions); ok {
		if p, ok := perms.([]string); ok {
			return p
		}
	}
	return nil
}

// GetSession retrieves the current session from context
func GetSession(c *gin.Context) *Session {
	if s, ok := c.Get(ContextKeySession); ok {
		if session, ok := s.(*Session); ok {
			return session
		}
	}
	return nil
}

// HasPermission checks if the user has a specific permission
func HasPermission(c *gin.Context, permission string) bool {
	perms := GetPermissions(c)
	for _, p := range perms {
		// Check for exact match or wildcard
		if p == permission || p == "admin:*" {
			return true
		}
		// Check for category wildcard (e.g., "users:*" matches "users:read")
		if len(p) > 2 && p[len(p)-2:] == ":*" {
			category := p[:len(p)-2]
			if len(permission) > len(category) && permission[:len(category)] == category {
				return true
			}
		}
	}
	return false
}

// HasAnyPermission checks if the user has any of the specified permissions
func HasAnyPermission(c *gin.Context, permissions ...string) bool {
	for _, perm := range permissions {
		if HasPermission(c, perm) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the user has all of the specified permissions
func HasAllPermissions(c *gin.Context, permissions ...string) bool {
	for _, perm := range permissions {
		if !HasPermission(c, perm) {
			return false
		}
	}
	return true
}

// IsAdmin checks if the user has admin system role
func IsAdmin(c *gin.Context) bool {
	return HasPermission(c, "admin:*")
}

// IsAuthenticated checks if there is an authenticated user
func IsAuthenticated(c *gin.Context) bool {
	return GetUser(c) != nil
}

// IsEmailVerified checks if the authenticated user has verified their email
func IsEmailVerified(c *gin.Context) bool {
	user := GetUser(c)
	if user == nil {
		return false
	}
	return user.EmailVerified
}

// IsMemberOfOrg checks if the user is a member of the current organization
func IsMemberOfOrg(c *gin.Context) bool {
	return GetMembership(c) != nil
}

// GetCurrentRole returns the user's role in the current organization
func GetCurrentRole(c *gin.Context) *Role {
	membership := GetMembership(c)
	if membership == nil {
		return nil
	}
	return membership.Role
}

// setUser sets the authenticated user in context (internal use)
func setUser(c *gin.Context, user *User) {
	c.Set(ContextKeyUser, user)
}

// setOrganization sets the current organization in context (internal use)
func setOrganization(c *gin.Context, org *Organization) {
	c.Set(ContextKeyOrganization, org)
}

// setMembership sets the user's membership in context (internal use)
func setMembership(c *gin.Context, membership *OrganizationMember) {
	c.Set(ContextKeyMembership, membership)
}

// setPermissions sets the user's permissions in context (internal use)
func setPermissions(c *gin.Context, permissions []string) {
	c.Set(ContextKeyPermissions, permissions)
}

// setSession sets the current session in context (internal use)
func setSession(c *gin.Context, session *Session) {
	c.Set(ContextKeySession, session)
}
