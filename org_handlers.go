package t7qoq

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/youssefsiam38/t7qoq/internal/crypto"
	"github.com/youssefsiam38/t7qoq/internal/database"
)

// =============================================================================
// Organization Request/Response Types
// =============================================================================

// CreateOrganizationRequest represents a request to create an organization
type CreateOrganizationRequest struct {
	Name        string `json:"name" binding:"required,min=2,max=100"`
	Slug        string `json:"slug" binding:"omitempty,min=2,max=50"`
	Description string `json:"description"`
	LogoURL     string `json:"logo_url"`
}

// UpdateOrganizationRequest represents a request to update an organization
type UpdateOrganizationRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	LogoURL     *string `json:"logo_url"`
}

// InviteMemberRequest represents a request to invite a member to an organization
type InviteMemberRequest struct {
	Email  string `json:"email" binding:"required,email"`
	RoleID string `json:"role_id" binding:"required,uuid"`
}

// UpdateMemberRoleRequest represents a request to update a member's role
type UpdateMemberRoleRequest struct {
	RoleID string `json:"role_id" binding:"required,uuid"`
}

// AcceptInviteRequest represents a request to accept an organization invitation
type AcceptInviteRequest struct {
	Token string `json:"token" binding:"required"`
}

// =============================================================================
// User Organization Handlers
// =============================================================================

// handleListMyOrganizations lists all organizations the current user belongs to
func (t *T7qoq) handleListMyOrganizations(c *gin.Context) {
	user := GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	ctx := c.Request.Context()

	memberships, err := t.db.GetUserOrganizations(ctx, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get organizations",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Convert to response format
	var orgs []map[string]any
	for _, m := range memberships {
		org := map[string]any{
			"id":          m.OrganizationID,
			"name":        m.OrgName,
			"slug":        m.OrgSlug,
			"role_id":     m.RoleID,
			"role_name":   m.RoleName,
			"status":      m.Status,
			"joined_at":   m.CreatedAt,
		}
		orgs = append(orgs, org)
	}

	c.JSON(http.StatusOK, gin.H{
		"organizations": orgs,
	})
}

// handleCreateOrganization creates a new organization
func (t *T7qoq) handleCreateOrganization(c *gin.Context) {
	var req CreateOrganizationRequest
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

	// Generate slug if not provided
	slug := req.Slug
	if slug == "" {
		slug = generateSlug(req.Name)
	}

	// Create organization
	orgRow, err := t.db.CreateOrganization(ctx, req.Name, slug, &req.Description)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "organization with this slug already exists",
				"code":  ErrCodeConflict,
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create organization",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Get the "Owner" role for the organization
	ownerRole, err := t.db.GetRoleByName(ctx, "Owner", "organization", nil)
	if err != nil {
		// If Owner role doesn't exist, try to create it
		ownerRole, err = t.db.CreateRole(ctx, "Owner", "organization", nil, "Full access to organization")
		if err != nil {
			// Rollback org creation
			t.db.DeleteOrganization(ctx, orgRow.ID)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to setup organization roles",
				"code":  ErrCodeInternalError,
			})
			return
		}
	}

	// Add creator as owner
	_, err = t.db.AddOrganizationMember(ctx, orgRow.ID, user.ID, ownerRole.ID, nil)
	if err != nil {
		t.db.DeleteOrganization(ctx, orgRow.ID)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to add owner to organization",
			"code":  ErrCodeInternalError,
		})
		return
	}

	org := orgRowToOrganization(orgRow)

	c.JSON(http.StatusCreated, org)
}

// handleGetOrganization gets organization details
func (t *T7qoq) handleGetOrganization(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
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

	// Check if user is a member
	membership, err := t.db.GetOrganizationMember(ctx, orgID, user.ID)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "you are not a member of this organization",
			"code":  ErrCodeForbidden,
		})
		return
	}

	if membership.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "your membership is not active",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Get organization
	orgRow, err := t.db.GetOrganizationByID(ctx, orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "organization not found",
			"code":  ErrCodeNotFound,
		})
		return
	}

	org := orgRowToOrganization(orgRow)

	c.JSON(http.StatusOK, org)
}

// handleUpdateOrganization updates organization details
func (t *T7qoq) handleUpdateOrganization(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	var req UpdateOrganizationRequest
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

	// Check permission (requires org:update permission or Owner role)
	if !t.userCanManageOrg(ctx, user.ID, orgID) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "you don't have permission to update this organization",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Update organization
	err = t.db.UpdateOrganization(ctx, orgID, req.Name, req.Description, req.LogoURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to update organization",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Get updated organization
	orgRow, err := t.db.GetOrganizationByID(ctx, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get organization",
			"code":  ErrCodeInternalError,
		})
		return
	}

	org := orgRowToOrganization(orgRow)

	c.JSON(http.StatusOK, org)
}

// handleDeleteOrganization deletes an organization
func (t *T7qoq) handleDeleteOrganization(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
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

	// Only owner can delete
	if !t.userIsOrgOwner(ctx, user.ID, orgID) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "only the organization owner can delete it",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Delete organization (cascades to memberships, invites, etc.)
	if err := t.db.DeleteOrganization(ctx, orgID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to delete organization",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "organization deleted successfully",
	})
}

// =============================================================================
// Organization Members Handlers
// =============================================================================

// handleListOrgMembers lists all members of an organization
func (t *T7qoq) handleListOrgMembers(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
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

	// Check if user is a member
	_, err = t.db.GetOrganizationMember(ctx, orgID, user.ID)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "you are not a member of this organization",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Get members
	members, err := t.db.GetOrganizationMembers(ctx, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get members",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Convert to response format
	var result []map[string]any
	for _, m := range members {
		member := map[string]any{
			"id":         m.ID,
			"user_id":    m.UserID,
			"email":      m.UserEmail,
			"first_name": m.UserFirstName,
			"last_name":  m.UserLastName,
			"avatar_url": m.UserAvatarURL,
			"role_id":    m.RoleID,
			"role_name":  m.RoleName,
			"status":     m.Status,
			"joined_at":  m.CreatedAt,
		}
		result = append(result, member)
	}

	c.JSON(http.StatusOK, gin.H{
		"members": result,
	})
}

// handleInviteMember invites a user to an organization
func (t *T7qoq) handleInviteMember(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	var req InviteMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid role ID",
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

	// Check permission
	if !t.userCanManageOrgMembers(ctx, user.ID, orgID) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "you don't have permission to invite members",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Check if user is already a member
	existingMember, _ := t.db.GetOrganizationMemberByEmail(ctx, orgID, strings.ToLower(req.Email))
	if existingMember != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "user is already a member of this organization",
			"code":  ErrCodeConflict,
		})
		return
	}

	// Check for existing pending invite
	existingInvite, _ := t.db.GetPendingInviteByEmail(ctx, orgID, strings.ToLower(req.Email))
	if existingInvite != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error": "an invitation has already been sent to this email",
			"code":  ErrCodeConflict,
		})
		return
	}

	// Generate invite token
	token, err := crypto.GenerateToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to generate invitation token",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Create invitation (expires in 7 days)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	invite, err := t.db.CreateOrganizationInvite(ctx, orgID, strings.ToLower(req.Email), roleID, user.ID, token, expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create invitation",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Get org name for email
	orgRow, _ := t.db.GetOrganizationByID(ctx, orgID)
	orgName := ""
	if orgRow != nil {
		orgName = orgRow.Name
	}

	// Send invitation email
	go t.sendOrganizationInviteEmail(c.Copy(), req.Email, user.FullName(), orgName, token)

	c.JSON(http.StatusCreated, gin.H{
		"message":   "invitation sent successfully",
		"invite_id": invite.ID,
	})
}

// handleAcceptInvite accepts an organization invitation
func (t *T7qoq) handleAcceptInvite(c *gin.Context) {
	var req AcceptInviteRequest
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

	// Get invite by token
	invite, err := t.db.GetInviteByToken(ctx, req.Token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid or expired invitation",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	// Check if invite is for this user's email
	if strings.ToLower(invite.Email) != strings.ToLower(user.Email) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "this invitation is for a different email address",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Check if already a member
	existingMember, _ := t.db.GetOrganizationMember(ctx, invite.OrganizationID, user.ID)
	if existingMember != nil {
		// Mark invite as accepted and return success
		t.db.AcceptInvite(ctx, invite.ID)
		c.JSON(http.StatusOK, gin.H{
			"message": "you are already a member of this organization",
		})
		return
	}

	// Add user to organization
	_, err = t.db.AddOrganizationMember(ctx, invite.OrganizationID, user.ID, invite.RoleID, &invite.InvitedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to join organization",
			"code":  ErrCodeInternalError,
		})
		return
	}

	// Mark invite as accepted
	t.db.AcceptInvite(ctx, invite.ID)

	// Get organization details
	orgRow, _ := t.db.GetOrganizationByID(ctx, invite.OrganizationID)
	var org *Organization
	if orgRow != nil {
		org = orgRowToOrganization(orgRow)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "successfully joined organization",
		"organization": org,
	})
}

// handleRemoveMember removes a member from an organization
func (t *T7qoq) handleRemoveMember(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	memberID, err := uuid.Parse(c.Param("memberId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid member ID",
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

	// Check permission
	if !t.userCanManageOrgMembers(ctx, user.ID, orgID) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "you don't have permission to remove members",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Get member to be removed
	member, err := t.db.GetOrganizationMemberByID(ctx, memberID)
	if err != nil || member.OrganizationID != orgID {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "member not found",
			"code":  ErrCodeNotFound,
		})
		return
	}

	// Can't remove yourself this way - use leave endpoint
	if member.UserID == user.ID {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "use the leave endpoint to leave the organization",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	// Can't remove the owner
	if t.userIsOrgOwner(ctx, member.UserID, orgID) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "cannot remove the organization owner",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Remove member
	if err := t.db.RemoveOrganizationMember(ctx, memberID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to remove member",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "member removed successfully",
	})
}

// handleLeaveOrganization allows a user to leave an organization
func (t *T7qoq) handleLeaveOrganization(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
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

	// Check if user is a member
	membership, err := t.db.GetOrganizationMember(ctx, orgID, user.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "you are not a member of this organization",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	// Owner can't leave - must transfer ownership or delete org
	if t.userIsOrgOwner(ctx, user.ID, orgID) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "organization owner cannot leave. Transfer ownership or delete the organization.",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Remove membership
	if err := t.db.RemoveOrganizationMember(ctx, membership.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to leave organization",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "successfully left organization",
	})
}

// handleUpdateMemberRole updates a member's role
func (t *T7qoq) handleUpdateMemberRole(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	memberID, err := uuid.Parse(c.Param("memberId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid member ID",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	var req UpdateMemberRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid role ID",
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

	// Check permission
	if !t.userCanManageOrgMembers(ctx, user.ID, orgID) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "you don't have permission to update member roles",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Get member
	member, err := t.db.GetOrganizationMemberByID(ctx, memberID)
	if err != nil || member.OrganizationID != orgID {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "member not found",
			"code":  ErrCodeNotFound,
		})
		return
	}

	// Can't change owner's role
	if t.userIsOrgOwner(ctx, member.UserID, orgID) && member.UserID != user.ID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "cannot change the organization owner's role",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Update role
	if err := t.db.UpdateOrganizationMemberRole(ctx, memberID, roleID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to update member role",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "member role updated successfully",
	})
}

// handleListOrgInvites lists pending invitations for an organization
func (t *T7qoq) handleListOrgInvites(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
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

	// Check permission
	if !t.userCanManageOrgMembers(ctx, user.ID, orgID) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "you don't have permission to view invitations",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Get invites
	invites, err := t.db.GetOrganizationInvites(ctx, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get invitations",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"invitations": invites,
	})
}

// handleCancelInvite cancels a pending invitation
func (t *T7qoq) handleCancelInvite(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
			"code":  ErrCodeBadRequest,
		})
		return
	}

	inviteID, err := uuid.Parse(c.Param("inviteId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid invitation ID",
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

	// Check permission
	if !t.userCanManageOrgMembers(ctx, user.ID, orgID) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "you don't have permission to cancel invitations",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Cancel invite
	if err := t.db.CancelInvite(ctx, inviteID, orgID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to cancel invitation",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "invitation cancelled successfully",
	})
}

// handleListMyInvites lists pending invitations for the current user
func (t *T7qoq) handleListMyInvites(c *gin.Context) {
	user := GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
			"code":  ErrCodeUnauthorized,
		})
		return
	}

	ctx := c.Request.Context()

	invites, err := t.db.GetUserPendingInvites(ctx, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get invitations",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"invitations": invites,
	})
}

// =============================================================================
// Organization Roles Handlers
// =============================================================================

// handleListOrgRoles lists roles available for an organization
func (t *T7qoq) handleListOrgRoles(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid organization ID",
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

	// Check if user is a member
	_, err = t.db.GetOrganizationMember(ctx, orgID, user.ID)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "you are not a member of this organization",
			"code":  ErrCodeForbidden,
		})
		return
	}

	// Get organization roles (both default org roles and org-specific)
	roles, err := t.db.GetOrganizationRoles(ctx, &orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get roles",
			"code":  ErrCodeInternalError,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"roles": roles,
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

// userCanManageOrg checks if user can manage org settings
func (t *T7qoq) userCanManageOrg(ctx context.Context, userID, orgID uuid.UUID) bool {
	// Check for org:update or org:* permission
	return t.userHasOrgPermission(ctx, userID, orgID, "org:update") ||
		t.userHasOrgPermission(ctx, userID, orgID, "org:*")
}

// userCanManageOrgMembers checks if user can manage org members
func (t *T7qoq) userCanManageOrgMembers(ctx context.Context, userID, orgID uuid.UUID) bool {
	// Check for org:members or org:* permission
	return t.userHasOrgPermission(ctx, userID, orgID, "org:members") ||
		t.userHasOrgPermission(ctx, userID, orgID, "org:*")
}

// userIsOrgOwner checks if user is the organization owner
func (t *T7qoq) userIsOrgOwner(ctx context.Context, userID, orgID uuid.UUID) bool {
	membership, err := t.db.GetOrganizationMember(ctx, orgID, userID)
	if err != nil {
		return false
	}

	role, err := t.db.GetRoleByID(ctx, membership.RoleID)
	if err != nil {
		return false
	}

	return role.Name == "Owner"
}

// userHasOrgPermission checks if user has a specific org permission
func (t *T7qoq) userHasOrgPermission(ctx context.Context, userID, orgID uuid.UUID, permission string) bool {
	permissions, err := t.db.GetUserOrganizationPermissions(ctx, userID, orgID)
	if err != nil {
		return false
	}

	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// orgRowToOrganization converts a database organization row to the public Organization type
func orgRowToOrganization(row *database.OrganizationRow) *Organization {
	if row == nil {
		return nil
	}

	org := &Organization{
		ID:        row.ID,
		Name:      row.Name,
		Slug:      row.Slug,
		Status:    OrgStatus(row.Status),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}

	if row.Description != nil {
		org.Description = *row.Description
	}
	if row.LogoURL != nil {
		org.LogoURL = *row.LogoURL
	}
	if row.Plan != nil {
		org.Plan = *row.Plan
	}

	return org
}

// generateSlug creates a URL-friendly slug from a name
func generateSlug(name string) string {
	slug := strings.ToLower(name)
	slug = strings.ReplaceAll(slug, " ", "-")
	// Remove non-alphanumeric characters except hyphens
	var result []rune
	for _, r := range slug {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result = append(result, r)
		}
	}
	return string(result)
}

// sendOrganizationInviteEmail sends an organization invitation email
func (t *T7qoq) sendOrganizationInviteEmail(c *gin.Context, toEmail, inviterName, orgName, token string) error {
	if t.email == nil || !t.email.IsConfigured() {
		return nil
	}

	inviteURL := t.buildURL(c, t.config.AuthRoutesPrefix+"/accept-invite", map[string]string{
		"token": token,
	})

	data := t.getEmailData()
	return t.email.SendOrganizationInviteEmail(toEmail, inviterName, orgName, inviteURL, data)
}
