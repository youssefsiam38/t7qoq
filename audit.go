package t7qoq

import (
	"context"
	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuditAction represents different types of audit actions
type AuditAction string

const (
	AuditActionUserLogin          AuditAction = "user.login"
	AuditActionUserLogout         AuditAction = "user.logout"
	AuditActionUserRegister       AuditAction = "user.register"
	AuditActionUserUpdate         AuditAction = "user.update"
	AuditActionUserDelete         AuditAction = "user.delete"
	AuditActionUserPasswordChange AuditAction = "user.password_change"
	AuditActionUserPasswordReset  AuditAction = "user.password_reset"
	AuditActionUser2FAEnable      AuditAction = "user.2fa_enable"
	AuditActionUser2FADisable     AuditAction = "user.2fa_disable"
	AuditActionUserEmailVerify    AuditAction = "user.email_verify"

	AuditActionOrgCreate       AuditAction = "org.create"
	AuditActionOrgUpdate       AuditAction = "org.update"
	AuditActionOrgDelete       AuditAction = "org.delete"
	AuditActionOrgMemberAdd    AuditAction = "org.member_add"
	AuditActionOrgMemberRemove AuditAction = "org.member_remove"
	AuditActionOrgMemberUpdate AuditAction = "org.member_update"
	AuditActionOrgInviteCreate AuditAction = "org.invite_create"
	AuditActionOrgInviteAccept AuditAction = "org.invite_accept"
	AuditActionOrgInviteCancel AuditAction = "org.invite_cancel"

	AuditActionRoleCreate        AuditAction = "role.create"
	AuditActionRoleUpdate        AuditAction = "role.update"
	AuditActionRoleDelete        AuditAction = "role.delete"
	AuditActionPermissionCreate  AuditAction = "permission.create"
	AuditActionPermissionUpdate  AuditAction = "permission.update"
	AuditActionPermissionDelete  AuditAction = "permission.delete"

	AuditActionFeatureCreate AuditAction = "feature.create"
	AuditActionFeatureUpdate AuditAction = "feature.update"
	AuditActionFeatureDelete AuditAction = "feature.delete"

	AuditActionSettingsUpdate AuditAction = "settings.update"
	AuditActionSessionRevoke  AuditAction = "session.revoke"
)

// AuditResourceType represents the type of resource being audited
type AuditResourceType string

const (
	AuditResourceUser         AuditResourceType = "user"
	AuditResourceOrganization AuditResourceType = "organization"
	AuditResourceRole         AuditResourceType = "role"
	AuditResourcePermission   AuditResourceType = "permission"
	AuditResourceFeature      AuditResourceType = "feature"
	AuditResourceSession      AuditResourceType = "session"
	AuditResourceSettings     AuditResourceType = "settings"
	AuditResourceInvite       AuditResourceType = "invite"
)

// AuditEntry represents an entry in the audit log
type AuditEntry struct {
	ActorID        *uuid.UUID
	ActorType      string // "user", "system", "api"
	ActorIP        string
	ActorUserAgent string
	OrganizationID *uuid.UUID
	Action         AuditAction
	ResourceType   AuditResourceType
	ResourceID     *uuid.UUID
	OldValues      map[string]any
	NewValues      map[string]any
	Metadata       map[string]any
}

// LogAudit logs an audit entry to the database
func (t *T7qoq) LogAudit(ctx context.Context, entry AuditEntry) error {
	oldValuesJSON, _ := json.Marshal(entry.OldValues)
	newValuesJSON, _ := json.Marshal(entry.NewValues)
	metadataJSON, _ := json.Marshal(entry.Metadata)

	return t.db.CreateAuditLog(ctx,
		entry.ActorID,
		entry.ActorType,
		entry.ActorIP,
		entry.ActorUserAgent,
		entry.OrganizationID,
		string(entry.Action),
		string(entry.ResourceType),
		entry.ResourceID,
		oldValuesJSON,
		newValuesJSON,
		metadataJSON,
	)
}

// LogAuditFromContext logs an audit entry using context information
func (t *T7qoq) LogAuditFromContext(c *gin.Context, action AuditAction, resourceType AuditResourceType, resourceID *uuid.UUID, oldValues, newValues, metadata map[string]any) {
	user := GetUser(c)
	org := GetOrganization(c)

	entry := AuditEntry{
		ActorType:    "user",
		ActorIP:      c.ClientIP(),
		ActorUserAgent: c.GetHeader("User-Agent"),
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		OldValues:    oldValues,
		NewValues:    newValues,
		Metadata:     metadata,
	}

	if user != nil {
		entry.ActorID = &user.ID
	}
	if org != nil {
		entry.OrganizationID = &org.ID
	}

	// Log asynchronously to avoid blocking the request
	go func() {
		ctx := context.Background()
		t.LogAudit(ctx, entry)
	}()
}

// LogUserAction is a helper for logging user-related actions
func (t *T7qoq) LogUserAction(c *gin.Context, action AuditAction, userID uuid.UUID, metadata map[string]any) {
	t.LogAuditFromContext(c, action, AuditResourceUser, &userID, nil, nil, metadata)
}

// LogOrgAction is a helper for logging organization-related actions
func (t *T7qoq) LogOrgAction(c *gin.Context, action AuditAction, orgID uuid.UUID, metadata map[string]any) {
	t.LogAuditFromContext(c, action, AuditResourceOrganization, &orgID, nil, nil, metadata)
}
