package t7qoq

import (
	"github.com/gin-gonic/gin"
)

// registerAuthRoutes registers all authentication routes
func (t *T7qoq) registerAuthRoutes(router *gin.Engine) {
	auth := router.Group(t.config.AuthRoutesPrefix)
	{
		// Public auth routes
		auth.POST("/login", t.handleLogin)
		auth.POST("/register", t.handleRegister)
		auth.POST("/refresh", t.handleRefresh)
		auth.POST("/forgot-password", t.handleForgotPassword)
		auth.POST("/reset-password", t.handleResetPassword)
		auth.GET("/verify-email", t.handleVerifyEmail)

		// 2FA verify - public route for login flow
		if t.config.Enable2FA {
			auth.POST("/2fa/verify", t.handle2FAVerify)
		}

		// Auth UI pages (HTML templates)
		auth.GET("/login", t.renderLoginPage)
		auth.GET("/register", t.renderRegisterPage)
		auth.GET("/forgot-password", t.renderForgotPasswordPage)
		auth.GET("/reset-password", t.renderResetPasswordPage)
		auth.GET("/verify-email-sent", t.renderVerifyEmailSentPage)

		// Protected auth routes
		protected := auth.Group("/")
		protected.Use(t.Middleware.RequireAuth())
		{
			protected.POST("/logout", t.handleLogout)
			protected.GET("/profile", t.renderProfilePage)
			protected.POST("/profile", t.handleUpdateProfile)
			protected.POST("/change-password", t.handleChangePassword)

			// 2FA routes (setup/disable require auth)
			if t.config.Enable2FA {
				protected.GET("/2fa/setup", t.render2FASetupPage)
				protected.POST("/2fa/setup", t.handle2FASetup)
				protected.POST("/2fa/disable", t.handle2FADisable)
			}

			// Session management
			protected.GET("/sessions", t.handleListSessions)
			protected.DELETE("/sessions/:sessionId", t.handleRevokeSession)

			// Organization routes (user-facing)
			protected.GET("/organizations", t.handleListMyOrganizations)
			protected.POST("/organizations", t.handleCreateOrganization)
			protected.GET("/organizations/:orgId", t.handleGetOrganization)
			protected.PUT("/organizations/:orgId", t.handleUpdateOrganization)
			protected.DELETE("/organizations/:orgId", t.handleDeleteOrganization)
			protected.POST("/organizations/:orgId/leave", t.handleLeaveOrganization)

			// Organization members
			protected.GET("/organizations/:orgId/members", t.handleListOrgMembers)
			protected.POST("/organizations/:orgId/members/invite", t.handleInviteMember)
			protected.DELETE("/organizations/:orgId/members/:memberId", t.handleRemoveMember)
			protected.PUT("/organizations/:orgId/members/:memberId/role", t.handleUpdateMemberRole)

			// Organization invitations
			protected.GET("/organizations/:orgId/invites", t.handleListOrgInvites)
			protected.DELETE("/organizations/:orgId/invites/:inviteId", t.handleCancelInvite)

			// Organization roles
			protected.GET("/organizations/:orgId/roles", t.handleListOrgRoles)

			// User invitations
			protected.GET("/invites", t.handleListMyInvites)
			protected.POST("/invites/accept", t.handleAcceptInvite)
		}
	}
}

// registerAdminRoutes registers the admin panel routes
func (t *T7qoq) registerAdminRoutes(router *gin.Engine) {
	admin := router.Group(t.config.AdminRoutesPrefix)
	{
		// Admin panel login (separate from user auth)
		admin.GET("/login", t.renderAdminLoginPage)
		admin.POST("/login", t.handleAdminLogin)

		// Serve static assets for admin panel (public)
		admin.GET("/assets/*filepath", t.serveAdminAssets)

		// Protected admin routes
		protected := admin.Group("/")
		protected.Use(t.Middleware.RequireAuth(), t.Middleware.RequireAdmin())
		{
			// Serve React SPA for admin panel using embedded files
			protected.GET("/", func(c *gin.Context) {
				c.Set("filepath", "/")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/dashboard", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/users", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/users/*path", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/organizations", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/organizations/*path", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/permissions", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/roles", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/roles/*path", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/sessions", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/features", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/features/*path", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/audit", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})
			protected.GET("/settings", func(c *gin.Context) {
				c.Set("filepath", "/index.html")
				t.serveAdminPanelEmbed(c)
			})

			// Admin API endpoints
			api := protected.Group("/api")
			{
				// Users
				api.GET("/users", t.adminListUsers)
				api.GET("/users/:id", t.adminGetUser)
				api.POST("/users", t.adminCreateUser)
				api.PUT("/users/:id", t.adminUpdateUser)
				api.DELETE("/users/:id", t.adminDeleteUser)

				// Organizations
				api.GET("/organizations", t.adminListOrganizations)
				api.GET("/organizations/:id", t.adminGetOrganization)
				api.POST("/organizations", t.adminCreateOrganization)
				api.PUT("/organizations/:id", t.adminUpdateOrganization)
				api.DELETE("/organizations/:id", t.adminDeleteOrganization)

				// Organization members
				api.GET("/organizations/:id/members", t.adminListOrgMembers)
				api.POST("/organizations/:id/members", t.adminAddOrgMember)
				api.DELETE("/organizations/:id/members/:userId", t.adminRemoveOrgMember)

				// Permissions
				api.GET("/permissions", t.adminListPermissions)
				api.POST("/permissions", t.adminCreatePermission)
				api.PUT("/permissions/:id", t.adminUpdatePermission)
				api.DELETE("/permissions/:id", t.adminDeletePermission)

				// Roles
				api.GET("/roles", t.adminListRoles)
				api.GET("/roles/:id", t.adminGetRole)
				api.POST("/roles", t.adminCreateRole)
				api.PUT("/roles/:id", t.adminUpdateRole)
				api.DELETE("/roles/:id", t.adminDeleteRole)

				// Sessions
				api.GET("/sessions", t.adminListSessions)
				api.DELETE("/sessions/:id", t.adminRevokeSession)

				// Feature flags
				api.GET("/features", t.adminListFeatures)
				api.GET("/features/:id", t.adminGetFeature)
				api.POST("/features", t.adminCreateFeature)
				api.PUT("/features/:id", t.adminUpdateFeature)
				api.DELETE("/features/:id", t.adminDeleteFeature)

				// Audit logs
				api.GET("/audit", t.adminListAuditLogs)
				api.GET("/audit/:id", t.adminGetAuditLog)

				// Settings
				api.GET("/settings", t.adminGetSettings)
				api.PUT("/settings", t.adminUpdateSettings)

				// Stats/Dashboard
				api.GET("/stats", t.adminGetStats)
			}
		}
	}
}
