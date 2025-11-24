package t7qoq

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/youssefsiam38/t7qoq/internal/database"
	"github.com/youssefsiam38/t7qoq/internal/email"
	internalJWT "github.com/youssefsiam38/t7qoq/internal/jwt"
)

// T7qoq is the main instance of the authentication layer
type T7qoq struct {
	config           Config
	db               *database.DB
	jwt              *internalJWT.Service
	email            *email.Service
	templateRenderer *templateRenderer
	Middleware       *MiddlewareGroup
}

// MiddlewareGroup holds all middleware functions
type MiddlewareGroup struct {
	t *T7qoq
}

// New creates a new t7qoq instance and runs migrations
func New(config Config) (*T7qoq, error) {
	// Apply defaults
	config.applyDefaults()

	// Validate config
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create database wrapper
	db := &database.DB{Pool: config.DB}

	// Run migrations
	ctx := context.Background()
	if err := db.RunMigrations(ctx); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Create JWT service
	jwtService := internalJWT.NewService(config.JWTSecret, config.AccessTokenExpiry, config.RefreshTokenExpiry)

	// Create email service
	var emailService *email.Service
	if config.SMTP != nil && config.SMTP.Host != "" {
		var err error
		emailService, err = email.NewService(email.Config{
			Host:       config.SMTP.Host,
			Port:       config.SMTP.Port,
			Username:   config.SMTP.Username,
			Password:   config.SMTP.Password,
			From:       config.SMTP.From,
			FromName:   config.SMTP.FromName,
			Encryption: config.SMTP.Encryption,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize email service: %w", err)
		}
	}

	t := &T7qoq{
		config: config,
		db:     db,
		jwt:    jwtService,
		email:  emailService,
	}

	// Initialize template renderer
	renderer, err := newTemplateRenderer(config.CustomTemplatesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize templates: %w", err)
	}
	t.templateRenderer = renderer

	// Create middleware group
	t.Middleware = &MiddlewareGroup{t: t}

	return t, nil
}

// RegisterRoutes registers all t7qoq routes on the Gin engine
func (t *T7qoq) RegisterRoutes(router *gin.Engine) {
	// Store t7qoq instance in context for handlers
	router.Use(func(c *gin.Context) {
		c.Set(ContextKeyT7qoq, t)
		c.Next()
	})

	// Register auth routes
	t.registerAuthRoutes(router)

	// Register admin panel routes
	if t.config.EnableAdminPanel {
		t.registerAdminRoutes(router)
	}
}

// GetDB returns the database pool
func (t *T7qoq) GetDB() *database.DB {
	return t.db
}

// GetConfig returns the configuration (read-only)
func (t *T7qoq) GetConfig() Config {
	return t.config
}

// =============================================================================
// Feature Flags - Context-based (uses user/org from context)
// =============================================================================

// IsFeatureEnabled checks if a feature flag is enabled for the current user/org
func IsFeatureEnabled(c *gin.Context, key string) bool {
	t := getT7qoqInstance(c)
	if t == nil {
		return false
	}

	userID := GetUserID(c)
	orgID := GetOrganizationID(c)

	enabled, _ := t.isFeatureEnabledInternal(c.Request.Context(), key, userID, orgID)
	return enabled
}

// GetFeatureValue gets the value of a feature flag for the current user/org
func GetFeatureValue(c *gin.Context, key string) any {
	t := getT7qoqInstance(c)
	if t == nil {
		return nil
	}

	userID := GetUserID(c)
	orgID := GetOrganizationID(c)

	value, _ := t.getFeatureValueInternal(c.Request.Context(), key, userID, orgID)
	return value
}

// =============================================================================
// Feature Flags - ByID variants (explicit user/org IDs)
// =============================================================================

// IsFeatureEnabledByID checks if a feature flag is enabled for specific user/org
func IsFeatureEnabledByID(c *gin.Context, key string, userID, orgID *uuid.UUID) bool {
	t := getT7qoqInstance(c)
	if t == nil {
		return false
	}

	enabled, _ := t.isFeatureEnabledInternal(c.Request.Context(), key, userID, orgID)
	return enabled
}

// HasPermissionByID checks if a specific user has a permission in specific org
func HasPermissionByID(c *gin.Context, permission string, userID, orgID *uuid.UUID) bool {
	t := getT7qoqInstance(c)
	if t == nil {
		return false
	}

	has, _ := t.hasPermissionInternal(c.Request.Context(), permission, userID, orgID)
	return has
}

// =============================================================================
// Internal helpers
// =============================================================================

// getT7qoqInstance retrieves the t7qoq instance from context
func getT7qoqInstance(c *gin.Context) *T7qoq {
	if t, ok := c.Get(ContextKeyT7qoq); ok {
		if instance, ok := t.(*T7qoq); ok {
			return instance
		}
	}
	return nil
}

// isFeatureEnabledInternal is the internal implementation
func (t *T7qoq) isFeatureEnabledInternal(ctx context.Context, key string, userID, orgID *uuid.UUID) (bool, error) {
	// Get the feature flag
	flag, err := t.db.GetFeatureFlag(ctx, key)
	if err != nil {
		return false, err
	}

	// If flag is globally disabled, return false
	if !flag.IsEnabled {
		return false, nil
	}

	// Check for user/org specific overrides
	override, err := t.db.GetFeatureFlagOverride(ctx, flag.ID, userID, orgID)
	if err == nil && override != nil {
		return *override, nil
	}

	// Return the default state (enabled)
	return true, nil
}

// getFeatureValueInternal is the internal implementation
func (t *T7qoq) getFeatureValueInternal(ctx context.Context, key string, userID, orgID *uuid.UUID) (any, error) {
	// Get the feature flag
	_, err := t.db.GetFeatureFlag(ctx, key)
	if err != nil {
		return nil, err
	}

	// For now, just return whether it's enabled
	enabled, err := t.isFeatureEnabledInternal(ctx, key, userID, orgID)
	if err != nil {
		return nil, err
	}

	return enabled, nil
}

// hasPermissionInternal is the internal implementation
func (t *T7qoq) hasPermissionInternal(ctx context.Context, permission string, userID, orgID *uuid.UUID) (bool, error) {
	if userID == nil {
		return false, nil
	}

	// Check system permissions first
	systemPerms, err := t.db.GetUserSystemPermissions(ctx, *userID)
	if err == nil {
		for _, p := range systemPerms {
			// Check for exact match or admin:* wildcard
			if p == permission || p == "admin:*" {
				return true, nil
			}
			// Check category wildcard
			if len(p) > 2 && p[len(p)-2:] == ":*" {
				category := p[:len(p)-2]
				if len(permission) > len(category) && permission[:len(category)] == category {
					return true, nil
				}
			}
		}
	}

	// If orgID is provided, check org permissions
	if orgID != nil {
		orgPerms, err := t.db.GetUserOrganizationPermissions(ctx, *userID, *orgID)
		if err == nil {
			for _, p := range orgPerms {
				// Check for exact match or wildcard
				if p == permission || p == "org:*" {
					return true, nil
				}
				// Check category wildcard
				if len(p) > 2 && p[len(p)-2:] == ":*" {
					category := p[:len(p)-2]
					if len(permission) > len(category) && permission[:len(category)] == category {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}
