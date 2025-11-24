package t7qoq

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed dashboard/dist/*
var dashboardFiles embed.FS

// getDashboardFS returns the filesystem for the dashboard
func getDashboardFS() (http.FileSystem, error) {
	subFS, err := fs.Sub(dashboardFiles, "dashboard/dist")
	if err != nil {
		return nil, err
	}
	return http.FS(subFS), nil
}

// serveAdminPanelEmbed serves the embedded React admin panel (index.html for SPA routing)
func (t *T7qoq) serveAdminPanelEmbed(c *gin.Context) {
	fsys, err := getDashboardFS()
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to load admin panel")
		return
	}

	// Always serve index.html for SPA routing
	c.FileFromFS("index.html", fsys)
}

// serveAdminAssets serves the static assets for the admin panel
func (t *T7qoq) serveAdminAssets(c *gin.Context) {
	fsys, err := getDashboardFS()
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to load assets")
		return
	}

	path := c.Param("filepath")
	c.FileFromFS("assets"+path, fsys)
}
