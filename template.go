package t7qoq

import (
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/youssefsiam38/t7qoq/templates"
)

// TemplateData holds common data for templates
type TemplateData struct {
	Title      string
	AppName    string
	Theme      Theme
	AuthPrefix string
	Error      string
	Success    string
	User       *User
	Token      string
	Email      string
}

// templateRenderer handles HTML template rendering
type templateRenderer struct {
	templates *template.Template
}

// newTemplateRenderer creates a new template renderer
func newTemplateRenderer(customDir string) (*templateRenderer, error) {
	var tmpl *template.Template
	var err error

	if customDir != "" {
		// Load custom templates from directory
		tmpl, err = template.ParseGlob(filepath.Join(customDir, "*.html"))
		if err != nil {
			return nil, err
		}
	} else {
		// Load embedded templates
		tmpl = template.New("")
		err = fs.WalkDir(templates.EmbedTemplates, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Ext(path) != ".html" {
				return nil
			}
			content, err := templates.EmbedTemplates.ReadFile(path)
			if err != nil {
				return err
			}
			_, err = tmpl.New(path).Parse(string(content))
			return err
		})
		if err != nil {
			return nil, err
		}
	}

	return &templateRenderer{templates: tmpl}, nil
}

// render renders a template with the given data
func (r *templateRenderer) render(c *gin.Context, templateName string, data TemplateData) {
	c.Header("Content-Type", "text/html; charset=utf-8")

	// Try to render as embedded template
	if err := r.templates.ExecuteTemplate(c.Writer, templateName, data); err != nil {
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// SetupTemplates initializes templates for the Gin engine
func (t *T7qoq) SetupTemplates(router *gin.Engine) error {
	renderer, err := newTemplateRenderer(t.config.CustomTemplatesDir)
	if err != nil {
		return err
	}

	// Store renderer in t7qoq instance
	t.templateRenderer = renderer

	return nil
}

// getTemplateData creates common template data
func (t *T7qoq) getTemplateData(title string) TemplateData {
	return TemplateData{
		Title:      title,
		AppName:    t.config.AppName,
		Theme:      t.getTheme(),
		AuthPrefix: t.config.AuthRoutesPrefix,
	}
}

// getTheme returns the current theme settings
func (t *T7qoq) getTheme() Theme {
	// TODO: Load from database settings
	return Theme{
		PrimaryColor:    "#4F46E5",
		SecondaryColor:  "#7C3AED",
		AccentColor:     "#06B6D4",
		BackgroundColor: "#F9FAFB",
		TextColor:       "#111827",
		AppName:         t.config.AppName,
	}
}
