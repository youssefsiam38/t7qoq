package t7qoq

import (
	"html/template"
	"net/http"
	"os"
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
	baseTemplate     *template.Template
	contentTemplates map[string]string // templateName -> content
	customDir        string
}

// newTemplateRenderer creates a new template renderer
func newTemplateRenderer(customDir string) (*templateRenderer, error) {
	renderer := &templateRenderer{
		contentTemplates: make(map[string]string),
		customDir:        customDir,
	}

	if customDir != "" {
		// Load custom base template
		baseContent, err := os.ReadFile(filepath.Join(customDir, "base.html"))
		if err != nil {
			return nil, err
		}
		renderer.baseTemplate, err = template.New("base").Parse(string(baseContent))
		if err != nil {
			return nil, err
		}

		// Load content templates
		files, err := filepath.Glob(filepath.Join(customDir, "*.html"))
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			name := filepath.Base(file)
			if name == "base.html" {
				continue
			}
			content, err := os.ReadFile(file)
			if err != nil {
				return nil, err
			}
			renderer.contentTemplates[name] = string(content)
		}
	} else {
		// Load embedded base template
		baseContent, err := templates.EmbedTemplates.ReadFile("base.html")
		if err != nil {
			return nil, err
		}
		renderer.baseTemplate, err = template.New("base").Parse(string(baseContent))
		if err != nil {
			return nil, err
		}

		// Load embedded content templates
		entries, err := templates.EmbedTemplates.ReadDir(".")
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || entry.Name() == "base.html" {
				continue
			}
			content, err := templates.EmbedTemplates.ReadFile(entry.Name())
			if err != nil {
				return nil, err
			}
			renderer.contentTemplates[entry.Name()] = string(content)
		}
	}

	return renderer, nil
}

// render renders a template with the given data
func (r *templateRenderer) render(c *gin.Context, templateName string, data TemplateData) {
	c.Header("Content-Type", "text/html; charset=utf-8")

	// Get content template
	content, ok := r.contentTemplates[templateName]
	if !ok {
		c.String(http.StatusInternalServerError, "Template not found: %s", templateName)
		return
	}

	// Clone base template and parse content into it
	tmpl, err := r.baseTemplate.Clone()
	if err != nil {
		c.String(http.StatusInternalServerError, "Template clone error: %v", err)
		return
	}

	// Parse the content template which defines the "content" block
	_, err = tmpl.Parse(content)
	if err != nil {
		c.String(http.StatusInternalServerError, "Template parse error: %v", err)
		return
	}

	// Execute the "base" template
	if err := tmpl.ExecuteTemplate(c.Writer, "base", data); err != nil {
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
