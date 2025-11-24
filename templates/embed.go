package templates

import "embed"

//go:embed *.html
var EmbedTemplates embed.FS
