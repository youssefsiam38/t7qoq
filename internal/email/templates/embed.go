package templates

import "embed"

//go:embed *.html
var EmailTemplates embed.FS
