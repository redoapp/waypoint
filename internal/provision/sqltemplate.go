package provision

import (
	"bytes"
	"fmt"
	"text/template"
)

// SQLTemplateData holds the variables available in SQL templates.
type SQLTemplateData struct {
	Role string // Sanitized PG role identifier
}

// renderSQL executes a SQL template string with the given data.
func renderSQL(tmpl string, data SQLTemplateData) (string, error) {
	t, err := template.New("sql").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("invalid sql template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("sql template execution failed: %w", err)
	}
	return buf.String(), nil
}
