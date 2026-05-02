package provision

import (
	"fmt"
	"strings"
)

// presetHint returns a helpful error message when a permissions entry is not a valid preset.
func presetHint(input string) string {
	lower := strings.ToLower(strings.TrimSpace(input))

	// Bare privilege keywords → suggest preset
	switch lower {
	case "select", "read":
		return fmt.Sprintf("unknown preset %q; did you mean \"readonly\"? Valid presets: %s", input, strings.Join(PresetNames, ", "))
	case "insert", "update", "delete", "write":
		return fmt.Sprintf("unknown preset %q; did you mean \"readwrite\"? Valid presets: %s", input, strings.Join(PresetNames, ", "))
	case "all":
		return fmt.Sprintf("unknown preset %q; did you mean \"admin\"? Valid presets: %s", input, strings.Join(PresetNames, ", "))
	}

	// Looks like old-style GRANT fragment
	if strings.Contains(lower, " on ") {
		return fmt.Sprintf("permissions now accepts preset names only; %q looks like a GRANT fragment — move it to the \"sql\" field as \"GRANT %s TO {{.Role}}\". Valid presets: %s", input, input, strings.Join(PresetNames, ", "))
	}

	return fmt.Sprintf("unknown preset %q; valid presets: %s", input, strings.Join(PresetNames, ", "))
}
