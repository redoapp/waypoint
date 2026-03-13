package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	tabStyle = lipgloss.NewStyle().
			Padding(0, 2)

	activeTabStyle = tabStyle.
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62"))

	inactiveTabStyle = tabStyle.
				Foreground(lipgloss.Color("250"))

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("252")).
			BorderBottom(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240"))

	cellStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("236"))

	healthyStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("76"))
	warningStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	criticalStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("248"))

	confirmStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("214"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))
)

func healthStyle(status string) lipgloss.Style {
	switch status {
	case "healthy":
		return healthyStyle
	case "warning":
		return warningStyle
	default:
		return criticalStyle
	}
}
