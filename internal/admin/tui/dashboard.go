package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/redoapp/waypoint/internal/monitor"
)

type instanceModel struct {
	items  []monitor.InstanceInfo
	cursor int
	offset int // scroll offset
}

func newInstanceModel() instanceModel {
	return instanceModel{}
}

func (m instanceModel) update(msg tea.KeyMsg) instanceModel {
	switch msg.String() {
	case "j", "down":
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "g":
		m.cursor = 0
	case "G":
		if len(m.items) > 0 {
			m.cursor = len(m.items) - 1
		}
	}
	return m
}

func (m instanceModel) view(width, height int) string {
	if len(m.items) == 0 {
		return cellStyle.Render("No instances found")
	}

	// Column definitions: header, width, alignment.
	type col struct {
		header string
		width  int
	}
	cols := []col{
		{"Health", 10},
		{"Hostname", 16},
		{"Instance ID", 14},
		{"Uptime", 12},
		{"Listeners", 20},
		{"Active", 8},
		{"Total", 8},
		{"Bytes R", 10},
		{"Bytes W", 10},
	}

	// Adjust last column to fill remaining width.
	totalFixed := 0
	for _, c := range cols {
		totalFixed += c.width
	}
	if width > totalFixed {
		cols[4].width += width - totalFixed // expand Listeners
	}

	// Header row.
	var headerCells []string
	for _, c := range cols {
		headerCells = append(headerCells, headerStyle.Width(c.width).Render(c.header))
	}
	header := lipgloss.JoinHorizontal(lipgloss.Top, headerCells...)

	// Visible rows (subtract 1 for header).
	visibleRows := height - 1
	if visibleRows < 1 {
		visibleRows = 1
	}

	// Scroll to keep cursor visible.
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+visibleRows {
		m.offset = m.cursor - visibleRows + 1
	}

	var rows []string
	end := m.offset + visibleRows
	if end > len(m.items) {
		end = len(m.items)
	}

	for i := m.offset; i < end; i++ {
		inst := m.items[i]
		status := inst.HealthStatus()
		healthLabel := healthStyle(status).Render(status)

		cells := []string{
			cellStyle.Width(cols[0].width).Render(healthLabel),
			cellStyle.Width(cols[1].width).Render(truncate(inst.Hostname, cols[1].width-1)),
			cellStyle.Width(cols[2].width).Render(truncate(inst.ID, cols[2].width-1)),
			cellStyle.Width(cols[3].width).Render(inst.Uptime().String()),
			cellStyle.Width(cols[4].width).Render(truncate(inst.Listeners, cols[4].width-1)),
			cellStyle.Width(cols[5].width).Render(fmt.Sprintf("%d", inst.ActiveConns)),
			cellStyle.Width(cols[6].width).Render(fmt.Sprintf("%d", inst.TotalConns)),
			cellStyle.Width(cols[7].width).Render(formatBytes(inst.BytesRead)),
			cellStyle.Width(cols[8].width).Render(formatBytes(inst.BytesWritten)),
		}

		row := lipgloss.JoinHorizontal(lipgloss.Top, cells...)
		if i == m.cursor {
			row = selectedStyle.Width(width).Render(row)
		}
		rows = append(rows, row)
	}

	return lipgloss.JoinVertical(lipgloss.Left, append([]string{header}, rows...)...)
}

func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func formatBandwidthList(stats []monitor.BandwidthStat) string {
	if len(stats) == 0 {
		return "none"
	}
	var parts []string
	for _, s := range stats {
		parts = append(parts, fmt.Sprintf("%s: %s", s.PeriodStr, formatBytes(s.Bytes)))
	}
	return strings.Join(parts, ", ")
}
