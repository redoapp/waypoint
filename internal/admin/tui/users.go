package tui

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/redoapp/waypoint/internal/monitor"
)

type userAction int

const (
	actionResetConns userAction = iota
	actionResetBytes
	actionResetAll
)

func (a userAction) String() string {
	switch a {
	case actionResetConns:
		return "reset connections"
	case actionResetBytes:
		return "reset bytes"
	case actionResetAll:
		return "reset all"
	default:
		return "unknown"
	}
}

type userModel struct {
	items  []monitor.UserStats
	cursor int
	offset int

	confirming    bool
	pendingAction userAction
}

func newUserModel() userModel {
	return userModel{}
}

func (m userModel) update(msg tea.KeyMsg, store *monitor.Store) (userModel, tea.Cmd) {
	if m.confirming {
		switch msg.String() {
		case "y", "Y":
			m.confirming = false
			action := m.pendingAction
			user := m.selectedUser()
			return m, func() tea.Msg {
				return executeAction(store, user, action)
			}
		case "n", "N", "esc":
			m.confirming = false
			return m, nil
		}
		return m, nil
	}

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
	case "c":
		if len(m.items) > 0 {
			m.confirming = true
			m.pendingAction = actionResetConns
		}
	case "b":
		if len(m.items) > 0 {
			m.confirming = true
			m.pendingAction = actionResetBytes
		}
	case "x":
		if len(m.items) > 0 {
			m.confirming = true
			m.pendingAction = actionResetAll
		}
	}
	return m, nil
}

func (m userModel) selectedUser() string {
	if m.cursor < len(m.items) {
		return m.items[m.cursor].LoginName
	}
	return ""
}

func (m userModel) view(width, height int) string {
	if m.confirming {
		user := m.selectedUser()
		prompt := confirmStyle.Render(
			fmt.Sprintf("Confirm %s for user %q? (y/n)", m.pendingAction, user),
		)
		return lipgloss.JoinVertical(lipgloss.Left, prompt, m.renderTable(width, height-1))
	}

	return m.renderTable(width, height)
}

func (m userModel) renderTable(width, height int) string {
	if len(m.items) == 0 {
		return cellStyle.Render("No users found")
	}

	type col struct {
		header string
		width  int
	}
	cols := []col{
		{"Login Name", 24},
		{"Active Conns", 14},
		{"Total Bytes", 14},
		{"Bandwidth", 0}, // fills remaining
	}

	fixedWidth := 0
	for _, c := range cols {
		fixedWidth += c.width
	}
	remaining := width - fixedWidth
	if remaining < 20 {
		remaining = 20
	}
	cols[3].width = remaining

	// Header.
	var headerCells []string
	for _, c := range cols {
		headerCells = append(headerCells, headerStyle.Width(c.width).Render(c.header))
	}
	header := lipgloss.JoinHorizontal(lipgloss.Top, headerCells...)

	// Visible rows.
	visibleRows := height - 1
	if visibleRows < 1 {
		visibleRows = 1
	}

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
		u := m.items[i]
		cells := []string{
			cellStyle.Width(cols[0].width).Render(truncate(u.LoginName, cols[0].width-1)),
			cellStyle.Width(cols[1].width).Render(fmt.Sprintf("%d", u.ActiveConns)),
			cellStyle.Width(cols[2].width).Render(formatBytes(u.TotalBytes)),
			cellStyle.Width(cols[3].width).Render(truncate(formatBandwidthList(u.Bandwidth), cols[3].width-1)),
		}

		row := lipgloss.JoinHorizontal(lipgloss.Top, cells...)
		if i == m.cursor {
			row = selectedStyle.Width(width).Render(row)
		}
		rows = append(rows, row)
	}

	return lipgloss.JoinVertical(lipgloss.Left, append([]string{header}, rows...)...)
}

func executeAction(store *monitor.Store, user string, action userAction) tea.Msg {
	ctx := context.Background()
	var err error
	var msg string

	switch action {
	case actionResetConns:
		err = store.ResetConns(ctx, user)
		msg = fmt.Sprintf("Reset connections for %s", user)
	case actionResetBytes:
		err = store.ResetBytes(ctx, user)
		msg = fmt.Sprintf("Reset bytes for %s", user)
	case actionResetAll:
		err = store.ResetAll(ctx, user)
		msg = fmt.Sprintf("Reset all for %s", user)
	}

	return actionMsg{message: msg, err: err}
}
