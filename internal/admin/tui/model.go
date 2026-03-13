package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/redoapp/waypoint/internal/monitor"
)

const (
	tabInstances = iota
	tabUsers
)

const refreshInterval = 5 * time.Second

// tickMsg triggers a data refresh.
type tickMsg struct{}

// dataMsg carries refreshed data from Redis.
type dataMsg struct {
	instances []monitor.InstanceInfo
	users     []monitor.UserStats
	err       error
}

// actionMsg is the result of a user management action.
type actionMsg struct {
	message string
	err     error
}

// Model is the root Bubble Tea model for the admin TUI.
type Model struct {
	store     *monitor.Store
	loginName string

	width  int
	height int

	activeTab int
	instances instanceModel
	users     userModel

	status    string
	statusErr bool
}

// NewModel creates the root TUI model.
func NewModel(store *monitor.Store, loginName string, width, height int) Model {
	return Model{
		store:     store,
		loginName: loginName,
		width:     width,
		height:    height,
		instances: newInstanceModel(),
		users:     newUserModel(),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.fetchData,
		tickCmd(),
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Global keybinds.
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activeTab = (m.activeTab + 1) % 2
			return m, nil
		case "r":
			return m, m.fetchData
		}

		// Delegate to active tab.
		switch m.activeTab {
		case tabInstances:
			m.instances = m.instances.update(msg)
		case tabUsers:
			var cmd tea.Cmd
			m.users, cmd = m.users.update(msg, m.store)
			if cmd != nil {
				return m, cmd
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		return m, tea.Batch(m.fetchData, tickCmd())

	case dataMsg:
		if msg.err != nil {
			m.status = fmt.Sprintf("Error: %v", msg.err)
			m.statusErr = true
		} else {
			m.instances.items = msg.instances
			m.users.items = msg.users
			m.status = fmt.Sprintf("Updated %s", time.Now().Format("15:04:05"))
			m.statusErr = false
		}

	case actionMsg:
		if msg.err != nil {
			m.status = fmt.Sprintf("Error: %v", msg.err)
			m.statusErr = true
		} else {
			m.status = msg.message
			m.statusErr = false
		}
		return m, m.fetchData
	}

	return m, nil
}

func (m Model) View() string {
	if m.width == 0 {
		return ""
	}

	// Title bar.
	title := titleStyle.Render("Waypoint Monitor")
	userInfo := statusStyle.Render(fmt.Sprintf(" %s", m.loginName))
	titleBar := lipgloss.JoinHorizontal(lipgloss.Center, title, userInfo)

	// Tabs.
	tabs := m.renderTabs()

	// Content area (everything between tabs and footer).
	footerHeight := 2 // status + help
	headerHeight := lipgloss.Height(titleBar) + lipgloss.Height(tabs)
	contentHeight := m.height - headerHeight - footerHeight
	if contentHeight < 1 {
		contentHeight = 1
	}

	var content string
	switch m.activeTab {
	case tabInstances:
		content = m.instances.view(m.width, contentHeight)
	case tabUsers:
		content = m.users.view(m.width, contentHeight)
	}

	// Status bar.
	var statusBar string
	if m.statusErr {
		statusBar = errorStyle.Render(m.status)
	} else {
		statusBar = statusStyle.Render(m.status)
	}

	// Help line.
	var help string
	switch m.activeTab {
	case tabInstances:
		help = helpStyle.Render("tab: switch tab | j/k: navigate | r: refresh | q: quit")
	case tabUsers:
		if m.users.confirming {
			help = helpStyle.Render("y: confirm | n/esc: cancel")
		} else {
			help = helpStyle.Render("tab: switch tab | j/k: navigate | c: reset conns | b: reset bytes | x: reset all | r: refresh | q: quit")
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		titleBar,
		tabs,
		content,
		statusBar,
		help,
	)
}

func (m Model) renderTabs() string {
	tabs := []string{"Instances", "Users"}
	var rendered []string
	for i, t := range tabs {
		if i == m.activeTab {
			rendered = append(rendered, activeTabStyle.Render(t))
		} else {
			rendered = append(rendered, inactiveTabStyle.Render(t))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Bottom, rendered...)
}

func (m Model) fetchData() tea.Msg {
	ctx := context.Background()
	instances, err := m.store.DiscoverInstances(ctx)
	if err != nil {
		return dataMsg{err: err}
	}
	users, err := m.store.ListUsers(ctx)
	if err != nil {
		return dataMsg{err: err}
	}
	return dataMsg{instances: instances, users: users}
}

func tickCmd() tea.Cmd {
	return tea.Tick(refreshInterval, func(time.Time) tea.Msg {
		return tickMsg{}
	})
}
