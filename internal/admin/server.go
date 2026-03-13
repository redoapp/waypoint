package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/redoapp/waypoint/internal/admin/tui"
	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/monitor"
	"golang.org/x/crypto/ssh"
	"tailscale.com/client/local"
)

// Server handles SSH connections and launches the TUI for authorized users.
type Server struct {
	lc        *local.Client
	store     *monitor.Store
	logger    *slog.Logger
	sshConfig *ssh.ServerConfig
}

// New creates a new admin SSH server.
func New(lc *local.Client, store *monitor.Store, logger *slog.Logger, hostKeyPath string) (*Server, error) {
	signer, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}

	sshCfg := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	sshCfg.AddHostKey(signer)

	return &Server{
		lc:        lc,
		store:     store,
		logger:    logger,
		sshConfig: sshCfg,
	}, nil
}

// Serve accepts SSH connections on the given listener until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logger.Error("accept failed", "error", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, netConn net.Conn) {
	defer netConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.sshConfig)
	if err != nil {
		s.logger.Debug("ssh handshake failed", "error", err)
		return
	}
	defer sshConn.Close()

	// Check manager capability via WhoIs.
	result, err := auth.AuthorizeManager(ctx, s.lc, netConn.RemoteAddr().String())
	if err != nil {
		s.logger.Info("access denied", "remote", netConn.RemoteAddr(), "error", err)
		// Try to send a message before closing.
		// We need to accept the session channel first.
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				newCh.Reject(ssh.UnknownChannelType, "unsupported")
				continue
			}
			ch, _, err := newCh.Accept()
			if err != nil {
				continue
			}
			io.WriteString(ch, "Access denied: you do not have the waypointManager capability.\r\n")
			ch.Close()
		}
		return
	}

	s.logger.Info("ssh session", "user", result.LoginName, "node", result.NodeName, "remote", netConn.RemoteAddr())

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			s.logger.Error("accept channel", "error", err)
			continue
		}
		s.handleSession(ctx, ch, requests, result, sshConn)
	}
}

func (s *Server) handleSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, authResult *auth.ManagerAuthResult, conn *ssh.ServerConn) {
	defer ch.Close()

	// Wait for a pty-req or shell request before starting the TUI.
	var winWidth, winHeight int
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			// Parse pty-req: term(string) + width(uint32) + height(uint32) + ...
			if len(req.Payload) >= 4 {
				termLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
				offset := 4 + termLen
				if len(req.Payload) >= offset+8 {
					winWidth = int(req.Payload[offset])<<24 | int(req.Payload[offset+1])<<16 | int(req.Payload[offset+2])<<8 | int(req.Payload[offset+3])
					winHeight = int(req.Payload[offset+4])<<24 | int(req.Payload[offset+5])<<16 | int(req.Payload[offset+6])<<8 | int(req.Payload[offset+7])
				}
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				req.Reply(true, nil)
			}
			s.runTUI(ctx, ch, reqs, authResult, winWidth, winHeight)
			return
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (s *Server) runTUI(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, authResult *auth.ManagerAuthResult, width, height int) {
	if width == 0 {
		width = 80
	}
	if height == 0 {
		height = 24
	}

	model := tui.NewModel(s.store, authResult.LoginName, width, height)
	p := tea.NewProgram(
		model,
		tea.WithInput(ch),
		tea.WithOutput(ch),
		tea.WithAltScreen(),
	)

	// Forward window-change requests.
	go func() {
		for req := range reqs {
			switch req.Type {
			case "window-change":
				if len(req.Payload) >= 8 {
					w := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
					h := int(req.Payload[4])<<24 | int(req.Payload[5])<<16 | int(req.Payload[6])<<8 | int(req.Payload[7])
					p.Send(tea.WindowSizeMsg{Width: w, Height: h})
				}
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()

	if _, err := p.Run(); err != nil {
		s.logger.Error("tui error", "user", authResult.LoginName, "error", err)
	}
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read host key: %w", err)
	}

	// Generate a new ed25519 key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Marshal to OpenSSH format.
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Ensure directory exists.
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create key directory: %w", err)
		}
	}

	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}

	return ssh.ParsePrivateKey(pemData)
}
