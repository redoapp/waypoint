package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
)

func TestIsBenignDisconnect(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"eof", io.EOF, true},
		{"wrapped eof", fmt.Errorf("read post-hello message: read header: %w", io.EOF), true},
		{"unexpected eof", io.ErrUnexpectedEOF, true},
		{"net closed", net.ErrClosed, true},
		{"conn reset", syscall.ECONNRESET, true},
		{"wrapped conn reset", fmt.Errorf("read: %w", syscall.ECONNRESET), true},
		{"real error", errors.New("client proof mismatch"), false},
		{"timeout", fmt.Errorf("dial tcp: %w", context.DeadlineExceeded), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBenignDisconnect(tt.err); got != tt.want {
				t.Errorf("isBenignDisconnect(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
