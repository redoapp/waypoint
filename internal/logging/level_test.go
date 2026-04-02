package logging

import (
	"log/slog"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
		err   bool
	}{
		{"debug", slog.LevelDebug, false},
		{"DEBUG", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"INFO", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"WARN", slog.LevelWarn, false},
		{"warning", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"ERROR", slog.LevelError, false},
		{" info ", slog.LevelInfo, false},
		{"", 0, true},
		{"trace", 0, true},
		{"fatal", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseLevel(tt.input)
			if tt.err && err == nil {
				t.Fatalf("expected error for %q", tt.input)
			}
			if !tt.err && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if !tt.err && got != tt.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveLevel(t *testing.T) {
	tests := []struct {
		name     string
		envVal   string
		cfgVal   string
		defLevel slog.Level
		want     slog.Level
		err      bool
	}{
		{"env wins over config", "warn", "debug", slog.LevelInfo, slog.LevelWarn, false},
		{"config used when no env", "", "debug", slog.LevelInfo, slog.LevelDebug, false},
		{"default when both empty", "", "", slog.LevelInfo, slog.LevelInfo, false},
		{"invalid env returns error", "bogus", "debug", slog.LevelInfo, 0, true},
		{"invalid config returns error", "", "bogus", slog.LevelInfo, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveLevel(tt.envVal, tt.cfgVal, tt.defLevel)
			if tt.err && err == nil {
				t.Fatal("expected error")
			}
			if !tt.err && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.err && got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
