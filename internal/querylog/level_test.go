package querylog

import "testing"

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Level
		wantErr bool
	}{
		{"off", "off", LevelOff, false},
		{"none alias", "none", LevelOff, false},
		{"metadata", "metadata", LevelMetadata, false},
		{"meta alias", "meta", LevelMetadata, false},
		{"normalized", "normalized", LevelNormalized, false},
		{"british spelling", "normalised", LevelNormalized, false},
		{"full", "full", LevelFull, false},
		{"mixed case", "  FuLL  ", LevelFull, false},
		{"unknown", "verbose", 0, true},
		{"empty", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLevel(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseLevel(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLevel(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLevelString(t *testing.T) {
	for _, l := range []Level{LevelOff, LevelMetadata, LevelNormalized, LevelFull} {
		got, err := ParseLevel(l.String())
		if err != nil {
			t.Fatalf("round-trip of %v: %v", l, err)
		}
		if got != l {
			t.Errorf("round-trip of %v gave %v", l, got)
		}
	}
}

func TestLevelClamp(t *testing.T) {
	tests := []struct {
		name    string
		want    Level
		ceiling Level
		result  Level
	}{
		{"under ceiling passes through", LevelMetadata, LevelFull, LevelMetadata},
		{"at ceiling passes through", LevelFull, LevelFull, LevelFull},
		{"over ceiling is capped", LevelFull, LevelNormalized, LevelNormalized},
		{"off ceiling disables entirely", LevelFull, LevelOff, LevelOff},
		{"off request stays off", LevelOff, LevelFull, LevelOff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Clamp(tt.want, tt.ceiling); got != tt.result {
				t.Errorf("Clamp(%v, %v) = %v, want %v", tt.want, tt.ceiling, got, tt.result)
			}
		})
	}
}
