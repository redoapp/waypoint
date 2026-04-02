package logging

import (
	"crypto/rand"
	"encoding/hex"
)

// NewConnID returns a 16-character random hex string for per-connection tracing.
func NewConnID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate conn ID: " + err.Error())
	}
	return hex.EncodeToString(b)
}
