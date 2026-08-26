//go:build integration

package web

import "github.com/redoapp/waypoint/internal/auth"

// testAuthResult stands in for the identity the tailnet would supply.
func testAuthResult() *auth.AuthResult {
	return &auth.AuthResult{
		LoginName:   "tester@example.com",
		NodeName:    "test-node",
		Permissions: []string{"readonly"},
	}
}
