//go:build e2e

package e2e

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	cleanupE2ESuite()
	os.Exit(code)
}
