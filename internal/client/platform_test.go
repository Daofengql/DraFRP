//go:build !linux

package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNonLinuxSourceIdentityRejectedBeforeStateCreation(t *testing.T) {
	for _, mode := range []string{"tun", "transparent"} {
		dir := filepath.Join(t.TempDir(), "unused-state")
		a, err := New(Config{CloudURL: "http://127.0.0.1:1", StateDir: dir, NetworkMode: mode})
		if err == nil {
			a.Close()
			t.Fatal("non-Linux native forwarding accepted")
		}
		if !strings.Contains(err.Error(), "requires a Linux client") {
			t.Fatal(err)
		}
		if _, err = os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("rejected mode created device state", err)
		}
	}
}
