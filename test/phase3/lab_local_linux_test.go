package phase3_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestGoTimeoutRequiresExternalRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cleanup-ran")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestLegacyTimeoutChild$", "-test.timeout=100ms")
	cmd.WaitDelay = time.Second
	cmd.Env = []string{"PATH=/usr/bin:/bin", "RABIV_PRIVATE_TIMEOUT_MARKER=" + path}
	output, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("test timed out")) {
		t.Fatalf("timeout baseline not reproduced: err=%v output=%s", err, output)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Go timeout unexpectedly completed the registered cleanup")
	}
	t.Log("confirmed: Go suite timeout exits without t.Cleanup; external recovery is required")
}

func TestLegacyTimeoutChild(t *testing.T) {
	path := os.Getenv("RABIV_PRIVATE_TIMEOUT_MARKER")
	if path == "" {
		return
	}
	t.Cleanup(func() { _ = os.WriteFile(path, []byte("cleanup"), 0600) })
	select {}
}

// These tests mock account/systemd commands. They never run the VM entry point.
func TestVMLabLocalRegressions(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-B", "vm_lab_test.py")
	cmd.WaitDelay = time.Second
	cmd.Env = []string{"PATH=/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1"}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged VM harness regressions: %v\n%s", err, output)
	}
}
