//go:build linux && rabiv_integration

package phase3_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rabiv-org/rabiv/internal/adapters/syft"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
)

// This executes an installed Syft on the test's own ELF, never the ELF itself.
// It validates CLI/schema/digest compatibility, not privileged Worker isolation.
func TestInstalledSyft(t *testing.T) {
	tool, err := exec.LookPath("syft")
	if err != nil {
		t.Skip("Syft is not installed; live CLI compatibility unverified")
	}
	tool, err = filepath.Abs(tool)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c, err := syft.New(syft.Config{Binary: tool, Workspace: dir, Timeout: 2 * time.Minute, MaxOutput: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Scan(context.Background(), data, acquire.Hash(data))
	if err != nil {
		t.Fatal(err)
	}
	if syft.Validate(b, acquire.Hash(data)) != nil {
		t.Fatal("generated SBOM is unbound")
	}
}
