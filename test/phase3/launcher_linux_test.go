//go:build linux && rabiv_vmtest

package phase3_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/rabiv-org/rabiv/internal/adapters/worker"
)

// Reserve the exact identity with the independent supervisor before invoking
// the launcher. Only the supervisor is allowed to allocate test units.
func launchVMLab(ctx context.Context, bundle, slot, profile string, args []string) ([]byte, error) {
	control := os.Getenv("RABIV_PHASE3_CONTROL")
	info, err := os.Lstat(control)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != 0 || filepath.Dir(control) != "/var/lib/rabiv-phase3-lab" {
		return nil, errors.New("private lab control required")
	}
	p, err := worker.Load(profile)
	if err != nil || p.TimeoutSeconds != 180 || p.MemoryBytes != 2<<30 || p.CPUPercent != 100 || p.Tasks != 64 {
		return nil, errors.New("VM lab profile exceeds reviewed scope")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-B", filepath.Join(bundle, "vm_lab.py"), "reserve-unit", control, slot)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1"}
	b, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var reservation struct {
		Name  string `json:"name"`
		Nonce string `json:"nonce"`
	}
	if len(b) > 1024 || json.Unmarshal(b, &reservation) != nil || reservation.Name == "" {
		return nil, errors.New("invalid lab unit reservation")
	}
	return worker.LaunchForVMTest(ctx, profile, args, reservation.Name, reservation.Nonce)
}
