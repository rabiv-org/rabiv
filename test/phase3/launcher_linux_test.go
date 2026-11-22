//go:build linux && rabiv_vmtest

package phase3_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/rabiv-org/rabiv/internal/adapters/worker"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
)

// launchVMLab tests the production profile/Worker, not production Launch error
// cleanup. The independent supervisor owns and recovers these two lab units.
func launchVMLab(ctx context.Context, bundle, slot, profile string, args []string) ([]byte, error) {
	control := os.Getenv("RABIV_PHASE3_CONTROL")
	info, err := os.Lstat(control)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != 0 || filepath.Dir(control) != "/var/lib/rabiv-phase3-lab" {
		return nil, errors.New("private lab control required")
	}
	path := filepath.Join(control, "state.json")
	if !rootRegular(path) {
		return nil, errors.New("untrusted lab state")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := acquire.ReadLimit(f, 1<<20)
	if err != nil {
		return nil, err
	}
	var state struct {
		Units map[string]struct{ Name string }
	}
	if json.Unmarshal(b, &state) != nil || state.Units[slot].Name == "" {
		return nil, errors.New("lab unit slot unavailable")
	}
	p, err := worker.Load(profile)
	if err != nil {
		return nil, err
	}
	ns, err := os.Stat("/proc/self/ns/net")
	if err != nil || ns.Sys().(*syscall.Stat_t).Ino != p.HostNetNS {
		return nil, errors.New("lab host network namespace changed")
	}
	unit := state.Units[slot].Name
	if _, err = p.Arguments(profile, unit, args); err != nil {
		return nil, err
	}
	argv, err := p.Arguments(profile, unit, []string{"--request-stdin"})
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(struct {
		Argv    []string `json:"argv"`
		Request []string `json:"request"`
	}{argv, args})
	if err != nil || len(payload) > 512<<10 {
		return nil, errors.New("lab unit request too large")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", filepath.Join(bundle, "vm_lab.py"), "unit", control, slot)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1"}
	cmd.Stdin = bytes.NewReader(payload)
	return cmd.Output()
}
