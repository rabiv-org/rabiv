// Package worker implements a transient systemd isolation profile and runtime
// preflight. A profile string or environment flag is not proof of OS enforcement.
// New privileged VM execution always requires separate owner authorization.
package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

var ErrIsolation = errors.New("worker isolation preflight failed")

// Config must be a root-owned, non-writable administrator file outside home/tmp.
// Dedicated accounts have no other supplementary groups. Paths are deployment
// configuration, never CI/job/artifact claims. No credentials are included.
type Config struct {
	UID             int      `json:"uid"`
	GID             int      `json:"gid"`
	FetchReaderGID  int      `json:"fetch_reader_gid"`
	ResultReaderGID int      `json:"result_reader_gid"`
	FetchRoot       string   `json:"fetch_root"`
	ResultRoot      string   `json:"result_root"`
	Workspace       string   `json:"workspace"`
	Executable      string   `json:"executable"`
	SyftBinary      string   `json:"syft_binary"`
	DecisionRoot    string   `json:"decision_root"`
	CredentialPaths []string `json:"credential_paths"`
	HostNetNS       uint64   `json:"host_netns"`
	MemoryBytes     uint64   `json:"memory_bytes"`
	CPUPercent      int      `json:"cpu_percent"`
	Tasks           int      `json:"tasks"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
}

func canonical(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && !strings.ContainsAny(p, " \t\r\n:%$")
}
func within(a, b string) bool { return a == b || strings.HasPrefix(a, b+"/") }
func (c Config) Validate() error {
	if c.UID <= 0 || c.GID <= 0 || c.FetchReaderGID <= 0 || c.ResultReaderGID <= 0 || c.FetchReaderGID == c.GID || c.ResultReaderGID == c.GID || c.FetchReaderGID == c.ResultReaderGID || c.HostNetNS == 0 || c.MemoryBytes < 128<<20 || c.CPUPercent <= 0 || c.CPUPercent > 400 || c.Tasks < 8 || c.Tasks > 512 || c.TimeoutSeconds <= 0 || c.TimeoutSeconds > 3600 || len(c.CredentialPaths) == 0 {
		return ErrIsolation
	}
	paths := []string{c.FetchRoot, c.ResultRoot, c.Workspace, c.Executable, c.SyftBinary}
	for _, p := range paths {
		if !canonical(p) || within(p, "/home") || within(p, "/root") || within(p, "/tmp") || within(p, "/var/tmp") || within(p, "/run") {
			return ErrIsolation
		}
	}
	for _, p := range append([]string{c.DecisionRoot}, c.CredentialPaths...) {
		if !canonical(p) {
			return ErrIsolation
		}
		for _, allowed := range paths {
			if within(allowed, p) || within(p, allowed) {
				return ErrIsolation
			}
		}
	}
	for _, w := range []string{c.Workspace, c.ResultRoot} {
		for _, r := range append([]string{c.FetchRoot, c.Executable, c.SyftBinary, c.DecisionRoot}, c.CredentialPaths...) {
			if within(w, r) || within(r, w) {
				return ErrIsolation
			}
		}
	}
	if within(c.Workspace, c.ResultRoot) || within(c.ResultRoot, c.Workspace) {
		return ErrIsolation
	}
	return nil
}

// trusted opens through only root-owned, non-writable, nonsymlink ancestors.
func trusted(path string) (*os.File, error) {
	if !canonical(path) {
		return nil, ErrIsolation
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode().Perm()&0022 != 0 || i.Sys().(*syscall.Stat_t).Uid != 0 {
			return nil, ErrIsolation
		}
		if p == "/" {
			break
		}
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrIsolation
	}
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0022 != 0 || i.Sys().(*syscall.Stat_t).Uid != 0 {
		_ = f.Close()
		return nil, ErrIsolation
	}
	return f, nil
}

// Load does not accept a user-writable profile as an authorization mechanism.
func Load(path string) (Config, error) {
	var c Config
	f, e := trusted(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	b, e := acquire.ReadLimit(f, 64<<10)
	if e != nil || jsoninput.Decode(b, &c, true) != nil {
		return c, ErrIsolation
	}
	return c, c.Validate()
}

// Arguments describes the exact profile for an owner-controlled transient unit.
// Unit configuration is implemented here; actual enforcement requires VM tests.
func (c Config) Arguments(profile, unit string, args []string) ([]string, error) {
	if c.Validate() != nil || !canonical(profile) || !strings.HasPrefix(unit, "rabiv-worker-") || strings.ContainsAny(unit, " /\t\n") {
		return nil, ErrIsolation
	}
	for _, arg := range args {
		if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) || arg == "--profile" || arg == "-profile" || strings.HasPrefix(arg, "--profile=") || strings.HasPrefix(arg, "-profile=") {
			return nil, ErrIsolation
		}
	}
	props := []string{
		fmt.Sprintf("User=%d", c.UID), fmt.Sprintf("Group=%d", c.GID), fmt.Sprintf("SupplementaryGroups=%d %d", c.FetchReaderGID, c.ResultReaderGID),
		"NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any",
		"ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "PrivateMounts=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes",
		"RestrictNamespaces=yes", "RestrictRealtime=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes", "ProtectProc=invisible", "ProcSubset=pid", "SystemCallArchitectures=native", "UMask=0077",
		"ReadOnlyPaths=" + c.FetchRoot, "ReadWritePaths=" + c.Workspace + " " + c.ResultRoot,
		"InaccessiblePaths=" + c.DecisionRoot + " " + strings.Join(c.CredentialPaths, " ") + " -/run -/var/run",
		fmt.Sprintf("MemoryMax=%d", c.MemoryBytes), "MemorySwapMax=0", fmt.Sprintf("CPUQuota=%d%%", c.CPUPercent), fmt.Sprintf("TasksMax=%d", c.Tasks), fmt.Sprintf("RuntimeMaxSec=%d", c.TimeoutSeconds), "TimeoutStopSec=5s", "KillMode=control-group",
		"Description=" + unit,
	}
	out := []string{"--quiet", "--wait", "--collect", "--pipe", "--service-type=exec", "--unit=" + unit}
	for _, p := range props {
		out = append(out, "--property="+p)
	}
	out = append(out, "--", c.Executable, "worker", "--profile", profile)
	return append(out, args...), nil
}

func netNS() (uint64, error) {
	i, e := os.Stat("/proc/self/ns/net")
	if e != nil {
		return 0, e
	}
	return i.Sys().(*syscall.Stat_t).Ino, nil
}

// Check verifies actual IDs/groups, empty capability sets, no_new_privs, a
// different network namespace and read-only Fetch mount. It is defense in depth,
// not a standalone proof of every systemd property. Root/host admin is trusted.
func (c Config) Check() error {
	if c.Validate() != nil || os.Getuid() != c.UID || os.Geteuid() != c.UID || os.Getgid() != c.GID || os.Getegid() != c.GID {
		return ErrIsolation
	}
	groups, e := os.Getgroups()
	if e != nil {
		return ErrIsolation
	}
	expected := []int{c.FetchReaderGID, c.ResultReaderGID}
	for _, g := range groups {
		if g != c.GID && !slices.Contains(expected, g) {
			return ErrIsolation
		}
	}
	for _, g := range expected {
		if !slices.Contains(groups, g) {
			return ErrIsolation
		}
	}
	status, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return ErrIsolation
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		v, e := strconv.ParseUint(fields[k], 16, 64)
		if e != nil || v != 0 {
			return ErrIsolation
		}
	}
	if fields["NoNewPrivs"] != "1" {
		return ErrIsolation
	}
	for _, k := range []string{"Uid", "Gid"} {
		values := strings.Fields(fields[k])
		if len(values) != 4 {
			return ErrIsolation
		}
		want := c.UID
		if k == "Gid" {
			want = c.GID
		}
		for _, v := range values {
			if v != strconv.Itoa(want) {
				return ErrIsolation
			}
		}
	}
	ns, e := netNS()
	if e != nil || ns == c.HostNetNS {
		return ErrIsolation
	}
	i, e := os.Stat(c.Workspace)
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0700 || int(i.Sys().(*syscall.Stat_t).Uid) != c.UID {
		return ErrIsolation
	}
	var stat syscall.Statfs_t
	if syscall.Statfs(c.FetchRoot, &stat) != nil || stat.Flags&syscall.MS_RDONLY == 0 {
		return ErrIsolation
	}
	for _, p := range append([]string{c.DecisionRoot}, c.CredentialPaths...) {
		f, e := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if e == nil {
			_ = f.Close()
			return ErrIsolation
		}
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if strings.Contains(key, "TOKEN") || strings.Contains(key, "PASSWORD") || strings.HasPrefix(key, "GIT_") || key == "SSH_AUTH_SOCK" {
			return ErrIsolation
		}
	}
	return nil
}

// Launch requires explicit owner execution as root and reviewed root-owned
// binaries. It never invokes sudo, changes users/groups or installs a service.
func Launch(ctx context.Context, profile string, args []string) ([]byte, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrIsolation
	}
	c, e := Load(profile)
	if e != nil {
		return nil, e
	}
	for _, p := range []string{c.Executable, c.SyftBinary} {
		f, e := trusted(p)
		if e != nil {
			return nil, e
		}
		_ = f.Close()
	}
	ns, e := netNS()
	if e != nil || ns != c.HostNetNS {
		return nil, ErrIsolation
	}
	unit := "rabiv-worker-" + strings.ToLower(rand.Text())
	// Validate the requested arguments, then pass them as opaque JSON over stdin.
	// Subject names containing dollars/percent signs must not undergo systemd
	// ExecStart environment/specifier expansion or shell interpretation.
	if _, e = c.Arguments(profile, unit, args); e != nil {
		return nil, e
	}
	request, e := json.Marshal(args)
	if e != nil || len(request) > 256<<10 {
		return nil, ErrIsolation
	}
	argv, e := c.Arguments(profile, unit, []string{"--request-stdin"})
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds+15)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", argv...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.Stdin = bytes.NewReader(request)
	stdout := &outputLimit{max: 1 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 5 * time.Second
	e = cmd.Run()
	if e != nil {
		// On cancellation, stop only a unit whose description matches our random
		// invocation. Never stop a pre-existing unit merely by name collision.
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		show := exec.CommandContext(cleanup, "/usr/bin/systemctl", "show", "--property=Description", "--value", unit)
		if b, err := show.Output(); err == nil && strings.TrimSpace(string(b)) == unit {
			_ = exec.CommandContext(cleanup, "/usr/bin/systemctl", "stop", unit).Run()
		}
		return nil, ErrIsolation
	}
	return bytes.Clone(stdout.buf.Bytes()), nil
}

type outputLimit struct {
	buf bytes.Buffer
	max int
}

func (w *outputLimit) Write(b []byte) (int, error) {
	if w.buf.Len()+len(b) > w.max {
		return 0, ErrIsolation
	}
	return w.buf.Write(b)
}
