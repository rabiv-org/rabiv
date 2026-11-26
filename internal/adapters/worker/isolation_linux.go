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
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
	"github.com/rabiv-org/rabiv/internal/platform/process"
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
	return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && utf8.ValidString(p) &&
		!strings.ContainsAny(p, " :%$\\\"'") && strings.IndexFunc(p, unicode.IsControl) == -1
}
func within(a, b string) bool { return a == b || strings.HasPrefix(a, b+"/") }
func (c Config) Validate() error {
	if !c.validIdentity() || !c.validLimits() || len(c.CredentialPaths) == 0 {
		return ErrIsolation
	}
	paths := []string{c.FetchRoot, c.ResultRoot, c.Workspace, c.Executable, c.SyftBinary}
	for _, p := range paths {
		if !visibleWorkerPath(p) {
			return ErrIsolation
		}
	}
	protected := append([]string{c.DecisionRoot}, c.CredentialPaths...)
	for _, p := range protected {
		if !canonical(p) {
			return ErrIsolation
		}
	}
	if !disjoint(paths, protected) {
		return ErrIsolation
	}
	readOnly := append([]string{c.FetchRoot, c.Executable, c.SyftBinary, c.DecisionRoot}, c.CredentialPaths...)
	if !disjoint([]string{c.Workspace, c.ResultRoot}, readOnly) {
		return ErrIsolation
	}
	if within(c.Workspace, c.ResultRoot) || within(c.ResultRoot, c.Workspace) {
		return ErrIsolation
	}
	return nil
}

func visibleWorkerPath(p string) bool {
	if !canonical(p) {
		return false
	}
	for _, hidden := range []string{"/home", "/root", "/tmp", "/var/tmp", "/run", "/var/run"} {
		if within(p, hidden) {
			return false
		}
	}
	return true
}

func (c Config) validIdentity() bool {
	return c.UID > 0 && c.GID > 0 && c.FetchReaderGID > 0 && c.ResultReaderGID > 0 && c.FetchReaderGID != c.GID && c.ResultReaderGID != c.GID && c.FetchReaderGID != c.ResultReaderGID && c.HostNetNS != 0
}
func (c Config) validLimits() bool {
	return c.MemoryBytes >= 128<<20 && c.CPUPercent > 0 && c.CPUPercent <= 400 && c.Tasks >= 8 && c.Tasks <= 512 && c.TimeoutSeconds > 0 && c.TimeoutSeconds <= 3600
}
func disjoint(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if within(x, y) || within(y, x) {
				return false
			}
		}
	}
	return true
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
	defer func() { _ = f.Close() }()
	b, e := acquire.ReadLimit(f, 64<<10)
	if e != nil || jsoninput.Decode(b, &c, true) != nil {
		return c, ErrIsolation
	}
	return c, c.Validate()
}

// Arguments describes the exact profile for an owner-controlled transient unit.
// Unit configuration is implemented here; actual enforcement requires VM tests.
func (c Config) Arguments(profile, unit string) ([]string, error) {
	if c.Validate() != nil || !c.profileVisible(profile) || !strings.HasPrefix(unit, "rabiv-worker-") || strings.ContainsAny(unit, " /\t\n") {
		return nil, ErrIsolation
	}
	var inaccessible []string
	for _, path := range append([]string{c.DecisionRoot}, c.CredentialPaths...) {
		if within(path, "/run") || within(path, "/var/run") {
			// /var/run aliases /run on the supported Ubuntu deployment. A path
			// below the overlay is already hidden and need not exist in the unit.
			continue
		}
		inaccessible = append(inaccessible, path)
	}
	props := []string{
		fmt.Sprintf("User=%d", c.UID), fmt.Sprintf("Group=%d", c.GID), fmt.Sprintf("SupplementaryGroups=%d %d", c.FetchReaderGID, c.ResultReaderGID),
		"NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any",
		"ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "PrivateMounts=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes",
		"RestrictNamespaces=yes", "RestrictRealtime=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes", "ProtectProc=invisible", "ProcSubset=pid", "SystemCallArchitectures=native", "UMask=0077",
		"ReadOnlyPaths=" + c.FetchRoot + " /tmp /var/tmp", "ReadWritePaths=" + c.Workspace + " " + c.ResultRoot,
		// systemd v255 needs /run during namespace setup. Mask the host's
		// contents with a private mount instead of marking /run inaccessible.
		"TemporaryFileSystem=/run:ro,nosuid,nodev,noexec,mode=0755",
		fmt.Sprintf("MemoryMax=%d", c.MemoryBytes), "MemorySwapMax=0", fmt.Sprintf("CPUQuota=%d%%", c.CPUPercent), fmt.Sprintf("TasksMax=%d", c.Tasks), fmt.Sprintf("RuntimeMaxSec=%d", c.TimeoutSeconds), "TimeoutStopSec=5s", "KillMode=control-group",
		"Description=" + unit,
	}
	if len(inaccessible) > 0 {
		props = append(props, "InaccessiblePaths="+strings.Join(inaccessible, " "))
	}
	out := []string{"--quiet", "--wait", "--collect", "--pipe", "--service-type=exec", "--unit=" + unit}
	for _, p := range props {
		out = append(out, "--property="+p)
	}
	return append(out, "--", c.Executable, "worker", "--profile", profile, "--request-stdin"), nil
}

func (c Config) profileVisible(profile string) bool {
	if !canonical(profile) {
		return false
	}
	for _, root := range []string{"/home", "/root", "/run", "/var/run", "/tmp", "/var/tmp", "/dev", "/proc", "/sys"} {
		if within(profile, root) {
			return false
		}
	}
	for _, denied := range append([]string{c.DecisionRoot}, c.CredentialPaths...) {
		if within(profile, denied) {
			return false
		}
	}
	return true
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
	if c.Validate() != nil {
		return ErrIsolation
	}
	if process.CheckIdentity(c.UID, c.GID, []int{c.FetchReaderGID, c.ResultReaderGID}) != nil {
		return ErrIsolation
	}
	if err := c.checkSandbox(); err != nil {
		return err
	}
	if !validWorkerEnvironment(os.Environ()) {
		return ErrIsolation
	}

	return nil
}

func (c Config) checkSandbox() error {
	ns, e := netNS()
	if e != nil || ns == c.HostNetNS {
		return ErrIsolation
	}
	i, e := os.Stat(c.Workspace)
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0700 || int(i.Sys().(*syscall.Stat_t).Uid) != c.UID {
		return ErrIsolation
	}
	if err := c.checkMounts(); err != nil {
		return err
	}
	for _, p := range append([]string{c.DecisionRoot}, c.CredentialPaths...) {
		f, e := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if e == nil {
			_ = f.Close()
			return ErrIsolation
		}
	}

	return nil
}

func (c Config) checkMounts() error {
	var stat syscall.Statfs_t
	if syscall.Statfs(c.FetchRoot, &stat) != nil || stat.Flags&syscall.MS_RDONLY == 0 {
		return ErrIsolation
	}
	if syscall.Statfs("/run", &stat) != nil || stat.Flags&syscall.MS_RDONLY == 0 {
		return ErrIsolation
	}
	runtimeDir, err := os.Stat("/run")
	runtimeAlias, aliasErr := os.Stat("/var/run")
	if err != nil || aliasErr != nil || !os.SameFile(runtimeDir, runtimeAlias) {
		return ErrIsolation
	}
	if _, err := os.Lstat("/run/systemd/private"); !errors.Is(err, os.ErrNotExist) {
		return ErrIsolation
	}

	return nil
}

func validWorkerEnvironment(entries []string) bool {
	for _, entry := range entries {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if strings.Contains(key, "TOKEN") || strings.Contains(key, "PASSWORD") || strings.HasPrefix(key, "GIT_") || key == "SSH_AUTH_SOCK" {
			return false
		}
	}
	return true
}

// Launch requires explicit owner execution as root and reviewed root-owned
// binaries. It never invokes sudo, changes users/groups or installs a service.
func Launch(ctx context.Context, profile string, args []string) ([]byte, error) {
	unit := "rabiv-worker-" + strings.ToLower(rand.Text())
	marker := "rabiv-launch-" + strings.ToLower(rand.Text())
	return launch(ctx, profile, args, unit, marker)
}

//nolint:gocognit,gocyclo // Keep privileged start and bounded ownership-aware recovery in their required order.
func launch(ctx context.Context, profile string, args []string, unit, marker string) ([]byte, error) {
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
	for _, arg := range args {
		if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) {
			return nil, ErrIsolation
		}
	}
	// The profile and all systemd properties are outside the opaque JSON request.
	request, e := json.Marshal(args)
	if e != nil || len(request) > 256<<10 {
		return nil, ErrIsolation
	}
	argv, e := c.Arguments(profile, unit)
	if e != nil {
		return nil, e
	}
	argv = append([]string{"--property=SyslogIdentifier=" + marker}, argv...)
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
		if cmd.Process == nil {
			return nil, fmt.Errorf("%w: systemd client did not start", ErrIsolation)
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := recoverLaunch(cleanup, systemctl, unit, marker); err != nil {
			return nil, fmt.Errorf("%w: worker exited without acknowledgement; %w", ErrIsolation, err)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: owned unit stopped: %w", ErrIsolation, ctx.Err())
		}
		return nil, fmt.Errorf("%w: worker exited without acknowledgement; owned unit stopped", ErrIsolation)
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
