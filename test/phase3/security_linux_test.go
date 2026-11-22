//go:build linux && rabiv_vmtest

package phase3_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	input "github.com/rabiv-org/rabiv/internal/adapters/storage/input"
	"github.com/rabiv-org/rabiv/internal/adapters/worker"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/platform/process"
)

type vmActor struct {
	UID, GID int
	Groups   []int
}
type vmConfig struct {
	Root, Binary, Ingestor, Syft string
	Actors                       map[string]vmActor
	Channels                     map[string]string
}

func vmEnvironment() bool {
	b, e := os.ReadFile("/etc/os-release")
	if e != nil || !bytes.Contains(b, []byte("ID=ubuntu")) || !bytes.Contains(b, []byte("VERSION_ID=\"24.04\"")) {
		return false
	}
	out, e := exec.Command("/usr/bin/systemd-detect-virt", "--vm").Output()
	return e == nil && (strings.TrimSpace(string(out)) == "kvm" || strings.TrimSpace(string(out)) == "qemu")
}
func rootRegular(path string) bool {
	i, e := os.Lstat(path)
	return e == nil && i.Mode().IsRegular() && i.Mode().Perm()&0022 == 0 && i.Sys().(*syscall.Stat_t).Uid == 0
}
func vmLoad(path string) (vmConfig, error) {
	var c vmConfig
	if !rootRegular(path) {
		return c, errors.New("untrusted VM config")
	}
	b, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(b, &c) != nil || !strings.HasPrefix(c.Root, "/var/lib/rabiv-phase3-lab/run.") || filepath.Clean(c.Root) != c.Root || !rootRegular(filepath.Join(c.Root, "authorized")) {
		return c, errors.New("unsafe VM root")
	}
	return c, nil
}

// The private probe exists only in this opt-in test binary. It has no decision or
// release operation and cannot enable a production Worker/Publisher test mode.
func init() {
	if len(os.Args) == 5 && os.Args[1] == "worker" && os.Args[2] == "--profile" && os.Args[4] == "--request-stdin" {
		if !vmEnvironment() {
			os.Exit(2)
		}
		p, e := worker.Load(os.Args[3])
		if e != nil || p.Check() != nil {
			os.Exit(2)
		}
		ok := map[string]bool{}
		denied := func(path string, flags int) bool {
			f, e := os.OpenFile(path, flags, 0600)
			if e == nil {
				_ = f.Close()
			}
			return e != nil
		}
		ok["fetch_readonly"] = denied(filepath.Join(p.FetchRoot, "probe"), os.O_WRONLY|os.O_CREATE)
		ok["credentials_inaccessible"] = denied(p.CredentialPaths[0], os.O_RDONLY)
		ok["decision_writes_denied"] = denied(filepath.Join(p.DecisionRoot, "forged"), os.O_WRONLY|os.O_CREATE)
		ok["private_tmp_readonly"] = denied("/tmp/rabiv-worker-probe", os.O_WRONLY|os.O_CREATE)
		ok["outside_workspace_readonly"] = denied("/etc/rabiv-worker-probe", os.O_WRONLY|os.O_CREATE)
		_, e = os.Lstat("/run/systemd/private")
		ok["host_run_socket_hidden"] = errors.Is(e, os.ErrNotExist)
		_, e = os.Lstat("/var/run/systemd/private")
		ok["host_var_run_alias_hidden"] = errors.Is(e, os.ErrNotExist)
		fd, e := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if e == nil {
			_ = syscall.Close(fd)
		}
		ok["inet_socket_denied"] = errors.Is(e, syscall.EPERM) || errors.Is(e, syscall.EAFNOSUPPORT) || errors.Is(e, syscall.EACCES)
		file, e := os.OpenFile(filepath.Join(p.Workspace, "allowed"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		ok["workspace_write_allowed"] = e == nil
		if e == nil {
			_ = file.Close()
		}
		cg, e := os.ReadFile("/proc/self/cgroup")
		if e == nil {
			for _, line := range strings.Split(string(cg), "\n") {
				if strings.HasPrefix(line, "0::/") {
					rel := strings.TrimPrefix(line, "0::")
					if !strings.Contains(rel, "..") {
						base := filepath.Join("/sys/fs/cgroup", rel)
						for name, want := range map[string]uint64{"memory.max": p.MemoryBytes, "pids.max": uint64(p.Tasks)} {
							b, e := os.ReadFile(filepath.Join(base, name))
							n, f := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
							ok[name] = e == nil && f == nil && n == want
						}
						b, e := os.ReadFile(filepath.Join(base, "cpu.max"))
						fields := strings.Fields(string(b))
						if e == nil && len(fields) == 2 {
							quota, q := strconv.ParseUint(fields[0], 10, 64)
							period, f := strconv.ParseUint(fields[1], 10, 64)
							ok["cpu.max"] = q == nil && f == nil && quota > 0 && period > 0 && quota*100 <= period*uint64(p.CPUPercent)
						}
					}
				}
			}
		}
		for _, key := range []string{"fetch_readonly", "credentials_inaccessible", "decision_writes_denied", "private_tmp_readonly", "outside_workspace_readonly", "host_run_socket_hidden", "host_var_run_alias_hidden", "inet_socket_denied", "workspace_write_allowed", "memory.max", "pids.max", "cpu.max"} {
			if !ok[key] {
				_, _ = fmt.Fprintln(os.Stderr, "VM worker assertion failed:", key)
				os.Exit(1)
			}
		}
		if json.NewEncoder(os.Stdout).Encode(ok) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func TestVMHelper(t *testing.T) {
	path := os.Getenv("RABIV_PHASE3_VM_CONFIG")
	if path == "" {
		t.Skip("owner-run VM helper only")
	}
	if !vmEnvironment() {
		t.Fatal("Ubuntu/KVM required")
	}
	c, e := vmLoad(path)
	if e != nil {
		t.Fatal(e)
	}
	name := os.Getenv("RABIV_VM_ACTOR")
	a, ok := c.Actors[name]
	if !ok {
		t.Fatal("unknown actor")
	}
	expectedGroups := a.Groups
	if os.Getenv("RABIV_VM_NO_GROUPS") == "1" {
		expectedGroups = nil
	}
	if name == "capture" {
		if a.UID != 0 || os.Getuid() != 0 || os.Geteuid() != 0 {
			t.Fatal("owner capture identity mismatch")
		}
	} else if e = process.Check(a.UID, a.GID, expectedGroups); e != nil {
		t.Fatal(e)
	}
	key := os.Getenv("RABIV_VM_CHANNEL")
	cfg, e := input.LoadConfig(c.Channels[key])
	if e != nil {
		t.Fatal(e)
	}
	action := os.Getenv("RABIV_VM_ACTION")
	switch action {
	case "put":
		s, e := input.OpenWriter(cfg)
		if e != nil {
			t.Fatal(e)
		}
		defer func() { _ = s.Close() }()
		b, e := acquire.ReadLimit(os.Stdin, 32<<20)
		if e != nil {
			t.Fatal(e)
		}
		ref, e := s.Put(context.Background(), os.Getenv("RABIV_VM_ID"), bytes.NewReader(b), 32<<20)
		if e != nil {
			t.Fatal(e)
		}
		if e = json.NewEncoder(os.Stdout).Encode(ref); e != nil {
			t.Fatal(e)
		}
	case "get":
		s, e := input.OpenReader(cfg)
		if e != nil {
			t.Fatal(e)
		}
		defer func() { _ = s.Close() }()
		ref, e := acquire.ParseReference(os.Getenv("RABIV_VM_REF"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Get(context.Background(), ref, 32<<20); e != nil {
			t.Fatal(e)
		}
	case "read-denied", "write-denied":
		flags := os.O_RDONLY
		if action == "write-denied" {
			flags = os.O_WRONLY | os.O_CREATE
		}
		target := filepath.Join(cfg.RootDir, "committed", "object-snapshot")
		if os.Getenv("RABIV_VM_STAGING") == "1" {
			target = filepath.Join(cfg.RootDir, "staging", "private")
		}
		f, e := os.OpenFile(target, flags, 0600)
		if e == nil {
			_ = f.Close()
			t.Fatal("kernel unexpectedly permitted operation")
		}
		if !errors.Is(e, os.ErrPermission) {
			t.Fatalf("expected kernel EACCES, got %v", e)
		}
	default:
		t.Fatal("unknown helper action")
	}
}

func TestVMPhase3(t *testing.T) {
	if os.Getenv("RABIV_PHASE3_VM_APPROVED") != "owner-approved" {
		t.Skip("explicit owner-controlled execution required")
	}
	if os.Getuid() != 0 || !vmEnvironment() {
		t.Fatal("root on dedicated Ubuntu/KVM required")
	}
	for _, path := range []string{"/run/systemd/private", "/var/run/systemd/private"} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			t.Fatal("host systemd socket is required for the namespace visibility check")
		}
	}
	// Provisioning modes must not depend on the invoking sudo shell's umask.
	// This changes only this isolated test process; 0700 staging/workspaces stay
	// private and runtime adapters still refuse to repair administrator layouts.
	oldMask := syscall.Umask(0022)
	defer syscall.Umask(oldMask)
	for _, tool := range []string{"useradd", "userdel", "groupadd", "groupdel", "setpriv", "getfacl", "findmnt", "systemd-run", "systemctl", "getent", "pkill"} {
		if _, e := exec.LookPath(tool); e != nil {
			t.Fatal("missing tool", tool)
		}
	}
	bundle := os.Getenv("RABIV_PHASE3_REVIEWED")
	exe, e := os.Executable()
	if e != nil || !rootRegular(exe) || !rootRegular(filepath.Join(bundle, "rabiv-ingestor")) {
		t.Fatal("reviewed root-owned binaries required")
	}
	syft := os.Getenv("RABIV_PHASE3_SYFT")
	if !rootRegular(syft) {
		t.Fatal("root-owned Syft binary required")
	}
	fs, e := exec.Command("findmnt", "-n", "-o", "FSTYPE", "-T", "/var/lib").Output()
	if e != nil || strings.TrimSpace(string(fs)) != "ext4" {
		t.Fatal("guest ext4 required before mutation")
	}
	base := "/var/lib/rabiv-phase3-lab"
	if e = os.Mkdir(base, 0755); e != nil && !errors.Is(e, os.ErrExist) {
		t.Fatal(e)
	}
	i, e := os.Lstat(base)
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0755 || i.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("unsafe lab base")
	}
	fs, e = exec.Command("findmnt", "-n", "-o", "FSTYPE", "-T", base).Output()
	if e != nil || strings.TrimSpace(string(fs)) != "ext4" {
		t.Fatal("guest ext4 required")
	}
	root, e := os.MkdirTemp(base, "run.")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	t.Log("isolated evidence root:", root)
	if e = os.WriteFile(filepath.Join(root, "authorized"), []byte("RABIV_PHASE3_VM_ONLY\n"), 0444); e != nil {
		t.Fatal(e)
	}
	acl, e := exec.Command("getfacl", "-cp", root).Output()
	if e != nil || strings.Count(strings.TrimSpace(string(acl)), "\n") != 2 {
		t.Fatal("unexpected ACL entries")
	}
	c := vmConfig{Root: root, Binary: filepath.Join(root, "acquisition.test"), Ingestor: filepath.Join(root, "rabiv-ingestor"), Syft: syft, Actors: map[string]vmActor{}, Channels: map[string]string{}}
	for src, dst := range map[string]string{exe: c.Binary, filepath.Join(bundle, "rabiv-ingestor"): c.Ingestor} {
		b, e := os.ReadFile(src)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(dst, b, 0555); e != nil {
			t.Fatal(e)
		}
	}
	command := func(name string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("%s failed (%T)", name, e)
		}
		return b
	}
	var users, groups []string
	baselineUIDs := map[int]bool{}
	procEntries, e := os.ReadDir("/proc")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range procEntries {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		status, e := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				for _, value := range strings.Fields(strings.TrimPrefix(line, "Uid:")) {
					uid, e := strconv.Atoi(value)
					if e == nil {
						baselineUIDs[uid] = true
					}
				}
			}
		}
	}
	createdUIDs := map[string]int{}
	t.Cleanup(func() {
		for _, name := range users {
			if b, e := exec.Command("id", "-u", name).Output(); e == nil {
				uid := strings.TrimSpace(string(b))
				n, e := strconv.Atoi(uid)
				if e != nil || createdUIDs[name] != n || baselineUIDs[n] {
					t.Errorf("unsafe cleanup UID for %s; no process/account removal attempted", name)
					continue
				}
				_ = exec.Command("pkill", "-TERM", "-u", uid).Run()
				time.Sleep(50 * time.Millisecond)
				_ = exec.Command("pkill", "-KILL", "-u", uid).Run()
			}
			if e := exec.Command("userdel", name).Run(); e != nil {
				t.Errorf("cleanup user %s: %v", name, e)
			}
		}
		for _, name := range groups {
			if exec.Command("getent", "group", name).Run() == nil {
				if e := exec.Command("groupdel", name).Run(); e != nil {
					t.Errorf("cleanup group %s: %v", name, e)
				}
			}
		}
		if e := os.Chmod(root, 0700); e != nil {
			t.Error(e)
		}
	})
	tag := strings.ToLower(rand.Text()[:8])
	group := func(label string) int {
		name := "r3" + label + tag
		command("groupadd", "--system", name)
		groups = append(groups, name)
		out := command("getent", "group", name)
		parts := strings.Split(string(out), ":")
		gid, e := strconv.Atoi(parts[2])
		if e != nil {
			t.Fatal(e)
		}
		return gid
	}
	for _, role := range []string{"fetch", "collector", "worker", "finalizer", "verifier", "attacker"} {
		gid := group(role[:2])
		name := "r3" + role[:2] + tag
		command("useradd", "--system", "--gid", strconv.Itoa(gid), "--no-create-home", "--shell", "/usr/sbin/nologin", name)
		users = append(users, name)
		uid, e := strconv.Atoi(strings.TrimSpace(string(command("id", "-u", name))))
		if e != nil {
			t.Fatal(e)
		}
		createdUIDs[name] = uid
		if baselineUIDs[uid] {
			t.Fatal("allocated lab UID already used by an existing process; no tests will use it")
		}
		c.Actors[role] = vmActor{UID: uid, GID: gid}
	}
	type directed struct{ key, writer, reader string }
	c.Actors["capture"] = vmActor{UID: 0, GID: 0}
	channels := []directed{{"fetch_collector", "fetch", "collector"}, {"fetch_worker", "fetch", "worker"}, {"fetch_finalizer", "fetch", "finalizer"}, {"worker_finalizer", "worker", "finalizer"}, {"collector_verifier", "collector", "verifier"}, {"ingestor_verifier", "finalizer", "verifier"}, {"capture_collector", "capture", "collector"}}
	for n, ch := range channels {
		g := group("c" + strconv.Itoa(n))
		w, r := c.Actors[ch.writer], c.Actors[ch.reader]
		w.Groups = append(w.Groups, g)
		r.Groups = append(r.Groups, g)
		c.Actors[ch.writer] = w
		c.Actors[ch.reader] = r
		dir := filepath.Join(root, ch.key)
		if e = os.Mkdir(dir, 0755); e != nil {
			t.Fatal(e)
		}
		for name, mode := range map[string]os.FileMode{"staging": 0700, "committed": 0750 | os.ModeSetgid} {
			p := filepath.Join(dir, name)
			if e = os.Mkdir(p, 0700); e != nil {
				t.Fatal(e)
			}
			gid := w.GID
			if name == "committed" {
				gid = g
			}
			if e = os.Chown(p, w.UID, gid); e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(p, mode); e != nil {
				t.Fatal(e)
			}
		}
		cfg := input.Config{RootDir: dir, WriterUID: w.UID, WriterGID: w.GID, ReaderUID: r.UID, ReaderPrimaryGID: r.GID, ReaderGID: g}
		path := filepath.Join(root, ch.key+".json")
		b, e := json.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0444); e != nil {
			t.Fatal(e)
		}
		c.Channels[ch.key] = path
	}
	config := filepath.Join(root, "vm.json")
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(config, b, 0444); e != nil {
		t.Fatal(e)
	}
	actor := func(role string, emptyGroups bool, exe string, args []string, stdin []byte, extra ...string) ([]byte, error) {
		a := c.Actors[role]
		argv := []string{"--reuid", strconv.Itoa(a.UID), "--regid", strconv.Itoa(a.GID), "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all"}
		if emptyGroups || len(a.Groups) == 0 {
			argv = append(argv, "--clear-groups")
		} else {
			var groups []string
			for _, g := range a.Groups {
				groups = append(groups, strconv.Itoa(g))
			}
			argv = append(argv, "--groups", strings.Join(groups, ","))
		}
		argv = append(argv, "--", exe)
		argv = append(argv, args...)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "setpriv", argv...)
		cmd.Stdin = bytes.NewReader(stdin)
		cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "RABIV_PHASE3_VM_CONFIG=" + config, "RABIV_VM_ACTOR=" + role}, extra...)
		if emptyGroups {
			cmd.Env = append(cmd.Env, "RABIV_VM_NO_GROUPS=1")
		}
		return cmd.CombinedOutput()
	}
	helper := func(role, key, action, id, ref string, body []byte, emptyGroups bool) ([]byte, error) {
		return actor(role, emptyGroups, c.Binary, []string{"-test.run=^TestVMHelper$"}, body, "RABIV_VM_CHANNEL="+key, "RABIV_VM_ACTION="+action, "RABIV_VM_ID="+id, "RABIV_VM_REF="+ref)
	}
	parseRef := func(b []byte) artifact.ObjectReference {
		t.Helper()
		for _, line := range bytes.Split(b, []byte("\n")) {
			var r artifact.ObjectReference
			if json.Unmarshal(line, &r) == nil && r.Validate() == nil {
				return r
			}
		}
		t.Fatal("missing committed reference")
		return artifact.ObjectReference{}
	}
	for _, ch := range channels {
		t.Logf("channel %s writer=%+v reader=%+v", ch.key, c.Actors[ch.writer], c.Actors[ch.reader])
		raw, e := helper(ch.writer, ch.key, "put", "snapshot", "", []byte("complete snapshot"), false)
		if e != nil {
			t.Fatal(ch.key, "writer failed", e)
		}
		ref := parseRef(raw)
		token := ref.ID + "@" + ref.Digest.Value
		if _, e = helper(ch.reader, ch.key, "get", "", token, nil, false); e != nil {
			t.Fatal(ch.key, "authorized reader failed", e)
		}
		if _, e = helper(ch.reader, ch.key, "read-denied", "", "", nil, true); e != nil {
			t.Fatal(ch.key, "reader without groups kernel-denial assertion failed", e)
		}
		if _, e = helper("attacker", ch.key, "write-denied", "", "", nil, false); e != nil {
			t.Fatal(ch.key, "attacker write denial failed", e)
		}
		if _, e = helper("attacker", ch.key, "read-denied", "", "", nil, false); e != nil {
			t.Fatal(ch.key, "attacker read denial failed", e)
		}
	}
	// Direct kernel checks for private staging and syscall-level symlink refusal.
	var fw input.Config
	data, e := os.ReadFile(c.Channels["fetch_worker"])
	if e != nil || json.Unmarshal(data, &fw) != nil {
		t.Fatal("channel config")
	}
	private := filepath.Join(fw.RootDir, "staging", "private")
	if e = os.WriteFile(private, []byte("private"), 0440); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(private, fw.WriterUID, fw.ReaderGID); e != nil {
		t.Fatal(e)
	}
	if _, e = actor("worker", false, c.Binary, []string{"-test.run=^TestVMHelper$"}, nil, "RABIV_VM_CHANNEL=fetch_worker", "RABIV_VM_ACTION=read-denied", "RABIV_VM_STAGING=1"); e != nil {
		t.Fatal("uncommitted staging became readable", e)
	}
	if e = os.Symlink("object-snapshot", filepath.Join(fw.RootDir, "committed", "object-link")); e != nil {
		t.Fatal(e)
	}
	if _, e = helper("worker", "fetch_worker", "get", "", "link@"+acquire.Hash([]byte("complete snapshot")).Value, nil, false); e == nil {
		t.Fatal("input adapter followed symlink")
	}
	// Probe real namespaces/mounts/cgroups without contacting any network target.
	workspace := filepath.Join(root, "workspace")
	if e = os.Mkdir(workspace, 0700); e != nil {
		t.Fatal(e)
	}
	wa := c.Actors["worker"]
	if e = os.Chown(workspace, wa.UID, wa.GID); e != nil {
		t.Fatal(e)
	}
	probePath := filepath.Join(fw.RootDir, "probe")
	if e = os.WriteFile(probePath, []byte("readonly mount sentinel"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(probePath, wa.UID, wa.GID); e != nil {
		t.Fatal(e)
	}
	credentials := filepath.Join(root, "credential-sentinel")
	if e = os.WriteFile(credentials, []byte("not a credential"), 0444); e != nil {
		t.Fatal(e)
	}
	decisions := filepath.Join(root, "decision-sentinel")
	if e = os.Mkdir(decisions, 0755); e != nil {
		t.Fatal(e)
	}
	var resultCfg input.Config
	data, e = os.ReadFile(c.Channels["worker_finalizer"])
	if e != nil || json.Unmarshal(data, &resultCfg) != nil {
		t.Fatal("result channel config")
	}
	ni, e := os.Stat("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	p := worker.Config{UID: wa.UID, GID: wa.GID, FetchReaderGID: fw.ReaderGID, ResultReaderGID: resultCfg.ReaderGID, FetchRoot: fw.RootDir, ResultRoot: resultCfg.RootDir, Workspace: workspace, Executable: c.Binary, SyftBinary: c.Syft, DecisionRoot: decisions, CredentialPaths: []string{credentials}, HostNetNS: ni.Sys().(*syscall.Stat_t).Ino, MemoryBytes: 2 << 30, CPUPercent: 100, Tasks: 64, TimeoutSeconds: 180}
	profile := filepath.Join(root, "probe-profile.json")
	data, e = json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(profile, data, 0444); e != nil {
		t.Fatal(e)
	}
	probe, e := worker.Launch(context.Background(), profile, []string{})
	if e != nil {
		t.Fatal("actual worker OS probe failed", e)
	}
	t.Log("worker enforcement:", string(probe))
	// Execute the real production Worker and Finalizer with a reviewed ELF input.
	elf, e := os.ReadFile(c.Ingestor)
	if e != nil {
		t.Fatal(e)
	}
	var transport bytes.Buffer
	zw := zip.NewWriter(&transport)
	zf, e := zw.Create("out/probe")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = zf.Write(elf); e != nil {
		t.Fatal(e)
	}
	if e = zw.Close(); e != nil {
		t.Fatal(e)
	}
	put := func(key, id string, b []byte) artifact.ObjectReference {
		raw, e := helper("fetch", key, "put", id, "", b, false)
		if e != nil {
			t.Fatal("fetch fixture publication", e)
		}
		return parseRef(raw)
	}
	contextClaim := build.Context{Identity: build.Identity{Provider: build.GitLab, Instance: "https://ci.example", ProjectID: "5", JobID: "27"}, PipelineID: "73", Source: &build.SourceRevision{RepositoryURI: "https://ci.example/team/project", CommitSHA: strings.Repeat("a", 40)}}
	var jobRef artifact.ObjectReference
	for _, key := range []string{"fetch_worker", "fetch_finalizer"} {
		meta, e := json.Marshal(contextClaim)
		if e != nil {
			t.Fatal(e)
		}
		m := put(key, "metadata", meta)
		a := put(key, "archive", transport.Bytes())
		j := acquire.Job{Version: acquire.Version, Build: contextClaim, Metadata: &m, Archive: &a, ArtifactsRequested: true, RecordedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		b, e := json.Marshal(j)
		if e != nil {
			t.Fatal(e)
		}
		r := put(key, "job", b)
		if jobRef.ID != "" && !jobRef.Equal(r) {
			t.Fatal("fetch fixture differs across channels")
		}
		jobRef = r
	}
	p.Executable = c.Ingestor
	profile = filepath.Join(root, "worker-profile.json")
	data, e = json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(profile, data, 0444); e != nil {
		t.Fatal(e)
	}
	raw, e := worker.Launch(context.Background(), profile, []string{"--fetch-channel", c.Channels["fetch_worker"], "--output-channel", c.Channels["worker_finalizer"], "--job-ref", jobRef.ID + "@" + jobRef.Digest.Value, "--id", "processed", "--subject", "out/probe", "--max-entry", "33554432", "--max-expanded", "67108864"})
	if e != nil {
		t.Fatal("production isolated Worker failed", e)
	}
	wr := parseRef(raw)
	raw, e = actor("finalizer", false, c.Ingestor, []string{"finalize", "--fetch-channel", c.Channels["fetch_finalizer"], "--worker-channel", c.Channels["worker_finalizer"], "--output-channel", c.Channels["ingestor_verifier"], "--job-ref", jobRef.ID + "@" + jobRef.Digest.Value, "--worker-ref", wr.ID + "@" + wr.Digest.Value, "--id", "manifest", "--workflow-id", "workflow", "--group-id", "subjects", "--subject", "out/probe"}, nil)
	if e != nil {
		t.Fatal("production Finalizer failed", e)
	}
	mr := parseRef(raw)
	var finalCfg input.Config
	data, e = os.ReadFile(c.Channels["ingestor_verifier"])
	if e != nil || json.Unmarshal(data, &finalCfg) != nil {
		t.Fatal("final input channel")
	}
	data, e = os.ReadFile(filepath.Join(finalCfg.RootDir, "committed", "object-"+mr.ID))
	if e != nil {
		t.Fatal(e)
	}
	m, e := v1.DecodeArtifactManifest(data)
	if e != nil || m.State != v1.Finalized || m.Payload.SBOMRef == nil {
		t.Fatal("invalid real Worker manifest", e)
	}
	if _, e = helper("verifier", "ingestor_verifier", "get", "", mr.ID+"@"+mr.Digest.Value, nil, false); e != nil {
		t.Fatal("Verifier cannot read final manifest", e)
	}
}
