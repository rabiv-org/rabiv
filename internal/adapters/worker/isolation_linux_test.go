package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func profile() Config {
	return Config{UID: 41001, GID: 41001, FetchReaderGID: 41002, ResultReaderGID: 41003, FetchRoot: "/var/lib/example/fetch", ResultRoot: "/var/lib/example/result", Workspace: "/var/lib/example/work", Executable: "/opt/example/rabiv-ingestor", SyftBinary: "/opt/example/syft", DecisionRoot: "/var/lib/example/decisions", CredentialPaths: []string{"/etc/example/credentials"}, HostNetNS: 1234, MemoryBytes: 1 << 30, CPUPercent: 100, Tasks: 64, TimeoutSeconds: 120}
}

func TestProfileProperties(t *testing.T) {
	c := profile()
	args, err := c.Arguments("/etc/example/worker.json", "rabiv-worker-example")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	for _, required := range []string{"User=41001", "SupplementaryGroups=41002 41003", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "ReadOnlyPaths=/var/lib/example/fetch /tmp /var/tmp", "ReadWritePaths=/var/lib/example/work /var/lib/example/result", "InaccessiblePaths=/var/lib/example/decisions /etc/example/credentials", "TemporaryFileSystem=/run:ro,nosuid,nodev,noexec,mode=0755", "MemoryMax=1073741824", "KillMode=control-group"} {
		if !strings.Contains(joined, "--property="+required+"\n") {
			t.Fatalf("missing property %s", required)
		}
	}
	if strings.Contains(joined, "sudo") || strings.Contains(joined, "docker.sock") || strings.Contains(joined, "/bin/sh") {
		t.Fatal("unexpected privilege/command path")
	}
}

func TestPathsUnderRunAreMaskedByOverlay(t *testing.T) {
	c := profile()
	c.CredentialPaths = append(c.CredentialPaths, "/run/rabiv/credential", "/var/run/rabiv/credential")
	args, err := c.Arguments("/etc/example/worker.json", "rabiv-worker-example")
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--property=InaccessiblePaths=") && strings.Contains(arg, "/run") {
			t.Fatalf("uses an inaccessible mount under the /run overlay: %s", arg)
		}
	}
	c.Workspace = "/var/run/rabiv/work"
	if err := c.Validate(); !errors.Is(err, ErrIsolation) {
		t.Fatalf("workspace accepted under /var/run: %v", err)
	}
}

func TestUnitRejectsHiddenProfileAndSystemdListSyntax(t *testing.T) {
	c := profile()
	for _, path := range []string{"/home/example/profile.json", "/run/worker.json", "/tmp/example.json", "/var/tmp/example.json", "/etc/example/credentials/worker.json", "/var/lib/example/decisions/profile.json"} {
		if _, err := c.Arguments(path, "rabiv-worker-example"); !errors.Is(err, ErrIsolation) {
			t.Fatalf("profile unavailable in sandbox was accepted: %s", path)
		}
	}
	for _, path := range []string{`/var/lib/example/a"b`, `/var/lib/example/a'b`, `/var/lib/example/a\b`} {
		unsafe := c
		unsafe.FetchRoot = path
		if unsafe.Validate() == nil {
			t.Fatalf("systemd list syntax accepted: %s", path)
		}
	}
}

func TestUnsafeProfilesAndNoImplicitPrivilege(t *testing.T) {
	for _, mutate := range []func(*Config){func(c *Config) { c.UID = 0 }, func(c *Config) { c.FetchReaderGID = c.GID }, func(c *Config) { c.Workspace = c.FetchRoot }, func(c *Config) { c.Workspace = "/tmp/unsafe" }, func(c *Config) { c.HostNetNS = 0 }, func(c *Config) { c.CredentialPaths = nil }} {
		c := profile()
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("unsafe profile accepted")
		}
	}
	if _, err := Load(t.TempDir() + "/profile.json"); !errors.Is(err, ErrIsolation) {
		t.Fatalf("untrusted profile: %v", err)
	}
	if _, err := Launch(context.Background(), "/does-not-exist", nil); !errors.Is(err, ErrIsolation) {
		t.Fatalf("implicit privilege: %v", err)
	}
	if profile().Check() == nil {
		t.Fatal("ordinary host process accepted as isolated worker")
	}
}

func TestProfileBoundaryAndPathSeparation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
		valid  bool
	}{
		{"minimum memory", func(c *Config) { c.MemoryBytes = 128 << 20 }, true},
		{"insufficient memory", func(c *Config) { c.MemoryBytes = (128 << 20) - 1 }, false},
		{"maximum cpu", func(c *Config) { c.CPUPercent = 400 }, true},
		{"excess cpu", func(c *Config) { c.CPUPercent = 401 }, false},
		{"minimum tasks", func(c *Config) { c.Tasks = 8 }, true},
		{"insufficient tasks", func(c *Config) { c.Tasks = 7 }, false},
		{"maximum timeout", func(c *Config) { c.TimeoutSeconds = 3600 }, true},
		{"excess timeout", func(c *Config) { c.TimeoutSeconds = 3601 }, false},
		{"distinct primary gid", func(c *Config) { c.GID = 41077 }, true},
		{"credential ancestor", func(c *Config) { c.CredentialPaths = []string{"/var/lib/example"} }, false},
		{"workspace ancestor", func(c *Config) { c.Workspace = "/var/lib/example" }, false},
		{"result under workspace", func(c *Config) { c.ResultRoot = c.Workspace + "/result" }, false},
		{"fetch under result", func(c *Config) { c.FetchRoot = c.ResultRoot + "/fetch" }, false},
		{"read only overlap", func(c *Config) { c.SyftBinary = c.Executable }, true},
		{"runtime credentials masked", func(c *Config) {
			c.CredentialPaths = []string{"/run/example/credential", "/var/run/example/credential"}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := profile()
			tc.change(&c)
			if err := c.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

func TestWorkerEnvironmentRetainsRoleSpecificPolicy(t *testing.T) {
	for _, tc := range []struct {
		entry string
		valid bool
	}{
		{"LANG=token-in-value", true}, {"PATH=/usr/bin:/bin", true}, {"HOME=/nonexistent", true},
		// Worker has no Docker socket; do not silently broaden its environment deny policy.
		{"DOCKER_HOST=x", true}, {"git_config=x", false}, {"SSH_AUTH_SOCK=x", false}, {"custom_token=x", false}, {"password_file=x", false},
	} {
		if got := validWorkerEnvironment([]string{tc.entry}); got != tc.valid {
			t.Fatalf("worker environment policy changed for %q", tc.entry)
		}
	}
}
