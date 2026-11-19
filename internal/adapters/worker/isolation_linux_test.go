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
	args, err := c.Arguments("/etc/example/worker.json", "rabiv-worker-example", []string{"--id", "test"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	for _, required := range []string{"User=41001", "SupplementaryGroups=41002 41003", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "ReadOnlyPaths=/var/lib/example/fetch", "ReadWritePaths=/var/lib/example/work /var/lib/example/result", "InaccessiblePaths=/var/lib/example/decisions /etc/example/credentials -/run -/var/run", "MemoryMax=1073741824", "KillMode=control-group"} {
		if !strings.Contains(joined, "--property="+required+"\n") {
			t.Fatalf("missing property %s", required)
		}
	}
	if strings.Contains(joined, "sudo") || strings.Contains(joined, "docker.sock") || strings.Contains(joined, "/bin/sh") {
		t.Fatal("unexpected privilege/command path")
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
