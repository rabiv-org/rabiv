package syft

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
)

func sbom(hash string) string {
	return fmt.Sprintf(`{"descriptor":{"name":"syft","version":"test-format"},"schema":{"version":"supported-example"},"source":{"type":"file","metadata":{"digests":[{"algorithm":"sha256","value":%q}]}},"artifacts":[]}`, hash)
}

func TestCLIEnvironmentBytesAndCleanup(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "synthetic-must-not-inherit")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Binary: "/usr/bin/syft", Workspace: dir, Timeout: time.Second, MaxOutput: 4096})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("source bytes")
	digest := acquire.Hash(data)
	c.run = func(cmd *exec.Cmd) error {
		for _, e := range cmd.Env {
			if strings.Contains(e, "synthetic-must-not-inherit") || strings.HasPrefix(e, "GITLAB_") {
				t.Fatal("inherited credentials")
			}
		}
		if cmd.Stdin != nil || len(cmd.ExtraFiles) != 0 || cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
			t.Fatal("unsafe subprocess context")
		}
		if cmd.Args[3] != "scan" || !strings.HasPrefix(cmd.Args[4], "file:") {
			t.Fatalf("bad invocation: %v", cmd.Args)
		}
		b, e := os.ReadFile(strings.TrimPrefix(cmd.Args[4], "file:"))
		if e != nil || acquire.Hash(b) != digest {
			t.Fatal("wrong subject bytes")
		}
		b, e = os.ReadFile(cmd.Args[2])
		if e != nil || string(b) != "{}\n" {
			t.Fatal("ambient scanner config")
		}
		_, e = io.WriteString(cmd.Stdout, sbom(digest.Value))
		return e
	}
	if _, err = c.Scan(context.Background(), data, digest); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("private input/config not cleaned")
	}
	c.run = func(cmd *exec.Cmd) error { _, e := io.WriteString(cmd.Stdout, strings.Repeat("x", 4097)); return e }
	if _, err = c.Scan(context.Background(), data, digest); err == nil {
		t.Fatal("accepted unbounded subprocess output")
	}
}

func TestSBOMBindingAndFormat(t *testing.T) {
	d := acquire.Hash([]byte("x"))
	if Validate([]byte(sbom(d.Value)), d) != nil {
		t.Fatal("valid SBOM rejected")
	}
	for _, raw := range []string{sbom(strings.Repeat("a", 64)), `{"descriptor":{"name":"syft"}}`, strings.Replace(sbom(d.Value), `"artifacts":[]`, `"artifacts":null`, 1), strings.Replace(sbom(d.Value), `"file"`, `"image"`, 1)} {
		if Validate([]byte(raw), d) == nil {
			t.Fatal("unbound/unsupported SBOM accepted")
		}
	}
}
