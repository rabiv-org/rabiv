package input

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenConfigThroughSearchOnlyDirectory(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "config")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "channel.json"), []byte("{}"), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0100); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(directory, 0700) }()
	if os.Geteuid() != 0 {
		oldRoot, err := os.OpenRoot(directory)
		if oldRoot != nil {
			_ = oldRoot.Close()
		}
		if !errors.Is(err, syscall.EACCES) {
			t.Fatalf("original data-style directory open did not reach the expected permission check: %v", err)
		}
	}
	root, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	f, err := openConfigAt(root, []string{"config", "channel.json"}, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("failed to open known config through search-only directory: %v", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "{}" {
		t.Fatalf("config file changed: %q %v", b, err)
	}

	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("config", filepath.Join(base, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("channel.json", filepath.Join(directory, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, parts := range [][]string{{"alias", "channel.json"}, {"config", "alias"}} {
		if f, err := openConfigAt(root, parts, uint32(os.Geteuid())); err == nil {
			_ = f.Close()
			t.Fatalf("followed a symlink in config path %v", parts)
		}
	}
	if err := os.Chmod(directory, 0720); err != nil {
		t.Fatal(err)
	}
	if f, err := openConfigAt(root, []string{"config", "channel.json"}, uint32(os.Geteuid())); !errors.Is(err, ErrUnsafe) {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("accepted group-writable config directory: %v", err)
	}
}
