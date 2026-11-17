package decision

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rabiv-org/rabiv/internal/app/publish"
	"github.com/rabiv-org/rabiv/internal/app/verify"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

// These ordinary functional tests exercise private file-protocol helpers in a
// same-UID temporary tree. They do NOT establish multi-UID OS authorization.
func functionalStore(t *testing.T) *snapshotFS {
	t.Helper()
	base := t.TempDir()
	for _, name := range []string{"staging", "committed"} {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	r, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	s, err := r.OpenRoot("staging")
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.OpenRoot("committed")
	if err != nil {
		t.Fatal(err)
	}
	fs := &snapshotFS{root: r, staging: s, committed: c, cfg: Config{RootDir: base, VerifierUID: os.Geteuid(), ReaderGID: os.Getegid()}, syncFile: func(f *os.File) error { return f.Sync() }}
	t.Cleanup(func() {
		if err := fs.close(); err != nil {
			t.Error(err)
		}
	})
	return fs
}

func TestPrivateStagingAndDurableOrdering(t *testing.T) {
	s := functionalStore(t)
	payload := []byte(`{"complete":"record"}`)
	var stages []string
	s.syncFile = func(f *os.File) error {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		temps, err := os.ReadDir(filepath.Join(s.cfg.RootDir, "staging"))
		if err != nil {
			return err
		}
		finals, err := os.ReadDir(filepath.Join(s.cfg.RootDir, "committed"))
		if err != nil {
			return err
		}
		if !info.IsDir() {
			stages = append(stages, "file")
			if info.Mode().Perm() != 0440 || len(temps) != 1 || len(finals) != 0 {
				return fmt.Errorf("file metadata/visibility ordering violated")
			}
			got, err := os.ReadFile(filepath.Join(s.cfg.RootDir, "staging", temps[0].Name()))
			if err != nil || !bytes.Equal(got, payload) {
				return fmt.Errorf("incomplete staged bytes: %w", err)
			}
		} else if len(temps) == 1 && len(finals) == 1 {
			stages = append(stages, "committed directory")
		} else if len(temps) == 0 && len(finals) == 1 {
			stages = append(stages, "staging directory")
		} else {
			return fmt.Errorf("directory sync ordering violated")
		}
		return f.Sync()
	}
	if err := s.putBytes(context.Background(), "d-1", payload); err != nil {
		t.Fatal(err)
	}
	if strings.Join(stages, ",") != "file,committed directory,staging directory" {
		t.Fatal(stages)
	}
	got, err := s.read(context.Background(), "d-1")
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("committed read", err)
	}
}

func TestSnapshotSyncFailures(t *testing.T) {
	for _, stage := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			s := functionalStore(t)
			calls := 0
			injected := errors.New("injected sync error")
			s.syncFile = func(f *os.File) error {
				calls++
				if calls == stage {
					return injected
				}
				return f.Sync()
			}
			err := s.putBytes(context.Background(), "d-1", []byte("complete"))
			if !errors.Is(err, injected) {
				t.Fatal(err)
			}
			_, readErr := s.read(context.Background(), "d-1")
			if stage == 1 {
				if !errors.Is(readErr, os.ErrNotExist) || errors.Is(err, ErrCommitUncertain) {
					t.Fatal("pre-visibility failure misclassified", err, readErr)
				}
			} else if !errors.Is(err, ErrCommitUncertain) || readErr != nil {
				t.Fatal("post-visibility failure must preserve final and report uncertainty", err, readErr)
			}
		})
	}
}

func TestCleanupFailureAfterVisibilityIsUncertain(t *testing.T) {
	s := functionalStore(t)
	s.syncFile = func(f *os.File) error {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Test-only fault: another cleanup removed our private name after
			// Link. The final must survive; the failed cleanup is not an ACK.
			entries, err := os.ReadDir(filepath.Join(s.cfg.RootDir, "staging"))
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if err := s.staging.Remove(entry.Name()); err != nil {
					return err
				}
			}
		}
		return f.Sync()
	}
	err := s.putBytes(context.Background(), "d-1", []byte("complete"))
	if !errors.Is(err, ErrCommitUncertain) {
		t.Fatal(err)
	}
	if data, err := s.read(context.Background(), "d-1"); err != nil || string(data) != "complete" {
		t.Fatal("cleanup error removed final", err)
	}
}

func TestDuplicatesConflictsAndRestart(t *testing.T) {
	s := functionalStore(t)
	raw := []byte("original")
	for range 2 {
		if err := s.putBytes(context.Background(), "d-1", raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.putBytes(context.Background(), "d-1", []byte("different")); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	got, err := s.read(context.Background(), "d-1")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("conflict replaced final", err)
	}
	// A new descriptor reads the acknowledged snapshot without a live writer.
	r, err := os.OpenRoot(filepath.Join(s.cfg.RootDir, "committed"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	restarted := &snapshotFS{committed: r, cfg: s.cfg}
	got, err = restarted.read(context.Background(), "d-1")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal(err)
	}
	// Duplicate ACK must also synchronize an existing visible snapshot.
	s.syncFile = func(f *os.File) error {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() {
			return syscall.EIO
		}
		return f.Sync()
	}
	if err := s.putBytes(context.Background(), "d-1", raw); !errors.Is(err, ErrCommitUncertain) {
		t.Fatal(err)
	}
}

func TestConcurrentReadersNeverObservePartialFinals(t *testing.T) {
	s := functionalStore(t)
	raw := bytes.Repeat([]byte("x"), publish.MaxDecisionBytes)
	done := make(chan struct{})
	readErrors := make(chan error, 1)
	go func() {
		defer close(done)
		for i := 0; i < 8; i++ {
			id := fmt.Sprintf("d-%d", i)
			for {
				data, err := s.read(context.Background(), id)
				if errors.Is(err, os.ErrNotExist) {
					time.Sleep(time.Millisecond)
					continue
				}
				if err != nil || !bytes.Equal(data, raw) {
					readErrors <- fmt.Errorf("partial final %s: %w", id, err)
					return
				}
				break
			}
		}
	}()
	for i := 0; i < 8; i++ {
		if err := s.putBytes(context.Background(), fmt.Sprintf("d-%d", i), raw); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader timeout")
	}
	select {
	case err := <-readErrors:
		t.Fatal(err)
	default:
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() { errs <- s.putBytes(context.Background(), "duplicate", []byte("same")) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadObjectAndSizeGuards(t *testing.T) {
	for _, kind := range []string{"wrong-mode", "wrong-owner", "wrong-group", "directory", "symlink", "fifo", "large"} {
		t.Run(kind, func(t *testing.T) {
			s := functionalStore(t)
			name := "decision-d-1.json"
			path := filepath.Join(s.cfg.RootDir, "committed", name)
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0440); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(s.cfg.RootDir, "outside"), path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0440); err != nil {
					t.Fatal(err)
				}
			default:
				data := []byte("record")
				if kind == "large" {
					data = bytes.Repeat([]byte("x"), publish.MaxDecisionBytes+1)
				}
				if err := os.WriteFile(path, data, 0440); err != nil {
					t.Fatal(err)
				}
				if kind == "wrong-mode" {
					if err := os.Chmod(path, 0640); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "wrong-owner" {
					s.cfg.VerifierUID++
				}
				if kind == "wrong-group" {
					s.cfg.ReaderGID++
				}
			}
			if _, err := s.read(context.Background(), "d-1"); err == nil {
				t.Fatal("unsafe object read")
			}
		})
	}
	s := functionalStore(t)
	for _, id := range []string{"../escape", "/absolute", ""} {
		if _, err := s.read(context.Background(), id); err == nil {
			t.Fatal("unsafe ID accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.putBytes(ctx, "cancelled", []byte("data")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.read(ctx, "d"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestPublicGuardsAndRecordValidation(t *testing.T) {
	for _, cfg := range []Config{{}, {RootDir: "relative"}, {RootDir: "/", VerifierUID: 1, PublisherUID: 2}, {RootDir: "/unused", VerifierUID: 1, PublisherUID: 1, VerifierPrimaryGID: 2, PublisherPrimaryGID: 2, ReaderGID: 3}} {
		if _, err := NewWriter(cfg); err == nil {
			t.Fatal("unsafe writer configuration accepted")
		}
		if _, err := NewReader(cfg); err == nil {
			t.Fatal("unsafe reader configuration accepted")
		}
	}
	if r, err := openAnchor("/tmp"); err == nil {
		_ = r.Close()
		t.Fatal("writable ancestor accepted")
	}
	s := functionalStore(t)
	w := &Writer{fs: s}
	r, err := verify.NewDiagnostic(verify.DiagnosticRequest{DecisionID: "diag", WorkflowID: "wf", Build: build.Identity{Provider: build.GitLab, Instance: "https://gitlab.example", ProjectID: "1", JobID: "2"}}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := w.Put(context.Background(), r)
	if err != nil || ref.Validate() != nil {
		t.Fatal(err)
	}
	r.Decision.Build.Source = &build.SourceRevision{RepositoryURI: "https://gitlab.example/" + strings.Repeat("a", publish.MaxDecisionBytes), CommitSHA: strings.Repeat("b", 40)}
	if _, err := w.Put(context.Background(), r); !errors.Is(err, publish.ErrTooLarge) {
		t.Fatal(err)
	}
	r.Decision.DecisionID = ""
	if _, err := w.Put(context.Background(), r); err == nil {
		t.Fatal("invalid record accepted")
	}
}
