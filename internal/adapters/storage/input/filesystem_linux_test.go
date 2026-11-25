package input

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

// Functional tests exercise real files with the same UID. They intentionally do
// not use production OpenWriter or claim cross-UID Linux authorization evidence.
func fixture(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "staging"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "staging"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "committed"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "committed"), 0750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := layout(r, Config{WriterUID: os.Getuid(), WriterGID: os.Getgid(), ReaderGID: os.Getgid()}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSnapshots(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	payload := []byte("exact snapshot")
	ref, err := s.Put(ctx, "record", bytes.NewReader(payload), 1024)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Get(ctx, ref, 1024)
	if err != nil || !bytes.Equal(b, payload) {
		t.Fatalf("read: %v", err)
	}
	duplicate, err := s.Put(ctx, "record", bytes.NewReader(payload), 1024)
	if err != nil || duplicate != ref {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.Put(ctx, "record", bytes.NewBufferString("different"), 1024); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := s.Put(ctx, "record", bytes.NewBufferString("short"), 5); !errors.Is(err, ErrConflict) {
		t.Fatalf("size mismatch was not a conflict: %v", err)
	}
	if _, err := s.Put(ctx, "record", bytes.NewReader(bytes.Repeat([]byte("x"), len(payload))), 1024); !errors.Is(err, ErrConflict) {
		t.Fatalf("same size with different bytes was not a conflict: %v", err)
	}
	if _, err := s.Put(ctx, "oversize", bytes.NewReader(payload), 1); err == nil {
		t.Fatal("accepted oversize")
	}
	wrong := ref
	wrong.Digest = acquire.Hash([]byte("wrong"))
	if _, err := s.Get(ctx, wrong, 1024); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("integrity: %v", err)
	}
	if _, err := s.Get(ctx, artifact.ObjectReference{ID: "../escape", Digest: ref.Digest}, 1024); err == nil {
		t.Fatal("path escaped")
	}
	if err := s.committed.Symlink("object-record", "object-link"); err != nil {
		t.Fatal(err)
	}
	link := ref
	link.ID = "link"
	if _, err := s.Get(ctx, link, 1024); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestConcurrentCommit(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	payload := bytes.Repeat([]byte("x"), 1<<18)
	ref := artifact.ObjectReference{ID: "concurrent", Digest: acquire.Hash(payload)}
	var wg sync.WaitGroup
	defer wg.Wait()
	for range 4 {
		wg.Go(func() {
			for range 50 {
				b, err := s.Get(ctx, ref, int64(len(payload)))
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Error(err)
					return
				}
				if err == nil && !bytes.Equal(b, payload) {
					t.Error("partial final")
				}
			}
		})
	}
	if _, err := s.Put(ctx, ref.ID, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
}

func TestSynchronizationOutcomes(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "file_before_visibility", true: "directory_after_visibility"}[after], func(t *testing.T) {
			s := fixture(t)
			s.sync = func(f *os.File) error {
				info, err := f.Stat()
				if err != nil {
					return err
				}
				if info.IsDir() == after {
					return errors.New("injected sync")
				}
				return f.Sync()
			}
			_, err := s.Put(context.Background(), "sync", bytes.NewBufferString("bytes"), 1024)
			if err == nil || errors.Is(err, ErrCommitUncertain) != after {
				t.Fatalf("outcome: %v", err)
			}
			_, statErr := s.committed.Stat("object-sync")
			if (statErr == nil) != after {
				t.Fatalf("visibility: %v", statErr)
			}
		})
	}
}

func TestProductionRejectsUserWritableAncestors(t *testing.T) {
	if _, err := anchor(t.TempDir()); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("unsafe ancestor: %v", err)
	}
}
