// Package decision implements protected local decision snapshots on Linux.
// It authenticates a storage boundary under trusted administrator/Verifier
// assumptions, not evaluator honesty, policy authorization, or release authority.
package decision

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/publish"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

var (
	ErrCredentials     = errors.New("unexpected process credentials")
	ErrUnsafeStore     = errors.New("unsafe decision storage")
	ErrConflict        = errors.New("decision ID already has different bytes")
	ErrCommitUncertain = errors.New("decision visible but durable commit not acknowledged")
)

// Config is administrator-controlled. RootDir is root-owned 0755 and contains
// staging (VerifierUID:VerifierPrimaryGID 0700) and committed
// (VerifierUID:ReaderGID 2750). ReaderGID is supplementary, not shared primary GID.
type Config struct {
	RootDir             string
	VerifierUID         int
	PublisherUID        int
	VerifierPrimaryGID  int
	PublisherPrimaryGID int
	ReaderGID           int
}

func (c Config) validate() error {
	if !filepath.IsAbs(c.RootDir) || filepath.Clean(c.RootDir) != c.RootDir || c.RootDir == "/" {
		return fmt.Errorf("%w: canonical absolute root required", ErrUnsafeStore)
	}
	if c.VerifierUID <= 0 || c.PublisherUID <= 0 || c.VerifierUID == c.PublisherUID || c.VerifierPrimaryGID <= 0 || c.PublisherPrimaryGID <= 0 || c.ReaderGID <= 0 || c.ReaderGID == c.VerifierPrimaryGID || c.ReaderGID == c.PublisherPrimaryGID {
		return ErrCredentials
	}
	return nil
}

func (c Config) checkRole(writer bool) error {
	if err := c.validate(); err != nil {
		return err
	}
	uid, gid := c.PublisherUID, c.PublisherPrimaryGID
	if writer {
		uid, gid = c.VerifierUID, c.VerifierPrimaryGID
	}
	if os.Getuid() != uid || os.Geteuid() != uid || os.Getgid() != gid || os.Getegid() != gid {
		return ErrCredentials
	}
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	for _, group := range groups {
		if group == c.ReaderGID {
			return nil
		}
	}
	return fmt.Errorf("%w: dedicated reader group missing", ErrCredentials)
}

type snapshotFS struct {
	root      *os.Root
	staging   *os.Root
	committed *os.Root
	cfg       Config
	// Private I/O seam for ordinary functional tests; never configurable by CLI.
	syncFile func(*os.File) error
}

// Writer accepts validated declarations, never untrusted fixture files from CLI.
type Writer struct{ fs *snapshotFS }

// Reader only opens the committed namespace; it never opens private staging.
type Reader struct{ fs *snapshotFS }

// NewWriter checks the real process and protected layout. It creates no directories.
func NewWriter(cfg Config) (*Writer, error) {
	if err := cfg.checkRole(true); err != nil {
		return nil, err
	}
	fs, err := openStore(cfg, true)
	if err != nil {
		return nil, err
	}
	return &Writer{fs: fs}, nil
}

// NewReader requires the Publisher UID/primary GID and actual reader group.
func NewReader(cfg Config) (*Reader, error) {
	if err := cfg.checkRole(false); err != nil {
		return nil, err
	}
	fs, err := openStore(cfg, false)
	if err != nil {
		return nil, err
	}
	return &Reader{fs: fs}, nil
}

func metadata(info os.FileInfo) (*syscall.Stat_t, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, ErrUnsafeStore
	}
	return s, nil
}

func checkDir(info os.FileInfo, uid, gid int, mode os.FileMode) error {
	s, err := metadata(info)
	if err != nil {
		return err
	}
	if !info.IsDir() || int(s.Uid) != uid || (gid >= 0 && int(s.Gid) != gid) || info.Mode()&(os.ModePerm|os.ModeSetgid|os.ModeSetuid|os.ModeSticky) != mode {
		return ErrUnsafeStore
	}
	return nil
}

func openChild(parent *os.Root, name string, uid, gid int, mode os.FileMode) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := checkDir(before, uid, gid, mode); err != nil {
		return nil, err
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	after, err := child.Stat(".")
	if err == nil && !os.SameFile(before, after) {
		err = ErrUnsafeStore
	}
	if err == nil {
		err = checkDir(after, uid, gid, mode)
	}
	if err != nil {
		return nil, errors.Join(err, child.Close())
	}
	return child, nil
}

// openAnchor walks only trusted, non-writable root-owned ancestors. os.Root alone
// is insufficient because it follows confined symlinks. No checked absolute path
// is later reopened; the final root remains pinned by its descriptor.
func openAnchor(name string) (*os.Root, error) {
	r, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	initial, err := r.Stat(".")
	if err == nil {
		err = checkAncestor(initial)
	}
	if err != nil {
		return nil, errors.Join(err, r.Close())
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		info, e := r.Lstat(part)
		if e == nil {
			e = checkAncestor(info)
		}
		if e != nil {
			return nil, errors.Join(e, r.Close())
		}
		next, e := r.OpenRoot(part)
		if e != nil {
			return nil, errors.Join(e, r.Close())
		}
		after, e := next.Stat(".")
		if e == nil && !os.SameFile(info, after) {
			e = ErrUnsafeStore
		}
		if e == nil {
			e = checkAncestor(after)
		}
		if e != nil {
			return nil, errors.Join(e, next.Close(), r.Close())
		}
		if e := r.Close(); e != nil {
			return nil, errors.Join(e, next.Close())
		}
		r = next
	}
	info, err := r.Stat(".")
	if err == nil {
		err = checkDir(info, 0, 0, 0755)
	}
	if err != nil {
		return nil, errors.Join(err, r.Close())
	}
	return r, nil
}

func checkAncestor(info os.FileInfo) error {
	s, err := metadata(info)
	if err != nil {
		return err
	}
	if !info.IsDir() || s.Uid != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 {
		return ErrUnsafeStore
	}
	return nil
}

func device(r *os.Root) (uint64, error) {
	info, err := r.Stat(".")
	if err != nil {
		return 0, err
	}
	s, err := metadata(info)
	if err != nil {
		return 0, err
	}
	return uint64(s.Dev), nil
}

func openStore(cfg Config, writer bool) (*snapshotFS, error) {
	r, err := openAnchor(cfg.RootDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsafeStore, err)
	}
	fs := &snapshotFS{root: r, cfg: cfg, syncFile: func(f *os.File) error { return f.Sync() }}
	fs.committed, err = openChild(r, "committed", cfg.VerifierUID, cfg.ReaderGID, 0750|os.ModeSetgid)
	if err == nil && writer {
		fs.staging, err = openChild(r, "staging", cfg.VerifierUID, cfg.VerifierPrimaryGID, 0700)
		if err == nil {
			var a, b uint64
			a, err = device(fs.staging)
			if err == nil {
				b, err = device(fs.committed)
			}
			if err == nil && a != b {
				err = fmt.Errorf("%w: staging and committed differ in filesystem", ErrUnsafeStore)
			}
		}
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%w: %w", ErrUnsafeStore, err), fs.close())
	}
	return fs, nil
}

func (s *snapshotFS) close() error {
	var errs []error
	for _, r := range []*os.Root{s.staging, s.committed, s.root} {
		if r != nil {
			errs = append(errs, r.Close())
		}
	}
	return errors.Join(errs...)
}

// Close releases pinned descriptors after all Writer calls have finished.
func (w *Writer) Close() error { return w.fs.close() }

// Close releases pinned descriptors after all Reader calls have finished.
func (r *Reader) Close() error { return r.fs.close() }

func fileName(id string) (string, error) {
	if err := artifact.ValidateID(id); err != nil {
		return "", err
	}
	return "decision-" + id + ".json", nil
}

func (s *snapshotFS) read(ctx context.Context, id string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := fileName(id)
	if err != nil {
		return nil, err
	}
	f, err := s.committed.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, err := metadata(info)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0440 || int(st.Uid) != s.cfg.VerifierUID || int(st.Gid) != s.cfg.ReaderGID {
		return nil, ErrUnsafeStore
	}
	if info.Size() > publish.MaxDecisionBytes {
		return nil, publish.ErrTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, publish.MaxDecisionBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > publish.MaxDecisionBytes {
		return nil, publish.ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

// Read bounds data before decoding and checks the opened inode, not a path Stat.
// It does not calculate an object hash or establish release authority.
func (r *Reader) Read(ctx context.Context, id string) ([]byte, error) { return r.fs.read(ctx, id) }

func (s *snapshotFS) syncDir(r *os.Root) error {
	f, err := r.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(s.syncFile(f), f.Close())
}

func (s *snapshotFS) putBytes(ctx context.Context, id string, data []byte) (err error) {
	name, err := fileName(id)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temp := ".pending-" + hex.EncodeToString(nonce[:])
	f, err := s.staging.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	fileOpen, tempLive, visible := true, true, false
	defer func() {
		if fileOpen {
			err = errors.Join(err, f.Close())
		}
		if tempLive {
			e := s.staging.Remove(temp)
			if !errors.Is(e, os.ErrNotExist) {
				err = errors.Join(err, e)
			}
		}
		if err != nil && visible && !errors.Is(err, ErrCommitUncertain) {
			err = fmt.Errorf("%w: %w", ErrCommitUncertain, err)
		}
	}()
	if n, e := f.Write(data); e != nil {
		return e
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	if err = f.Chown(-1, s.cfg.ReaderGID); err != nil {
		return err
	}
	if err = f.Chmod(0440); err != nil {
		return err
	}
	info, e := f.Stat()
	if e != nil {
		return e
	}
	st, e := metadata(info)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0440 || int(st.Uid) != s.cfg.VerifierUID || int(st.Gid) != s.cfg.ReaderGID {
		return ErrUnsafeStore
	}
	if err = s.syncFile(f); err != nil {
		return err
	}
	err = f.Close()
	fileOpen = false
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	err = s.root.Link("staging/"+temp, "committed/"+name)
	if errors.Is(err, os.ErrExist) {
		existing, e := s.read(ctx, id)
		if e != nil {
			return e
		}
		if !bytes.Equal(existing, data) {
			return ErrConflict
		}
	} else if err != nil {
		return err
	}
	visible = true
	// After visibility, finish synchronization even if cancellation arrives.
	if err = s.syncDir(s.committed); err != nil {
		return err
	}
	if err = s.staging.Remove(temp); err != nil {
		return err
	}
	tempLive = false
	if err = s.syncDir(s.staging); err != nil {
		return err
	}
	return nil
}

// Put acknowledges only after file sync, atomic no-overwrite Link, committed-dir
// sync, staging cleanup and staging-dir sync. A visible record can precede ACK;
// post-visibility errors never promise rollback. No cross-filesystem fallback exists.
func (w *Writer) Put(ctx context.Context, record v1.DecisionRecord) (artifact.ObjectReference, error) {
	var zero artifact.ObjectReference
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if err := record.Validate(); err != nil {
		return zero, err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return zero, err
	}
	if len(data) > publish.MaxDecisionBytes {
		return zero, publish.ErrTooLarge
	}
	if err := w.fs.putBytes(ctx, record.Decision.DecisionID, data); err != nil {
		return zero, err
	}
	sum := sha256.Sum256(data)
	return artifact.ObjectReference{ID: record.Decision.DecisionID, Digest: artifact.Digest{Algorithm: "sha256", Value: hex.EncodeToString(sum[:])}}, nil
}
