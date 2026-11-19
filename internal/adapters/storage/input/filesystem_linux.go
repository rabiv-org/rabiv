// Package input stores producer-owned input claims, not protected decisions.
// Producer DAC identifies a channel writer; it does not establish input honesty,
// policy authorization, verified staging or permission to publish an artifact.
package input

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

var (
	ErrUnsafe          = errors.New("unsafe input channel or credentials")
	ErrIntegrity       = errors.New("input object digest mismatch")
	ErrConflict        = errors.New("input object ID conflicts with existing bytes")
	ErrCommitUncertain = errors.New("input visible but commit not acknowledged")
)

// Config describes one directed channel. An administrator creates root:root
// 0755 RootDir under root-owned non-writable ancestors, staging Writer:WriterGID
// 0700, and committed Writer:ReaderGID 2750. No runtime mkdir/chown repair occurs.
// WriterUID may be root only for explicitly owner-controlled telemetry capture.
// Each other producer and each consumer has its own nonroot UID. ReaderGID is a
// dedicated supplementary group, never shared-group write authorization.
type Config struct {
	RootDir                                                      string
	WriterUID, WriterGID, ReaderUID, ReaderPrimaryGID, ReaderGID int
}

// Store pins an already provisioned local channel. It never initializes a layout.
type Store struct {
	root, staging, committed *os.Root
	cfg                      Config
	write                    bool
	sync                     func(*os.File) error // private fault-injection seam; never a CLI option
}

func (c Config) validate(writer bool) error {
	if !filepath.IsAbs(c.RootDir) || filepath.Clean(c.RootDir) != c.RootDir || c.RootDir == "/" || c.WriterUID < 0 || c.ReaderUID <= 0 || c.WriterUID == c.ReaderUID || c.WriterGID < 0 || c.ReaderPrimaryGID <= 0 || c.ReaderGID <= 0 || c.ReaderGID == c.WriterGID || c.ReaderGID == c.ReaderPrimaryGID {
		return ErrUnsafe
	}
	u, g := c.ReaderUID, c.ReaderPrimaryGID
	if writer {
		u, g = c.WriterUID, c.WriterGID
	}
	if os.Getuid() != u || os.Geteuid() != u || os.Getgid() != g || os.Getegid() != g {
		return ErrUnsafe
	}
	groups, err := os.Getgroups()
	if err != nil {
		return ErrUnsafe
	}
	for _, gid := range groups {
		if gid == c.ReaderGID {
			return nil
		}
	}
	return ErrUnsafe
}

// OpenWriter checks actual credentials and trusted directory descriptors.
func OpenWriter(c Config) (*Store, error) { return open(c, true) }

// OpenReader has no access to private staging and cannot Put.
func OpenReader(c Config) (*Store, error) { return open(c, false) }

func open(c Config, writer bool) (*Store, error) {
	if err := c.validate(writer); err != nil {
		return nil, err
	}
	r, err := anchor(c.RootDir)
	if err != nil {
		return nil, err
	}
	return layout(r, c, writer)
}

func metadata(info os.FileInfo, uid, gid int, mode os.FileMode, dir bool) error {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != uid || int(s.Gid) != gid || info.Mode()&(os.ModePerm|os.ModeSetgid|os.ModeSetuid|os.ModeSticky) != mode || info.IsDir() != dir || !dir && !info.Mode().IsRegular() {
		return ErrUnsafe
	}
	return nil
}

func ancestor(info os.FileInfo) error {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || s.Uid != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 {
		return ErrUnsafe
	}
	return nil
}

func anchor(name string) (*os.Root, error) {
	r, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		info, e := r.Lstat(part)
		if e == nil {
			e = ancestor(info)
		}
		if e != nil {
			_ = r.Close()
			return nil, ErrUnsafe
		}
		next, e := r.OpenRoot(part)
		if e != nil {
			_ = r.Close()
			return nil, ErrUnsafe
		}
		after, e := next.Stat(".")
		if e != nil || !os.SameFile(info, after) || ancestor(after) != nil {
			_ = next.Close()
			_ = r.Close()
			return nil, ErrUnsafe
		}
		if e = r.Close(); e != nil {
			_ = next.Close()
			return nil, e
		}
		r = next
	}
	info, err := r.Stat(".")
	if err != nil || metadata(info, 0, 0, 0755, true) != nil {
		_ = r.Close()
		return nil, ErrUnsafe
	}
	return r, nil
}

func child(r *os.Root, name string, uid, gid int, mode os.FileMode) (*os.Root, error) {
	info, err := r.Lstat(name)
	if err != nil {
		return nil, err
	}
	if metadata(info, uid, gid, mode, true) != nil {
		return nil, ErrUnsafe
	}
	c, err := r.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	after, err := c.Stat(".")
	if err != nil || !os.SameFile(info, after) || metadata(after, uid, gid, mode, true) != nil {
		_ = c.Close()
		return nil, ErrUnsafe
	}
	return c, nil
}

func layout(r *os.Root, c Config, writer bool) (*Store, error) {
	s := &Store{root: r, cfg: c, write: writer, sync: func(f *os.File) error { return f.Sync() }}
	var err error
	s.committed, err = child(r, "committed", c.WriterUID, c.ReaderGID, 0750|os.ModeSetgid)
	if err == nil && writer {
		s.staging, err = child(r, "staging", c.WriterUID, c.WriterGID, 0700)
	}
	if err == nil && writer {
		a, e := s.staging.Stat(".")
		b, f := s.committed.Stat(".")
		if e != nil || f != nil || a.Sys().(*syscall.Stat_t).Dev != b.Sys().(*syscall.Stat_t).Dev {
			err = ErrUnsafe
		}
	}
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Close releases pinned descriptors after outstanding operations finish.
func (s *Store) Close() error {
	var errs []error
	for _, r := range []*os.Root{s.staging, s.committed, s.root} {
		if r != nil {
			errs = append(errs, r.Close())
		}
	}
	return errors.Join(errs...)
}

func objectName(id string) (string, error) {
	if artifact.ValidateID(id) != nil {
		return "", ErrUnsafe
	}
	return "object-" + id, nil
}

// os.Root follows confined symlinks before its final open. Use openat on a
// pinned directory FD so O_NOFOLLOW applies to the original final component.
func openFile(r *os.Root, name string, flags int, mode uint32) (*os.File, error) {
	d, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	fd, err := syscall.Openat(int(d.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// Get verifies exact bytes into a bounded private memory snapshot. A reference
// match authenticates no producer; later verification must resolve inputs again.
func (s *Store) Get(ctx context.Context, ref artifact.ObjectReference, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ref.Validate() != nil {
		return nil, ErrUnsafe
	}
	name, err := objectName(ref.ID)
	if err != nil {
		return nil, err
	}
	f, err := openFile(s.committed, name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if metadata(info, s.cfg.WriterUID, s.cfg.ReaderGID, 0440, false) != nil || info.Size() > limit {
		return nil, ErrUnsafe
	}
	b, err := acquire.ReadLimit(f, limit)
	if err != nil {
		return nil, err
	}
	if acquire.Hash(b) != ref.Digest {
		return nil, ErrIntegrity
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Store) syncDir(r *os.Root) error {
	f, err := r.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return s.sync(f)
}

// Put hashes actual bytes, stages privately, then links without overwrite. Same
// ID/exact bytes is idempotent; different bytes conflict. After visibility any
// failed synchronization/cleanup is commit-uncertain, never simulated rollback.
// This is producer protocol immutability, not protection from that producer/root.
func (s *Store) Put(ctx context.Context, id string, src io.Reader, limit int64) (artifact.ObjectReference, error) {
	var zero artifact.ObjectReference
	if !s.write || limit <= 0 || limit > 1<<30 {
		return zero, ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	name, err := objectName(id)
	if err != nil {
		return zero, err
	}
	tmp := ".pending-" + rand.Text()
	f, err := openFile(s.staging, tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return zero, err
	}
	defer func() { _ = s.staging.Remove(tmp) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(src, limit+1))
	if err == nil && n > limit {
		err = errors.New("input object too large")
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = f.Chown(-1, s.cfg.ReaderGID)
	}
	if err == nil {
		err = f.Chmod(0440)
	}
	if err == nil {
		err = s.sync(f)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return zero, err
	}
	ref := artifact.ObjectReference{ID: id, Digest: artifact.Digest{Algorithm: "sha256", Value: hex.EncodeToString(h.Sum(nil))}}
	err = s.root.Link("staging/"+tmp, "committed/"+name)
	if errors.Is(err, os.ErrExist) {
		before, e := s.Get(ctx, ref, limit)
		if errors.Is(e, ErrIntegrity) {
			return zero, ErrConflict
		}
		if e != nil {
			return zero, e
		}
		// Get checks the full existing snapshot, including its exact hash.
		if !bytes.Equal(h.Sum(nil), shaBytes(before)) {
			return zero, ErrConflict
		}
	} else if err != nil {
		return zero, err
	}
	if err = s.syncDir(s.committed); err == nil {
		err = s.staging.Remove(tmp)
	}
	if err == nil {
		err = s.syncDir(s.staging)
	}
	if err != nil {
		return zero, fmt.Errorf("%w: synchronization or private cleanup failed", ErrCommitUncertain)
	}
	return ref, nil
}

func shaBytes(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
