package input

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
	"golang.org/x/sys/unix"
)

// LoadConfig reads only administrator-owned channel configuration, never a
// user-writable file as permission authority. Directory setup remains external.
func LoadConfig(path string) (Config, error) {
	var c Config
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return c, ErrUnsafe
	}
	root, err := os.Open("/")
	if err != nil {
		return c, err
	}
	defer func() { _ = root.Close() }()
	f, err := openConfigAt(root, strings.Split(path[1:], "/"), 0)
	if err != nil {
		return c, err
	}
	defer func() { _ = f.Close() }()
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0022 != 0 || i.Sys().(*syscall.Stat_t).Uid != 0 {
		return c, ErrUnsafe
	}
	b, err := acquire.ReadLimit(f, 16<<10)
	if err != nil || jsoninput.Decode(b, &c, true) != nil {
		return c, ErrUnsafe
	}
	return c, nil
}

// openConfigAt walks canonical path components from a pinned directory. O_PATH
// lets a role traverse a trusted directory with search permission alone.
// O_DIRECTORY with O_NOFOLLOW rejects symlink ancestors. The file itself is
// opened without following symlinks and checked by descriptor in LoadConfig.
func openConfigAt(root *os.File, parts []string, owner uint32) (*os.File, error) {
	dir := root
	defer func() {
		if dir != root {
			_ = dir.Close()
		}
	}()
	for i, name := range parts {
		info, err := dir.Stat()
		if err != nil || trustedAncestor(info, owner) != nil {
			return nil, ErrUnsafe
		}
		flags := unix.O_PATH | unix.O_DIRECTORY
		last := i == len(parts)-1
		if last {
			flags = unix.O_RDONLY | unix.O_NONBLOCK
		}
		fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		next := os.NewFile(uintptr(fd), name)
		if last {
			return next, nil
		}
		if dir != root {
			_ = dir.Close()
		}
		dir = next
	}
	return nil, ErrUnsafe
}

// OpenConfig validates configuration and actual role credentials before opening.
func OpenConfig(path string, writer bool) (*Store, error) {
	c, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	if writer {
		return OpenWriter(c)
	}
	return OpenReader(c)
}
