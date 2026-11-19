package input

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

// LoadConfig reads only administrator-owned channel configuration, never a
// user-writable file as permission authority. Directory setup remains external.
func LoadConfig(path string) (Config, error) {
	var c Config
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return c, ErrUnsafe
	}
	r, err := anchor(filepath.Dir(path))
	if err != nil {
		return c, err
	}
	defer r.Close()
	f, err := openFile(r, filepath.Base(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return c, err
	}
	defer f.Close()
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
