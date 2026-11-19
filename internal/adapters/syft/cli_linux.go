// Package syft invokes an administrator-selected CLI inside the isolated Worker.
// It never discovers credentials, uses a shell, or scans a Docker daemon/image.
package syft

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

var ErrScan = &acquire.InputError{Code: v1.ProducerError}

type Config struct {
	Binary, Workspace string
	Timeout           time.Duration
	MaxOutput         int64
}
type CLI struct {
	cfg Config
	run func(*exec.Cmd) error
}

func New(c Config) (*CLI, error) {
	if !filepath.IsAbs(c.Binary) || !filepath.IsAbs(c.Workspace) || filepath.Clean(c.Binary) != c.Binary || filepath.Clean(c.Workspace) != c.Workspace || c.Timeout <= 0 || c.MaxOutput <= 0 || c.MaxOutput > 64<<20 {
		return nil, ErrScan
	}
	return &CLI{cfg: c, run: func(cmd *exec.Cmd) error { return cmd.Run() }}, nil
}

type bounded struct {
	buf bytes.Buffer
	max int64
}

func (w *bounded) Write(b []byte) (int, error) {
	if int64(w.buf.Len())+int64(len(b)) > w.max {
		return 0, ErrScan
	}
	return w.buf.Write(b)
}

// Validate checks a supported Syft JSON projection and exact scanned-file binding.
// It establishes neither SBOM correctness nor complete package coverage.
func Validate(data []byte, expected artifact.Digest) error {
	var raw struct {
		Descriptor struct{ Name, Version string } `json:"descriptor"`
		Schema     struct {
			Version string `json:"version"`
		} `json:"schema"`
		Source struct {
			Type     string `json:"type"`
			Metadata struct {
				Digests []struct{ Algorithm, Value string } `json:"digests"`
			} `json:"metadata"`
		} `json:"source"`
		Artifacts []jsonArtifact `json:"artifacts"`
	}
	if expected.Validate() != nil || jsoninput.Decode(data, &raw, false) != nil || raw.Descriptor.Name != "syft" || raw.Descriptor.Version == "" || raw.Schema.Version == "" || raw.Source.Type != "file" || raw.Artifacts == nil {
		return &acquire.InputError{Code: v1.UnsupportedInput}
	}
	matches := 0
	for _, d := range raw.Source.Metadata.Digests {
		if d.Algorithm == "sha256" {
			if d.Value != expected.Value {
				return &acquire.InputError{Code: v1.InvalidInput}
			}
			matches++
		}
	}
	if matches != 1 {
		return &acquire.InputError{Code: v1.InvalidInput}
	}
	return nil
}

type jsonArtifact struct {
	ID string `json:"id"`
}

// Scan receives bytes, never an artifact-derived path. Private random filenames
// and an explicit empty config suppress ambient Syft config. The clean child
// environment has no GitLab token, proxy, SSH agent or Docker configuration.
func (c *CLI) Scan(parent context.Context, data []byte, digest artifact.Digest) ([]byte, error) {
	if acquire.Hash(data) != digest {
		return nil, &acquire.InputError{Code: v1.InvalidInput}
	}
	r, err := os.OpenRoot(c.cfg.Workspace)
	if err != nil {
		return nil, ErrScan
	}
	defer r.Close()
	info, err := r.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return nil, ErrScan
	}
	name := "subject-" + rand.Text()
	config := "config-" + rand.Text()
	write := func(name string, b []byte) error {
		f, e := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		return errors.Join(e, f.Close())
	}
	defer func() { _ = r.Remove(name); _ = r.Remove(config) }()
	if write(name, data) != nil || write(config, []byte("{}\n")) != nil {
		return nil, ErrScan
	}
	ctx, cancel := context.WithTimeout(parent, c.cfg.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.cfg.Binary, "--config", filepath.Join(c.cfg.Workspace, config), "scan", "file:"+filepath.Join(c.cfg.Workspace, name), "--parallelism", "1", "-o", "syft-json")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent", "SYFT_CHECK_FOR_APP_UPDATE=false", "GOMAXPROCS=2"}
	cmd.Dir = c.cfg.Workspace
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = time.Second * 5
	out := &bounded{max: c.cfg.MaxOutput}
	stderr := &bounded{max: 64 << 10}
	cmd.Stdout = out
	cmd.Stderr = stderr
	if c.run(cmd) != nil {
		return nil, ErrScan
	}
	b := out.buf.Bytes()
	if Validate(b, digest) != nil {
		return nil, &acquire.InputError{Code: v1.InvalidInput}
	}
	return bytes.Clone(b), nil
}
