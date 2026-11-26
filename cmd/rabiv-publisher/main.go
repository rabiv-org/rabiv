package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	store "github.com/rabiv-org/rabiv/internal/adapters/storage/decision"
	"github.com/rabiv-org/rabiv/internal/app/publish"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
)

func run(ctx context.Context, args []string, errOut io.Writer) (err error) {
	flags := flag.NewFlagSet("rabiv-publisher", flag.ContinueOnError)
	flags.SetOutput(errOut)
	var cfg store.Config
	flags.StringVar(&cfg.RootDir, "decision-dir", "", "root-owned common root containing committed/")
	flags.IntVar(&cfg.VerifierUID, "verifier-uid", -1, "configured nonroot Verifier UID")
	flags.IntVar(&cfg.PublisherUID, "publisher-uid", -1, "configured distinct nonroot Publisher UID")
	flags.IntVar(&cfg.VerifierPrimaryGID, "verifier-gid", -1, "Verifier primary GID")
	flags.IntVar(&cfg.PublisherPrimaryGID, "publisher-gid", -1, "Publisher primary GID")
	flags.IntVar(&cfg.ReaderGID, "reader-gid", -1, "dedicated supplementary reader GID")
	var ref artifact.ObjectReference
	ref.Digest.Algorithm = "sha256"
	flags.StringVar(&ref.ID, "decision-id", "", "explicit current decision ID; never implicit latest")
	flags.StringVar(&ref.Digest.Value, "decision-sha256", "", "digest from trusted current snapshot reference")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	r, err := store.NewReader(cfg)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, r.Close()) }()
	checker := publish.Checker{Source: r, Now: func() time.Time { return time.Now().UTC() }, MaxValidity: publish.DefaultMaxValidity}
	// Phase 4/5 has not supplied trusted current workflow context. Received data
	// must never supply its own expectation, even for a structurally valid ALLOW.
	if _, err := checker.Check(ctx, ref, nil); err != nil {
		return err
	}
	return publish.ErrReleaseUnavailable
}

func main() { os.Exit(mainExitCode()) }

func mainExitCode() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "rabiv-publisher:", err)
		return 1
	}
	return 0
}
