package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	store "github.com/rabiv-org/rabiv/internal/adapters/storage/decision"
	"github.com/rabiv-org/rabiv/internal/app/verify"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

func run(ctx context.Context, args []string, out, errOut io.Writer) (err error) {
	flags := flag.NewFlagSet("rabiv-verifier", flag.ContinueOnError)
	flags.SetOutput(errOut)
	var cfg store.Config
	flags.StringVar(&cfg.RootDir, "decision-dir", "", "root-owned common root containing staging/ and committed/")
	flags.IntVar(&cfg.VerifierUID, "verifier-uid", -1, "configured nonroot Verifier UID")
	flags.IntVar(&cfg.PublisherUID, "publisher-uid", -1, "configured distinct nonroot Publisher UID")
	flags.IntVar(&cfg.VerifierPrimaryGID, "verifier-gid", -1, "Verifier primary GID")
	flags.IntVar(&cfg.PublisherPrimaryGID, "publisher-gid", -1, "Publisher primary GID")
	flags.IntVar(&cfg.ReaderGID, "reader-gid", -1, "dedicated supplementary reader GID")
	diagnostic := flags.Bool("diagnostic-handoff", false, "emit only diagnostic INDETERMINATE; no real evaluation")
	var req verify.DiagnosticRequest
	flags.StringVar(&req.DecisionID, "decision-id", "", "new immutable diagnostic snapshot ID")
	flags.StringVar(&req.WorkflowID, "workflow-id", "", "operator-supplied diagnostic workflow ID")
	req.Build.Provider = build.GitLab
	flags.StringVar(&req.Build.Instance, "ci-instance", "", "canonical GitLab base URL")
	flags.StringVar(&req.Build.ProjectID, "project-id", "", "GitLab decimal project ID")
	flags.StringVar(&req.Build.JobID, "job-id", "", "GitLab decimal job ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*diagnostic {
		return fmt.Errorf("phase 2 requires --diagnostic-handoff; genuine evaluation is unavailable")
	}
	record, err := verify.NewDiagnostic(req, time.Now().UTC())
	if err != nil {
		return err
	}
	w, err := store.NewWriter(cfg)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, w.Close()) }()
	ref, err := verify.Handoff(ctx, w, record)
	if err != nil {
		return err
	}
	// Only a durable snapshot reference is acknowledged, not publication authority.
	return json.NewEncoder(out).Encode(ref)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "rabiv-verifier:", err)
		os.Exit(1)
	}
}
