package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	zipadapter "github.com/rabiv-org/rabiv/internal/adapters/archive"
	provadapter "github.com/rabiv-org/rabiv/internal/adapters/provenance"
	input "github.com/rabiv-org/rabiv/internal/adapters/storage/input"
	"github.com/rabiv-org/rabiv/internal/adapters/syft"
	"github.com/rabiv-org/rabiv/internal/adapters/worker"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/ingest"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

func runWorkerLauncher(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 2 || args[0] != "--profile" {
		return errors.New("worker-run requires --profile PATH followed by worker arguments")
	}
	if _, err := parseWorkerWithProfile(args[2:], args[1]); err != nil {
		return err
	}
	b, err := worker.Launch(ctx, args[1], args[2:])
	if err != nil {
		return err
	}
	_, err = out.Write(b)
	return err
}

// The root launcher supplies the profile separately from the bounded JSON
// payload. Loading the trusted profile precedes reading any worker request.
func readWorkerRequest(profile string, in io.Reader) ([]string, error) {
	if _, err := worker.Load(profile); err != nil {
		return nil, err
	}
	b, err := acquire.ReadLimit(in, 256<<10)
	if err != nil {
		return nil, err
	}
	var request []string
	if jsoninput.Decode(b, &request, true) != nil {
		return nil, errors.New("invalid worker request")
	}
	return request, nil
}

type workerOptions struct {
	outputOptions
	profile, fetchChannel, jobRef string
	archive                       zipadapter.Reader
	maxSBOM                       int64
	subjects                      list
}

func parseWorker(args []string) (workerOptions, error) {
	return parseWorkerWithProfile(args, "")
}

func parseWorkerWithProfile(args []string, trustedProfile string) (workerOptions, error) {
	f, output := commandFlags("worker")
	o := workerOptions{profile: trustedProfile}
	if trustedProfile == "" {
		f.StringVar(&o.profile, "profile", "", "root-owned isolation profile")
	}
	f.StringVar(&o.fetchChannel, "fetch-channel", "", "Worker's Fetch channel")
	f.StringVar(&o.jobRef, "job-ref", "", "fetched snapshot id@sha256hex")
	f.StringVar(&o.archive.ProvenanceEntry, "provenance-entry", "artifacts-metadata.json", "exact optional Runner ZIP entry")
	f.StringVar(&o.archive.SBOMEntry, "existing-sbom-entry", "", "exact optional supplied SBOM ZIP entry")
	f.Int64Var(&o.archive.Limits.Archive, "max-archive", 32<<20, "transport byte limit")
	f.Int64Var(&o.archive.Limits.Entry, "max-entry", 16<<20, "per ZIP entry byte limit")
	f.Int64Var(&o.archive.Limits.Expanded, "max-expanded", 48<<20, "sum of declared expanded entry bytes")
	f.IntVar(&o.archive.Limits.Entries, "max-entries", 1024, "ZIP entry count limit")
	f.Int64Var(&o.maxSBOM, "max-sbom", 8<<20, "per scanner output limit")
	f.Uint64Var(&o.archive.Limits.Ratio, "max-ratio", 100, "maximum ZIP compression ratio")
	f.Var(&o.subjects, "subject", "exact selected subject name, repeatable")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return o, errors.New("invalid worker arguments")
	}
	o.outputOptions = *output
	return o, nil
}

func runWorker(ctx context.Context, args []string, out io.Writer) error {
	profile := ""
	if len(args) == 3 && args[0] == "--profile" && args[2] == "--request-stdin" {
		request, err := readWorkerRequest(args[1], os.Stdin)
		if err != nil {
			return err
		}
		profile, args = args[1], request
	}
	o, e := parseWorkerWithProfile(args, profile)
	if e != nil {
		return e
	}
	p, e := worker.Load(o.profile)
	if e != nil {
		return e
	}
	if e = p.Check(); e != nil {
		return e
	}
	fc, e := input.LoadConfig(o.fetchChannel)
	if e != nil {
		return e
	}
	oc, e := input.LoadConfig(o.channel)
	if e != nil {
		return e
	}
	if e = checkWorkerChannels(p, fc, oc); e != nil {
		return e
	}
	source, e := input.OpenReader(fc)
	if e != nil {
		return e
	}
	defer func() { _ = source.Close() }()
	sink, e := input.OpenWriter(oc)
	if e != nil {
		return e
	}
	defer func() { _ = sink.Close() }()
	job, e := acquire.ParseReference(o.jobRef)
	if e != nil {
		return e
	}
	scanner, e := syft.New(syft.Config{Binary: p.SyftBinary, Workspace: p.Workspace, Timeout: time.Duration(p.TimeoutSeconds) * time.Second, MaxOutput: o.maxSBOM})
	if e != nil {
		return e
	}
	ref, e := ingest.Process(ctx, source, sink, o.archive, scanner, provadapter.Parser{}, job, o.id, o.subjects, o.archive.Limits.Archive, o.archive.Limits.Entry, o.maxSBOM)
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(ref)
}

func checkWorkerChannels(p worker.Config, fc, oc input.Config) error {
	if fc.RootDir != p.FetchRoot || oc.RootDir != p.ResultRoot || fc.ReaderGID != p.FetchReaderGID || oc.ReaderGID != p.ResultReaderGID {
		return errors.New("worker channel/profile mismatch")
	}
	return nil
}
