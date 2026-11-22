package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	input "github.com/rabiv-org/rabiv/internal/adapters/storage/input"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/ingest"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/platform/process"
)

type finalizeOptions struct {
	outputOptions
	fetchChannel, workerChannel string
	jobRef, workerRef           string
	workflowID, groupID         string
	maxArchive, maxSBOM         int64
	subjects                    list
}

func parseFinalize(args []string) (finalizeOptions, error) {
	f, output := commandFlags("finalize")
	var o finalizeOptions
	f.StringVar(&o.fetchChannel, "fetch-channel", "", "Finalizer Fetch channel")
	f.StringVar(&o.workerChannel, "worker-channel", "", "Worker result channel")
	f.StringVar(&o.jobRef, "job-ref", "", "expected fetched snapshot id@sha256hex")
	f.StringVar(&o.workerRef, "worker-ref", "", "worker snapshot id@sha256hex; absent becomes FAILED")
	f.StringVar(&o.workflowID, "workflow-id", "", "explicit workflow ID")
	f.StringVar(&o.groupID, "group-id", "", "explicit subject group ID")
	f.Int64Var(&o.maxArchive, "max-archive", 32<<20, "transport/subject byte limit")
	f.Int64Var(&o.maxSBOM, "max-sbom", 8<<20, "per SBOM byte limit")
	f.Var(&o.subjects, "subject", "exact expected subject name, repeatable")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return o, errors.New("invalid finalization arguments")
	}
	o.outputOptions = *output
	return o, nil
}

func runFinalize(ctx context.Context, args []string, out io.Writer) error {
	o, e := parseFinalize(args)
	if e != nil {
		return e
	}
	fc, e := input.LoadConfig(o.fetchChannel)
	if e != nil {
		return e
	}
	wc, e := input.LoadConfig(o.workerChannel)
	if e != nil {
		return e
	}
	oc, e := input.LoadConfig(o.channel)
	if e != nil {
		return e
	}
	if fc.WriterUID == wc.WriterUID {
		return errors.New("fetch and worker require distinct identities")
	}
	if e = process.Check(oc.WriterUID, oc.WriterGID, []int{fc.ReaderGID, wc.ReaderGID, oc.ReaderGID}); e != nil {
		return e
	}
	fetch, e := input.OpenReader(fc)
	if e != nil {
		return e
	}
	defer func() { _ = fetch.Close() }()
	work, e := input.OpenReader(wc)
	if e != nil {
		return e
	}
	defer func() { _ = work.Close() }()
	sink, e := input.OpenWriter(oc)
	if e != nil {
		return e
	}
	defer func() { _ = sink.Close() }()
	job, e := acquire.ParseReference(o.jobRef)
	if e != nil {
		return e
	}
	var wr *artifact.ObjectReference
	if o.workerRef != "" {
		r, e := acquire.ParseReference(o.workerRef)
		if e != nil {
			return e
		}
		wr = &r
	}
	ref, e := ingest.Finalize(ctx, fetch, work, sink, ingest.FinalizeRequest{JobRef: job, WorkerRef: wr, ManifestID: o.id, WorkflowID: o.workflowID, GroupID: o.groupID, Subjects: o.subjects, At: time.Now().UTC(), MaxArchive: o.maxArchive, MaxSBOM: o.maxSBOM})
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(ref)
}
