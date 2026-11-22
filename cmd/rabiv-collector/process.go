package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	input "github.com/rabiv-org/rabiv/internal/adapters/storage/input"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/collect"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/platform/process"
)

func runProcess(ctx context.Context, args []string, out io.Writer) error {
	f, output := commandFlags("process")
	capConfig := f.String("capture-channel", "", "capture input channel config")
	fetchConfig := f.String("fetch-channel", "", "metadata-only Fetch channel config")
	capRef := f.String("capture-ref", "", "id@sha256hex")
	target := f.String("target", "", "target fetched snapshot ID")
	workflow := f.String("workflow-id", "", "explicit workflow association")
	maxCapture := f.Int64("max-capture", 64<<20, "capture size limit")
	var jobRefs list
	f.Var(&jobRefs, "job-ref", "fetched metadata snapshot id@sha256hex, repeatable")
	if f.Parse(args) != nil || f.NArg() != 0 || len(jobRefs) == 0 {
		return errors.New("invalid processing arguments")
	}
	cc, e := input.LoadConfig(*capConfig)
	if e != nil {
		return e
	}
	fc, e := input.LoadConfig(*fetchConfig)
	if e != nil {
		return e
	}
	oc, e := input.LoadConfig(output.channel)
	if e != nil {
		return e
	}
	if e = process.Check(oc.WriterUID, oc.WriterGID, []int{cc.ReaderGID, fc.ReaderGID, oc.ReaderGID}); e != nil {
		return e
	}
	source, e := input.OpenReader(cc)
	if e != nil {
		return e
	}
	defer func() { _ = source.Close() }()
	fetch, e := input.OpenReader(fc)
	if e != nil {
		return e
	}
	defer func() { _ = fetch.Close() }()
	sink, e := input.OpenWriter(oc)
	if e != nil {
		return e
	}
	defer func() { _ = sink.Close() }()
	cr, e := acquire.ParseReference(*capRef)
	if e != nil {
		return e
	}
	targets, selected, e := loadTargets(ctx, fetch, jobRefs, *target)
	if e != nil {
		return e
	}
	ref, e := collect.Produce(ctx, source, sink, cr, targets, selected, *workflow, output.id, time.Now().UTC(), *maxCapture)
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(ref)
}

// loadTargets retains an incomplete selected job so Produce can record FAILED.
// Other incomplete builds cannot participate in runtime correlation.
func loadTargets(ctx context.Context, fetch acquire.Source, jobRefs []string, target string) ([]build.Context, build.Identity, error) {
	var targets []build.Context
	var selected build.Identity
	for _, raw := range jobRefs {
		r, e := acquire.ParseReference(raw)
		if e != nil {
			return nil, build.Identity{}, e
		}
		b, e := fetch.Get(ctx, r, 1<<20)
		if e != nil {
			return nil, build.Identity{}, e
		}
		j, e := acquire.DecodeJob(b)
		if e != nil {
			return nil, build.Identity{}, e
		}
		if j.ArtifactsRequested {
			return nil, build.Identity{}, errors.New("collector requires metadata-only channel")
		}
		if j.Build.ValidateComplete() == nil || r.ID == target {
			targets = append(targets, j.Build)
		}
		if r.ID == target {
			selected = j.Build.Identity
		}
	}
	return targets, selected, nil
}
