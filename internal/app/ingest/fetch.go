// Package ingest implements bounded one-shot acquisition and finalization.
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

// CI is available only to Fetch, never an archive/SBOM worker.
type CI interface {
	Job(context.Context, build.Identity) (build.Context, []byte, error)
	Artifacts(context.Context, build.Identity) ([]byte, error)
}

// FetchChannels are distinct directed OS channels. Collector gets metadata only;
// Worker and Finalizer get equal pinned snapshots in separate reader namespaces.
// Cross-channel publication is not an atomic transaction; acknowledged refs are
// returned individually on partial failure, without claiming all-channel success.
type FetchChannels struct{ Collector, Worker, Finalizer acquire.Sink }
type FetchRefs struct {
	Collector artifact.ObjectReference `json:"collector"`
	Worker    artifact.ObjectReference `json:"worker"`
	Finalizer artifact.ObjectReference `json:"finalizer"`
}

type fetched struct {
	record            acquire.Job
	metadata, archive []byte
}

func prepare(ctx context.Context, ci CI, id string, job build.Identity, at time.Time, maxArchive int64) (fetched, error) {
	var f fetched
	if artifact.ValidateID(id) != nil || artifact.ValidateID(id+".metadata") != nil || artifact.ValidateID(id+".archive") != nil || job.Validate() != nil || build.ValidateTime(at) != nil || maxArchive <= 0 {
		return f, errors.New("invalid fetch request")
	}
	f.record = acquire.Job{Version: acquire.Version, Build: build.Context{Identity: job}, ArtifactsRequested: true, RecordedAt: at}
	bc, metadata, err := ci.Job(ctx, job)
	if err != nil {
		f.record.Failure = acquire.Failure(err)
		return f, nil
	}
	if bc.Identity != job || bc.ValidateComplete() != nil {
		return f, errors.New("CI returned a mismatched build")
	}
	f.record.Build = bc
	f.metadata = metadata
	f.archive, err = ci.Artifacts(ctx, job)
	if err != nil {
		f.record.Failure = acquire.Failure(err)
	}
	return f, nil
}
func persist(ctx context.Context, sink acquire.Sink, id string, f fetched, metadataOnly bool, maxArchive int64) (artifact.ObjectReference, error) {
	var zero artifact.ObjectReference
	r := f.record
	r.ArtifactsRequested = !metadataOnly
	if f.metadata != nil {
		ref, e := sink.Put(ctx, id+".metadata", bytes.NewReader(f.metadata), 1<<20)
		if e != nil {
			return zero, e
		}
		r.Metadata = &ref
		if metadataOnly {
			r.Failure = nil
		}
	}
	if !metadataOnly && r.Failure == nil {
		ref, e := sink.Put(ctx, id+".archive", bytes.NewReader(f.archive), maxArchive)
		if e != nil {
			return zero, e
		}
		r.Archive = &ref
	}
	if err := r.Validate(); err != nil {
		return zero, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return zero, err
	}
	return sink.Put(ctx, id, bytes.NewReader(b), 1<<20)
}

// Fetch writes one artifact-bearing channel, useful to explicitly selected consumers.
func Fetch(ctx context.Context, ci CI, sink acquire.Sink, id string, job build.Identity, at time.Time, maxArchive int64) (artifact.ObjectReference, error) {
	f, err := prepare(ctx, ci, id, job, at, maxArchive)
	if err != nil {
		return artifact.ObjectReference{}, err
	}
	return persist(ctx, sink, id, f, false, maxArchive)
}

// FetchTo acquires once, then publishes to three least-privilege channels. No
// archive is parsed and no worker inherits this process's API credential.
func FetchTo(ctx context.Context, ci CI, out FetchChannels, id string, job build.Identity, at time.Time, maxArchive int64) (FetchRefs, error) {
	var refs FetchRefs
	if out.Collector == nil || out.Worker == nil || out.Finalizer == nil {
		return refs, errors.New("three fetch channels required")
	}
	f, err := prepare(ctx, ci, id, job, at, maxArchive)
	if err != nil {
		return refs, err
	}
	refs.Collector, err = persist(ctx, out.Collector, id, f, true, maxArchive)
	if err != nil {
		return refs, err
	}
	refs.Worker, err = persist(ctx, out.Worker, id, f, false, maxArchive)
	if err != nil {
		return refs, err
	}
	refs.Finalizer, err = persist(ctx, out.Finalizer, id, f, false, maxArchive)
	return refs, err
}
