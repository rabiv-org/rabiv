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

// CI is consumed only by the credential-bearing fetch invocation. Workers never
// receive it, a credential, arbitrary URLs, or a Docker client.
type CI interface {
	Job(context.Context, build.Identity) (build.Context, []byte, error)
	Artifacts(context.Context, build.Identity) ([]byte, error)
}

// Fetch stores allowlisted metadata and opaque archive bytes, without parsing.
// A provider failure produces an explicit failed input snapshot, not a verdict.
func Fetch(ctx context.Context, ci CI, sink acquire.Sink, id string, job build.Identity, at time.Time, maxArchive int64) (artifact.ObjectReference, error) {
	var zero artifact.ObjectReference
	if artifact.ValidateID(id+".metadata") != nil || artifact.ValidateID(id+".archive") != nil || job.Validate() != nil || build.ValidateTime(at) != nil || maxArchive <= 0 {
		return zero, errors.New("invalid fetch request")
	}
	record := acquire.Job{Version: acquire.Version, Build: build.Context{Identity: job}, RecordedAt: at}
	bc, metadata, err := ci.Job(ctx, job)
	if err != nil {
		record.Failure = acquire.Failure(err)
	} else {
		if bc.Identity != job || bc.ValidateComplete() != nil {
			return zero, errors.New("CI returned a mismatched build")
		}
		record.Build = bc
		ref, e := sink.Put(ctx, id+".metadata", bytes.NewReader(metadata), 1<<20)
		if e != nil {
			return zero, e
		}
		record.Metadata = &ref
		archive, e := ci.Artifacts(ctx, job)
		if e != nil {
			record.Failure = acquire.Failure(e)
		} else {
			ref, e = sink.Put(ctx, id+".archive", bytes.NewReader(archive), maxArchive)
			if e != nil {
				return zero, e
			}
			record.Archive = &ref
		}
	}
	if err = record.Validate(); err != nil {
		return zero, err
	}
	b, err := json.Marshal(record)
	if err != nil {
		return zero, err
	}
	return sink.Put(ctx, id, bytes.NewReader(b), 1<<20)
}
