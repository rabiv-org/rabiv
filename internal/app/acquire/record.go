// Package acquire defines the internal one-shot acquisition handoffs. These
// records describe input claims, never decision authority or scheduling state.
package acquire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

// Version versions only intermediate acquisition records, not contracts/v1.
const Version = "acquisition/v1"

// InputError carries only a sanitized acquisition outcome across adapter ports.
type InputError struct{ Code v1.FailureCode }

func (e *InputError) Error() string { return "acquisition input failure: " + string(e.Code) }

// Failure preserves invalid/unsupported/unavailable distinctions without copying
// provider response bodies, credentials, signed URLs or arbitrary error text.
func Failure(err error) *v1.Failure {
	var input *InputError
	if errors.As(err, &input) && (v1.Failure{Code: input.Code}).Validate() == nil {
		return &v1.Failure{Code: input.Code}
	}
	return &v1.Failure{Code: v1.ProducerError}
}

// Source returns a bounded, independently hashed snapshot of exact object bytes.
type Source interface {
	Get(context.Context, artifact.ObjectReference, int64) ([]byte, error)
}

// Sink atomically commits a bounded byte stream with no overwrite by object ID.
type Sink interface {
	Put(context.Context, string, io.Reader, int64) (artifact.ObjectReference, error)
}

// Job is a fetched GitLab metadata snapshot, with independently acquired archive.
// An absent archive with a Failure is a terminal acquisition outcome, not DENY.
type Job struct {
	Version            string                    `json:"version"`
	ArtifactsRequested bool                      `json:"artifacts_requested"`
	Build              build.Context             `json:"build"`
	Metadata           *artifact.ObjectReference `json:"metadata,omitempty"`
	Archive            *artifact.ObjectReference `json:"archive,omitempty"`
	Failure            *v1.Failure               `json:"failure,omitempty"`
	RecordedAt         time.Time                 `json:"recorded_at"`
}

// Validate does not authenticate the fetcher, CI claims, or referenced bytes.
func (j Job) Validate() error {
	if j.Version != Version || j.Build.Validate() != nil || build.ValidateTime(j.RecordedAt) != nil {
		return errors.New("invalid fetched job record")
	}
	if j.Metadata != nil && j.Metadata.Validate() != nil {
		return errors.New("invalid metadata reference")
	}
	if !j.ArtifactsRequested {
		if j.Archive != nil {
			return errors.New("metadata-only handoff contains an archive")
		}
		if j.Failure != nil {
			return j.Failure.Validate()
		}
		if j.Metadata == nil || j.Build.ValidateComplete() != nil {
			return errors.New("incomplete CI metadata handoff")
		}
		return nil
	}
	if j.Archive != nil {
		if j.Failure != nil || j.Metadata == nil || j.Build.ValidateComplete() != nil {
			return errors.New("archive and failure conflict")
		}
		return j.Archive.Validate()
	}
	if j.Failure == nil {
		return errors.New("missing archive requires explicit failure")
	}
	return j.Failure.Validate()
}

// DecodeJob checks the closed, bounded intermediate record.
func DecodeJob(data []byte) (Job, error) {
	var j Job
	if len(data) > 1<<20 || jsoninput.Decode(data, &j, true) != nil {
		return j, errors.New("invalid fetched job JSON")
	}
	return j, j.Validate()
}

// Hash names actual bytes without authenticating their origin.
func Hash(data []byte) artifact.Digest {
	h := sha256.Sum256(data)
	return artifact.Digest{Algorithm: "sha256", Value: hex.EncodeToString(h[:])}
}

// ReadLimit bounds bytes even when a peer lies about its content length.
func ReadLimit(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 || limit > 1<<30 {
		return nil, errors.New("invalid byte limit")
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, errors.New("input read failed or limit exceeded")
	}
	return b, nil
}
