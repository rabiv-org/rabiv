package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

type FinalizeRequest struct {
	JobRef                          artifact.ObjectReference
	WorkerRef                       *artifact.ObjectReference
	ManifestID, WorkflowID, GroupID string
	Subjects                        []string
	At                              time.Time
	MaxArchive, MaxEntry, MaxSBOM   int64
}

// Finalize copies independently hash-checked snapshots into Ingestor's namespace.
// It binds the exact fetched-job snapshot, archive and explicit subject selection.
// It does not trust a worker's AUTHENTICATED claim or authorize a release. Worker
// subject-to-archive extraction remains a producer claim until Phase 5 evaluation.
func Finalize(ctx context.Context, fetch, worker acquire.Source, out acquire.Sink, q FinalizeRequest) (artifact.ObjectReference, error) {
	var zero artifact.ObjectReference
	if artifact.ValidateID(q.ManifestID) != nil || artifact.ValidateID(q.WorkflowID) != nil || artifact.ValidateID(q.GroupID) != nil || build.ValidateTime(q.At) != nil || q.JobRef.Validate() != nil || !validByteLimit(q.MaxArchive) || !validByteLimit(q.MaxEntry) || !validByteLimit(q.MaxSBOM) {
		return zero, errors.New("invalid finalization request")
	}
	selected, err := subjectSelection(q.Subjects, q.JobRef.Digest)
	if err != nil {
		return zero, err
	}
	data, err := fetch.Get(ctx, q.JobRef, 1<<20)
	if err != nil {
		return zero, err
	}
	job, err := acquire.DecodeJob(data)
	if err != nil {
		return zero, err
	}
	if !job.ArtifactsRequested {
		return zero, errors.New("artifact finalization requires artifact-bearing fetch input")
	}
	m := v1.ArtifactManifest{ManifestHeader: v1.ManifestHeader{SchemaVersion: v1.SchemaVersion, Kind: v1.KindArtifactManifest, ManifestID: q.ManifestID, WorkflowID: q.WorkflowID, Build: job.Build, RecordedAt: q.At, State: v1.Failed, Failure: job.Failure}}
	finish := func() (artifact.ObjectReference, error) {
		if e := m.Validate(); e != nil {
			return zero, e
		}
		b, e := json.Marshal(m)
		if e != nil {
			return zero, e
		}
		if _, e = v1.DecodeArtifactManifest(b); e != nil {
			return zero, e
		}
		return out.Put(ctx, q.ManifestID, bytes.NewReader(b), 1<<20)
	}
	if job.Failure != nil {
		return finish()
	}
	if q.WorkerRef == nil {
		m.Failure = &v1.Failure{Code: v1.InputUnavailable}
		return finish()
	}
	data, err = worker.Get(ctx, *q.WorkerRef, 1<<20)
	if err != nil {
		return zero, err
	}
	r, err := DecodeWorker(data)
	if err != nil {
		return zero, err
	}
	if !r.JobRef.Equal(q.JobRef) || !r.Build.Consistent(job.Build) || r.Build.ValidateComplete() != nil || job.Archive == nil || !r.Archive.Equal(*job.Archive) {
		return zero, errors.New("worker job/archive binding mismatch")
	}
	if len(selected) != len(r.RequestedSubjects) {
		return zero, errors.New("worker subject selection mismatch")
	}
	for _, name := range r.RequestedSubjects {
		if !selected[name] {
			return zero, errors.New("worker subject selection mismatch")
		}
	}
	if r.Failure != nil {
		m.Failure = r.Failure
		return finish()
	}
	copyObject := func(source acquire.Source, ref artifact.ObjectReference, limit int64) (artifact.ObjectReference, error) {
		b, e := source.Get(ctx, ref, limit)
		if e != nil {
			return zero, e
		}
		return out.Put(ctx, "sha256-"+acquire.Hash(b).Value, bytes.NewReader(b), limit)
	}
	transport, err := copyObject(fetch, r.Archive, q.MaxArchive)
	if err != nil {
		return zero, err
	}
	p := &v1.ArtifactPayload{Transport: artifact.TransportArchive{Reference: transport, MediaType: "application/zip"}, SubjectGroup: artifact.SubjectGroup{ID: q.GroupID, Subjects: []artifact.Subject{}}}
	for _, s := range r.Subjects {
		ref, e := copyObject(worker, s.Reference, q.MaxEntry)
		if e != nil {
			return zero, e
		}
		if ref.Digest != s.Subject.Digest {
			return zero, errors.New("subject byte integrity mismatch")
		}
		p.SubjectGroup.Subjects = append(p.SubjectGroup.Subjects, s.Subject)
	}
	index := SBOMBundle{Version: "sbom-bundle/v1", SBOMs: []SBOMObject{}, Issues: r.Issues}
	for _, s := range r.SBOMs {
		ref, e := copyObject(worker, s.Reference, q.MaxSBOM)
		if e != nil {
			return zero, e
		}
		s.Reference = ref
		index.SBOMs = append(index.SBOMs, s)
	}
	if r.ExistingSBOM != nil {
		ref, e := copyObject(worker, *r.ExistingSBOM, q.MaxSBOM)
		if e != nil {
			return zero, e
		}
		index.ExistingSBOM = &ref
	}
	if r.ProvenanceRaw != nil {
		ref, e := copyObject(worker, *r.ProvenanceRaw, 1<<20)
		if e != nil {
			return zero, e
		}
		index.ProvenanceRaw = &ref
		if r.Provenance != nil {
			claim := *r.Provenance
			claim.Reference = ref
			p.Provenance = &claim
		}
	}
	encoded, err := json.Marshal(index)
	if err != nil {
		return zero, err
	}
	ref, err := out.Put(ctx, "sha256-"+acquire.Hash(encoded).Value, bytes.NewReader(encoded), 1<<20)
	if err != nil {
		return zero, err
	}
	p.SBOMRef = &ref
	m.Payload = p
	m.State = v1.Finalized
	m.Failure = nil
	return finish()
}
