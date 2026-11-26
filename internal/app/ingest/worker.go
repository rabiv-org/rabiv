package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/provenance"
	"github.com/rabiv-org/rabiv/internal/platform/jsoninput"
)

// SubjectBytes associates an exact logical name with selected archive bytes.
// Names never become filesystem destinations; SubjectObject pins stored bytes.
type SubjectBytes struct {
	Name  string
	Bytes []byte
}
type Contents struct {
	Subjects                       []SubjectBytes
	Provenance, ExistingSBOM       []byte
	ProvenancePresent, SBOMPresent bool
}
type ArchiveReader interface {
	Read(context.Context, []byte, []string) (Contents, error)
}
type Scanner interface {
	Scan(context.Context, []byte, artifact.Digest) ([]byte, error)
}
type ProvenanceParser interface {
	Parse([]byte, artifact.ObjectReference) (*provenance.Reference, []string)
}

type SubjectObject struct {
	Subject   artifact.Subject         `json:"subject"`
	Reference artifact.ObjectReference `json:"reference"`
}
type SBOMObject struct {
	Subject   artifact.Subject         `json:"subject"`
	Reference artifact.ObjectReference `json:"reference"`
}

// SBOMBundle explicitly indexes one Syft file scan per selected subject. Its
// reference fits v1's single SBOMRef without claiming one file scan covers the
// whole release group. Raw supplied SBOM/provenance bytes remain separately pinned.
type SBOMBundle struct {
	Version       string                    `json:"version"`
	SBOMs         []SBOMObject              `json:"sboms"`
	ProvenanceRaw *artifact.ObjectReference `json:"provenance_raw,omitempty"`
	ExistingSBOM  *artifact.ObjectReference `json:"existing_sbom,omitempty"`
	Issues        []string                  `json:"issues"`
}

// WorkerResult is an untrusted producer claim. Finalization independently checks
// references/bytes/build bindings. A compromised worker can still poison its own
// inputs; no provenance authenticity or security assessment is asserted here.
type WorkerResult struct {
	Version           string                    `json:"version"`
	Build             build.Context             `json:"build"`
	JobRef            artifact.ObjectReference  `json:"job_ref"`
	Archive           artifact.ObjectReference  `json:"archive"`
	RequestedSubjects []string                  `json:"requested_subjects"`
	Subjects          []SubjectObject           `json:"subjects"`
	SBOMs             []SBOMObject              `json:"sboms"`
	ProvenanceRaw     *artifact.ObjectReference `json:"provenance_raw,omitempty"`
	Provenance        *provenance.Reference     `json:"provenance,omitempty"`
	ExistingSBOM      *artifact.ObjectReference `json:"existing_sbom,omitempty"`
	Issues            []string                  `json:"issues"`
	Failure           *v1.Failure               `json:"failure,omitempty"`
}

const workerResultVersion = "acquisition-worker/v2"

func subjectSelection(names []string, digest artifact.Digest) (map[string]bool, error) {
	if len(names) == 0 || len(names) > 128 {
		return nil, errors.New("invalid subject selection")
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] || (artifact.Subject{Name: name, Digest: digest}).Validate() != nil {
			return nil, errors.New("invalid subject selection")
		}
		seen[name] = true
	}
	return seen, nil
}

func validByteLimits(limits ...int64) bool {
	for _, limit := range limits {
		if limit <= 0 || limit > acquire.MaxObjectBytes {
			return false
		}
	}
	return len(limits) > 0
}

func (r WorkerResult) Validate() error {
	if r.Version != workerResultVersion || r.Build.ValidateComplete() != nil || r.JobRef.Validate() != nil || r.Archive.Validate() != nil || r.Subjects == nil || r.SBOMs == nil || r.Issues == nil {
		return errors.New("invalid worker result")
	}
	requested, err := subjectSelection(r.RequestedSubjects, r.JobRef.Digest)
	if err != nil {
		return err
	}
	if err := r.validateMetadata(); err != nil {
		return err
	}
	subjects, err := r.validateSubjects(requested)
	if err != nil {
		return err
	}
	if r.Failure == nil && (len(subjects) != len(requested) || len(r.SBOMs) != len(subjects)) {
		return errors.New("missing subjects or SBOMs")
	}
	if err := r.validateSBOMs(subjects); err != nil {
		return err
	}
	if r.Failure != nil {
		return r.Failure.Validate()
	}
	return nil
}

func (r WorkerResult) validateMetadata() error {
	for _, ref := range []*artifact.ObjectReference{r.ProvenanceRaw, r.ExistingSBOM} {
		if ref != nil && ref.Validate() != nil {
			return errors.New("invalid raw metadata reference")
		}
	}
	if r.Provenance != nil {
		if r.Provenance.Validate() != nil || r.Provenance.OriginStatus != provenance.OriginUnauthenticated || r.ProvenanceRaw == nil || !r.Provenance.Reference.Equal(*r.ProvenanceRaw) {
			return errors.New("invalid or authenticated worker provenance claim")
		}
	}
	for _, issue := range r.Issues {
		if !slices.Contains([]string{"PROVENANCE_MISSING", "PROVENANCE_MALFORMED", "PROVENANCE_UNSUPPORTED", "PROVENANCE_INVALID_SUBJECTS", "PROVENANCE_INVALID_DEPENDENCY_DIGEST", "PROVENANCE_PREDICATE_INCOMPLETE", "PROVENANCE_SUBJECT_MISMATCH", "EXISTING_SBOM_UNVERIFIED"}, issue) {
			return errors.New("invalid acquisition issue code")
		}
	}

	return nil
}

func (r WorkerResult) validateSubjects(requested map[string]bool) (map[string]artifact.Digest, error) {
	subjects := make(map[string]artifact.Digest, len(r.Subjects))
	for _, s := range r.Subjects {
		_, duplicate := subjects[s.Subject.Name]
		if s.Reference.Validate() != nil || s.Reference.Digest != s.Subject.Digest || !requested[s.Subject.Name] || duplicate {
			return nil, errors.New("subject reference mismatch")
		}
		subjects[s.Subject.Name] = s.Subject.Digest
	}

	return subjects, nil
}

func (r WorkerResult) validateSBOMs(subjects map[string]artifact.Digest) error {
	seen := map[string]bool{}
	for _, s := range r.SBOMs {
		if s.Reference.Validate() != nil || s.Subject.Validate() != nil || seen[s.Subject.Name] || subjects[s.Subject.Name] != s.Subject.Digest {
			return errors.New("invalid SBOM binding")
		}
		seen[s.Subject.Name] = true
	}

	return nil
}

func DecodeWorker(data []byte) (WorkerResult, error) {
	var r WorkerResult
	if len(data) > 1<<20 || jsoninput.Decode(data, &r, true) != nil {
		return r, errors.New("invalid worker JSON")
	}
	return r, r.Validate()
}

// Process runs only after OS isolation preflight in the composition root. No CI
// client, token, socket or decision-storage writer is available through its ports.
// Raw malformed provenance is stored before parsing and never silently repaired.
func Process(ctx context.Context, fetch acquire.Source, out acquire.Sink, archive ArchiveReader, scanner Scanner, parser ProvenanceParser, jobRef artifact.ObjectReference, id string, names []string, maxArchive, maxEntry, maxSBOM int64) (artifact.ObjectReference, error) {
	var zero artifact.ObjectReference
	if artifact.ValidateID(id) != nil || jobRef.Validate() != nil || !validByteLimits(maxArchive, maxEntry, maxSBOM) {
		return zero, errors.New("invalid worker request")
	}
	// Reuse domain validation for exact logical names and duplicate selection.
	// The already validated reference digest is only a syntax-validation input
	// here. Actual subject digests are computed from selected bytes below.
	if _, err := subjectSelection(names, jobRef.Digest); err != nil {
		return zero, errors.New("invalid worker subject selection")
	}
	b, err := fetch.Get(ctx, jobRef, 1<<20)
	if err != nil {
		return zero, err
	}
	job, err := acquire.DecodeJob(b)
	if err != nil {
		return zero, err
	}
	if !job.ArtifactsRequested || job.Archive == nil || job.Failure != nil {
		return zero, errors.New("fetched archive unavailable")
	}
	r := WorkerResult{Version: workerResultVersion, Build: job.Build, JobRef: jobRef, Archive: *job.Archive, RequestedSubjects: slices.Clone(names), Subjects: []SubjectObject{}, SBOMs: []SBOMObject{}, Issues: []string{}}

	transport, err := fetch.Get(ctx, *job.Archive, maxArchive)
	if err != nil {
		// A referenced-object read can fail because of storage or integrity.
		// Preserve that error, as for the job read above, instead of inventing
		// a producer outcome from bytes we could not safely load.
		return zero, err
	}
	contents, err := archive.Read(ctx, transport, names)
	if err != nil {
		r.Failure = acquire.Failure(err)
		return writeWorkerResult(ctx, out, id, r)
	}
	if err := r.storeMetadata(ctx, out, parser, contents, maxSBOM); err != nil {
		return zero, err
	}
	if err := r.scanSubjects(ctx, out, scanner, contents.Subjects, maxEntry, maxSBOM); err != nil {
		return zero, err
	}
	r.noteProvenanceMismatch()
	return writeWorkerResult(ctx, out, id, r)
}

func storeContent(ctx context.Context, out acquire.Sink, data []byte, limit int64) (artifact.ObjectReference, error) {
	return out.Put(ctx, "sha256-"+acquire.Hash(data).Value, bytes.NewReader(data), limit)
}

func (r *WorkerResult) storeMetadata(ctx context.Context, out acquire.Sink, parser ProvenanceParser, contents Contents, maxSBOM int64) error {
	if contents.ProvenancePresent {
		ref, e := storeContent(ctx, out, contents.Provenance, 1<<20)
		if e != nil {
			return e
		}
		r.ProvenanceRaw = &ref
		r.Provenance, r.Issues = parser.Parse(contents.Provenance, ref)
	} else {
		r.Issues = append(r.Issues, "PROVENANCE_MISSING")
	}
	if contents.SBOMPresent {
		ref, e := storeContent(ctx, out, contents.ExistingSBOM, maxSBOM)
		if e != nil {
			return e
		}
		r.ExistingSBOM = &ref
		r.Issues = append(r.Issues, "EXISTING_SBOM_UNVERIFIED")
	}

	return nil
}

func (r *WorkerResult) scanSubjects(ctx context.Context, out acquire.Sink, scanner Scanner, subjects []SubjectBytes, maxEntry, maxSBOM int64) error {
	for _, s := range subjects {
		ref, e := storeContent(ctx, out, s.Bytes, maxEntry)
		if e != nil {
			return e
		}
		subject := artifact.Subject{Name: s.Name, Digest: ref.Digest}
		r.Subjects = append(r.Subjects, SubjectObject{Subject: subject, Reference: ref})
		sbom, e := scanner.Scan(ctx, s.Bytes, ref.Digest)
		if e != nil {
			r.Failure = acquire.Failure(e)
			// Scanner failure is a producer outcome; channel failures return errors.
			return nil
		}
		ref, e = storeContent(ctx, out, sbom, maxSBOM)
		if e != nil {
			return e
		}
		r.SBOMs = append(r.SBOMs, SBOMObject{Subject: subject, Reference: ref})
	}

	return nil
}

func writeWorkerResult(ctx context.Context, out acquire.Sink, id string, r WorkerResult) (artifact.ObjectReference, error) {
	if e := r.Validate(); e != nil {
		return artifact.ObjectReference{}, e
	}
	data, e := json.Marshal(r)
	if e != nil {
		return artifact.ObjectReference{}, e
	}
	return out.Put(ctx, id, bytes.NewReader(data), 1<<20)
}

func (r *WorkerResult) noteProvenanceMismatch() {
	if r.Failure == nil && r.Provenance != nil {
		var subjects []artifact.Subject
		for _, s := range r.Subjects {
			subjects = append(subjects, s.Subject)
		}
		if !artifact.ContainsSubjects(r.Provenance.Subjects, subjects) {
			r.Issues = append(r.Issues, "PROVENANCE_SUBJECT_MISMATCH")
		}
	}
}
