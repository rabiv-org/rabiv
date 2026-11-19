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
	Version       string                    `json:"version"`
	Build         build.Context             `json:"build"`
	JobRef        artifact.ObjectReference  `json:"job_ref"`
	Archive       artifact.ObjectReference  `json:"archive"`
	Subjects      []SubjectObject           `json:"subjects"`
	SBOMs         []SBOMObject              `json:"sboms"`
	ProvenanceRaw *artifact.ObjectReference `json:"provenance_raw,omitempty"`
	Provenance    *provenance.Reference     `json:"provenance,omitempty"`
	ExistingSBOM  *artifact.ObjectReference `json:"existing_sbom,omitempty"`
	Issues        []string                  `json:"issues"`
	Failure       *v1.Failure               `json:"failure,omitempty"`
}

func (r WorkerResult) Validate() error {
	if r.Version != acquire.Version || r.Build.ValidateComplete() != nil || r.JobRef.Validate() != nil || r.Archive.Validate() != nil || r.Subjects == nil || r.SBOMs == nil || r.Issues == nil {
		return errors.New("invalid worker result")
	}
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
	var subjects []artifact.Subject
	for _, s := range r.Subjects {
		if s.Reference.Validate() != nil || s.Reference.Digest != s.Subject.Digest {
			return errors.New("subject reference mismatch")
		}
		subjects = append(subjects, s.Subject)
	}
	if len(subjects) > 0 && artifact.ValidateSubjects(subjects) != nil {
		return errors.New("invalid partial subjects")
	}
	if r.Failure == nil && (len(subjects) == 0 || len(r.SBOMs) != len(subjects)) {
		return errors.New("missing subjects or SBOMs")
	}
	seen := map[string]bool{}
	for _, s := range r.SBOMs {
		if s.Reference.Validate() != nil || s.Subject.Validate() != nil || seen[s.Subject.Name] || !artifact.ContainsSubjects(subjects, []artifact.Subject{s.Subject}) {
			return errors.New("invalid SBOM binding")
		}
		seen[s.Subject.Name] = true
	}
	if r.Failure != nil {
		return r.Failure.Validate()
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
func Process(ctx context.Context, fetch acquire.Source, out acquire.Sink, archive ArchiveReader, scanner Scanner, parser ProvenanceParser, jobRef artifact.ObjectReference, id string, names []string, maxArchive, maxSBOM int64) (artifact.ObjectReference, error) {
	var zero artifact.ObjectReference
	if artifact.ValidateID(id) != nil || len(names) == 0 || len(names) > 128 {
		return zero, errors.New("invalid worker request")
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
	r := WorkerResult{Version: acquire.Version, Build: job.Build, JobRef: jobRef, Archive: *job.Archive, Subjects: []SubjectObject{}, SBOMs: []SBOMObject{}, Issues: []string{}}
	finish := func() (artifact.ObjectReference, error) {
		if e := r.Validate(); e != nil {
			return zero, e
		}
		data, e := json.Marshal(r)
		if e != nil {
			return zero, e
		}
		return out.Put(ctx, id, bytes.NewReader(data), 1<<20)
	}
	transport, err := fetch.Get(ctx, *job.Archive, maxArchive)
	if err != nil {
		r.Failure = acquire.Failure(err)
		return finish()
	}
	contents, err := archive.Read(ctx, transport, names)
	if err != nil {
		r.Failure = acquire.Failure(err)
		return finish()
	}
	put := func(data []byte, limit int64) (artifact.ObjectReference, error) {
		return out.Put(ctx, "sha256-"+acquire.Hash(data).Value, bytes.NewReader(data), limit)
	}
	if contents.ProvenancePresent {
		ref, e := put(contents.Provenance, 1<<20)
		if e != nil {
			return zero, e
		}
		r.ProvenanceRaw = &ref
		r.Provenance, r.Issues = parser.Parse(contents.Provenance, ref)
	} else {
		r.Issues = append(r.Issues, "PROVENANCE_MISSING")
	}
	if contents.SBOMPresent {
		ref, e := put(contents.ExistingSBOM, maxSBOM)
		if e != nil {
			return zero, e
		}
		r.ExistingSBOM = &ref
		r.Issues = append(r.Issues, "EXISTING_SBOM_UNVERIFIED")
	}
	for _, s := range contents.Subjects {
		ref, e := put(s.Bytes, maxArchive)
		if e != nil {
			return zero, e
		}
		subject := artifact.Subject{Name: s.Name, Digest: ref.Digest}
		r.Subjects = append(r.Subjects, SubjectObject{Subject: subject, Reference: ref})
		sbom, e := scanner.Scan(ctx, s.Bytes, ref.Digest)
		if e != nil {
			r.Failure = acquire.Failure(e)
			return finish()
		}
		ref, e = put(sbom, maxSBOM)
		if e != nil {
			return zero, e
		}
		r.SBOMs = append(r.SBOMs, SBOMObject{Subject: subject, Reference: ref})
	}
	if r.Provenance != nil {
		var subjects []artifact.Subject
		for _, s := range r.Subjects {
			subjects = append(subjects, s.Subject)
		}
		if !artifact.ContainsSubjects(r.Provenance.Subjects, subjects) {
			r.Issues = append(r.Issues, "PROVENANCE_SUBJECT_MISMATCH")
		}
	}
	return finish()
}
