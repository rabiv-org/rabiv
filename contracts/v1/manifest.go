// Package v1 defines closed, versioned records for Rabiv's four processes.
// Records carry claims, not authenticated authority. Future receiving boundaries
// must size-bound untrusted input before passing it to these in-memory decoders.
package v1

import (
	"fmt"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
	"github.com/rabiv-org/rabiv/internal/domain/provenance"
)

// SchemaVersion is immutable. Unknown fields/enums require a new wire version.
const SchemaVersion = "v1"

// Kind discriminates record types independently of their producer state.
type Kind string

const (
	KindEvidenceManifest Kind = "EvidenceManifest"
	KindArtifactManifest Kind = "ArtifactManifest"
	KindWorkflowState    Kind = "WorkflowState"
	KindDecisionRecord   Kind = "DecisionRecord"
)

func validateEnvelope(version string, kind, expected Kind) error {
	if version != SchemaVersion || kind != expected {
		return fmt.Errorf("unsupported schema version or record kind")
	}
	return nil
}

// ProducerState describes production, not verification or authorization.
type ProducerState string

const (
	Pending   ProducerState = "PENDING"
	Finalized ProducerState = "FINALIZED"
	Failed    ProducerState = "FAILED"
)

// Validate rejects unknown producer states rather than assuming readiness.
func (s ProducerState) Validate() error {
	switch s {
	case Pending, Finalized, Failed:
		return nil
	}
	return fmt.Errorf("invalid producer state")
}

// FailureCode is sanitized metadata, without arbitrary credential-bearing text.
type FailureCode string

const (
	ProducerError    FailureCode = "PRODUCER_ERROR"
	InputUnavailable FailureCode = "INPUT_UNAVAILABLE"
	InvalidInput     FailureCode = "INVALID_INPUT"
	UnsupportedInput FailureCode = "UNSUPPORTED_INPUT"
)

// Failure reports production failure without asserting a security violation.
type Failure struct {
	Code FailureCode `json:"code"`
}

// Validate checks the closed failure vocabulary.
func (f Failure) Validate() error {
	switch f.Code {
	case ProducerError, InputUnavailable, InvalidInput, UnsupportedInput:
		return nil
	}
	return fmt.Errorf("invalid failure code")
}

// ManifestHeader is shared metadata for immutable manifest snapshots. Every new
// snapshot, including a state update, gets a new ManifestID. No self-digest is stored.
type ManifestHeader struct {
	SchemaVersion string        `json:"schema_version"`
	Kind          Kind          `json:"kind"`
	ManifestID    string        `json:"manifest_id"`
	WorkflowID    string        `json:"workflow_id"`
	Build         build.Context `json:"build"`
	RecordedAt    time.Time     `json:"recorded_at"`
	State         ProducerState `json:"state"`
	Failure       *Failure      `json:"failure,omitempty"`
}

func (h ManifestHeader) validate(kind Kind) error {
	if err := validateEnvelope(h.SchemaVersion, h.Kind, kind); err != nil {
		return err
	}
	if err := artifact.ValidateID(h.ManifestID); err != nil {
		return err
	}
	if err := artifact.ValidateID(h.WorkflowID); err != nil {
		return err
	}
	if err := h.Build.Validate(); err != nil {
		return err
	}
	if err := build.ValidateTime(h.RecordedAt); err != nil {
		return err
	}
	if err := h.State.Validate(); err != nil {
		return err
	}
	if h.State == Failed {
		if h.Failure == nil {
			return fmt.Errorf("failed manifest requires failure metadata")
		}
		return h.Failure.Validate()
	}
	if h.Failure != nil {
		return fmt.Errorf("failure metadata requires FAILED state")
	}
	return nil
}

// EvidenceManifest is produced by Collector for Verifier. FINALIZED does not
// establish coverage, sufficient evidence, or trust.
type EvidenceManifest struct {
	ManifestHeader
	Payload *evidence.Bundle `json:"payload,omitempty"`
}

// Validate delegates evidence invariants without evaluating their sufficiency.
func (m EvidenceManifest) Validate() error {
	if err := m.validate(KindEvidenceManifest); err != nil {
		return err
	}
	if m.Payload == nil {
		if m.State == Finalized {
			return fmt.Errorf("finalized evidence requires a payload")
		}
		return nil
	}
	return m.Payload.Validate()
}

// ArtifactPayload separates transport bytes from individual release subjects.
// Missing provenance or SBOM remains representable after finalization.
type ArtifactPayload struct {
	Transport    artifact.TransportArchive `json:"transport"`
	SubjectGroup artifact.SubjectGroup     `json:"subject_group"`
	SBOMRef      *artifact.ObjectReference `json:"sbom_ref,omitempty"`
	Provenance   *provenance.Reference     `json:"provenance,omitempty"`
}

// Validate checks structure; it does not verify archive/subject/provenance bytes.
func (p ArtifactPayload) Validate() error {
	if err := p.Transport.Validate(); err != nil {
		return err
	}
	if err := p.SubjectGroup.Validate(); err != nil {
		return err
	}
	if p.SBOMRef != nil {
		if err := p.SBOMRef.Validate(); err != nil {
			return err
		}
	}
	if p.Provenance != nil {
		return p.Provenance.Validate()
	}
	return nil
}

// ArtifactManifest is produced by Ingestor for Verifier, not a release grant.
type ArtifactManifest struct {
	ManifestHeader
	Payload *ArtifactPayload `json:"payload,omitempty"`
}

// Validate permits finalized but insufficient metadata without authorizing it.
func (m ArtifactManifest) Validate() error {
	if err := m.validate(KindArtifactManifest); err != nil {
		return err
	}
	if m.Payload == nil {
		if m.State == Finalized {
			return fmt.Errorf("finalized artifacts require a payload")
		}
		return nil
	}
	return m.Payload.Validate()
}
