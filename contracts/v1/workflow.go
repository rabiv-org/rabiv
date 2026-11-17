package v1

import (
	"fmt"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

// ProcessingState is persistent workflow state, not readiness or worker ownership.
type ProcessingState string

const (
	Open    ProcessingState = "OPEN"
	Decided ProcessingState = "DECIDED"
)

// FailureSource records a reporting route without authenticating that route.
type FailureSource string

const (
	ProducerReport      FailureSource = "PRODUCER_REPORT"
	VerifierObservation FailureSource = "VERIFIER_OBSERVATION"
)

// InputFailure can report a producer failure before any manifest was persisted.
type InputFailure struct {
	Code   FailureCode   `json:"code"`
	Source FailureSource `json:"source"`
}

// Validate checks failure metadata; timeout alone is not producer-failure proof.
func (f InputFailure) Validate() error {
	if err := (Failure{Code: f.Code}).Validate(); err != nil {
		return err
	}
	if f.Source != ProducerReport && f.Source != VerifierObservation {
		return fmt.Errorf("invalid input failure source")
	}
	return nil
}

// InputSnapshot tracks evidence and artifact readiness independently.
type InputSnapshot struct {
	State       ProducerState             `json:"state"`
	ManifestRef *artifact.ObjectReference `json:"manifest_ref,omitempty"`
	Failure     *InputFailure             `json:"failure,omitempty"`
}

// Validate allows FAILED without a manifest, but never without failure metadata.
func (s InputSnapshot) Validate() error {
	if err := s.State.Validate(); err != nil {
		return err
	}
	if s.ManifestRef != nil {
		if err := s.ManifestRef.Validate(); err != nil {
			return err
		}
	}
	if s.State == Failed {
		if s.Failure == nil {
			return fmt.Errorf("failed input requires failure metadata")
		}
		return s.Failure.Validate()
	}
	if s.Failure != nil {
		return fmt.Errorf("failure metadata requires FAILED input")
	}
	if s.State == Finalized && s.ManifestRef == nil {
		return fmt.Errorf("finalized input requires a manifest reference")
	}
	return nil
}

// WorkflowState is owned and persisted by Verifier. It contains no claim/lock,
// lease, retry, scheduler, or publication state. Those responsibilities are deferred.
type WorkflowState struct {
	SchemaVersion string                    `json:"schema_version"`
	Kind          Kind                      `json:"kind"`
	WorkflowID    string                    `json:"workflow_id"`
	Build         build.Context             `json:"build"`
	CreatedAt     time.Time                 `json:"created_at"`
	UpdatedAt     time.Time                 `json:"updated_at"`
	InputDeadline time.Time                 `json:"input_deadline"`
	State         ProcessingState           `json:"state"`
	EvidenceInput InputSnapshot             `json:"evidence_input"`
	ArtifactInput InputSnapshot             `json:"artifact_input"`
	DecisionRef   *artifact.ObjectReference `json:"decision_ref,omitempty"`
}

// Validate checks one snapshot, not transition history or storage concurrency.
func (w WorkflowState) Validate() error {
	if err := validateEnvelope(w.SchemaVersion, w.Kind, KindWorkflowState); err != nil {
		return err
	}
	if err := artifact.ValidateID(w.WorkflowID); err != nil {
		return err
	}
	if err := w.Build.Validate(); err != nil {
		return err
	}
	for _, ts := range []time.Time{w.CreatedAt, w.UpdatedAt, w.InputDeadline} {
		if err := build.ValidateTime(ts); err != nil {
			return err
		}
	}
	if w.UpdatedAt.Before(w.CreatedAt) || !w.InputDeadline.After(w.CreatedAt) {
		return fmt.Errorf("invalid workflow time ordering")
	}
	if err := w.EvidenceInput.Validate(); err != nil {
		return err
	}
	if err := w.ArtifactInput.Validate(); err != nil {
		return err
	}
	switch w.State {
	case Open:
		if w.DecisionRef != nil {
			return fmt.Errorf("open workflow must not have a decision reference")
		}
	case Decided:
		if w.DecisionRef == nil {
			return fmt.Errorf("decided workflow requires a decision reference")
		}
		return w.DecisionRef.Validate()
	default:
		return fmt.Errorf("invalid processing state")
	}
	return nil
}

// RequiresEvaluationAt derives readiness, without claiming work or authorizing
// release. Invalid snapshots/times return false; callers use Validate for errors.
// Multiple workers may get true: concurrency, restart, and idempotency belong to
// future application/storage boundaries. DECIDED is never reopened by this helper.
func (w WorkflowState) RequiresEvaluationAt(now time.Time) bool {
	if w.Validate() != nil || build.ValidateTime(now) != nil || w.State != Open {
		return false
	}
	return w.EvidenceInput.State == Failed || w.ArtifactInput.State == Failed ||
		w.EvidenceInput.State == Finalized && w.ArtifactInput.State == Finalized || !now.Before(w.InputDeadline)
}
