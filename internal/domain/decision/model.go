// Package decision models declared verification results, not authenticated release
// authority. Validation never verifies policy execution, origin, or object bytes.
package decision

import (
	"fmt"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/policy"
)

// Verdict separates confirmed violations from insufficient trustworthy inputs.
type Verdict string

const (
	Allow         Verdict = "ALLOW"
	Deny          Verdict = "DENY"
	Indeterminate Verdict = "INDETERMINATE"
)

// Sufficiency concerns all required evaluation inputs, not just proof of a violation.
type Sufficiency string

const (
	SufficiencyUnknown Sufficiency = "UNKNOWN"
	Insufficient       Sufficiency = "INSUFFICIENT"
	Sufficient         Sufficiency = "SUFFICIENT"
)

// Compliance is separate from availability and trust.
type Compliance string

const (
	ComplianceNotEvaluated Compliance = "NOT_EVALUATED"
	Satisfied              Compliance = "SATISFIED"
	Violated               Compliance = "VIOLATED"
)

// TrustAssessment declares whether applicable trust requirements were met.
type TrustAssessment string

const (
	TrustNotEvaluated       TrustAssessment = "NOT_EVALUATED"
	TrustRequirementsNotMet TrustAssessment = "REQUIREMENTS_NOT_MET"
	TrustRequirementsMet    TrustAssessment = "REQUIREMENTS_MET"
)

// Assessment values are assertions by the evaluator, not verified guarantees.
type Assessment struct {
	Sufficiency Sufficiency     `json:"sufficiency"`
	Compliance  Compliance      `json:"compliance"`
	Trust       TrustAssessment `json:"trust"`
}

// Validate checks the closed assessment vocabularies.
func (a Assessment) Validate() error {
	switch a.Sufficiency {
	case SufficiencyUnknown, Insufficient, Sufficient:
	default:
		return fmt.Errorf("invalid sufficiency")
	}
	switch a.Compliance {
	case ComplianceNotEvaluated, Satisfied, Violated:
	default:
		return fmt.Errorf("invalid compliance")
	}
	switch a.Trust {
	case TrustNotEvaluated, TrustRequirementsNotMet, TrustRequirementsMet:
	default:
		return fmt.Errorf("invalid trust assessment")
	}
	return nil
}

// ReasonCode is a closed vocabulary; confirmed reasons remain evaluator claims.
type ReasonCode string

const (
	RequiredChecksPassed         ReasonCode = "REQUIRED_CHECKS_PASSED"
	ConfirmedPolicyViolation     ReasonCode = "CONFIRMED_POLICY_VIOLATION"
	PolicyAuthorizationViolation ReasonCode = "POLICY_AUTHORIZATION_VIOLATION"
	MissingRequiredEvidence      ReasonCode = "MISSING_REQUIRED_EVIDENCE"
	MissingRequiredMetadata      ReasonCode = "MISSING_REQUIRED_METADATA"
	EvidenceGap                  ReasonCode = "EVIDENCE_GAP"
	ProducerFailed               ReasonCode = "PRODUCER_FAILED"
	InputTimeout                 ReasonCode = "INPUT_TIMEOUT"
	UntrustedInput               ReasonCode = "UNTRUSTED_INPUT"
	ConsistencyMismatch          ReasonCode = "CONSISTENCY_MISMATCH"
	ChecksIncomplete             ReasonCode = "CHECKS_INCOMPLETE"
)

// Decision binds a declared result to a job, workflow and exact subject group.
// SubjectGroup conveys authorization only under an authenticated, enforced ALLOW.
type Decision struct {
	DecisionID          string                         `json:"decision_id"`
	WorkflowID          string                         `json:"workflow_id"`
	Build               build.Context                  `json:"build"`
	Verdict             Verdict                        `json:"verdict"`
	Assessment          Assessment                     `json:"assessment"`
	Reasons             []ReasonCode                   `json:"reasons"`
	IssuedAt            time.Time                      `json:"issued_at"`
	ExpiresAt           *time.Time                     `json:"expires_at,omitempty"`
	SubjectGroup        *artifact.SubjectGroup         `json:"subject_group,omitempty"`
	EvidenceManifestRef *artifact.ObjectReference      `json:"evidence_manifest_ref,omitempty"`
	ArtifactManifestRef *artifact.ObjectReference      `json:"artifact_manifest_ref,omitempty"`
	ProvenanceRef       *artifact.ObjectReference      `json:"provenance_ref,omitempty"`
	SBOMRef             *artifact.ObjectReference      `json:"sbom_ref,omitempty"`
	Baseline            *policy.BaselineSnapshot       `json:"baseline,omitempty"`
	ProjectProfile      *policy.ProjectProfileSnapshot `json:"project_profile,omitempty"`
}

// Validate enforces structure and the verdict/assessment/reason matrix. It does
// not check current time, freshness against stored workflow state, authenticity,
// reference bytes, or whether any assessment/violation has actually been proved.
func (d Decision) Validate() error {
	if err := artifact.ValidateID(d.DecisionID); err != nil {
		return err
	}
	if err := artifact.ValidateID(d.WorkflowID); err != nil {
		return err
	}
	if err := d.Build.Validate(); err != nil {
		return err
	}
	if err := d.Assessment.Validate(); err != nil {
		return err
	}
	if err := build.ValidateTime(d.IssuedAt); err != nil {
		return err
	}
	if d.ExpiresAt != nil {
		if err := build.ValidateTime(*d.ExpiresAt); err != nil {
			return err
		}
		if !d.ExpiresAt.After(d.IssuedAt) {
			return fmt.Errorf("expiry must follow issue time")
		}
	}
	missingEvidence, err := d.validateInputReferences()
	if err != nil {
		return err
	}
	if err := d.validatePolicyMetadata(); err != nil {
		return err
	}
	missingMetadata := d.Build.ValidateComplete() != nil || d.SubjectGroup == nil || d.Baseline == nil || d.ProjectProfile == nil
	facts, err := d.validateReasons()
	if err != nil {
		return err
	}
	if err := d.validateRequiredInputs(missingEvidence, missingMetadata, facts); err != nil {
		return err
	}
	return d.validateVerdict(missingEvidence, missingMetadata, facts)
}

func (d Decision) validateInputReferences() (bool, error) {
	missingEvidence := false
	for _, ref := range []*artifact.ObjectReference{d.EvidenceManifestRef, d.ArtifactManifestRef, d.ProvenanceRef, d.SBOMRef} {
		if ref == nil {
			missingEvidence = true
			continue
		}
		if err := ref.Validate(); err != nil {
			return false, err
		}
	}

	return missingEvidence, nil
}

func (d Decision) validatePolicyMetadata() error {
	if d.SubjectGroup != nil {
		if err := d.SubjectGroup.Validate(); err != nil {
			return err
		}
	}
	if d.Baseline != nil {
		if err := d.Baseline.Validate(); err != nil {
			return err
		}
	}
	if d.ProjectProfile != nil {
		if err := d.ProjectProfile.Validate(); err != nil {
			return err
		}
		if d.ProjectProfile.Project != d.Build.Identity.Project() {
			return fmt.Errorf("profile applies to a different project")
		}
	}

	return nil
}

type reasonFacts struct {
	seen      map[ReasonCode]bool
	confirmed bool
}

func (d Decision) validateReasons() (reasonFacts, error) {
	if len(d.Reasons) == 0 {
		return reasonFacts{}, fmt.Errorf("decision reasons are required")
	}
	seen := make(map[ReasonCode]bool, len(d.Reasons))
	confirmed := false
	for _, reason := range d.Reasons {
		if seen[reason] {
			return reasonFacts{}, fmt.Errorf("duplicate decision reason")
		}
		seen[reason] = true
		if err := d.validateReason(reason); err != nil {
			return reasonFacts{}, err
		}
		if reason == ConfirmedPolicyViolation || reason == PolicyAuthorizationViolation {
			confirmed = true
		}

	}

	return reasonFacts{seen, confirmed}, nil
}

func (d Decision) validateReason(reason ReasonCode) error {
	switch reason {
	case RequiredChecksPassed:
		if d.Verdict != Allow {
			return fmt.Errorf("success reason requires ALLOW")
		}
	case ConfirmedPolicyViolation, PolicyAuthorizationViolation:
		if d.Verdict != Deny {
			return fmt.Errorf("confirmed violation reason requires DENY")
		}
		if reason == PolicyAuthorizationViolation && d.Assessment.Trust != TrustRequirementsNotMet {
			return fmt.Errorf("policy authorization violation requires unmet trust")
		}
	case MissingRequiredEvidence, MissingRequiredMetadata, EvidenceGap, ProducerFailed, InputTimeout:
		if d.Assessment.Sufficiency != Insufficient {
			return fmt.Errorf("missing/gap/failure reason requires insufficient inputs")
		}
	default:
		return d.validateAssessmentReason(reason)
	}
	return nil
}

func (d Decision) validateAssessmentReason(reason ReasonCode) error {
	switch reason {
	case UntrustedInput:
		if d.Assessment.Trust != TrustRequirementsNotMet {
			return fmt.Errorf("untrusted input requires unmet trust")
		}
	case ConsistencyMismatch:
		if d.Assessment.Sufficiency != Insufficient || d.Assessment.Trust != TrustRequirementsNotMet {
			return fmt.Errorf("consistency mismatch requires insufficient inputs and unmet trust")
		}
	case ChecksIncomplete:
		if d.Assessment.Sufficiency != SufficiencyUnknown && d.Assessment.Compliance != ComplianceNotEvaluated && d.Assessment.Trust != TrustNotEvaluated {
			return fmt.Errorf("incomplete checks reason requires an unestablished assessment")
		}
	default:
		return fmt.Errorf("invalid decision reason")
	}
	return nil
}

func (d Decision) validateRequiredInputs(missingEvidence, missingMetadata bool, reasons reasonFacts) error {
	if missingEvidence && (!reasons.seen[MissingRequiredEvidence] || d.Assessment.Sufficiency != Insufficient) {
		return fmt.Errorf("missing input references require explicit insufficiency")
	}
	if missingMetadata && (!reasons.seen[MissingRequiredMetadata] || d.Assessment.Sufficiency != Insufficient) {
		return fmt.Errorf("missing metadata requires explicit insufficiency")
	}

	return nil
}

func (d Decision) validateVerdict(missingEvidence, missingMetadata bool, reasons reasonFacts) error {
	allPositive := d.Assessment.Sufficiency == Sufficient && d.Assessment.Compliance == Satisfied && d.Assessment.Trust == TrustRequirementsMet
	switch d.Verdict {
	case Allow:
		return d.validateAllow(allPositive, missingEvidence, missingMetadata, reasons)
	case Deny:
		if d.Assessment.Compliance != Violated || !reasons.confirmed {
			return fmt.Errorf("DENY requires a declared confirmed violation")
		}
	case Indeterminate:
		if d.Assessment.Compliance == Violated || allPositive {
			return fmt.Errorf("contradictory INDETERMINATE")
		}
	default:
		return fmt.Errorf("invalid verdict")
	}
	return nil
}

func (d Decision) validateAllow(allPositive, missingEvidence, missingMetadata bool, reasons reasonFacts) error {
	if !allPositive || d.ExpiresAt == nil || missingEvidence || missingMetadata || len(d.Reasons) != 1 || !reasons.seen[RequiredChecksPassed] {
		return fmt.Errorf("contradictory or incomplete ALLOW")
	}

	return nil
}
