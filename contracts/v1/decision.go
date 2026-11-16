package v1

import "github.com/rabiv-org/rabiv/internal/domain/decision"

// DecisionRecord is produced by Verifier for Publisher. Syntax-valid records are
// not release authority without trusted storage/authenticated IPC and enforcement.
type DecisionRecord struct {
	SchemaVersion string            `json:"schema_version"`
	Kind          Kind              `json:"kind"`
	Decision      decision.Decision `json:"decision"`
}

// Validate delegates the domain verdict matrix. It does not authenticate Verifier.
func (r DecisionRecord) Validate() error {
	if err := validateEnvelope(r.SchemaVersion, r.Kind, KindDecisionRecord); err != nil {
		return err
	}
	return r.Decision.Validate()
}
