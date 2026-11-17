// Package verify provides diagnostic-only decision handoff in Phase 2.
// It does not evaluate evidence, policies, or genuine release authority.
package verify

import (
	"context"
	"fmt"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/decision"
)

// DecisionSink persists an immutable snapshot. An error never acknowledges a
// durable commit; after publication, an error may mean commit uncertainty.
type DecisionSink interface {
	Put(context.Context, v1.DecisionRecord) (artifact.ObjectReference, error)
}

// DiagnosticRequest contains operator-supplied identity claims, not verified CI data.
type DiagnosticRequest struct {
	DecisionID string
	WorkflowID string
	Build      build.Identity
}

// NewDiagnostic explicitly reports missing evaluation inputs. Optional ALLOW-only
// fields remain absent. Invalid identity/time is an error, not a fallback verdict.
func NewDiagnostic(req DiagnosticRequest, now time.Time) (v1.DecisionRecord, error) {
	r := v1.DecisionRecord{SchemaVersion: v1.SchemaVersion, Kind: v1.KindDecisionRecord,
		Decision: decision.Decision{
			DecisionID: req.DecisionID, WorkflowID: req.WorkflowID,
			Build: build.Context{Identity: req.Build}, Verdict: decision.Indeterminate,
			Assessment: decision.Assessment{Sufficiency: decision.Insufficient, Compliance: decision.ComplianceNotEvaluated, Trust: decision.TrustNotEvaluated},
			Reasons:    []decision.ReasonCode{decision.MissingRequiredEvidence, decision.MissingRequiredMetadata, decision.ChecksIncomplete}, IssuedAt: now,
		}}
	if err := r.Validate(); err != nil {
		return v1.DecisionRecord{}, fmt.Errorf("diagnostic: %w", err)
	}
	return r, nil
}

// Handoff validates a declared record before passing it to trusted storage.
// Structural validity and storage acknowledgment are not publication authorization.
func Handoff(ctx context.Context, sink DecisionSink, record v1.DecisionRecord) (artifact.ObjectReference, error) {
	if err := ctx.Err(); err != nil {
		return artifact.ObjectReference{}, err
	}
	if err := record.Validate(); err != nil {
		return artifact.ObjectReference{}, err
	}
	if sink == nil {
		return artifact.ObjectReference{}, fmt.Errorf("decision sink unavailable")
	}
	return sink.Put(ctx, record)
}
