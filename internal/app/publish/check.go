// Package publish checks decision handoffs without providing a release operation.
package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/decision"
)

// These Phase 2 parameters are not project-wide policy invariants.
const (
	MaxDecisionBytes   = 1 << 20
	DefaultMaxValidity = 5 * time.Minute
)

var (
	ErrTooLarge           = errors.New("decision exceeds Phase 2 size limit")
	ErrDigestMismatch     = errors.New("decision bytes do not match expected reference")
	ErrInvalidRecord      = errors.New("invalid decision record")
	ErrNonAllow           = errors.New("decision is not ALLOW")
	ErrFreshness          = errors.New("decision freshness requirements not met")
	ErrContextUnavailable = errors.New("trusted expected context unavailable")
	ErrBindingMismatch    = errors.New("decision context binding mismatch")
	ErrReleaseUnavailable = errors.New("release authority and publication are unavailable in Phase 2")
)

// DecisionSource must read at most MaxDecisionBytes from a protected namespace,
// checking OS ownership/access metadata. It must never resolve arbitrary paths.
type DecisionSource interface {
	Read(context.Context, string) ([]byte, error)
}

// ExpectedContext must be independently supplied by trusted orchestration.
// It must not be copied from the received decision to make a comparison pass.
type ExpectedContext struct {
	WorkflowID   string
	Build        build.Identity
	SubjectGroup artifact.SubjectGroup
}

func (e ExpectedContext) validate() error {
	if err := artifact.ValidateID(e.WorkflowID); err != nil {
		return err
	}
	if err := e.Build.Validate(); err != nil {
		return err
	}
	return e.SubjectGroup.Validate()
}

// CheckedHandoff is metadata for further verification, never a release capability.
type CheckedHandoff struct {
	Reference artifact.ObjectReference
	Record    v1.DecisionRecord
}

// Checker has no publication port. Now is injected for reproducible checks.
type Checker struct {
	Source      DecisionSource
	Now         func() time.Time
	MaxValidity time.Duration
}

// Check verifies only decision-byte integrity against the supplied trusted ref,
// syntax/domain structure, freshness and supplied metadata context. It does not
// verify referenced artifact/evidence bytes, provenance, policy execution or authority.
func (c Checker) Check(ctx context.Context, ref artifact.ObjectReference, expected *ExpectedContext) (CheckedHandoff, error) {
	var zero CheckedHandoff
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if err := ref.Validate(); err != nil {
		return zero, err
	}
	if c.Source == nil || c.Now == nil || c.MaxValidity <= 0 {
		return zero, fmt.Errorf("checker configuration unavailable")
	}
	raw, err := c.Source.Read(ctx, ref.ID)
	if err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if len(raw) > MaxDecisionBytes {
		return zero, ErrTooLarge
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != ref.Digest.Value {
		return zero, ErrDigestMismatch
	}
	record, err := v1.DecodeDecisionRecord(raw)
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrInvalidRecord, err)
	}
	d := record.Decision
	if d.DecisionID != ref.ID {
		return zero, ErrBindingMismatch
	}
	// A valid diagnostic has no ALLOW-only fields. Reject its verdict before
	// inspecting expiry or expected context, rather than calling it malformed.
	if d.Verdict != decision.Allow {
		return zero, ErrNonAllow
	}
	if err := c.checkFreshness(d); err != nil {
		return zero, err
	}
	if err := checkExpectedContext(d, expected); err != nil {
		return zero, err
	}
	return CheckedHandoff{Reference: ref, Record: record}, nil
}

func (c Checker) checkFreshness(d decision.Decision) error {
	now := c.Now()
	if build.ValidateTime(now) != nil || now.Before(d.IssuedAt) || !now.Before(*d.ExpiresAt) || d.ExpiresAt.Sub(d.IssuedAt) > c.MaxValidity {
		return ErrFreshness
	}
	return nil
}

func checkExpectedContext(d decision.Decision, expected *ExpectedContext) error {
	if expected == nil {
		return ErrContextUnavailable
	}
	if err := expected.validate(); err != nil {
		return fmt.Errorf("expected context: %w", err)
	}
	if d.WorkflowID != expected.WorkflowID || d.Build.Identity != expected.Build || !d.SubjectGroup.Equal(expected.SubjectGroup) {
		return ErrBindingMismatch
	}
	return nil
}
