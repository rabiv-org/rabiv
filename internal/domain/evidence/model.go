// Package evidence preserves observation claims, uncertainty, and known gaps.
package evidence

import (
	"fmt"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
)

// ObservationWindow reports observation bounds, not continuous or full coverage.
type ObservationWindow struct {
	From  time.Time `json:"from"`
	Until time.Time `json:"until"`
}

// Validate permits a zero-duration reported interval but not reversed bounds.
func (w ObservationWindow) Validate() error {
	if err := build.ValidateTime(w.From); err != nil {
		return err
	}
	if err := build.ValidateTime(w.Until); err != nil {
		return err
	}
	if w.Until.Before(w.From) {
		return fmt.Errorf("observation window is reversed")
	}
	return nil
}

// CoverageStatus is a producer claim, never independently verified assurance.
type CoverageStatus string

const (
	CoverageUnknown         CoverageStatus = "UNKNOWN"
	CoveragePartial         CoverageStatus = "PARTIAL"
	CoverageClaimedComplete CoverageStatus = "CLAIMED_COMPLETE"
)

// ObservationCoverage is independent of window bounds and loss measurements.
type ObservationCoverage struct {
	Status CoverageStatus `json:"status"`
}

// Validate rejects unknown enum values, including the empty zero value.
func (c ObservationCoverage) Validate() error {
	switch c.Status {
	case CoverageUnknown, CoveragePartial, CoverageClaimedComplete:
		return nil
	}
	return fmt.Errorf("invalid coverage status")
}

// LossStatus distinguishes absent measurement from an observed zero counter.
type LossStatus string

const (
	LossUnknown    LossStatus = "UNKNOWN"
	NoLossReported LossStatus = "NO_LOSS_REPORTED"
	LossReported   LossStatus = "LOSS_REPORTED"
)

// EventLoss preserves a loss report. Nil Count does not mean zero.
type EventLoss struct {
	Status LossStatus `json:"status"`
	Count  *uint64    `json:"count,omitempty"`
	Source string     `json:"source,omitempty"`
}

// Validate checks the internal consistency of a report, not its truth.
func (l EventLoss) Validate() error {
	switch l.Status {
	case LossUnknown:
		if l.Count != nil {
			return fmt.Errorf("unknown loss must not carry a count")
		}
		if l.Source != "" {
			return artifact.ValidateID(l.Source)
		}
	case NoLossReported:
		if l.Count == nil || *l.Count != 0 {
			return fmt.Errorf("no-loss report requires an explicit zero")
		}
		return artifact.ValidateID(l.Source)
	case LossReported:
		if l.Count != nil && *l.Count == 0 {
			return fmt.Errorf("reported loss count must be positive when known")
		}
		return artifact.ValidateID(l.Source)
	default:
		return fmt.Errorf("invalid event loss status")
	}
	return nil
}

// GapCode describes known missing observations without retaining raw arguments.
type GapCode string

const (
	TruncatedRecord          GapCode = "TRUNCATED_RECORD"
	UnresolvedScope          GapCode = "UNRESOLVED_SCOPE"
	AmbiguousScope           GapCode = "AMBIGUOUS_SCOPE"
	ScopeMetadataUnavailable GapCode = "SCOPE_METADATA_UNAVAILABLE"
	ObservationInterrupted   GapCode = "OBSERVATION_INTERRUPTED"
)

// Gap is explicit evidence of an observation problem, not a policy violation.
type Gap struct {
	Code GapCode `json:"code"`
}

// Validate checks the supported gap vocabulary.
func (g Gap) Validate() error {
	switch g.Code {
	case TruncatedRecord, UnresolvedScope, AmbiguousScope, ScopeMetadataUnavailable, ObservationInterrupted:
		return nil
	}
	return fmt.Errorf("invalid evidence gap")
}

// ScopeObservation binds an event-source report to a declared execution scope.
type ScopeObservation struct {
	ScopeID     string  `json:"scope_id"`
	EventSource string  `json:"event_source"`
	EventCount  *uint64 `json:"event_count,omitempty"`
}

// Validate checks identifiers; scope existence is checked by Bundle.Validate.
func (o ScopeObservation) Validate() error {
	if err := artifact.ValidateID(o.ScopeID); err != nil {
		return err
	}
	return artifact.ValidateID(o.EventSource)
}

// Bundle is available metadata. Finalization belongs to its producer envelope;
// sufficiency and trust belong to the Verifier, not this model.
type Bundle struct {
	Reference         artifact.ObjectReference `json:"reference"`
	Scopes            []build.ExecutionScope   `json:"scopes"`
	Observations      []ScopeObservation       `json:"observations"`
	ObservationWindow *ObservationWindow       `json:"observation_window,omitempty"`
	Coverage          ObservationCoverage      `json:"coverage"`
	EventLoss         EventLoss                `json:"event_loss"`
	Gaps              []Gap                    `json:"gaps"`
}

// Validate preserves known windows even with loss. A complete claim is not
// verified by this method and never implies artifact causality or permission.
func (b Bundle) Validate() error {
	if err := b.Reference.Validate(); err != nil {
		return err
	}
	if err := build.ValidateScopes(b.Scopes); err != nil {
		return err
	}
	if b.Observations == nil || b.Gaps == nil {
		return fmt.Errorf("observations and gaps arrays are required")
	}
	if b.ObservationWindow != nil {
		if err := b.ObservationWindow.Validate(); err != nil {
			return err
		}
	}
	if err := b.Coverage.Validate(); err != nil {
		return err
	}
	if err := b.EventLoss.Validate(); err != nil {
		return err
	}
	observed, err := b.validateObservations()
	if err != nil {
		return err
	}
	hasAttributionGap, err := b.validateGaps()
	if err != nil {
		return err
	}
	return b.validateCoverage(observed, hasAttributionGap)
}

func (b Bundle) validateCoverage(observed map[string]bool, hasAttributionGap bool) error {
	if (len(b.Scopes) == 0 || len(b.Observations) == 0) && !hasAttributionGap {
		return fmt.Errorf("missing scope/source metadata requires an attribution gap")
	}
	if b.Coverage.Status == CoverageClaimedComplete {
		if len(b.Scopes) == 0 || len(observed) != len(b.Scopes) || len(b.Gaps) != 0 || b.EventLoss.Status != NoLossReported {
			return fmt.Errorf("complete claim contradicts missing metadata, loss, or gaps")
		}
	}
	return nil
}

func (b Bundle) validateObservations() (map[string]bool, error) {
	scopes := make(map[string]bool, len(b.Scopes))
	for _, s := range b.Scopes {
		scopes[s.ScopeID] = true
	}
	type pair struct{ scope, source string }
	seen := make(map[pair]bool, len(b.Observations))
	observed := make(map[string]bool, len(b.Scopes))
	for _, o := range b.Observations {
		if err := o.Validate(); err != nil {
			return nil, err
		}
		key := pair{o.ScopeID, o.EventSource}
		if !scopes[o.ScopeID] || seen[key] {
			return nil, fmt.Errorf("unknown scope or duplicate observation")
		}
		seen[key], observed[o.ScopeID] = true, true
	}

	return observed, nil
}

func (b Bundle) validateGaps() (bool, error) {
	hasAttributionGap := false
	seenGaps := make(map[GapCode]bool, len(b.Gaps))
	for _, g := range b.Gaps {
		if err := g.Validate(); err != nil {
			return false, err
		}
		if seenGaps[g.Code] {
			return false, fmt.Errorf("duplicate gap")
		}
		seenGaps[g.Code] = true
		if g.Code == UnresolvedScope || g.Code == AmbiguousScope || g.Code == ScopeMetadataUnavailable {
			hasAttributionGap = true
		}
	}

	return hasAttributionGap, nil
}
