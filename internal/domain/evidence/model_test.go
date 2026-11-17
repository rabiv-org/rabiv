package evidence_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

func u64(n uint64) *uint64 { return &n }
func bundle() evidence.Bundle {
	start := time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC)
	return evidence.Bundle{
		Reference:         artifact.ObjectReference{ID: "evidence-1", Digest: artifact.Digest{Algorithm: "sha256", Value: strings.Repeat("a", 64)}},
		Scopes:            []build.ExecutionScope{{ScopeID: "scope-1", HostID: "host-1", BootID: "boot-1", Container: build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: strings.Repeat("a", 64)}, Role: build.RoleBuild, StartedAt: start}},
		Observations:      []evidence.ScopeObservation{{ScopeID: "scope-1", EventSource: "TETRAGON_PROCESS_EXEC", EventCount: u64(0)}},
		ObservationWindow: &evidence.ObservationWindow{From: start, Until: start.Add(time.Minute)},
		Coverage:          evidence.ObservationCoverage{Status: evidence.CoverageClaimedComplete},
		EventLoss:         evidence.EventLoss{Status: evidence.NoLossReported, Count: u64(0), Source: "COLLECTOR"},
		Gaps:              []evidence.Gap{},
	}
}

func TestCoverageWindowAndLoss(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*evidence.Bundle)
		valid  bool
	}{
		{"reported complete claim", func(*evidence.Bundle) {}, true},
		{"known window unknown coverage", func(b *evidence.Bundle) {
			b.Coverage.Status = evidence.CoverageUnknown
			b.EventLoss = evidence.EventLoss{Status: evidence.LossUnknown}
		}, true},
		{"known window with loss", func(b *evidence.Bundle) {
			b.Coverage.Status = evidence.CoveragePartial
			b.EventLoss = evidence.EventLoss{Status: evidence.LossReported, Count: u64(1), Source: "DECODER"}
			b.Gaps = []evidence.Gap{{Code: evidence.TruncatedRecord}}
		}, true},
		{"loss count unknown", func(b *evidence.Bundle) {
			b.Coverage.Status = evidence.CoveragePartial
			b.EventLoss = evidence.EventLoss{Status: evidence.LossReported, Source: "COLLECTOR"}
		}, true},
		{"unknown count is not zero", func(b *evidence.Bundle) {
			b.Coverage.Status = evidence.CoverageUnknown
			b.EventLoss = evidence.EventLoss{Status: evidence.LossUnknown, Count: u64(0)}
		}, false},
		{"zero report requires counter", func(b *evidence.Bundle) { b.EventLoss.Count = nil }, false},
		{"zero report requires source", func(b *evidence.Bundle) { b.EventLoss.Source = "" }, false},
		{"positive loss cannot be zero", func(b *evidence.Bundle) {
			b.Coverage.Status = evidence.CoveragePartial
			b.EventLoss.Status = evidence.LossReported
		}, false},
		{"complete conflicts with loss", func(b *evidence.Bundle) {
			b.EventLoss = evidence.EventLoss{Status: evidence.LossReported, Source: "COLLECTOR"}
		}, false},
		{"complete conflicts with unknown loss", func(b *evidence.Bundle) { b.EventLoss = evidence.EventLoss{Status: evidence.LossUnknown} }, false},
		{"complete conflicts with gap", func(b *evidence.Bundle) { b.Gaps = []evidence.Gap{{Code: evidence.ObservationInterrupted}} }, false},
		{"reversed window", func(b *evidence.Bundle) { b.ObservationWindow.Until = b.ObservationWindow.From.Add(-time.Second) }, false},
		{"missing window allowed", func(b *evidence.Bundle) { b.ObservationWindow = nil }, true},
		{"invalid coverage", func(b *evidence.Bundle) { b.Coverage.Status = "" }, false},
		{"invalid loss", func(b *evidence.Bundle) { b.EventLoss.Status = "OTHER" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bundle()
			tc.change(&b)
			before := b.Coverage.Status
			if err := b.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if b.Coverage.Status != before {
				t.Fatal("validation inferred coverage")
			}
		})
	}
}

func TestEvidenceReferencesAndScopes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*evidence.Bundle)
		valid  bool
	}{
		{"missing evidence reference", func(b *evidence.Bundle) { b.Reference.ID = "" }, false},
		{"dangling scope", func(b *evidence.Bundle) { b.Observations[0].ScopeID = "unknown" }, false},
		{"duplicate source scope", func(b *evidence.Bundle) { b.Observations = append(b.Observations, b.Observations[0]) }, false},
		{"missing event source", func(b *evidence.Bundle) { b.Observations[0].EventSource = "" }, false},
		{"invalid gap", func(b *evidence.Bundle) {
			b.Coverage.Status = evidence.CoveragePartial
			b.Gaps = []evidence.Gap{{Code: "OTHER"}}
		}, false},
		{"duplicate gap", func(b *evidence.Bundle) {
			b.Coverage.Status = evidence.CoveragePartial
			b.Gaps = []evidence.Gap{{Code: evidence.TruncatedRecord}, {Code: evidence.TruncatedRecord}}
		}, false},
		{"missing arrays", func(b *evidence.Bundle) { b.Gaps = nil }, false},
		{"unresolved attribution", func(b *evidence.Bundle) {
			b.Scopes = []build.ExecutionScope{}
			b.Observations = []evidence.ScopeObservation{}
			b.Coverage.Status = evidence.CoverageUnknown
			b.Gaps = []evidence.Gap{{Code: evidence.ScopeMetadataUnavailable}}
		}, true},
		{"no attribution gap", func(b *evidence.Bundle) {
			b.Scopes = []build.ExecutionScope{}
			b.Observations = []evidence.ScopeObservation{}
			b.Coverage.Status = evidence.CoverageUnknown
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bundle()
			tc.change(&b)
			if err := b.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
