package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/app/correlate"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

// Produce resolves an already committed capture using explicit fetched targets.
// Capture source and output sink are different configured namespaces/identities.
// The output object retains unresolved events and original capture reference.
func Produce(ctx context.Context, source acquire.Source, sink acquire.Sink, captureRef artifact.ObjectReference, targets []build.Context, job build.Identity, workflow, id string, at time.Time, maxCapture int64) (artifact.ObjectReference, error) {
	var zero artifact.ObjectReference
	if job.Validate() != nil || artifact.ValidateID(id) != nil || artifact.ValidateID(workflow) != nil || artifact.ValidateID(id+".evidence") != nil || build.ValidateTime(at) != nil {
		return zero, errors.New("invalid evidence production request")
	}
	var selected *build.Context
	for i := range targets {
		if targets[i].Identity == job {
			selected = &targets[i]
		}
	}
	if selected == nil {
		return zero, errors.New("target job is not supplied")
	}
	if selected.ValidateComplete() != nil {
		m := v1.EvidenceManifest{ManifestHeader: v1.ManifestHeader{SchemaVersion: v1.SchemaVersion, Kind: v1.KindEvidenceManifest, ManifestID: id, WorkflowID: workflow, Build: *selected, RecordedAt: at, State: v1.Failed, Failure: &v1.Failure{Code: v1.InputUnavailable}}}
		if e := m.Validate(); e != nil {
			return zero, e
		}
		b, e := json.Marshal(m)
		if e != nil {
			return zero, e
		}
		return sink.Put(ctx, id, bytes.NewReader(b), 1<<20)
	}
	b, err := source.Get(ctx, captureRef, maxCapture)
	if err != nil {
		return zero, err
	}
	c, err := correlate.DecodeCapture(b, maxCapture)
	if err != nil {
		return zero, err
	}
	r, err := correlate.Resolve(c, targets)
	if err != nil {
		return zero, err
	}
	object := struct {
		Version    string                   `json:"version"`
		CaptureRef artifact.ObjectReference `json:"capture_ref"`
		Result     correlate.Result         `json:"result"`
	}{"runtime-evidence/v1", captureRef, r}
	encoded, err := json.Marshal(object)
	if err != nil {
		return zero, err
	}
	ref, err := sink.Put(ctx, id+".evidence", bytes.NewReader(encoded), maxCapture+1<<20)
	if err != nil {
		return zero, err
	}
	p := &evidence.Bundle{Reference: ref, Scopes: []build.ExecutionScope{}, Observations: []evidence.ScopeObservation{}, ObservationWindow: &c.Window, Coverage: evidence.ObservationCoverage{Status: evidence.CoverageUnknown}, EventLoss: evidence.EventLoss{Status: evidence.LossUnknown}, Gaps: append([]evidence.Gap{}, r.Gaps...)}
	if c.Dropped > 0 {
		p.EventLoss = evidence.EventLoss{Status: evidence.LossReported, Count: &c.Dropped, Source: "LOCAL_CAPTURE_LIMIT"}
	}
	for _, e := range c.Events {
		if e.Kind == correlate.SourceLoss && e.LossCount != nil && *e.LossCount > 0 {
			p.EventLoss = evidence.EventLoss{Status: evidence.LossReported, Source: "CAPTURE_REPORTS"}
		}
	}
	counts := map[string]uint64{}
	for _, e := range r.Events {
		if e.Resolution == "MATCHED" {
			counts[e.ScopeID]++
		}
	}
	for _, s := range r.Scopes {
		if s.Build == job {
			p.Scopes = append(p.Scopes, s.Execution)
			if n := counts[s.Execution.ScopeID]; n > 0 {
				p.Observations = append(p.Observations, evidence.ScopeObservation{ScopeID: s.Execution.ScopeID, EventSource: "TETRAGON", EventCount: &n})
			}
		}
	}
	if len(p.Scopes) == 0 || len(p.Observations) == 0 {
		found := false
		for _, g := range p.Gaps {
			if g.Code == evidence.UnresolvedScope {
				found = true
			}
		}
		if !found {
			p.Gaps = append(p.Gaps, evidence.Gap{Code: evidence.UnresolvedScope})
		}
	}
	m := v1.EvidenceManifest{ManifestHeader: v1.ManifestHeader{SchemaVersion: v1.SchemaVersion, Kind: v1.KindEvidenceManifest, ManifestID: id, WorkflowID: workflow, Build: *selected, RecordedAt: at, State: v1.Finalized}, Payload: p}
	if c.Interrupted {
		m.State = v1.Failed
		m.Failure = &v1.Failure{Code: v1.InputUnavailable}
	}
	if err = m.Validate(); err != nil {
		return zero, err
	}
	encoded, err = json.Marshal(m)
	if err != nil {
		return zero, err
	}
	if _, err = v1.DecodeEvidenceManifest(encoded); err != nil {
		return zero, err
	}
	return sink.Put(ctx, id, bytes.NewReader(encoded), 1<<20)
}
