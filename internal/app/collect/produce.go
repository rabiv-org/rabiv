package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
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
	if job.Validate() != nil || artifact.ValidateID(id) != nil || artifact.ValidateID(workflow) != nil || artifact.ValidateID(id+".evidence") != nil || build.ValidateTime(at) != nil || maxCapture <= 0 || maxCapture > correlate.MaxCaptureBytes {
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
		var budget correlate.TargetBudget
		for _, target := range targets {
			if err := budget.Add(target); err != nil {
				return zero, err
			}
		}
		m := v1.EvidenceManifest{ManifestHeader: v1.ManifestHeader{SchemaVersion: v1.SchemaVersion, Kind: v1.KindEvidenceManifest, ManifestID: id, WorkflowID: workflow, Build: *selected, RecordedAt: at, State: v1.Failed, Failure: &v1.Failure{Code: v1.InputUnavailable}}}
		if e := m.Validate(); e != nil {
			return zero, e
		}
		b, e := json.Marshal(m)
		if e != nil {
			return zero, e
		}
		return sink.Put(ctx, id, bytes.NewReader(b), correlate.MaxManifestBytes)
	}
	b, err := source.Get(ctx, captureRef, maxCapture)
	if err != nil {
		return zero, err
	}
	c, r, err := correlate.DecodeAndResolve(b, maxCapture, targets)
	if err != nil {
		return zero, err
	}
	ref, err := putEvidence(ctx, sink, id+".evidence", captureRef, r)
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
	encoded, err := json.Marshal(m)
	if err != nil {
		return zero, err
	}
	if _, err = v1.DecodeEvidenceManifest(encoded); err != nil {
		return zero, err
	}
	return sink.Put(ctx, id, bytes.NewReader(encoded), correlate.MaxManifestBytes)
}

// Correlation adds per-record fields and may repeat build/scope metadata, so
// capture size is not a reliable output limit. A separate object budget counts
// actual encoded bytes at Put, without buffering the entire expanded JSON.
func putEvidence(ctx context.Context, sink acquire.Sink, id string, ref artifact.ObjectReference, r correlate.Result) (artifact.ObjectReference, error) {
	return putObject(ctx, sink, id, correlate.MaxEvidenceBytes, func(w io.Writer) error { return encodeEvidence(ctx, w, ref, r) })
}

func putObject(ctx context.Context, sink acquire.Sink, id string, limit int64, encode func(io.Writer) error) (artifact.ObjectReference, error) {
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		w := bufio.NewWriter(pw)
		err := encode(w)
		if err == nil {
			err = w.Flush()
		}
		_ = pw.CloseWithError(err)
	}()
	result, err := sink.Put(ctx, id, pr, limit)
	_ = pr.Close()
	<-done
	return result, err
}

func encodeEvidence(ctx context.Context, w io.Writer, ref artifact.ObjectReference, r correlate.Result) error {
	if _, err := io.WriteString(w, `{"version":"runtime-evidence/v1","capture_ref":`); err != nil {
		return err
	}
	if err := writeJSON(w, ref); err != nil {
		return err
	}
	if err := encodeRows(ctx, w, `,"result":{"scopes":[`, r.Scopes); err != nil {
		return err
	}
	if err := encodeRows(ctx, w, `],"events":[`, r.Events); err != nil {
		return err
	}
	if err := encodeRows(ctx, w, `],"gaps":[`, r.Gaps); err != nil {
		return err
	}
	if err := encodeRows(ctx, w, `],"diagnostics":[`, r.Diagnostics); err != nil {
		return err
	}
	_, err := io.WriteString(w, `]}}`)
	return err
}

func encodeRows[T any](ctx context.Context, w io.Writer, prefix string, rows []T) error {
	if _, err := io.WriteString(w, prefix); err != nil {
		return err
	}
	for i, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := writeJSON(w, row); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(w io.Writer, value any) error {
	return jsonv2.MarshalWrite(w, value, json.DefaultOptionsV1())
}
