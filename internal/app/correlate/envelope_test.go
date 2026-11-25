package correlate

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/evidence"
)

func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func envelopeFixture() Capture {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return Capture{Version: "runtime-capture/v1", CaptureID: "capture", HostID: "host", BootID: "boot", Window: evidence.ObservationWindow{From: at, Until: at}, Containers: []Container{}, Events: []Event{{Kind: ProcessExec, At: at, Source: "TETRAGON", ExecID: "exec"}}, Diagnostics: []Diagnostic{}, Gaps: []evidence.Gap{}}
}

func TestEnvelopeCanonicalByteBoundary(t *testing.T) {
	c := envelopeFixture()
	c.Events[0].Binary = "<>&中\u2028"
	raw := jsonBytes(t, c)
	for _, delta := range []int{-1, 0, 1} {
		_, err := DecodeCapture(raw, int64(len(raw)+delta))
		if (err == nil) != (delta >= 0) {
			t.Fatalf("delta=%d: %v", delta, err)
		}
	}
	compact := bytes.ReplaceAll(raw, []byte(`\u003c`), []byte(`<`))
	if _, err := DecodeCapture(compact, int64(len(compact))); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("unaccounted escaping: %v", err)
	}
	if _, err := DecodeCapture(compact, int64(len(raw))); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCapture(raw, MaxCaptureBytes+1); err == nil {
		t.Fatal("oversized reader configuration accepted")
	}
}

func TestQuotedSizeMatchesGoEncoder(t *testing.T) {
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	for _, s := range []string{"", string(all), "中😀�\u2028\u2029<>&\"\\\n\x00", "\xff\xfe", strings.Repeat("<", 1000)} {
		if got, want := quotedSize(s), int64(len(jsonBytes(t, s))); got != want {
			t.Fatalf("string size=%d want=%d", got, want)
		}
	}
}

func TestEnvelopeScopeWeightTracksEpochGrowth(t *testing.T) {
	b, err := NewCaptureBudget(strings.Repeat("h", 128), strings.Repeat("b", 128), MaxCaptureBytes, CaptureReserveBytes)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	o := Container{ID: strings.Repeat("a", 64), At: at, StartedAt: &at}
	for _, role := range []string{"", "build", "<>&中\u2028", "x", "<>&中\u2028"} {
		o.RawRole = role
		previous := b.scopes
		if err := b.Add(o); err != nil {
			t.Fatal(err)
		}
		s := build.ExecutionScope{ScopeID: strings.Repeat("s", 70), HostID: b.host, BootID: b.boot, Container: build.ContainerIdentity{Runtime: "DOCKER", CanonicalID: o.ID}, Role: build.RolePredefined, RawRole: role, StartedAt: at, EndedAt: &at}
		n := uint64(math.MaxUint64)
		obs := evidence.ScopeObservation{ScopeID: s.ScopeID, EventSource: "TETRAGON", EventCount: &n}
		want := max(previous, int64(len(jsonBytes(t, s))+len(jsonBytes(t, obs))+2))
		if b.scopes != want || len(b.epochs) != 1 {
			t.Fatalf("weight=%d want=%d epochs=%d", b.scopes, want, len(b.epochs))
		}
	}
	previous := b.scopes
	next := at.Add(-time.Second)
	o.StartedAt = &next
	if err := b.Add(o); err != nil || len(b.epochs) != 2 || b.scopes <= previous {
		t.Fatalf("second epoch not charged: %v", err)
	}
}

func TestEnvelopeScopeAndRecordBoundaryAtomicity(t *testing.T) {
	c := envelopeFixture()
	b, _ := NewCaptureBudget(c.HostID, c.BootID, MaxCaptureBytes, 0)
	b.records = MaxCaptureRecords - 1
	if err := b.Add(c.Events[0]); err != nil {
		t.Fatal(err)
	}
	used := b.bytes.used
	if err := b.Add(c.Events[0]); !errors.Is(err, ErrEnvelope) || b.bytes.used != used || b.records != MaxCaptureRecords {
		t.Fatal("failed record admission changed state")
	}
	b, _ = NewCaptureBudget(c.HostID, c.BootID, MaxCaptureBytes, 0)
	b.diagnostics = MaxDiagnosticRecords - 1
	if err := b.Add(Diagnostic{Code: "D", Count: 1}); err != nil {
		t.Fatal(err)
	}
	if err := b.Add(Diagnostic{Code: "D", Count: 1}); !errors.Is(err, ErrEnvelope) {
		t.Fatal("diagnostic ceiling ignored")
	}
	for _, delta := range []int64{-1, 0, 1} {
		b, _ = NewCaptureBudget(c.HostID, c.BootID, MaxCaptureBytes, 0)
		o := Container{ID: strings.Repeat("a", 64), At: c.Window.From, StartedAt: &c.Window.From, RawRole: "r"}
		weight := int64(336+len(c.HostID)+len(c.BootID)+148+12) + quotedSize(o.RawRole)
		b.scopes = ScopeBudgetBytes - weight + delta
		before := b.scopes
		err := b.Add(o)
		if (err == nil) != (delta <= 0) {
			t.Fatalf("scope delta=%d: %v", delta, err)
		}
		if delta > 0 && (b.scopes != before || len(b.epochs) != 0 || b.bytes.used != 0) {
			t.Fatal("failed scope reservation changed state")
		}
	}
}

func TestEnvelopeCheckedByteArithmetic(t *testing.T) {
	c := byteCounter{used: math.MaxInt64 - 1, limit: math.MaxInt64}
	if n, err := c.Write([]byte("x")); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, ErrEnvelope) || c.used != math.MaxInt64 {
		t.Fatal("counter overflow")
	}
	for _, n := range []int64{-1, 0, MaxCaptureBytes + 1, math.MaxInt64} {
		if _, err := NewCaptureBudget("host", "boot", n, 0); err == nil {
			t.Fatalf("invalid limit %d", n)
		}
	}
}

func TestEnvelopeAdmissionDoesNotResolveUncertainEpochs(t *testing.T) {
	for _, mode := range []string{"conflicting_same_epoch", "missing_starts", "distinct_unassociated_epochs"} {
		t.Run(mode, func(t *testing.T) {
			c := envelopeFixture()
			id := strings.Repeat("a", 64)
			c.Events[0].ContainerID = id[:16]
			c.Containers = []Container{{ID: id, At: c.Window.From, StartedAt: &c.Window.From, JobID: "12", ProjectID: "6", RawRole: strings.Repeat("r", 600<<10)}}
			other := c.Containers[0]
			switch mode {
			case "conflicting_same_epoch":
				other.RawRole = strings.Repeat("s", 500<<10)
			case "missing_starts":
				c.Containers[0].StartedAt, other.StartedAt = nil, nil
			case "distinct_unassociated_epochs":
				next := c.Window.From.Add(time.Second)
				other.StartedAt = &next
				c.Containers[0].ProjectID, other.ProjectID = "99", "99"
			}
			c.Containers = append(c.Containers, other)
			r, err := Resolve(c, []build.Context{target("12")})
			if mode == "distinct_unassociated_epochs" {
				if !errors.Is(err, ErrEnvelope) {
					t.Fatalf("unassociated epochs bypassed reservation: %v", err)
				}
				return
			}
			if err != nil || len(r.Scopes) != 0 || len(r.Events) != 1 || len(r.Gaps) == 0 {
				t.Fatalf("uncertainty changed: scopes=%d events=%d err=%v", len(r.Scopes), len(r.Events), err)
			}
			if mode == "conflicting_same_epoch" && r.Events[0].Resolution != "AMBIGUOUS" {
				t.Fatalf("conflict resolved: %s", r.Events[0].Resolution)
			}
		})
	}
}

func TestTargetEnvelopeExactBoundaries(t *testing.T) {
	c := target("12")
	c.Source.Ref = ""
	base := len(jsonBytes(t, c))
	c.Source.Ref = strings.Repeat("r", int(MaxContextBytes)-base-len(`,"ref":""`))
	if n := len(jsonBytes(t, c)); n != int(MaxContextBytes) {
		t.Fatalf("fixture=%d", n)
	}
	var b TargetBudget
	for range int(MaxTargetBytes / MaxContextBytes) {
		if err := b.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Add(c); !errors.Is(err, ErrEnvelope) || b.used != MaxTargetBytes {
		t.Fatal("aggregate overflow")
	}
	for _, delta := range []int{-1, 0, 1} {
		v := c
		source := *c.Source
		v.Source = &source
		v.Source.Ref += strings.Repeat("x", max(0, delta))
		if delta < 0 {
			v.Source.Ref = v.Source.Ref[:len(v.Source.Ref)-1]
		}
		var single TargetBudget
		if err := single.Add(v); (err == nil) != (delta <= 0) {
			t.Fatalf("context delta=%d: %v", delta, err)
		}
	}
	c = target("12")
	c.Identity = build.Identity{Provider: build.GitLab, Instance: "http://a", ProjectID: "1", JobID: ""}
	fixed := len(jsonBytes(t, c.Identity))
	for _, delta := range []int{-1, 0, 1} {
		c.Identity.JobID = strings.Repeat("1", int(MaxIdentityBytes)-fixed+delta)
		var one TargetBudget
		if err := one.Add(c); (err == nil) != (delta <= 0) {
			t.Fatalf("identity delta=%d: %v", delta, err)
		}
	}
}

func TestEnvelopeOutputProofAgainstGoEncoding(t *testing.T) {
	identity := build.Identity{Provider: build.GitLab, Instance: "http://a", ProjectID: "1", JobID: ""}
	identity.JobID = strings.Repeat("1", int(MaxIdentityBytes)-len(jsonBytes(t, identity)))
	if identity.Validate() != nil || len(jsonBytes(t, identity)) != int(MaxIdentityBytes) {
		t.Fatal("invalid maximal identity fixture")
	}
	row := AttributedEvent{Event: envelopeFixture().Events[0], Resolution: "MATCHED", ScopeID: strings.Repeat("s", 70), JobID: identity.JobID}
	if overhead := len(jsonBytes(t, row)) - len(jsonBytes(t, row.Event)); overhead != 1130 {
		t.Fatalf("event wrapper changed: %d", overhead)
	}
	scope := Scope{Build: identity}
	if overhead := len(jsonBytes(t, scope)) - len(jsonBytes(t, scope.Build)) - len(jsonBytes(t, scope.Execution)); overhead != 23 {
		t.Fatalf("scope wrapper changed: %d", overhead)
	}
	upper := MaxCaptureBytes + 1131*int64(MaxCaptureRecords) + 19*int64(MaxDiagnosticRecords) + ScopeBudgetBytes + 4096
	if upper != 1055509184 || upper > MaxEvidenceBytes {
		t.Fatalf("proof no longer fits storage: %d", upper)
	}
	// Compare the streaming sizing path independently with legacy Marshal.
	for _, value := range []any{row, scope, envelopeFixture(), identity, Diagnostic{Code: "<>&\u2028", Count: math.MaxUint64}} {
		n, err := encodedSize(value, MaxCaptureBytes)
		if err != nil || n != int64(len(jsonBytes(t, value))) {
			t.Fatalf("encoder mismatch: %T %d %v", value, n, err)
		}
	}
}

func TestEnvelopeFixedReservationsAgainstGoEncoding(t *testing.T) {
	at := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	c := envelopeFixture()
	c.CaptureID, c.HostID, c.BootID = strings.Repeat("i", 128), strings.Repeat("h", 128), strings.Repeat("b", 128)
	c.Window = evidence.ObservationWindow{From: at, Until: at}
	c.Events = []Event{}
	c.Interrupted, c.Dropped = true, math.MaxUint64
	for _, code := range []evidence.GapCode{evidence.TruncatedRecord, evidence.UnresolvedScope, evidence.AmbiguousScope, evidence.ScopeMetadataUnavailable, evidence.ObservationInterrupted} {
		c.Gaps = append(c.Gaps, evidence.Gap{Code: code})
	}
	for _, code := range []string{"CAPTURE_QUEUE_DISCARDED", "DOCKER_STREAM_ENDED", "TETRAGON_STREAM_ENDED", "CAPTURE_LIMIT", "DOCKER_RECORD_ERROR", "TETRAGON_RECORD_ERROR", "INSPECT_UNAVAILABLE", "INVENTORY_UNAVAILABLE", "NO_TELEMETRY_WITNESS"} {
		c.Diagnostics = append(c.Diagnostics, Diagnostic{Code: code, Count: math.MaxUint64})
	}
	if int64(len(jsonBytes(t, c))) > CaptureReserveBytes {
		t.Fatal("terminal reserve no longer fits")
	}
	ref := artifact.ObjectReference{ID: strings.Repeat("i", 128), Digest: artifact.Digest{Algorithm: "sha256", Value: strings.Repeat("a", 64)}}
	m := v1.EvidenceManifest{ManifestHeader: v1.ManifestHeader{SchemaVersion: v1.SchemaVersion, Kind: v1.KindEvidenceManifest, ManifestID: strings.Repeat("i", 128), WorkflowID: strings.Repeat("w", 128), RecordedAt: at, State: v1.Failed, Failure: &v1.Failure{Code: v1.InputUnavailable}}, Payload: &evidence.Bundle{Reference: ref, Scopes: []build.ExecutionScope{}, Observations: []evidence.ScopeObservation{}, ObservationWindow: &c.Window, Coverage: evidence.ObservationCoverage{Status: evidence.CoverageUnknown}, EventLoss: evidence.EventLoss{Status: evidence.LossReported, Count: &c.Dropped, Source: strings.Repeat("s", 128)}, Gaps: c.Gaps}}
	if fixed := len(jsonBytes(t, m)) - len(jsonBytes(t, m.Build)); fixed > 2048 {
		t.Fatalf("manifest fixed reserve exceeded: %d", fixed)
	}
	// Exercise the complete generated vocabulary at maximum counter width.
	r := Result{Scopes: []Scope{}, Events: []AttributedEvent{}, Gaps: c.Gaps, Diagnostics: []Diagnostic{}}
	for _, code := range []string{"AMBIGUOUS", "BUILD_LABEL_MISMATCH", "BUILD_LABEL_MISSING", "CONTRADICTORY_SCOPE_METADATA", "JOB_ASSOCIATION_UNRESOLVED", "LOCAL_CAPTURE_DROPPED_RECORDS", "MATCHED", "NO_CONTAINER_ID", "PROCESS_BINDING_UNRESOLVED", "PROCESS_EXEC_UNOBSERVED_OR_AMBIGUOUS", "RUNTIME_START_UNAVAILABLE", "SOURCE_LOSS_REPORT", "THROTTLE_OBSERVED", "UNRESOLVED", "UNSUPPORTED_EVENT_KIND"} {
		r.Diagnostics = append(r.Diagnostics, Diagnostic{Code: code, Count: math.MaxUint64})
	}
	object := struct {
		Version    string                   `json:"version"`
		CaptureRef artifact.ObjectReference `json:"capture_ref"`
		Result     Result                   `json:"result"`
	}{"runtime-evidence/v1", ref, r}
	if fixed := len(jsonBytes(t, object)); fixed > 4096 {
		t.Fatalf("evidence fixed reserve exceeded: %d", fixed)
	}
}
