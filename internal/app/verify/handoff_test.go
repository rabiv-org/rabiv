package verify_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/verify"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/decision"
)

func request() verify.DiagnosticRequest {
	return verify.DiagnosticRequest{DecisionID: "diag-1", WorkflowID: "wf-1", Build: build.Identity{Provider: build.GitLab, Instance: "https://gitlab.example", ProjectID: "1", JobID: "2"}}
}

func TestDiagnosticContractCompatibility(t *testing.T) {
	now := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	r, err := verify.NewDiagnostic(request(), now)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := v1.DecodeDecisionRecord(data)
	if err != nil || !reflect.DeepEqual(decoded, r) {
		t.Fatalf("contract round-trip: %v", err)
	}
	if r.Decision.Verdict != decision.Indeterminate || r.Decision.ExpiresAt != nil || r.Decision.SubjectGroup != nil || r.Decision.Baseline != nil || r.Decision.ProjectProfile != nil || r.Decision.Build.Source != nil || r.Decision.Build.PipelineID != "" {
		t.Fatal("diagnostic invented evaluation inputs")
	}
	for _, tc := range []struct {
		name   string
		change func(*verify.DiagnosticRequest)
		clock  time.Time
	}{
		{"decision ID", func(r *verify.DiagnosticRequest) { r.DecisionID = "" }, now},
		{"workflow ID", func(r *verify.DiagnosticRequest) { r.WorkflowID = "" }, now},
		{"build ID", func(r *verify.DiagnosticRequest) { r.Build.JobID = "" }, now},
		{"zero time", func(*verify.DiagnosticRequest) {}, time.Time{}},
		{"non UTC", func(*verify.DiagnosticRequest) {}, now.In(time.FixedZone("offset", 3600))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request()
			tc.change(&req)
			if _, err := verify.NewDiagnostic(req, tc.clock); err == nil {
				t.Fatal("invalid diagnostic accepted")
			}
		})
	}
}

type sink struct {
	calls int
	fail  error
}

func (s *sink) Put(context.Context, v1.DecisionRecord) (artifact.ObjectReference, error) {
	s.calls++
	return artifact.ObjectReference{}, s.fail
}

func TestHandoffFailurePaths(t *testing.T) {
	r, err := verify.NewDiagnostic(request(), time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("commit uncertain")
	s := &sink{fail: want}
	if _, err := verify.Handoff(context.Background(), s, r); !errors.Is(err, want) || s.calls != 1 {
		t.Fatal("sink error hidden", err)
	}
	r.Decision.Reasons = []decision.ReasonCode{decision.RequiredChecksPassed}
	if _, err := verify.Handoff(context.Background(), s, r); err == nil || s.calls != 1 {
		t.Fatal("invalid record reached sink")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verify.Handoff(ctx, s, r); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r, err = verify.NewDiagnostic(request(), time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify.Handoff(context.Background(), nil, r); err == nil {
		t.Fatal("missing sink accepted")
	}
}
