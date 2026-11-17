package v1_test

import (
	"reflect"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
)

func workflow() v1.WorkflowState {
	return v1.WorkflowState{SchemaVersion: v1.SchemaVersion, Kind: v1.KindWorkflowState, WorkflowID: "wf-1", Build: buildContext(), CreatedAt: testTime(), UpdatedAt: testTime(), InputDeadline: testTime().Add(10 * time.Minute), State: v1.Open, EvidenceInput: v1.InputSnapshot{State: v1.Pending}, ArtifactInput: v1.InputSnapshot{State: v1.Pending}}
}

func TestIndependentInputsAndReadiness(t *testing.T) {
	for _, tc := range []struct {
		evidence, artifacts v1.ProducerState
		ready               bool
	}{
		{v1.Pending, v1.Pending, false}, {v1.Finalized, v1.Pending, false}, {v1.Pending, v1.Finalized, false}, {v1.Finalized, v1.Finalized, true},
		{v1.Failed, v1.Pending, true}, {v1.Pending, v1.Failed, true}, {v1.Failed, v1.Finalized, true}, {v1.Failed, v1.Failed, true},
	} {
		t.Run(string(tc.evidence)+"/"+string(tc.artifacts), func(t *testing.T) {
			w := workflow()
			w.EvidenceInput.State, w.ArtifactInput.State = tc.evidence, tc.artifacts
			if tc.evidence == v1.Finalized {
				w.EvidenceInput.ManifestRef = objectRef("em-1", "e")
			}
			if tc.artifacts == v1.Finalized {
				w.ArtifactInput.ManifestRef = objectRef("am-1", "f")
			}
			if tc.evidence == v1.Failed {
				w.EvidenceInput.Failure = &v1.InputFailure{Code: v1.ProducerError, Source: v1.VerifierObservation}
			}
			if tc.artifacts == v1.Failed {
				w.ArtifactInput.Failure = &v1.InputFailure{Code: v1.ProducerError, Source: v1.ProducerReport}
			}
			if err := w.Validate(); err != nil {
				t.Fatal(err)
			}
			before := w.State
			if ready := w.RequiresEvaluationAt(testTime()); ready != tc.ready {
				t.Fatalf("ready=%v want=%v", ready, tc.ready)
			}
			if w.State != before {
				t.Fatal("readiness mutated persistent state")
			}
			decoded, err := v1.DecodeWorkflowState(marshal(t, w))
			if err != nil || !reflect.DeepEqual(w, decoded) {
				t.Fatalf("round-trip: %v", err)
			}
		})
	}
	w := workflow()
	if !w.RequiresEvaluationAt(w.InputDeadline) {
		t.Fatal("deadline must permit evaluation with missing inputs")
	}
	if w.EvidenceInput.State != v1.Pending {
		t.Fatal("deadline fabricated producer failure")
	}
	if w.RequiresEvaluationAt(time.Time{}) {
		t.Fatal("invalid clock accepted")
	}
	w.State, w.DecisionRef = v1.Decided, objectRef("decision-1", "a")
	if w.RequiresEvaluationAt(w.InputDeadline.Add(time.Hour)) {
		t.Fatal("decided workflow reopened")
	}
}

func TestWorkflowInvalidSnapshots(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*v1.WorkflowState)
	}{
		{"version", func(w *v1.WorkflowState) { w.SchemaVersion = "v2" }},
		{"kind", func(w *v1.WorkflowState) { w.Kind = v1.KindArtifactManifest }},
		{"workflow identity", func(w *v1.WorkflowState) { w.WorkflowID = "" }},
		{"time missing", func(w *v1.WorkflowState) { w.CreatedAt = time.Time{} }},
		{"time reversed", func(w *v1.WorkflowState) { w.UpdatedAt = w.CreatedAt.Add(-time.Second) }},
		{"invalid deadline", func(w *v1.WorkflowState) { w.InputDeadline = w.CreatedAt }},
		{"unknown input state", func(w *v1.WorkflowState) { w.EvidenceInput.State = "" }},
		{"finalized missing reference", func(w *v1.WorkflowState) { w.EvidenceInput.State = v1.Finalized }},
		{"failed missing metadata", func(w *v1.WorkflowState) { w.ArtifactInput.State = v1.Failed }},
		{"failure without failed", func(w *v1.WorkflowState) {
			w.EvidenceInput.Failure = &v1.InputFailure{Code: v1.ProducerError, Source: v1.ProducerReport}
		}},
		{"invalid failure source", func(w *v1.WorkflowState) {
			w.ArtifactInput.State = v1.Failed
			w.ArtifactInput.Failure = &v1.InputFailure{Code: v1.ProducerError, Source: "OTHER"}
		}},
		{"invalid failure code", func(w *v1.WorkflowState) {
			w.ArtifactInput.State = v1.Failed
			w.ArtifactInput.Failure = &v1.InputFailure{Code: "OTHER", Source: v1.ProducerReport}
		}},
		{"invalid manifest reference", func(w *v1.WorkflowState) { w.EvidenceInput.ManifestRef = objectRef("../manifest", "e") }},
		{"open decision reference", func(w *v1.WorkflowState) { w.DecisionRef = objectRef("decision-1", "a") }},
		{"decided without reference", func(w *v1.WorkflowState) { w.State = v1.Decided }},
		{"no persistent ready", func(w *v1.WorkflowState) { w.State = "READY_FOR_VERIFICATION" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := workflow()
			tc.change(&w)
			if w.Validate() == nil {
				t.Fatal("invalid workflow accepted")
			}
			if w.RequiresEvaluationAt(w.InputDeadline) {
				t.Fatal("invalid workflow became ready")
			}
		})
	}
}
