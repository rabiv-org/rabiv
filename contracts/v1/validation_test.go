package v1_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/decision"
	"github.com/rabiv-org/rabiv/internal/domain/provenance"
)

func replaceJSON(t *testing.T, raw []byte, old, replacement string) []byte {
	t.Helper()
	if !bytes.Contains(raw, []byte(old)) {
		t.Fatalf("fixture does not contain replacement target %q", old)
	}
	return bytes.Replace(raw, []byte(old), []byte(replacement), 1)
}

func TestStrictDecoding(t *testing.T) {
	base := marshal(t, workflow())
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil}, {"malformed", []byte(`{"schema_version":`)}, {"array root", []byte(`[]`)}, {"scalar root", []byte(`true`)}, {"null root", []byte(`null`)},
		{"trailing object", append(append([]byte{}, base...), []byte(` {}`)...)},
		{"trailing malformed", append(append([]byte{}, base...), []byte(` x`)...)},
		{"unknown field", replaceJSON(t, base, `"schema_version":"v1"`, `"schema_version":"v1","future_field":1`)},
		{"unknown nested field", replaceJSON(t, base, `"job_id":"18071578854"`, `"job_id":"18071578854","future_field":1`)},
		{"duplicate root key", replaceJSON(t, base, `"schema_version":"v1"`, `"schema_version":"v1","schema_version":"v1"`)},
		{"duplicate nested key", replaceJSON(t, base, `"job_id":"18071578854"`, `"job_id":"18071578854","job_id":"18071578855"`)},
		{"escaped duplicate key", replaceJSON(t, base, `"schema_version":"v1"`, `"schema_version":"v1","\u0073chema_version":"v1"`)},
		{"uppercase field", replaceJSON(t, base, `"schema_version"`, `"Schema_version"`)},
		{"Unicode field", replaceJSON(t, base, `"state"`, `"ſtate"`)},
		{"null optional source", replaceJSON(t, base, `"pipeline_id":"3074413145"`, `"pipeline_id":null`)},
		{"numeric job ID", replaceJSON(t, base, `"job_id":"18071578854"`, `"job_id":18071578854`)},
		{"unsupported version", replaceJSON(t, base, `"schema_version":"v1"`, `"schema_version":"v2"`)},
		{"numeric version", replaceJSON(t, base, `"schema_version":"v1"`, `"schema_version":1`)},
		{"wrong kind", replaceJSON(t, base, `"kind":"WorkflowState"`, `"kind":"ArtifactManifest"`)},
		{"unknown input enum", replaceJSON(t, base, `"state":"PENDING"`, `"state":"UNKNOWN"`)},
		{"missing required state", replaceJSON(t, base, `"state":"OPEN",`, ``)},
		{"missing required input", replaceJSON(t, base, `,"evidence_input":{"state":"PENDING"}`, ``)},
		{"zero timestamp", replaceJSON(t, base, `"2026-11-16T03:00:00Z"`, `"0001-01-01T00:00:00Z"`)},
		{"non UTC timestamp", replaceJSON(t, base, `"2026-11-16T03:00:00Z"`, `"2026-11-16T10:00:00+07:00"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v1.DecodeWorkflowState(tc.raw); err == nil {
				t.Fatal("invalid input decoded")
			}
		})
	}
	if _, err := v1.DecodeWorkflowState(append(append([]byte(" \n"), base...), []byte(" \t\n")...)); err != nil {
		t.Fatal(err)
	}
	// An escaped canonical key has the same decoded identity; spelling aliases
	// with different case are rejected, not accepted through encoding/json folding.
	escaped := replaceJSON(t, base, `"schema_version"`, `"\u0073chema_version"`)
	if _, err := v1.DecodeWorkflowState(escaped); err != nil {
		t.Fatal(err)
	}
	largeID := replaceJSON(t, base, `"job_id":"18071578854"`, `"job_id":"9007199254740993"`)
	w, err := v1.DecodeWorkflowState(largeID)
	if err != nil || w.Build.Identity.JobID != "9007199254740993" {
		t.Fatal("string ID lost precision", err)
	}
}

func TestNestedStrictDecoding(t *testing.T) {
	raw := marshal(t, evidenceManifest())
	for _, tc := range []struct{ name, old, replacement string }{
		{"required array null", `"gaps":[]`, `"gaps":null`},
		{"required array missing", `,"gaps":[]`, ``},
		{"null payload", `"payload":{`, `"payload":null,"ignored_payload":{`},
		{"nested duplicate", `"status":"UNKNOWN"`, `"status":"UNKNOWN","status":"PARTIAL"`},
		{"negative count", `"event_source":"TETRAGON_PROCESS_EXEC"`, `"event_source":"TETRAGON_PROCESS_EXEC","event_count":-1`},
		{"fractional count", `"event_source":"TETRAGON_PROCESS_EXEC"`, `"event_source":"TETRAGON_PROCESS_EXEC","event_count":0.5`},
		{"overflow count", `"event_source":"TETRAGON_PROCESS_EXEC"`, `"event_source":"TETRAGON_PROCESS_EXEC","event_count":18446744073709551616`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v1.DecodeEvidenceManifest(replaceJSON(t, raw, tc.old, tc.replacement)); err == nil {
				t.Fatal("invalid nested evidence decoded")
			}
		})
	}
	maxCount := replaceJSON(t, raw, `"event_source":"TETRAGON_PROCESS_EXEC"`, `"event_source":"TETRAGON_PROCESS_EXEC","event_count":18446744073709551615`)
	got, err := v1.DecodeEvidenceManifest(maxCount)
	if err != nil || *got.Payload.Observations[0].EventCount != ^uint64(0) {
		t.Fatal("uint64 was rounded", err)
	}
	badUTF8 := bytes.Replace(marshal(t, artifactManifest()), []byte("dist/My App"), []byte{'d', 0xff}, 1)
	if _, err := v1.DecodeArtifactManifest(badUTF8); err == nil {
		t.Fatal("invalid UTF-8 was repaired instead of rejected")
	}
	for _, decode := range []func([]byte) error{
		func(b []byte) error { _, err := v1.DecodeEvidenceManifest(b); return err },
		func(b []byte) error { _, err := v1.DecodeArtifactManifest(b); return err },
		func(b []byte) error { _, err := v1.DecodeDecisionRecord(b); return err },
	} {
		if decode([]byte(`{"schema_version":"v2"}`)) == nil {
			t.Fatal("unsupported/incomplete record decoded")
		}
	}
}

func TestDecodeArtifactManifestSurrogateEscapes(t *testing.T) {
	manifest := artifactManifest()
	base := marshal(t, manifest)
	oldName := `"name":` + string(marshal(t, manifest.Payload.SubjectGroup.Subjects[0].Name))
	for _, tc := range []struct {
		name   string
		quoted string
		want   string
		reject bool
	}{
		{name: "unpaired_high_d800", quoted: `"dist/\ud800.bin"`, reject: true},
		{name: "unpaired_high_d801", quoted: `"dist/\ud801.bin"`, reject: true},
		{name: "unpaired_high_dbff", quoted: `"dist/\udbff.bin"`, reject: true},
		{name: "unpaired_high_at_string_end", quoted: `"dist/\ud800"`, reject: true},
		{name: "unpaired_low_dc00", quoted: `"dist/\udc00.bin"`, reject: true},
		{name: "unpaired_low_dfff", quoted: `"dist/\udfff.bin"`, reject: true},
		{name: "high_then_ordinary_character", quoted: `"dist/\ud800x.bin"`, reject: true},
		{name: "high_then_high", quoted: `"dist/\ud800\ud801.bin"`, reject: true},
		{name: "high_then_bmp_escape", quoted: `"dist/\ud800\u4e2d.bin"`, reject: true},
		{name: "high_then_escaped_literal_low", quoted: `"dist/\ud800\\udc00.bin"`, reject: true},
		{name: "low_then_high", quoted: `"dist/\udc00\ud800.bin"`, reject: true},
		{name: "valid_pair_then_unpaired_high", quoted: `"dist/\ud83d\ude00\ud800.bin"`, reject: true},
		{name: "valid_surrogate_pair", quoted: `"dist/\ud83d\ude00.bin"`, want: "dist/😀.bin"},
		{name: "valid_pair_uppercase_hex", quoted: `"dist/\uD83D\uDE00.bin"`, want: "dist/😀.bin"},
		{name: "valid_pair_lower_boundary", quoted: `"dist/\ud800\udc00.bin"`, want: "dist/\U00010000.bin"},
		{name: "valid_pair_upper_boundary", quoted: `"dist/\udbff\udfff.bin"`, want: "dist/\U0010ffff.bin"},
		{name: "valid_bmp_escape", quoted: `"dist/\u4e2d.bin"`, want: "dist/中.bin"},
		{name: "valid_raw_utf8", quoted: `"dist/Việt–中😀.bin"`, want: "dist/Việt–中😀.bin"},
		{name: "valid_decomposed_utf8", quoted: `"dist/é.bin"`, want: "dist/e\u0301.bin"},
		{name: "valid_escaped_replacement", quoted: `"dist/\ufffd.bin"`, want: "dist/�.bin"},
		{name: "valid_raw_replacement", quoted: `"dist/�.bin"`, want: "dist/�.bin"},
		{name: "escaped_literal_high", quoted: `"dist/\\ud800.bin"`, want: `dist/\ud800.bin`},
		{name: "escaped_literal_low", quoted: `"dist/\\udc00.bin"`, want: `dist/\udc00.bin`},
		{name: "unicode_escaped_backslash", quoted: `"dist/\u005cud800.bin"`, want: `dist/\ud800.bin`},
		{name: "escaped_quote_and_valid_pair", quoted: `"dist/quote\"-\ud83d\ude00.bin"`, want: "dist/quote\"-😀.bin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := replaceJSON(t, base, oldName, `"name":`+tc.quoted)
			decoded, err := v1.DecodeArtifactManifest(raw)
			if tc.reject {
				if err == nil {
					t.Fatalf("accepted malformed subject name %s: decoded as %q (want error)", tc.quoted, decoded.Payload.SubjectGroup.Subjects[0].Name)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid subject name %s rejected: %v", tc.quoted, err)
			}
			if got := decoded.Payload.SubjectGroup.Subjects[0].Name; got != tc.want {
				t.Fatalf("subject identity changed: got %q, want %q", got, tc.want)
			}
		})
	}
}

func boundRecords() (v1.WorkflowState, v1.EvidenceManifest, v1.ArtifactManifest, v1.DecisionRecord) {
	w := workflow()
	w.EvidenceInput = v1.InputSnapshot{State: v1.Finalized, ManifestRef: objectRef("em-1", "e")}
	w.ArtifactInput = v1.InputSnapshot{State: v1.Finalized, ManifestRef: objectRef("am-1", "f")}
	return w, evidenceManifest(), artifactManifest(), decisionRecord()
}

func TestMetadataBindings(t *testing.T) {
	w, e, a, d := boundRecords()
	if err := v1.ValidateBindings(w, &e, &a, &d); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*v1.WorkflowState, *v1.EvidenceManifest, *v1.ArtifactManifest, *v1.DecisionRecord)
	}{
		{"job mismatch", func(_ *v1.WorkflowState, e *v1.EvidenceManifest, _ *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			e.Build.Identity.JobID = "18071578855"
		}},
		{"workflow mismatch", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, a *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			a.WorkflowID = "other"
		}},
		{"manifest ID mismatch", func(_ *v1.WorkflowState, e *v1.EvidenceManifest, _ *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			e.ManifestID = "other"
		}},
		{"reference digest mismatch", func(w *v1.WorkflowState, _ *v1.EvidenceManifest, _ *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			w.EvidenceInput.ManifestRef.Digest = testDigest("a")
		}},
		{"manifest state mismatch", func(_ *v1.WorkflowState, e *v1.EvidenceManifest, _ *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			e.State = v1.Pending
		}},
		{"decision workflow mismatch", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, _ *v1.ArtifactManifest, d *v1.DecisionRecord) {
			d.Decision.WorkflowID = "other"
		}},
		{"pipeline mismatch", func(_ *v1.WorkflowState, e *v1.EvidenceManifest, _ *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			e.Build.PipelineID = "2"
		}},
		{"pairwise source mismatch", func(w *v1.WorkflowState, e *v1.EvidenceManifest, _ *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			w.Build.Source = nil
			e.Build.Source.CommitSHA = strings.Repeat("b", 40)
		}},
		{"incomplete ALLOW context", func(_ *v1.WorkflowState, e *v1.EvidenceManifest, _ *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			e.Build.PipelineID = ""
		}},
		{"different subject group", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, _ *v1.ArtifactManifest, d *v1.DecisionRecord) {
			d.Decision.SubjectGroup.ID = "other"
		}},
		{"different subject bytes", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, _ *v1.ArtifactManifest, d *v1.DecisionRecord) {
			d.Decision.SubjectGroup.Subjects[0].Digest = testDigest("a")
		}},
		{"different exact subject name", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, _ *v1.ArtifactManifest, d *v1.DecisionRecord) {
			d.Decision.SubjectGroup.Subjects[0].Name = "dist/my app – linux amd64.bin"
		}},
		{"SBOM reference mismatch", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, a *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			a.Payload.SBOMRef.ID = "other"
		}},
		{"provenance reference mismatch", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, a *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			a.Payload.Provenance.Reference.Digest = testDigest("a")
		}},
		{"missing SBOM", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, a *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			a.Payload.SBOMRef = nil
		}},
		{"missing provenance", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, a *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			a.Payload.Provenance = nil
		}},
		{"provenance job mismatch", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, a *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			a.Payload.Provenance.ClaimedBuild.Identity.JobID = "2"
		}},
		{"provenance digest mismatch", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, a *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			a.Payload.Provenance.Subjects[0].Digest = testDigest("a")
		}},
		{"provenance name mismatch", func(_ *v1.WorkflowState, _ *v1.EvidenceManifest, a *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			a.Payload.Provenance.Subjects[0].Name = "different"
		}},
		{"decision ID mismatch", func(w *v1.WorkflowState, _ *v1.EvidenceManifest, _ *v1.ArtifactManifest, _ *v1.DecisionRecord) {
			w.State = v1.Decided
			w.DecisionRef = objectRef("other", "a")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, e, a, d := boundRecords()
			tc.change(&w, &e, &a, &d)
			if err := v1.ValidateBindings(w, &e, &a, &d); err == nil {
				t.Fatal("inconsistent records accepted")
			}
		})
	}
	if v1.ValidateBindings(w, nil, &a, &d) == nil || v1.ValidateBindings(w, &e, nil, &d) == nil {
		t.Fatal("ALLOW missing a manifest accepted")
	}
	w, e, a, d = boundRecords()
	e.State = v1.Pending
	w.EvidenceInput.State = v1.Pending
	if v1.ValidateBindings(w, &e, &a, &d) == nil {
		t.Fatal("ALLOW with pending producer accepted")
	}
}

func TestBindingsAllowOnlyMetadataClaims(t *testing.T) {
	w, e, a, d := boundRecords()
	// Agreeing digest metadata cannot establish the actual bytes of em-1.
	w.EvidenceInput.ManifestRef.Digest = testDigest("a")
	d.Decision.EvidenceManifestRef.Digest = testDigest("a")
	a.Payload.Provenance.OriginStatus = provenance.OriginAuthenticated
	a.Payload.Provenance.AuthenticationRef = objectRef("claimed-authentication", "a")
	if err := v1.ValidateBindings(w, &e, &a, &d); err != nil {
		t.Fatal(err)
	}
	// No authentication was performed, and coverage remains UNKNOWN. This helper
	// is not the policy evaluator or publisher enforcement boundary.
	w.State, w.DecisionRef = v1.Decided, objectRef(d.Decision.DecisionID, "b")
	if err := v1.ValidateBindings(w, &e, &a, &d); err != nil {
		t.Fatal(err)
	}
	// Subject set order and additional provenance subjects do not grant release
	// to anything beyond the exact artifact/decision group.
	extra := artifact.Subject{Name: "extra", Digest: testDigest("c")}
	a.Payload.SubjectGroup.Subjects = append(a.Payload.SubjectGroup.Subjects, extra)
	a.Payload.Provenance.Subjects = append(a.Payload.Provenance.Subjects, extra)
	d.Decision.SubjectGroup.Subjects = append([]artifact.Subject{extra}, d.Decision.SubjectGroup.Subjects...)
	if err := v1.ValidateBindings(w, &e, &a, &d); err != nil {
		t.Fatal(err)
	}
}

func TestBindingProducerFailureWithoutManifest(t *testing.T) {
	w := workflow()
	w.EvidenceInput = v1.InputSnapshot{State: v1.Failed, Failure: &v1.InputFailure{Code: v1.ProducerError, Source: v1.VerifierObservation}}
	if err := v1.ValidateBindings(w, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	e := evidenceManifest()
	if v1.ValidateBindings(w, &e, nil, nil) == nil {
		t.Fatal("unreferenced manifest smuggled into failed input")
	}
	for _, verdict := range []decision.Verdict{decision.Deny, decision.Indeterminate} {
		d := v1.DecisionRecord{SchemaVersion: v1.SchemaVersion, Kind: v1.KindDecisionRecord, Decision: decision.Decision{DecisionID: "decision-2", WorkflowID: w.WorkflowID, Build: build.Context{Identity: w.Build.Identity}, Verdict: verdict, Assessment: decision.Assessment{Sufficiency: decision.Insufficient, Compliance: decision.ComplianceNotEvaluated, Trust: decision.TrustNotEvaluated}, Reasons: []decision.ReasonCode{decision.MissingRequiredEvidence, decision.MissingRequiredMetadata, decision.ProducerFailed}, IssuedAt: testTime()}}
		if verdict == decision.Deny {
			d.Decision.Assessment.Compliance = decision.Violated
			d.Decision.Reasons = append(d.Decision.Reasons, decision.ConfirmedPolicyViolation)
		}
		if err := v1.ValidateBindings(w, nil, nil, &d); err != nil {
			t.Fatal(err)
		}
	}
	e.State, e.Failure = v1.Failed, &v1.Failure{Code: v1.ProducerError}
	w.EvidenceInput.ManifestRef = objectRef(e.ManifestID, "e")
	if err := v1.ValidateBindings(w, &e, nil, nil); err != nil {
		t.Fatal(err)
	}
	w.EvidenceInput.Failure.Code = v1.InvalidInput
	if v1.ValidateBindings(w, &e, nil, nil) == nil {
		t.Fatal("failure-code mismatch ignored")
	}
}

func TestPublishedExamples(t *testing.T) {
	// The documentation examples are also checked against the real exported APIs.
	data, err := os.ReadFile("../../docs/phase-1-contracts.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := strings.Split(string(data), "\n```json\n")[1:]
	if len(blocks) != 4 {
		t.Fatalf("expected four contract examples, got %d", len(blocks))
	}
	seen := make(map[v1.Kind]bool)
	for _, block := range blocks {
		body, _, ok := strings.Cut(block, "\n```")
		if !ok {
			t.Fatal("unterminated example")
		}
		var h struct {
			Kind v1.Kind `json:"kind"`
		}
		if err := json.Unmarshal([]byte(body), &h); err != nil {
			t.Fatal(err)
		}
		if seen[h.Kind] {
			t.Fatal("duplicate example kind")
		}
		seen[h.Kind] = true
		t.Run(string(h.Kind), func(t *testing.T) {
			var err error
			switch h.Kind {
			case v1.KindEvidenceManifest:
				_, err = v1.DecodeEvidenceManifest([]byte(body))
			case v1.KindArtifactManifest:
				_, err = v1.DecodeArtifactManifest([]byte(body))
			case v1.KindWorkflowState:
				_, err = v1.DecodeWorkflowState([]byte(body))
			case v1.KindDecisionRecord:
				_, err = v1.DecodeDecisionRecord([]byte(body))
			default:
				t.Fatal("unsupported example kind")
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
