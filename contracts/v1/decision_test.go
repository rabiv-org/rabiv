package v1_test

import (
	"reflect"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/domain/decision"
	"github.com/rabiv-org/rabiv/internal/domain/policy"
)

func decisionRecord() v1.DecisionRecord {
	a := artifactManifest()
	expires := testTime().Add(time.Minute)
	return v1.DecisionRecord{SchemaVersion: v1.SchemaVersion, Kind: v1.KindDecisionRecord, Decision: decision.Decision{
		DecisionID: "decision-1", WorkflowID: "wf-1", Build: buildContext(), Verdict: decision.Allow,
		Assessment: decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsMet},
		Reasons:    []decision.ReasonCode{decision.RequiredChecksPassed}, IssuedAt: testTime(), ExpiresAt: &expires,
		SubjectGroup: &a.Payload.SubjectGroup, EvidenceManifestRef: objectRef("em-1", "e"), ArtifactManifestRef: objectRef("am-1", "f"),
		ProvenanceRef: &a.Payload.Provenance.Reference, SBOMRef: a.Payload.SBOMRef,
		Baseline:       &policy.BaselineSnapshot{Reference: policy.Reference{ID: "baseline", Version: "1", Digest: testDigest("a")}},
		ProjectProfile: &policy.ProjectProfileSnapshot{Reference: policy.Reference{ID: "default-profile", Version: "1", Digest: testDigest("b")}, Project: buildContext().Identity.Project(), Selection: policy.SelectionAdminDefault},
	}}
}

func TestDecisionRecord(t *testing.T) {
	r := decisionRecord()
	decoded, err := v1.DecodeDecisionRecord(marshal(t, r))
	if err != nil || !reflect.DeepEqual(r, decoded) {
		t.Fatalf("decision round-trip: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*v1.DecisionRecord)
	}{
		{"version", func(r *v1.DecisionRecord) { r.SchemaVersion = "v2" }},
		{"kind", func(r *v1.DecisionRecord) { r.Kind = v1.KindEvidenceManifest }},
		{"contradictory ALLOW", func(r *v1.DecisionRecord) { r.Decision.Assessment.Compliance = decision.Violated }},
		{"diagnostic ALLOW", func(r *v1.DecisionRecord) { r.Decision.Reasons = append(r.Decision.Reasons, decision.ProducerFailed) }},
		{"missing ALLOW input", func(r *v1.DecisionRecord) { r.Decision.EvidenceManifestRef = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := decisionRecord()
			tc.change(&r)
			if _, err := v1.DecodeDecisionRecord(marshal(t, r)); err == nil {
				t.Fatal("invalid decision decoded")
			}
		})
	}
}
