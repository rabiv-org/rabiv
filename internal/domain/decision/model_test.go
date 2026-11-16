package decision_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/decision"
	"github.com/rabiv-org/rabiv/internal/domain/policy"
)

func allow() decision.Decision {
	digest := artifact.Digest{Algorithm: "sha256", Value: strings.Repeat("a", 64)}
	ref := func(id string) *artifact.ObjectReference { return &artifact.ObjectReference{ID: id, Digest: digest} }
	identity := build.Identity{Provider: build.GitLab, Instance: "https://gitlab.example", ProjectID: "88968390", JobID: "18071578854"}
	issued := time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC)
	expires := issued.Add(time.Minute)
	return decision.Decision{
		DecisionID: "decision-1", WorkflowID: "wf-1",
		Build:      build.Context{Identity: identity, PipelineID: "3074413145", Source: &build.SourceRevision{RepositoryURI: "https://gitlab.example/group/repo.git", CommitSHA: strings.Repeat("a", 40)}},
		Verdict:    decision.Allow,
		Assessment: decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsMet},
		Reasons:    []decision.ReasonCode{decision.RequiredChecksPassed}, IssuedAt: issued, ExpiresAt: &expires,
		SubjectGroup:        &artifact.SubjectGroup{ID: "sg-1", Subjects: []artifact.Subject{{Name: "dist/My App.bin", Digest: digest}}},
		EvidenceManifestRef: ref("em-1"), ArtifactManifestRef: ref("am-1"), ProvenanceRef: ref("provenance-1"), SBOMRef: ref("sbom-1"),
		Baseline:       &policy.BaselineSnapshot{Reference: policy.Reference{ID: "baseline", Version: "1", Digest: digest}},
		ProjectProfile: &policy.ProjectProfileSnapshot{Reference: policy.Reference{ID: "default-profile", Version: "1", Digest: digest}, Project: identity.Project(), Selection: policy.SelectionAdminDefault},
	}
}

func TestAllowRequirements(t *testing.T) {
	if err := allow().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*decision.Decision)
	}{
		{"decision identity", func(d *decision.Decision) { d.DecisionID = "" }},
		{"workflow identity", func(d *decision.Decision) { d.WorkflowID = "" }},
		{"provider", func(d *decision.Decision) { d.Build.Identity.Provider = "" }},
		{"instance", func(d *decision.Decision) { d.Build.Identity.Instance = "" }},
		{"project", func(d *decision.Decision) { d.Build.Identity.ProjectID = "" }},
		{"job", func(d *decision.Decision) { d.Build.Identity.JobID = "" }},
		{"pipeline", func(d *decision.Decision) { d.Build.PipelineID = "" }},
		{"source", func(d *decision.Decision) { d.Build.Source = nil }},
		{"repository", func(d *decision.Decision) { d.Build.Source.RepositoryURI = "" }},
		{"commit", func(d *decision.Decision) { d.Build.Source.CommitSHA = "" }},
		{"evidence reference", func(d *decision.Decision) { d.EvidenceManifestRef = nil }},
		{"artifact reference", func(d *decision.Decision) { d.ArtifactManifestRef = nil }},
		{"provenance reference", func(d *decision.Decision) { d.ProvenanceRef = nil }},
		{"SBOM reference", func(d *decision.Decision) { d.SBOMRef = nil }},
		{"baseline", func(d *decision.Decision) { d.Baseline = nil }},
		{"profile", func(d *decision.Decision) { d.ProjectProfile = nil }},
		{"profile project binding", func(d *decision.Decision) { d.ProjectProfile.Project.ProjectID = "2" }},
		{"subject group", func(d *decision.Decision) { d.SubjectGroup = nil }},
		{"empty group", func(d *decision.Decision) { d.SubjectGroup.Subjects = []artifact.Subject{} }},
		{"missing expiry", func(d *decision.Decision) { d.ExpiresAt = nil }},
		{"equal expiry", func(d *decision.Decision) { x := d.IssuedAt; d.ExpiresAt = &x }},
		{"reversed expiry", func(d *decision.Decision) { x := d.IssuedAt.Add(-time.Second); d.ExpiresAt = &x }},
		{"missing issue time", func(d *decision.Decision) { d.IssuedAt = time.Time{} }},
		{"invalid reference", func(d *decision.Decision) { d.SBOMRef.Digest.Value = "bad" }},
		{"missing reasons", func(d *decision.Decision) { d.Reasons = nil }},
		{"duplicate reason", func(d *decision.Decision) { d.Reasons = append(d.Reasons, d.Reasons[0]) }},
		{"unknown reason", func(d *decision.Decision) { d.Reasons = []decision.ReasonCode{"OTHER"} }},
		{"unknown verdict", func(d *decision.Decision) { d.Verdict = "PASS" }},
		{"unknown assessment", func(d *decision.Decision) { d.Assessment.Trust = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := allow()
			tc.change(&d)
			if err := d.Validate(); err == nil {
				t.Fatal("accepted invalid ALLOW")
			}
		})
	}
	d := allow()
	d.Build.Source.Ref = ""
	if err := d.Validate(); err != nil {
		t.Fatal("source ref is optional:", err)
	}
	d.ProjectProfile.Selection = policy.SelectionExplicit
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestVerdictAssessmentReasonMatrix(t *testing.T) {
	for _, tc := range []struct {
		name       string
		verdict    decision.Verdict
		assessment decision.Assessment
		reasons    []decision.ReasonCode
		valid      bool
	}{
		{"allow", decision.Allow, decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsMet}, []decision.ReasonCode{decision.RequiredChecksPassed}, true},
		{"allow insufficient", decision.Allow, decision.Assessment{Sufficiency: decision.Insufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsMet}, []decision.ReasonCode{decision.RequiredChecksPassed}, false},
		{"allow violated", decision.Allow, decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Violated, Trust: decision.TrustRequirementsMet}, []decision.ReasonCode{decision.RequiredChecksPassed}, false},
		{"allow unmet trust", decision.Allow, decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsNotMet}, []decision.ReasonCode{decision.RequiredChecksPassed}, false},
		{"allow diagnostic", decision.Allow, decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsMet}, []decision.ReasonCode{decision.RequiredChecksPassed, decision.UntrustedInput}, false},
		{"deny confirmed", decision.Deny, decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Violated, Trust: decision.TrustRequirementsMet}, []decision.ReasonCode{decision.ConfirmedPolicyViolation}, true},
		{"deny missing confirmation", decision.Deny, decision.Assessment{Sufficiency: decision.Insufficient, Compliance: decision.Violated, Trust: decision.TrustNotEvaluated}, []decision.ReasonCode{decision.EvidenceGap}, false},
		{"deny compliance contradicts", decision.Deny, decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsMet}, []decision.ReasonCode{decision.ConfirmedPolicyViolation}, false},
		{"authorization violation", decision.Deny, decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Violated, Trust: decision.TrustRequirementsNotMet}, []decision.ReasonCode{decision.PolicyAuthorizationViolation}, true},
		{"authorization with met trust", decision.Deny, decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Violated, Trust: decision.TrustRequirementsMet}, []decision.ReasonCode{decision.PolicyAuthorizationViolation}, false},
		{"indeterminate checks pending", decision.Indeterminate, decision.Assessment{Sufficiency: decision.SufficiencyUnknown, Compliance: decision.ComplianceNotEvaluated, Trust: decision.TrustNotEvaluated}, []decision.ReasonCode{decision.ChecksIncomplete}, true},
		{"indeterminate all positive", decision.Indeterminate, decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsMet}, []decision.ReasonCode{decision.ChecksIncomplete}, false},
		{"indeterminate confirmed violation", decision.Indeterminate, decision.Assessment{Sufficiency: decision.Insufficient, Compliance: decision.Violated, Trust: decision.TrustNotEvaluated}, []decision.ReasonCode{decision.ConfirmedPolicyViolation}, false},
		{"indeterminate success reason", decision.Indeterminate, decision.Assessment{Sufficiency: decision.SufficiencyUnknown, Compliance: decision.ComplianceNotEvaluated, Trust: decision.TrustNotEvaluated}, []decision.ReasonCode{decision.RequiredChecksPassed}, false},
		{"indeterminate untrusted", decision.Indeterminate, decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsNotMet}, []decision.ReasonCode{decision.UntrustedInput}, true},
		{"mismatch diagnostics", decision.Indeterminate, decision.Assessment{Sufficiency: decision.Insufficient, Compliance: decision.ComplianceNotEvaluated, Trust: decision.TrustRequirementsNotMet}, []decision.ReasonCode{decision.ConsistencyMismatch}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := allow()
			d.Verdict, d.Assessment, d.Reasons = tc.verdict, tc.assessment, tc.reasons
			if err := d.Validate(); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
	for _, reason := range []decision.ReasonCode{decision.MissingRequiredEvidence, decision.MissingRequiredMetadata, decision.EvidenceGap, decision.ProducerFailed, decision.InputTimeout} {
		t.Run(string(reason), func(t *testing.T) {
			d := allow()
			d.Verdict = decision.Indeterminate
			d.Assessment.Compliance = decision.ComplianceNotEvaluated
			d.Reasons = []decision.ReasonCode{reason}
			if d.Validate() == nil {
				t.Fatal("diagnostic accepted with sufficient assessment")
			}
			d.Assessment.Sufficiency = decision.Insufficient
			if err := d.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMissingInputsCanDenyOrRemainIndeterminate(t *testing.T) {
	for _, verdict := range []decision.Verdict{decision.Deny, decision.Indeterminate} {
		t.Run(string(verdict), func(t *testing.T) {
			d := decision.Decision{DecisionID: "decision-2", WorkflowID: "wf-2", Build: build.Context{Identity: allow().Build.Identity}, Verdict: verdict, Assessment: decision.Assessment{Sufficiency: decision.Insufficient, Compliance: decision.ComplianceNotEvaluated, Trust: decision.TrustNotEvaluated}, Reasons: []decision.ReasonCode{decision.MissingRequiredEvidence, decision.MissingRequiredMetadata}, IssuedAt: allow().IssuedAt}
			if verdict == decision.Deny {
				d.Assessment.Compliance = decision.Violated
				d.Reasons = append(d.Reasons, decision.ConfirmedPolicyViolation)
			}
			if err := d.Validate(); err != nil {
				t.Fatal(err)
			}
			d.Reasons = d.Reasons[1:]
			if d.Validate() == nil {
				t.Fatal("missing reference not explicitly represented")
			}
		})
	}
}
