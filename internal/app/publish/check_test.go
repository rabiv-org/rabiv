package publish_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	v1 "github.com/rabiv-org/rabiv/contracts/v1"
	"github.com/rabiv-org/rabiv/internal/app/publish"
	"github.com/rabiv-org/rabiv/internal/app/verify"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	"github.com/rabiv-org/rabiv/internal/domain/build"
	"github.com/rabiv-org/rabiv/internal/domain/decision"
	"github.com/rabiv-org/rabiv/internal/domain/policy"
)

func clock() time.Time { return time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC) }
func allowFixture() v1.DecisionRecord {
	// Synthetic assertions only; no evidence, policy, or origin was verified.
	d := artifact.Digest{Algorithm: "sha256", Value: strings.Repeat("a", 64)}
	ref := func(id string) *artifact.ObjectReference { return &artifact.ObjectReference{ID: id, Digest: d} }
	i := build.Identity{Provider: build.GitLab, Instance: "https://gitlab.example", ProjectID: "1", JobID: "2"}
	expires := clock().Add(time.Minute)
	return v1.DecisionRecord{SchemaVersion: v1.SchemaVersion, Kind: v1.KindDecisionRecord, Decision: decision.Decision{
		DecisionID: "d-1", WorkflowID: "wf-1", Build: build.Context{Identity: i, PipelineID: "3", Source: &build.SourceRevision{RepositoryURI: "https://gitlab.example/repo.git", CommitSHA: strings.Repeat("b", 40)}},
		Verdict: decision.Allow, Assessment: decision.Assessment{Sufficiency: decision.Sufficient, Compliance: decision.Satisfied, Trust: decision.TrustRequirementsMet}, Reasons: []decision.ReasonCode{decision.RequiredChecksPassed}, IssuedAt: clock(), ExpiresAt: &expires,
		SubjectGroup: &artifact.SubjectGroup{ID: "sg-1", Subjects: []artifact.Subject{{Name: "dist/My App – 中.bin", Digest: d}}}, EvidenceManifestRef: ref("em-1"), ArtifactManifestRef: ref("am-1"), ProvenanceRef: ref("prov-1"), SBOMRef: ref("sbom-1"),
		Baseline: &policy.BaselineSnapshot{Reference: policy.Reference{ID: "baseline", Version: "1", Digest: d}}, ProjectProfile: &policy.ProjectProfileSnapshot{Reference: policy.Reference{ID: "profile", Version: "1", Digest: d}, Project: i.Project(), Selection: policy.SelectionAdminDefault},
	}}
}

type source struct {
	raw  []byte
	fail error
}

func (s source) Read(context.Context, string) ([]byte, error) { return s.raw, s.fail }
func reference(id string, raw []byte) artifact.ObjectReference {
	sum := sha256.Sum256(raw)
	return artifact.ObjectReference{ID: id, Digest: artifact.Digest{Algorithm: "sha256", Value: hex.EncodeToString(sum[:])}}
}
func encode(t *testing.T, r v1.DecisionRecord) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func expected() *publish.ExpectedContext {
	r := allowFixture()
	return &publish.ExpectedContext{WorkflowID: r.Decision.WorkflowID, Build: r.Decision.Build.Identity, SubjectGroup: *r.Decision.SubjectGroup}
}
func checker(raw []byte) publish.Checker {
	return publish.Checker{Source: source{raw: raw}, Now: clock, MaxValidity: publish.DefaultMaxValidity}
}

func TestCheckerRejectsUnsafeDecisions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*v1.DecisionRecord)
		want   error
	}{
		{"expired", func(r *v1.DecisionRecord) {
			r.Decision.IssuedAt = clock().Add(-time.Minute)
			x := clock()
			r.Decision.ExpiresAt = &x
		}, publish.ErrFreshness},
		{"future", func(r *v1.DecisionRecord) { r.Decision.IssuedAt = clock().Add(time.Second) }, publish.ErrFreshness},
		{"excessive validity", func(r *v1.DecisionRecord) { x := clock().Add(6 * time.Minute); r.Decision.ExpiresAt = &x }, publish.ErrFreshness},
		{"contradictory ALLOW", func(r *v1.DecisionRecord) { r.Decision.Assessment.Trust = decision.TrustNotEvaluated }, publish.ErrInvalidRecord},
		{"unknown version", func(r *v1.DecisionRecord) { r.SchemaVersion = "v2" }, publish.ErrInvalidRecord},
		{"DENY", func(r *v1.DecisionRecord) {
			r.Decision.Verdict = decision.Deny
			r.Decision.Assessment.Compliance = decision.Violated
			r.Decision.Reasons = []decision.ReasonCode{decision.ConfirmedPolicyViolation}
		}, publish.ErrNonAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := allowFixture()
			tc.change(&r)
			raw := encode(t, r)
			if _, err := checker(raw).Check(context.Background(), reference(r.Decision.DecisionID, raw), expected()); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	r, err := verify.NewDiagnostic(verify.DiagnosticRequest{DecisionID: "diag", WorkflowID: "wf", Build: allowFixture().Decision.Build.Identity}, clock())
	if err != nil {
		t.Fatal(err)
	}
	raw := encode(t, r)
	if _, err := checker(raw).Check(context.Background(), reference("diag", raw), nil); !errors.Is(err, publish.ErrNonAllow) {
		t.Fatal("valid diagnostic misclassified", err)
	}
}

func TestCheckerBindingsAndNoAuthority(t *testing.T) {
	r := allowFixture()
	raw := encode(t, r)
	ref := reference(r.Decision.DecisionID, raw)
	for _, tc := range []struct {
		name   string
		change func(*publish.ExpectedContext)
	}{
		{"workflow", func(e *publish.ExpectedContext) { e.WorkflowID = "other" }},
		{"job", func(e *publish.ExpectedContext) { e.Build.JobID = "4" }},
		{"group", func(e *publish.ExpectedContext) { e.SubjectGroup.ID = "other" }},
		{"subject", func(e *publish.ExpectedContext) { e.SubjectGroup.Subjects[0].Name = "other" }},
		{"digest", func(e *publish.ExpectedContext) { e.SubjectGroup.Subjects[0].Digest.Value = strings.Repeat("c", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := expected()
			tc.change(e)
			if _, err := checker(raw).Check(context.Background(), ref, e); !errors.Is(err, publish.ErrBindingMismatch) {
				t.Fatal(err)
			}
		})
	}
	if _, err := checker(raw).Check(context.Background(), ref, nil); !errors.Is(err, publish.ErrContextUnavailable) {
		t.Fatal(err)
	}
	for range 2 {
		got, err := checker(raw).Check(context.Background(), ref, expected())
		if err != nil || !got.Reference.Equal(ref) {
			t.Fatal(err)
		}
	}
	// Rechecking valid metadata is permitted; no consumed ledger or publication exists.
	badRef := ref
	badRef.ID = "other"
	if _, err := checker(raw).Check(context.Background(), badRef, expected()); !errors.Is(err, publish.ErrBindingMismatch) {
		t.Fatal(err)
	}
	badRef = ref
	badRef.Digest.Value = strings.Repeat("0", 64)
	if _, err := checker(raw).Check(context.Background(), badRef, expected()); !errors.Is(err, publish.ErrDigestMismatch) {
		t.Fatal(err)
	}
}

func TestCheckerInputBoundary(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"schema_version":"v1","schema_version":"v1"}`), []byte(`null`), []byte(`{} {}`), []byte(`{"kind":"DecisionRecord","unknown":1}`)} {
		if _, err := checker(raw).Check(context.Background(), reference("d-1", raw), nil); !errors.Is(err, publish.ErrInvalidRecord) {
			t.Fatal(err)
		}
	}
	raw := []byte(strings.Repeat("x", publish.MaxDecisionBytes+1))
	if _, err := checker(raw).Check(context.Background(), reference("d-1", raw), nil); !errors.Is(err, publish.ErrTooLarge) {
		t.Fatal(err)
	}
	want := errors.New("permission denied")
	c := checker(nil)
	c.Source = source{fail: want}
	if _, err := c.Check(context.Background(), reference("d", nil), nil); !errors.Is(err, want) {
		t.Fatal(err)
	}
	c = checker(encode(t, allowFixture()))
	c.Now = nil
	if _, err := c.Check(context.Background(), reference("d-1", nil), nil); err == nil {
		t.Fatal("missing clock accepted")
	}
	c = checker(encode(t, allowFixture()))
	c.Now = func() time.Time { return time.Time{} }
	if _, err := c.Check(context.Background(), reference("d-1", c.Source.(source).raw), expected()); !errors.Is(err, publish.ErrFreshness) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Check(ctx, reference("d", nil), nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
