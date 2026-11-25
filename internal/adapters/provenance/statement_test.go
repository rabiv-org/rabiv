package provenance

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rabiv-org/rabiv/internal/app/acquire"
	"github.com/rabiv-org/rabiv/internal/domain/artifact"
	domain "github.com/rabiv-org/rabiv/internal/domain/provenance"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte(fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"subject","digest":{"sha256":%q}}],"predicate":{}}`, strings.Repeat("a", 64))))
	f.Add([]byte(`{"predicate":null}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		ref := artifact.ObjectReference{ID: "raw-provenance", Digest: acquire.Hash(data)}
		p, _ := (Parser{}).Parse(data, ref)
		if p != nil && (p.Validate() != nil || !p.Reference.Equal(ref) || p.OriginStatus != "UNAUTHENTICATED" || p.AuthenticationRef != nil || p.ClaimedBuild != nil) {
			t.Fatal("parsed projection fabricated integrity or origin assurance")
		}
	})
}

func TestRunnerInvalidDependencyPreserved(t *testing.T) {
	raw := fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"dist/中","digest":{"sha256":%q}}],"predicate":{"buildDefinition":{"resolvedDependencies":[{"digest":{"sha256":%q}}]}}}`, strings.Repeat("a", 64), strings.Repeat("b", 40))
	ref := artifact.ObjectReference{ID: "raw", Digest: acquire.Hash([]byte(raw))}
	p, issues := (Parser{}).Parse([]byte(raw), ref)
	if p == nil || p.Validate() != nil || p.OriginStatus != domain.OriginUnauthenticated || p.ClaimedBuild != nil || !p.Reference.Equal(ref) || !slices.Contains(issues, "PROVENANCE_INVALID_DEPENDENCY_DIGEST") {
		t.Fatalf("claim normalized or hidden: %+v %v", p, issues)
	}
	if (artifact.Digest{Algorithm: "sha256", Value: strings.Repeat("b", 40)}).Validate() == nil {
		t.Fatal("weakened SHA256")
	}
	for _, input := range []string{`{`, strings.Replace(raw, strings.Repeat("a", 64), strings.Repeat("a", 40), 1), strings.Replace(raw, "dist/中", `dist/\ud800`, 1), strings.Replace(raw, "provenance/v1", "provenance/v99", 1)} {
		claim, issues := (Parser{}).Parse([]byte(input), ref)
		if claim != nil || len(issues) == 0 {
			t.Fatal("malformed/unsupported provenance accepted")
		}
	}
}

func TestNullPredicateRemainsAnInvalidRawClaim(t *testing.T) {
	raw := fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"artifact","digest":{"sha256":%q}}],"predicate":null}`, strings.Repeat("a", 64))
	r := artifact.ObjectReference{ID: "raw", Digest: acquire.Hash([]byte(raw))}
	claim, issues := (Parser{}).Parse([]byte(raw), r)
	if claim != nil || !slices.Contains(issues, "PROVENANCE_PREDICATE_INCOMPLETE") {
		t.Fatal("null predicate presented as a supported projection")
	}
}

func TestExactSubjectProjection(t *testing.T) {
	raw := fmt.Appendf(nil, `{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"original","Name":"alias","digest":{"sha256":%q}}],"Subject":[],"predicate":{}}`, strings.Repeat("a", 64))
	p, issues := (Parser{}).Parse(raw, artifact.ObjectReference{ID: "raw", Digest: acquire.Hash(raw)})
	if p == nil || len(p.Subjects) != 1 || p.Subjects[0].Name != "original" || len(issues) != 0 {
		t.Fatalf("case variant changed the canonical projection: %+v %v", p, issues)
	}
}
