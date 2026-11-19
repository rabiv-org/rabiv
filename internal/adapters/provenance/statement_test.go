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
